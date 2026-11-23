import { inflateSync } from 'node:zlib';
import { parse } from 'node-html-parser';
import { curlAdvisoryWindow, pauseProjectSource, reserveProjectSource, retryAfter, terms } from './engine-routing.mjs';
import { fetchBoundedPublicBytes } from './url-reader.js';
import { datedCurlAdvisoryExcerpt, selectEvidence } from './evidence-select.mjs';

// A combined search may read one original page on reviewed documentation paths.
// The standalone reader still applies its regular URL, size, and timeout limits.
const paths = new Map([
    ['www.postgresql.org', /^\/docs\/(?:current|\d+)\//u],
    ['docs.python.org', /^\/3(?:\.(?:1[1-9]|[2-9]\d))?\/(?:library|reference|howto|tutorial|using)\//u],
    ['developer.mozilla.org', /^\/[a-z]{2,3}(?:-[a-z0-9]{2,8})?\/docs\/Web\//iu],
    ['kubernetes.io', /^\/docs\//u],
    ['specs.opencontainers.org', /^\/(?:image|runtime|distribution)-spec(?:\/[a-z0-9-]+)?\/?$/u],
    ['www.python-httpx.org', /^\/(?:(?:advanced\/[a-z0-9_-]+|api|async|compatibility|environment_variables|exceptions|logging|quickstart)\/)?$/u],
]);

const advisoryIndexes = new Map([
    ['mozilla.org', {url: 'https://www.mozilla.org/en-US/security/advisories/',
        path: /^\/en-US\/security\/advisories\/mfsa\d{4}-\d+\/?$/u, title: /\bFirefox\b/iu}],
    ['postgresql.org', {url: 'https://www.postgresql.org/about/newsarchive/security/',
        path: /^\/about\/news\/[a-z0-9-]+\/?$/u, title: /^PostgreSQL\s+\d/iu, versionedNotes: true}],
    ['python.org', {url: 'https://www.python.org/downloads/',
        path: /^\/downloads\/release\/python-\d{3,7}\/$/u, title: /^Python \d+\.\d+\.\d+$/u,
        inlineReleaseDates: true}],
    ['go.dev', {url: 'https://go.dev/doc/devel/release', title: 'Go release history', selectExcerpt: datedGoReleaseExcerpt}],
    ['curl.se', {url: 'https://curl.se/docs/security.html', title: 'curl published advisories', selectExcerpt: datedCurlAdvisoryExcerpt}],
]);
const dateLabel = /^(?:#{1,6}\s+|(?:posted|published|announced)(?: on)?\s*:?\s*)(\d{4}-\d{2}-\d{2}|[A-Z][a-z]+ \d{1,2}, \d{4})\b/iu;
const inlineDate = /^\s+([A-Za-z]{3,9}\.? \d{1,2}, \d{4})\b/u;
const PYTHON_INVENTORY = 'https://docs.python.org/3/objects.inv';
const PYTHON_INVENTORY_KEY = 'python-docs-inventory';
const REDHAT_CSAF = 'https://access.redhat.com/hydra/rest/securitydata/csaf.json';
const REDHAT_CSAF_KEY = 'redhat-security-data';
const HTTPX_INDEX = 'https://www.python-httpx.org/search/search_index.json';
const HTTPX_ORIGIN = new URL(HTTPX_INDEX).origin;
const GITHUB_DOCS_SEARCH = 'https://docs.github.com/api/search/v1';
const IETF_DOCUMENTS = 'https://datatracker.ietf.org/api/v1/doc/document/';
const INVENTORY_COMPRESSED_LIMIT = 256 * 1024;
const INVENTORY_TEXT_LIMIT = 2 * 1024 * 1024;
let inventory = null;
let inventoryExpires = 0;
let inventoryFetch;
let httpxIndex;
let httpxIndexExpires = 0;

async function fetchPacedBytes(key, url, limit, timeout, signal) {
    if (reserveProjectSource(key, timeout)) return {bytes: null, unavailable: true};
    const response = await fetchBoundedPublicBytes(url, limit, timeout, signal);
    if (response.challenged) pauseProjectSource(key, 'CAPTCHA');
    else if (response.status === 401 || response.status === 403) pauseProjectSource(key, 'access denied');
    else if (response.status === 429) pauseProjectSource(key, 'throttled', retryAfter(response.retry));
    return {...response, unavailable: response.challenged || response.status !== 200};
}

function decodeInventory(bytes) {
    const body = Buffer.from(bytes);
    let end = -1;
    for (let line = 0; line < 4; line++) {
        end = body.indexOf(10, end + 1);
        if (end < 0 || end > 512) return null;
    }
    const header = body.subarray(0, end).toString('ascii').split('\n');
    if (header[0] !== '# Sphinx inventory version 2' || header[1] !== '# Project: Python' ||
        !header[3].includes('compressed using zlib')) return null;
    return inflateSync(body.subarray(end + 1), {maxOutputLength: INVENTORY_TEXT_LIMIT}).toString('utf8');
}

async function readInventory(timeout, signal) {
    if (Date.now() < inventoryExpires) return inventory;
    if (!inventoryFetch) {
        inventoryFetch = fetchPacedBytes(PYTHON_INVENTORY_KEY, PYTHON_INVENTORY, INVENTORY_COMPRESSED_LIMIT, timeout, signal)
            .then(({bytes, status}) => ({result: bytes && decodeInventory(bytes), attempted: status !== undefined}))
            .catch(() => ({result: null, attempted: true}))
            .then(({result, attempted}) => {
                inventory = result;
                if (attempted) inventoryExpires = Date.now() + (result ? 86400000 : 300000);
                return result;
            }).finally(() => { inventoryFetch = undefined; });
    }
    return inventoryFetch;
}

export async function pythonInventoryLead(query, intent, remaining, signal) {
    const {site, category} = intent;
    if (site?.hostname !== 'docs.python.org' || category !== 'known-site' || remaining < 500 ||
        /(^|\s)!|\b(?:inurl|intitle|filetype):|"/iu.test(query)) return undefined;
    const text = query.trim().replace(/^site:\S+\s*/iu, '');
    const symbols = new Set(text.match(/\b(?:(?:[a-zA-Z_]\w*\.)+[a-zA-Z_]\w*|[A-Z][a-z0-9]+[A-Z]\w*)\b/gu));
    if (symbols.size !== 1) return undefined;
    const [symbol] = symbols;
    const body = await readInventory(Math.min(remaining, 2500), signal);
    if (!body) return undefined;
    const matches = new Map();
    for (const match of body.matchAll(/^(\S+) py:\S+ -?\d+ (\S+) /gmu)) {
        const [, name, uri] = match;
        if (name !== symbol && (symbol.includes('.') || !name.endsWith('.' + symbol))) continue;
        const section = URL.parse(uri.endsWith('$') ? uri.slice(0, -1) + name : uri, PYTHON_INVENTORY);
        if (!section || section.origin !== 'https://docs.python.org' || section.search || !section.hash ||
            !paths.get(section.hostname)?.test(section.pathname) || !allowed(section, site)) continue;
        const page = new URL(section);
        page.hash = '';
        matches.set(section.href, {url: page.href, title: name, section_url: section.href, source_index: PYTHON_INVENTORY,
            content: '', engines: [], score: 1});
    }
    return matches.size === 1 ? matches.values().next().value : undefined;
}

async function readHttpxIndex(remaining, signal) {
    if (Date.now() < httpxIndexExpires) return httpxIndex;
    try {
        const {bytes} = await fetchPacedBytes('httpx-docs-index', HTTPX_INDEX, 256 * 1024, Math.min(2500, remaining), signal);
        const records = bytes && JSON.parse(Buffer.from(bytes).toString('utf8')).docs;
        if (!Array.isArray(records)) return [];
        httpxIndex = records.slice(0, 400);
        httpxIndexExpires = Date.now() + 3600000;
        return httpxIndex;
    } catch {
        return [];
    }
}

export async function httpxDocsLeads(query, intent, remaining, signal) {
    if (remaining < 500 || !['general', 'known-site', 'documentation'].includes(intent.category) ||
        /(^|\s)!|\b(?:inurl|intitle|filetype):|"/iu.test(query) || (!intent.site && /\bsite:/iu.test(query))) return [];
    const site = intent.site;
    if (site ? !['python-httpx.org', 'www.python-httpx.org'].includes(site.hostname) : !/\bhttpx\b/iu.test(query)) return [];
    const keywords = intent.originalTerms.filter(word => word !== 'httpx');
    if (keywords.length < 2 || keywords.length > 20) return [];
    const phrases = keywords.slice(1).map((word, index) => keywords[index] + ' ' + word);
    const pages = new Map();
    for (const record of await readHttpxIndex(remaining, signal)) {
        if (typeof record?.location !== 'string' || typeof record.title !== 'string' || typeof record.text !== 'string') continue;
        const section = URL.parse(record.location, HTTPX_ORIGIN);
        if (!section || section.origin !== HTTPX_ORIGIN || !allowed(section, site)) continue;
        const title = record.title.replace(/<[^>]+>/gu, '').trim().slice(0, 180);
        if (!title) continue;
        const labels = new Set(terms(title + ' ' + section.pathname));
        const body = record.text.toLowerCase();
        const tokens = new Set(terms(body));
        const overlap = keywords.filter(word => tokens.has(word) || labels.has(word)).length;
        if (overlap < Math.max(2, Math.ceil(keywords.length / 2))) continue;
        const rank = overlap + .55 * keywords.filter(word => labels.has(word)).length +
            1.5 * phrases.filter(phrase => body.includes(phrase)).length;
        const page = new URL(section);
        page.hash = '';
        if ((pages.get(page.href)?.rank ?? 0) >= rank) continue;
        pages.set(page.href, {rank, lead: {url: page.href, title, section_url: section.href,
            source_index: HTTPX_INDEX, content: '', engines: [], score: 1}});
    }
    return [...pages.values()].sort((left, right) => right.rank - left.rank).slice(0, 3).map(row => row.lead);
}

export function githubDocsSearch(query, intent) {
    if (intent.category !== 'known-site' || intent.site?.hostname !== 'docs.github.com' ||
        /\b(?:inurl|intitle|filetype):|\b(?:enterprise (?:server|cloud)|GHES|GHEC)\b|(^|\s)!/iu.test(query) ||
        /\/enterprise-(?:server|cloud)@/iu.test(intent.site.pathname ?? '')) return null;
    const text = query.trim().replace(/^site:\S+\s*/iu, '');
    if (!text || text.length > 200) return null;
    const url = new URL(GITHUB_DOCS_SEARCH);
    url.search = new URLSearchParams({query: text, client_name: 'open-source-web-search', language: 'en', size: '25'});
    const product = /^(?:GitHub )?(actions|codespaces|copilot|packages|pages)\b/iu.exec(text)?.[1]?.toLowerCase();
    return {url, product};
}

export async function githubDocsLeads(query, intent, remaining, signal) {
    const lookup = githubDocsSearch(query, intent);
    if (!lookup || remaining < 500) return [];
    try {
        const {bytes} = await fetchPacedBytes('github-docs-search', lookup.url.href, 64 * 1024, Math.min(2200, remaining), signal);
        const records = bytes && JSON.parse(Buffer.from(bytes).toString('utf8'))?.hits;
        if (!Array.isArray(records)) return [];
        const leads = new Map();
        for (const row of records.slice(0, 25)) {
            const href = row?.url ?? row?.href;
            if (typeof href !== 'string' || typeof row?.title !== 'string') continue;
            const address = URL.parse(href, lookup.url);
            if (!address || address.origin !== lookup.url.origin || address.username || address.password || address.search || address.hash ||
                !/^\/en\/(?:[a-z0-9_-]+\/)*[a-z0-9_-]+\/?$/u.test(address.pathname) ||
                !withinSite(address, intent.site) || leads.has(address.href)) continue;
            const productMatch = Boolean(lookup.product && address.pathname.startsWith(`/en/${lookup.product}/`));
            leads.set(address.href, {url: address.href, title: row.title, source_index: lookup.url.href,
                productMatch, content: '', engines: [], score: 1});
        }
        return [...leads.values()].sort((a, b) => Number(b.productMatch) - Number(a.productMatch)).slice(0, 5)
            .map(({productMatch, ...lead}) => lead);
    } catch {
        return [];
    }
}

export function advisoryIndex(intent, query) {
    if (!intent.dateWindow) return undefined;
    const openshift = /\bOpenShift\b/iu.test(query) &&
        !/\b(?:AI|Virtualization|Dedicated|MicroShift|ROSA|Operators?|Dev Spaces)\b/iu.test(query);
    const kernel = /\b(?:RHEL|Red Hat Enterprise Linux)\b/iu.test(query) && /\bkernel\b/iu.test(query);
    if (intent.advisory && !intent.site && openshift !== kernel &&
        !/\b(?:CVE-|RHSA[-:]\d|v?\d+\.\d+)/iu.test(query)) {
        const day = (time) => new Date(time).toISOString().slice(0, 10);
        const [start, end] = intent.dateWindow;
        const from = day(start), to = day(end);
        const pkg = openshift ? 'rhcos-x86_64' : 'kernel';
        const count = openshift ? 5 : 2;
        const url = new URL(REDHAT_CSAF);
        url.search = new URLSearchParams({package: pkg, after: day(start - 86400000),
            before: day(end + 86400000), per_page: String(count)});
        return {url: url.href, fetchLeads: (remaining, signal) => redHatAdvisories(url.href, from, to, count, openshift, remaining, signal),
            ...(openshift && {leadDetail: 'The publisher index covers only advisories involving the RHCOS package. Open an original advisory to verify affected products, versions and dates.'})};
    }
    const entry = intent.advisory && !intent.site && advisoryIndexes.get(intent.publisher?.[1]);
    if (intent.advisory && intent.publisher?.[1] === 'openssl-library.org' &&
        !/\b(?:CVE-|v?\d+\.\d+|LibreSSL|BoringSSL|Debian|Ubuntu|Red Hat|RHEL)\b|\b(?:on|for)\s+(?:Windows|Linux|macOS)\b/iu.test(query)) {
        const url = intent.publisher[2];
        if (!withinSite(new URL(url), intent.site)) return undefined;
        return {url, fetchLeads: (remaining, signal) => openSslAdvisories(url, intent.dateWindow, remaining, signal)};
    }
    if (!entry) return undefined;
    if (entry.selectExcerpt === datedGoReleaseExcerpt)
        return {...entry, version: /\bGo\s+(\d+\.\d+(?:\.\d+)?)(?![\w.])/iu.exec(query)?.[1]};
    if (entry.selectExcerpt === datedCurlAdvisoryExcerpt && !curlAdvisoryWindow(query, intent)) return undefined;
    if (entry.versionedNotes)
        return {...entry, version: /\bPostgreSQL\s+v?(\d{1,2}(?:\.\d{1,3}){0,2})(?![\w.])/iu.exec(query)?.[1]};
    if (!entry.inlineReleaseDates) return entry;
    const version = /\bPython\s+(\d+\.\d+(?:\.\d+)?)(?![\w.])/iu.exec(query)?.[1];
    return version ? {...entry, version} : undefined;
}

async function openSslAdvisories(index, window, remaining, signal) {
    try {
        const {bytes, unavailable} = await fetchPacedBytes('openssl-advisory-index', index, 256 * 1024, Math.min(2200, remaining), signal);
        if (!bytes) return {state: unavailable ? 'provider_unavailable' : 'insufficient_evidence', leads: []};
        const rows = parse(Buffer.from(bytes).toString('utf8')).querySelectorAll('tbody tr');
        const leads = new Map();
        for (const row of rows) {
            const dateLabel = row.querySelector('td')?.text.trim();
            if (!/^\d{1,2} [A-Z][a-z]{2} \d{4}$/u.test(dateLabel ?? '')) continue;
            const date = Date.parse(`${dateLabel} UTC`);
            if (!Number.isFinite(date) || date < window[0] || date > window[1]) continue;
            const parsed = new Date(date);
            if (parsed.getUTCDate() !== Number(dateLabel.split(' ', 1)[0])) continue;
            const day = parsed.toISOString().slice(0, 10);
            const path = `/news/secadv/${day.replaceAll('-', '')}.txt`;
            if (!row.querySelectorAll('a').some(link => link.getAttribute('href') === path && link.text.trim() === 'Security Advisory')) continue;
            const url = new URL(path, index).href;
            leads.set(day, {url, title: `OpenSSL Security Advisory (${day})`, listed_date: day,
                source_index: index, engines: [], content: '', score: 1});
        }
        return {state: 'insufficient_evidence', leads: [...leads.values()].sort((a, b) => b.listed_date.localeCompare(a.listed_date)).slice(0, 5)};
    } catch {
        return {state: 'provider_unavailable', leads: []};
    }
}

async function redHatAdvisories(url, from, to, count, openshift, remaining, signal) {
    try {
        const {bytes, unavailable} = await fetchPacedBytes(REDHAT_CSAF_KEY, url, 96 * 1024, Math.min(2500, remaining), signal);
        const records = bytes ? JSON.parse(Buffer.from(bytes).toString('utf8')) : [];
        const leads = [];
        for (const row of Array.isArray(records) ? records.slice(0, count) : []) {
            const id = row?.RHSA;
            const date = typeof row?.released_on === 'string' && row.released_on.slice(0, 10);
            if (typeof id !== 'string' || !/^RHSA-\d{4}:\d+$/u.test(id) ||
                !/^\d{4}-\d{2}-\d{2}$/u.test(date) || date < from || date > to) continue;
            if (openshift && (!Array.isArray(row.released_packages) ||
                !row.released_packages.some(pkg => typeof pkg === 'string' && pkg.startsWith('rhcos-x86_64-')))) continue;
            const title = openshift ? `${id} Red Hat advisory mentioning RHCOS` : `${id} Red Hat kernel advisory`;
            leads.push({url: `https://access.redhat.com/errata/${id}`, title,
                listed_date: date, source_index: url, engines: [], content: '', score: 1});
        }
        return {state: unavailable ? 'provider_unavailable' : 'insufficient_evidence', leads};
    } catch {
        return {state: 'provider_unavailable', leads: []};
    }
}

export function exactTechnicalRecord(query, intent) {
    if (intent.category === 'fresh' || /(^|\s)!|\b(?:inurl|intitle|filetype):/iu.test(query) ||
        (!intent.site && /\bsite:/iu.test(query))) return undefined;
    const identifiers = new Set(Array.from(query.matchAll(/\b(RFC|PEP)[\s-]+(\d{1,5})(?!\d)/giu),
        ([, kind, number]) => `${kind.toUpperCase()} ${Number(number)}`));
    if (!/\b(?:compare|versus|vs|differences?|compatib\w*)\b/iu.test(query))
        for (const [, version] of query.matchAll(/\b(?:GPL|GNU General Public License)(?:\s+(?:version\s+|v)?|-|v)([123])(?:\.0)?(?![\w.])/giu))
            identifiers.add(`GPL ${version}`);
    if (identifiers.size !== 1) return undefined;
    const [title] = identifiers;
    const [kind, number] = title.split(' ');
    const site = intent.site;
    const datatracker = site && ['ietf.org', 'datatracker.ietf.org'].includes(site.hostname);
    let address;
    if (kind === 'RFC') address = datatracker ? `https://datatracker.ietf.org/doc/html/rfc${number}`
        : `https://www.rfc-editor.org/rfc/rfc${number}.html`;
    else if (kind === 'PEP') address = `https://peps.python.org/pep-${number.padStart(4, '0')}/`;
    else address = `https://www.gnu.org/licenses/${number === '3' ? '' : 'old-licenses/'}gpl-${number}.0.en.html`;
    const url = new URL(address);
    if (site && url.hostname !== site.hostname && !url.hostname.endsWith('.' + site.hostname)) return undefined;
    if (site?.pathname && url.pathname !== site.pathname && !url.pathname.startsWith(site.pathname + '/')) return undefined;
    return {url: url.href, title};
}

export function ietfSearch(query, intent) {
    if (intent.category === 'fresh' || /(^|\s)!|\b(?:inurl|intitle|filetype):/iu.test(query) ||
        (!intent.site && /\bsite:/iu.test(query))) return null;
    const host = intent.site?.hostname;
    if (host && !['ietf.org', 'datatracker.ietf.org', 'rfc-editor.org', 'www.rfc-editor.org'].includes(host)) return null;
    const text = query.replace(/^site:\S+\s*/iu, '');
    if (!host && !/\b(?:IETF|RFCs?|OAuth|HTTP\/?[123]?|DNS|TLS|QUIC|SMTP|TCP|BGP|SSH)\b/iu.test(text)) return null;
    const context = /^(?:IETF|RFCS?|HTTP|DNS|TLS|QUIC|SMTP|TCP|BGP|SSH|IPV[46]|URLS?|API|CODE|FLOW|DOCS)$/u;
    const topics = [...new Set(text.match(/\b[A-Z][A-Z\d]{3,11}\b/gu) ?? [])].filter(word => !context.test(word));
    if (topics.length !== 1) return null;
    const [topic] = topics;
    const url = new URL(IETF_DOCUMENTS);
    url.search = new URLSearchParams({name__startswith: 'rfc', abstract__icontains: topic, limit: '8'});
    return {url, topic, datatracker: host === 'ietf.org' || host === 'datatracker.ietf.org'};
}

export async function ietfLeads(query, intent, remaining, signal) {
    const lookup = ietfSearch(query, intent);
    if (!lookup || remaining < 500) return [];
    try {
        const {bytes} = await fetchPacedBytes('ietf-datatracker', lookup.url.href, 64 * 1024, Math.min(1800, remaining), signal);
        const records = bytes && JSON.parse(Buffer.from(bytes).toString('utf8'))?.objects;
        const word = new RegExp(`\\b${lookup.topic}\\b`, 'iu');
        const leads = new Map();
        for (const record of Array.isArray(records) ? records.slice(0, 8) : []) {
            if (typeof record?.name !== 'string' || !/^rfc[1-9]\d{0,4}$/u.test(record.name) ||
                typeof record.title !== 'string' || record.title.length > 240 || typeof record.abstract !== 'string' ||
                !word.test(record.abstract)) continue;
            const initials = record.title.split(/[\s-]+/u).filter(part => !/^(?:a|an|and|by|for|of|the|to)$/iu.test(part))
                .map(part => part[0]).join('').toUpperCase();
            if (!word.test(record.title) && !initials.startsWith(lookup.topic)) continue;
            const address = lookup.datatracker ? `https://datatracker.ietf.org/doc/html/${record.name}`
                : `https://www.rfc-editor.org/rfc/${record.name}.html`;
            if (withinSite(new URL(address), intent.site)) {
                leads.set(address, {url: address, title: record.title, source_index: lookup.url.href,
                    engines: [], content: '', score: 1});
            }
        }
        return [...leads.values()].slice(0, 3);
    } catch {
        return [];
    }
}

export function datedAdvisoryLeads(markdown, entry, window) {
    const origin = new URL(entry.url).origin;
    const lines = markdown.split('\n');
    const results = new Map();
    const notes = new Map();
    let headingDate;
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i].replaceAll('**', '').trim();
        if (/^#{1,6}\s/u.test(line) && !line.includes('](')) headingDate = dateLabel.exec(line)?.[1];
        for (const match of line.matchAll(/\[([^\]\n]+)\]\(([^\s)]+)\)/gu)) {
            const [, title, href] = match;
            const url = URL.parse(href, entry.url);
            if (!url || url.origin !== origin || url.search || url.hash || !entry.path.test(url.pathname) || !entry.title.test(title)) continue;
            const datedLine = /^#{1,6}\s/u.test(line) ? lines.slice(i + 1, i + 4).find(next => /^\s*(?:Posted|Published)\b/iu.test(next)) : null;
            let date;
            if (entry.inlineReleaseDates) {
                const version = title.slice('Python '.length);
                if ((version !== entry.version && !version.startsWith(entry.version + '.')) ||
                    url.pathname !== `/downloads/release/python-${version.replaceAll('.', '')}/`) continue;
                date = inlineDate.exec(line.slice(match.index + match[0].length))?.[1];
            } else {
                date = (datedLine ? dateLabel.exec(datedLine.replaceAll('**', '').trim())?.[1] : undefined) ?? headingDate;
            }
            const published = Date.parse(date?.includes(',') ? `${date} UTC` : date);
            if (!Number.isFinite(published) || published < window[0] || published > window[1]) continue;
            const stable = entry.versionedNotes ? postgresReleaseVersions(title).filter(version =>
                !entry.version || version === entry.version || version.startsWith(entry.version + '.')) : [];
            if (entry.versionedNotes && entry.version && !stable.length) continue;
            const lead = {url: url.href, title, listed_date: new Date(published).toISOString().slice(0, 10),
                source_index: entry.url, engines: [], content: '', score: 1};
            results.set(url.href, lead);
            for (const version of stable) {
                const address = new URL(`/docs/release/${version}/`, origin).href;
                notes.set(address, {...lead, url: address, title: `PostgreSQL ${version} release notes`});
            }
        }
    }
    // Versioned release notes give readers the fix details before the announcement summary.
    return [...notes.values(), ...results.values()].slice(0, 5);
}

function datedGoReleaseExcerpt(markdown, window, version) {
    const releases = [];
    for (const line of markdown.split('\n')) {
        const match = /^go(\d+\.\d+\.\d+) \(released (\d{4}-\d{2}-\d{2})\)/u.exec(line.trim());
        if (!match || !/\bsecurity fix(?:es)?\b/iu.test(line) ||
            (version && match[1] !== version && !match[1].startsWith(version + '.'))) continue;
        const date = Date.parse(match[2]);
        if (date >= window[0] && date <= window[1]) releases.push({date, text: line.trim()});
    }
    return releases.sort((left, right) => right.date - left.date).slice(0, 4).map(entry => entry.text).join('\n\n');
}

function postgresReleaseVersions(title) {
    const releases = /^PostgreSQL\s+(.+?)\s+Released\b/iu.exec(title)?.[1];
    return (releases?.split(/,\s*|\s+and\s+/u) ?? [])
        .map(part => part.replace(/^and\s+/iu, '').trim())
        .filter(part => /^\d{1,2}\.\d{1,3}(?:\.\d{1,3})?$/u.test(part));
}

function withinSite(url, site) {
    return !site || ((url.hostname === site.hostname || url.hostname.endsWith('.' + site.hostname)) &&
        (!site.pathname || url.pathname === site.pathname || url.pathname.startsWith(site.pathname + '/')));
}

function allowed(url, site) {
    return url.protocol === 'https:' && !url.port && !url.username && !url.password && !url.search &&
        !/%(?:2f|5c|25)|\/files\//iu.test(url.pathname) && paths.get(url.hostname)?.test(url.pathname) === true &&
        withinSite(url, site);
}

export function postgresSqlSearch(query, intent) {
    if (intent.category === 'fresh' || /(^|\s)!|\b(?:inurl|intitle|filetype):/iu.test(query) ||
        (!intent.site && /\bsite:/iu.test(query))) return null;
    const product = /\bPostgreSQL\s+/iu.exec(query);
    if (!product) return null;
    const command = /^(?:(\d{1,2}(?:\.\d{1,2})?)\s+)?(?:`([A-Za-z][^`\n]{0,129})`|([A-Z][A-Z\d_]*(?: [A-Z][A-Z\d_]*)*))/u
        .exec(query.slice(product.index + product[0].length));
    if (!command) return null;
    const version = command[1] ?? 'current';
    const prefix = (command[2] ?? command[3]).trim().toUpperCase().replaceAll(/\s+/gu, ' ');
    const url = new URL(`https://www.postgresql.org/docs/${version}/sql-commands.html`);
    if (intent.site && !allowed(url, intent.site)) return null;
    return {url, prefix, directory: `/docs/${version}/`};
}

export async function postgresSqlLead(query, intent, remaining, signal) {
    const lookup = postgresSqlSearch(query, intent);
    if (!lookup || remaining < 500) return null;
    try {
        const {bytes} = await fetchPacedBytes('postgres-sql-index', lookup.url.href, 128 * 1024, Math.min(2200, remaining), signal);
        if (!bytes) return null;
        const document = parse(Buffer.from(bytes).toString('utf8'));
        let best;
        for (const link of document.querySelectorAll('dt .refentrytitle a')) {
            const title = link.text.trim().replaceAll(/\s+/gu, ' ');
            if (!title || title.length <= (best?.title.length ?? 0) ||
                !(lookup.prefix === title || lookup.prefix.startsWith(title + ' '))) continue;
            const href = link.getAttribute('href');
            if (!/^sql-[a-z0-9-]+\.html$/u.test(href ?? '')) continue;
            const url = new URL(href, lookup.url);
            if (url.pathname.startsWith(lookup.directory) && allowed(url, intent.site)) {
                best = {url: url.href, title, source_index: lookup.url.href, content: '', engines: [], score: 1};
            }
        }
        return best ?? null;
    } catch {
        return null;
    }
}

function currentPostgresChapter(hit, url, intent, query) {
    if (!query || intent.category !== 'known-site' || !['postgresql.org', 'www.postgresql.org'].includes(intent.site?.hostname) ||
        url.hostname !== 'www.postgresql.org' || !/\bChapter\s+\d/iu.test(hit.title) ||
        /\b(?:PostgreSQL|postgres|version|v)\s*\d+\b|\b\d{1,2}\.\d{1,2}\b/iu.test(query)) return null;
    const chapter = /^\/docs\/\d+(?:\.\d+)?\/([a-z0-9-]+\.html)$/u.exec(url.pathname);
    if (!chapter) return null;
    const current = new URL(`/docs/current/${chapter[1]}`, url);
    return allowed(current, intent.site) ? current : null;
}

function postgresChapterLeads(packet, chapter, intent) {
    if (packet?.state !== 'publisher_excerpt') return [];
    const toc = packet.excerpt.split(/^\*{0,2}Table of Contents\*{0,2}\s*$/imu)[1];
    if (!toc) return [];
    const leads = new Map();
    for (const line of toc.trim().split(/\n\s*\n/u).slice(0, 64)) {
        const link = /^\[([^\]\n]+)\]\(([^\s)]+)\)$/u.exec(line.trim());
        if (!link) break;
        const [, title, href] = link;
        const url = URL.parse(href, chapter);
        if (!url || url.origin !== chapter.origin || !/^\/docs\/current\/[a-z0-9-]+\.html$/u.test(url.pathname) ||
            !allowed(url, intent.site)) continue;
        const keywords = new Set(terms(title));
        const matches = intent.originalTerms.filter(term => keywords.has(term)).length;
        const section_url = url.hash ? url.href : undefined;
        url.hash = '';
        if (matches < 2 || url.href === chapter.href) continue;
        const previous = leads.get(url.href);
        if (!previous || matches > previous.matches)
            leads.set(url.href, {url: url.href, title, section_url, source_index: chapter.href, matches});
    }
    return [...leads.values()].sort((left, right) => right.matches - left.matches).slice(0, 2)
        .map(({url, title, section_url, source_index}) => ({url, title, section_url, source_index, content: '', engines: [], score: 1}));
}

async function ociPublisherEvidence(target, read, query) {
    const pending = {state: 'candidate_leads', publisher_url: target.href,
        detail: 'The specification body could not be verified from a tagged official source.'};
    if (!query || /\bv?\d+\.\d+(?:\.\d+)?\b/iu.test(query)) return pending;
    const shell = await read(target.href, next => next.href === target.href, true);
    const source = /This content is served from\s+\[[^\]\n]+\]\((https:\/\/github\.com\/opencontainers\/[^\s)]+)\)/iu.exec(shell?.excerpt ?? '');
    const repository = target.pathname.split('/')[1];
    const match = source && /^\/opencontainers\/([a-z-]+)\/blob\/(v\d+\.\d+\.\d+)\/([a-zA-Z0-9-]+\.md)$/u.exec(new URL(source[1]).pathname);
    if (!match || match[1] !== repository) return pending;
    const raw = `https://raw.githubusercontent.com/opencontainers/${repository}/${match[2]}/${match[3]}`;
    const packet = await read(raw, next => next.href === raw, 'oci-source');
    return packet?.state === 'publisher_excerpt' ? {...packet, publisher_url: target.href, retrieved_from: raw} : pending;
}

export async function ociSourceMarkdown(raw, query, remaining, signal) {
    if (remaining < 500) return null;
    try {
        const {bytes} = await fetchPacedBytes('oci-spec-source', raw, 128 * 1024, Math.min(1800, remaining), signal);
        const markdown = bytes && Buffer.from(bytes).toString('utf8');
        if (!markdown?.trimStart().startsWith('# ')) return null;
        const excerpt = selectEvidence(markdown, query, 3200);
        if (!excerpt || /^(?:No matching complete|No useful terms)/u.test(excerpt)) return null;
        return {state: 'publisher_excerpt', excerpt, publication_date: null,
            retrieved_at: new Date().toISOString(), whole_document_reviewed: false, cached: false};
    } catch {
        return null;
    }
}

export async function bundlePublisherEvidence(result, intent, remaining, read, query = '') {
    if (intent.category !== 'fresh' && remaining >= 500) {
        for (const hit of result.results) {
            const target = URL.parse(hit.url);
            if (!target || !allowed(target, intent.site)) continue;
            if (target.hostname === 'specs.opencontainers.org') return ociPublisherEvidence(target, read, query);
            const chapter = currentPostgresChapter(hit, target, intent, query);
            if (chapter) {
                const packet = await read(chapter.href, next => next.href === chapter.href, true);
                const leads = postgresChapterLeads(packet, chapter, intent);
                return {state: 'candidate_leads', publisher_url: chapter.href, leads,
                    detail: leads.length ? 'Open an original documentation section before citing its facts.'
                        : 'The current chapter did not supply a matching section link.'};
            }
            if (result.search_assessment?.status !== 'partial_leads')
                return read(hit.url, next => next.origin === target.origin && allowed(next, intent.site));
        }
    }
    return {state: result.results.length ? 'candidate_leads' : result.search_assessment?.evidence_state ?? 'insufficient_evidence',
        detail: 'No eligible documentation excerpt was retrieved.'};
}
