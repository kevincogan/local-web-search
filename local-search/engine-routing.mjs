// Optional project policy applied at mcp-searxng's existing JSON search boundary.
import { DatabaseSync } from "node:sqlite";
import { createHash } from "node:crypto";
import { MCPSearXNGError } from "./error-handler.js";

const raw = process.env.OSWS_SEARCH_POLICY;
const policy = raw ? JSON.parse(raw) : null;
const PUBLISHER_INTERVALS = {'python-docs-inventory': 30000, 'redhat-security-data': 30000,
    'httpx-docs-index': 30000, 'gnu-license-reader': 30000, 'github-docs-search': 30000, 'oci-spec-source': 30000,
    'postgres-sql-index': 30000, 'ietf-datatracker': 30000, 'openssl-advisory-index': 30000,
    'github-docs-article': 30000, 'openshift-docs-source': 30000};
let reserveSource, readSource, pauseSource;
let readPerformance, recordPerformance, readFailures, recordFailure, clearFailures;
if (policy) {
    const { preferred, sources, specialists, attempt_ms, throttle_ms } = policy;
    const names = [...preferred, ...Object.values(specialists)];
    const specialistIntervals = policy.specialist_intervals_ms ?? {};
    if (Object.keys(specialists).some(category => !/^[a-z0-9-]+$/u.test(category)) ||
        Object.entries(specialistIntervals).some(([name, interval]) =>
            !Object.values(specialists).includes(name) || !Number.isSafeInteger(interval) || interval < 100)) {
        throw new Error('Invalid project specialist search policy');
    }
    if (preferred.length > 3 || new Set(names).size !== names.length ||
        names.some(name => !/^[a-z0-9_-]+(?:[. ][a-z0-9_-]+)*$/u.test(name)) ||
        Object.keys(sources).length !== preferred.length || preferred.some(name => {
            if (!Object.hasOwn(sources, name)) return true;
            const {min_interval_ms: interval, attempt_ms: attempt} = sources[name] ?? {};
            return (interval !== null && (!Number.isSafeInteger(interval) || interval < 100))
                || (attempt !== undefined && (!Number.isSafeInteger(attempt) || attempt < 100 || attempt > 6000));
        }) || !Number.isInteger(attempt_ms) || attempt_ms < 100 || attempt_ms > 6000 ||
        !Number.isSafeInteger(throttle_ms) || throttle_ms < attempt_ms) {
        throw new Error('Invalid project search policy');
    }
    const stateFile = process.env.OSWS_SEARCH_STATE;
    if (!stateFile) throw new Error('A project search state file is required');
    const previousMask = process.umask(0o077);
    let db;
    try {
        db = new DatabaseSync(stateFile);
    } finally {
        process.umask(previousMask);
    }
    db.exec(`PRAGMA busy_timeout = 250;
        CREATE TABLE IF NOT EXISTS source_state (
            engine TEXT PRIMARY KEY, until_ms INTEGER NOT NULL, status TEXT NOT NULL
        )`);
    reserveSource = db.prepare(`INSERT INTO source_state VALUES (?, ?, 'request budget')
        ON CONFLICT(engine) DO UPDATE SET until_ms=excluded.until_ms, status=excluded.status
        WHERE source_state.until_ms <= ? AND source_state.status NOT IN ('CAPTCHA', 'access denied')`);
    readSource = db.prepare('SELECT until_ms, status FROM source_state WHERE engine = ?');
    pauseSource = db.prepare(`UPDATE source_state SET until_ms = max(until_ms, ?), status = ?
        WHERE engine = ? AND status NOT IN ('CAPTCHA', 'access denied')`);
    if (policy.adaptive) {
        db.exec('CREATE TABLE IF NOT EXISTS search_performance (intent TEXT, engine TEXT, samples REAL, useful REAL, updated INTEGER, PRIMARY KEY(intent, engine))');
        readPerformance = db.prepare('SELECT samples, useful, updated FROM search_performance WHERE intent = ? AND engine = ?');
        recordPerformance = db.prepare('INSERT OR REPLACE INTO search_performance VALUES (?, ?, ?, ?, ?)');
        db.exec('CREATE TABLE IF NOT EXISTS search_failures (engine TEXT PRIMARY KEY, streak INTEGER, updated INTEGER)');
        readFailures = db.prepare('SELECT streak, updated FROM search_failures WHERE engine = ?');
        recordFailure = db.prepare('INSERT OR REPLACE INTO search_failures VALUES (?, ?, ?)');
        clearFailures = db.prepare('DELETE FROM search_failures WHERE engine = ?');
    }
}

const NOISE = new Set('a an and are as at be by can do does for from how i in is it latest me of on or please recent search show the this to was what when where which who with find explain official documentation information'.split(' '));
export const terms = text => (text.toLowerCase().match(/[\p{L}\p{N}_]+/gu) ?? [])
    .filter(word => word.length > 1 && !NOISE.has(word))
    .map(word => word.length > 4 && /[^s]s$/u.test(word) ? word.slice(0, -1) : word);
const PUBLISHERS = [
    [/\b(?:openshift|red hat)\b/iu, 'access.redhat.com', 'https://access.redhat.com/security/data', /^\/errata\/RHSA-\d{4}:\d+\/?$/iu],
    [/\bfirefox\b/iu, 'mozilla.org', 'https://www.mozilla.org/en-US/security/known-vulnerabilities/firefox/',
        /^\/en-US\/security\/advisories\/mfsa\d{4}-\d+\/?$/iu],
    [/\bpostgresql\b/iu, 'postgresql.org', 'https://www.postgresql.org/about/newsarchive/security/'],
    [/\bkubernetes\b/iu, 'kubernetes.io', 'https://kubernetes.io/docs/reference/issues-security/official-cve-feed/'],
    [/\b(?:sqlite|fts5)\b/iu, 'sqlite.org'],
    [/\bpython\b/iu, 'python.org', 'https://www.python.org/downloads/'],
    [/\bdebian\b/iu, 'security-tracker.debian.org', 'https://security-tracker.debian.org/tracker/'],
    [/\bopenssl\b/iu, 'openssl-library.org', 'https://www.openssl-library.org/news/timeline/'],
    [/\bcurl\b/iu, 'curl.se', 'https://curl.se/docs/vulnerabilities.html'],
    [/\bgo (?:1\.\d+|security|release)/iu, 'go.dev', 'https://go.dev/doc/devel/release'],
];
const DAY = 86400000;
const MONTHS = 'January|February|March|April|May|June|July|August|September|October|November|December';
const MONTH_RANGE = new RegExp(`\\b(?:(${MONTHS})(?:\\s+to\\s+|\\s*[-–]\\s*|\\s+))?(${MONTHS}) (20\\d{2})\\b`, 'iu');
const ISO_RANGE = /\b(?:from|between)\s+(\d{4}-\d{2}-\d{2})\s+(?:to|through|until|and)\s+(\d{4}-\d{2}-\d{2})\b/iu;

function freshnessWindow(query, now, explicitDates) {
    if (explicitDates) {
        const [start, end] = explicitDates.map(date => {
            const time = Date.parse(`${date}T00:00:00Z`);
            return Number.isFinite(time) && new Date(time).toISOString().startsWith(date) ? time : NaN;
        });
        return start <= end && start <= now ? [start, Math.min(now, end + DAY - 1)] : null;
    }
    const match = MONTH_RANGE.exec(query);
    if (match) {
        const endMonth = Date.parse(`${match[2]} 1, ${match[3]} UTC`);
        const first = match[1] ? Date.parse(`${match[1]} 1, ${match[3]} UTC`) : endMonth;
        const start = Math.min(first, endMonth);
        const boundary = new Date(Math.max(first, endMonth));
        boundary.setUTCMonth(boundary.getUTCMonth() + 1);
        return [start, Math.min(now, boundary.getTime() - 1)];
    }
    const period = /\b(?:past|last) (\d{1,3}) (day|week)s?\b/iu.exec(query);
    if (period) return [now - Number(period[1]) * (period[2].toLowerCase() === 'week' ? 7 : 1) * DAY, now];
    const day = new Date(now);
    day.setUTCHours(0, 0, 0, 0);
    if (/\btoday\b/iu.test(query)) return [day.getTime(), now];
    if (/\bthis week\b/iu.test(query)) return [day.getTime() - ((day.getUTCDay() + 6) % 7) * DAY, now];
    if (/\bthis month\b/iu.test(query)) return [day.setUTCDate(1), now];
    return [now - 30 * DAY, now];
}

export function classifySearch(query) {
    const site = requestedSite(query);
    const publisher = PUBLISHERS.find(([pattern]) => pattern.test(query));
    const advisory = /\b(?:security (?:updates?|advisor(?:y|ies)|(?:patch )?releases?)|RHSA|MFSA)\b/iu.test(query);
    const explicitDates = ISO_RANGE.exec(query)?.slice(1);
    const fresh = explicitDates || advisory || /\b(?:latest|current|recent|today|this (?:week|month)|(?:past|last) \d+ (?:days?|weeks?)|release announcements)\b/iu.test(query);
    const lookup = !site && !/-?\b(?:site|inurl|intitle|filetype):/iu.test(query) && [
        [/\b(?:github\s+)?(?:repository|repo)\s+([a-z0-9_.-]+\/[a-z0-9_.-]+)(?![a-z0-9_.\/-])/iu, 'github'],
        [/\bnpm package (@[a-z0-9_.-]+\/[a-z0-9_.-]+|[a-z0-9][a-z0-9_.-]*)(?![a-z0-9_.\/-])/iu, 'npm'],
        [/\b(?:hugging face |huggingface )?(model|dataset)\s+([a-z0-9_.-]+\/[a-z0-9_.-]+)(?![a-z0-9_.\/-])/iu, 'hub'],
    ].map(([pattern, engine]) => [pattern.exec(query), engine]).find(([match]) => match);
    const quoted = [...query.matchAll(/"([^"]{2,120})"/gu)].map(match => match[1].toLowerCase());
    const scopedQuery = query.trim().replace(/^site:\S+\s*/iu, '');
    const mdnScope = site?.hostname === 'developer.mozilla.org' && scopedQuery;
    const rewritten = lookup && (lookup[0][2] ?? lookup[0][1]);
    const specialist = lookup && (lookup[1] === 'hub'
        ? lookup[0][1].toLowerCase() === 'dataset' ? 'huggingface datasets' : 'huggingface'
        : lookup[1]) || (mdnScope ? 'mdn' : null);
    const originalTerms = [...new Set(terms(scopedQuery))];
    const category = /^https?:\/\/\S+$/iu.test(query.trim()) ? 'direct-url'
        : fresh ? 'fresh' : site ? 'known-site' : lookup ? 'exact'
        : /\b(?:documentation|manual|reference|docs)\b/iu.test(query) ? 'documentation'
        : !originalTerms.length ? 'ambiguous' : 'general';
    return {category, site, publisher, advisory, specialist, rewritten, specialistQuery: rewritten || mdnScope,
        quoted, originalTerms,
        explicitDates: Boolean(explicitDates),
        dateWindow: fresh ? freshnessWindow(query, Date.now(), explicitDates) : null};
}

export function curlAdvisoryWindow(query, intent = classifySearch(query)) {
    if (!intent.advisory || intent.publisher?.[1] !== 'curl.se' ||
        /\b(?:v?\d+\.\d+(?:\.\d+)?|CVE-\d{4}-\d{4,})\b/iu.test(query)) return null;
    return intent.dateWindow;
}

function performanceRow(intent, engine, now) {
    const prior = readPerformance?.get(intent, engine);
    if (!prior) return [0, 0];
    const decay = Math.exp(-(now - prior.updated) / 604800000);
    return [prior.samples * decay, prior.useful * decay];
}

function recordPerformanceSample(intent, engine, useful) {
    const now = Date.now();
    const [samples, good] = performanceRow(intent.category, engine, now);
    const factor = samples >= 100 ? .99 : 1;
    recordPerformance.run(intent.category, engine, samples * factor + 1, good * factor + Number(useful), now);
}

function orderProviders(scheduled, intent) {
    const now = Date.now();
    // A small number of local searches should not overturn the configured tie-break.
    const score = new Map(scheduled.map(engine => {
        const [samples, useful] = performanceRow(intent.category, engine, now);
        return [engine, samples >= 8 ? (useful - samples / 2) / (samples + 12) : 0];
    }));
    return [...scheduled].sort((left, right) => score.get(right) - score.get(left));
}

export function automaticSearch(filters) {
    return Boolean(policy?.adaptive && !filters.engines && (!filters.categories || filters.categories === 'general'));
}

const inFlight = new Map();
const resultCache = new Map();
const waiting = [];
let activeSearches = 0;
const DEFAULT_TTLS = {exact: 300000, documentation: 86400000, 'known-site': 3600000, general: 3600000};

async function withSearchSlot(execute, budgetMs) {
    const deadline = performance.now() + budgetMs;
    if (activeSearches < 4) activeSearches++;
    else {
        if (waiting.length >= 4 || budgetMs < 200) throw new MCPSearXNGError('The local search queue is full.');
        await new Promise((resolve, reject) => {
            const grant = () => {
                clearTimeout(timer);
                activeSearches++;
                resolve();
            };
            const timer = setTimeout(() => {
                waiting.splice(waiting.indexOf(grant), 1);
                reject(new MCPSearXNGError('The local search queue did not free a slot within its wait budget.'));
            }, Math.min(750, budgetMs - 100));
            waiting.push(grant);
        });
    }
    try {
        return await execute(Math.max(0, deadline - performance.now()));
    } finally {
        activeSearches--;
        waiting.shift()?.();
    }
}

export async function shareSearch(args, route, execute, refresh, budgetMs) {
    const key = createHash('sha256').update(JSON.stringify([args, route])).digest('hex');
    const saved = resultCache.get(key);
    if (!refresh && saved?.expires > Date.now()) {
        return {...saved.value, data: {...saved.value.data, search_cache: {hit: true, retrieved_at: saved.retrievedAt}}};
    }
    resultCache.delete(key);
    if (inFlight.has(key)) return inFlight.get(key);
    const pending = withSearchSlot(async remaining => {
        const value = await execute(remaining);
        const assessment = value.data.search_assessment;
        const unavailable = value.data.unresponsive_engines;
        // A pacing skip did not invalidate a useful response that another
        // provider delivered. Actual upstream errors still prevent caching.
        if (assessment?.status !== 'relevant_leads' || assessment.intent === 'fresh' ||
            unavailable.some(([, reason]) => reason !== 'request budget cooling down') ||
            JSON.stringify(value.data).length > 65536) return value;
        if (resultCache.size >= 48) resultCache.delete(resultCache.keys().next().value);
        const ttl = policy.cache_ttl_ms?.[assessment.intent] ?? DEFAULT_TTLS[assessment.intent];
        if (Number.isSafeInteger(ttl) && ttl > 0) {
            const cached = unavailable.length ? {...value, data: {...value.data, unresponsive_engines: []}} : value;
            resultCache.set(key, {value: cached, expires: Date.now() + ttl, retrievedAt: new Date().toISOString()});
        }
        return value;
    }, budgetMs);
    inFlight.set(key, pending);
    try {
        return await pending;
    } finally {
        inFlight.delete(key);
    }
}

function stoppedBy(reason) {
    // The stock processor reports an exception class, or the same reason in suspended form.
    if (/too.?many.?requests|rate.?limit|\b429\b|throttl/iu.test(reason)) return 'throttled';
    if (/captcha|bot challenge/iu.test(reason)) return 'CAPTCHA';
    if (/access.?denied|unauthori[sz]ed|forbidden|\b40[123]\b/iu.test(reason)) return 'access denied';
    return null;
}

// Both of the Hub search engines and the direct Hub catalogue use the same
// anonymous public API allowance. Read older dataset pauses as well.
function budgetKey(engine) {
    return engine === 'huggingface datasets' ? 'huggingface' : engine;
}

export function reserveProjectSource(engine, timeout) {
    const interval = policy?.sources[engine]?.min_interval_ms ?? policy?.specialist_intervals_ms?.[engine] ?? PUBLISHER_INTERVALS[engine];
    if (!policy || !Number.isSafeInteger(interval)) return 'no project request budget';
    const now = Date.now();
    const key = budgetKey(engine);
    if (key === 'huggingface') {
        const prior = readSource.get('huggingface datasets');
        if (prior && (prior.until_ms > now || ['CAPTCHA', 'access denied'].includes(prior.status)))
            return prior.status === 'request budget' ? 'request budget cooling down' : `paused: ${prior.status}`;
    }
    if (reserveSource.run(key, now + Math.max(timeout, interval), now).changes) return null;
    const status = readSource.get(key)?.status ?? 'request budget';
    return status === 'request budget' ? 'request budget cooling down' : `paused: ${status}`;
}

export function pauseProjectSource(engine, stop, retryAt = 0) {
    if (stop) pauseSource.run(stop === 'throttled' ? Math.max(Date.now() + policy.throttle_ms, retryAt) : Number.MAX_SAFE_INTEGER,
        stop, budgetKey(engine));
}

export function nextEligibleGeneralSource(route, attempts) {
    const now = Date.now();
    return route.find(engine => {
        if (!Object.hasOwn(policy.sources, engine) || attempts.some(([attempted]) => attempted === engine)) return false;
        const state = readSource.get(budgetKey(engine));
        return !state || state.until_ms <= now && state.status !== 'CAPTCHA' && state.status !== 'access denied';
    });
}

export function retryAfter(value) {
    if (typeof value !== 'string' && typeof value !== 'number') return 0;
    const text = String(value).trim();
    const now = Date.now();
    const end = /^\d+$/.test(text) ? now + Number(text) * 1000 : Date.parse(text);
    return Number.isSafeInteger(end) && end > now ? end : 0;
}

function recordTransient(engine, failed) {
    if (!readFailures) return;
    if (!failed) {
        clearFailures.run(engine);
        return;
    }
    const now = Date.now();
    const prior = readFailures.get(engine);
    const streak = Math.min(5, (prior && now - prior.updated < 3600000 ? prior.streak : 0) + 1);
    recordFailure.run(engine, streak, now);
    const base = policy.sources[engine]?.min_interval_ms ?? policy.specialist_intervals_ms[engine];
    pauseSource.run(now + Math.min(120000, Math.max(1000, base) * 2 ** streak), 'temporary backoff', budgetKey(engine));
}

export function planSearch(filters, page, pages, timeRange, query) {
    if (!policy) return null;
    const { engines, categories } = filters;
    const { preferred, sources, specialists } = policy;
    const scheduled = preferred.filter(name => sources[name].min_interval_ms !== null);
    if (pages !== 1 || engines?.includes(',') || categories?.includes(',')) {
        throw new MCPSearXNGError('This profile searches one page and one explicitly selected source at a time.');
    }
    const specialist = Object.hasOwn(specialists, categories) ? specialists[categories] : engines;
    if (Object.values(specialists).includes(specialist)) {
        // Forward the exact engine even when the caller selected its category.
        delete filters.categories;
        filters.engines = specialist;
        return policy.specialist_intervals_ms?.[specialist] === undefined ? null : [specialist];
    }
    if (categories && categories !== 'general' || engines && !scheduled.includes(engines)) {
        throw new MCPSearXNGError('The selected source has no active request budget in this profile.');
    }
    if (page !== 1) throw new MCPSearXNGError('General web search is first-page only.');
    if (timeRange && !engines) throw new MCPSearXNGError('Use date terms in the query; the general route does not guarantee a date filter.');
    if (engines || !automaticSearch(filters)) return engines ? [engines] : scheduled;
    const intent = classifySearch(query);
    if (intent.category === 'direct-url') throw new MCPSearXNGError('Read the supplied URL with web_url_read.');
    if (intent.category === 'ambiguous') throw new MCPSearXNGError('Specify the topic or exact identifier to search for.');
    const ranked = orderProviders(scheduled, intent);
    return intent.specialist && Object.values(specialists).includes(intent.specialist)
        && Number.isSafeInteger(policy.specialist_intervals_ms?.[intent.specialist])
        ? [intent.specialist, ...ranked] : ranked;
}

function requestedSite(query) {
    const [first, ...rest] = query.trim().split(/\s+/u);
    const match = /^site:([a-z0-9-]+(?:\.[a-z0-9-]+)+)(\/[a-z0-9._~%/-]*)?$/iu.exec(first);
    if (!match || rest.some(term => /^-?site:/iu.test(term))) return;
    const [, hostname, pathname = ''] = match;
    return { hostname: hostname.toLowerCase(), pathname: pathname.replace(/\/+$/u, '') };
}

function usable(hit, minScore, site) {
    if (!hit || typeof hit.title !== 'string' || !hit.title.trim() ||
        minScore !== undefined && (hit.score || 0) < minScore) return false;
    try {
        const url = new URL(hit.url);
        if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) return false;
        if (!site) return true;
        const sameHost = url.hostname === site.hostname || url.hostname.endsWith('.' + site.hostname);
        return sameHost && (!site.pathname || url.pathname === site.pathname || url.pathname.startsWith(site.pathname + '/'));
    } catch {
        return false;
    }
}

function assess(hit, intent) {
    const target = new URL(hit.url);
    const trustedPublisher = intent.publisher &&
        (target.hostname === intent.publisher[1] || target.hostname.endsWith('.' + intent.publisher[1]));
    const official = intent.site || trustedPublisher;
    const title = terms(hit.title);
    const body = terms(typeof hit.content === 'string' ? hit.content.slice(0, 1500) : '');
    const titleMatches = new Set(title);
    const words = new Set([...title, ...body]);
    const matched = intent.originalTerms.filter(word => words.has(word));
    const coverage = matched.length / Math.max(1, intent.originalTerms.length);
    const text = (hit.title + ' ' + (typeof hit.content === 'string' ? hit.content.slice(0, 1500) : '')).toLowerCase();
    const literal = intent.quoted.every(phrase => text.includes(phrase));
    const exact = intent.rewritten && (text.includes(intent.rewritten.toLowerCase()) || hit.url.toLowerCase().includes('/' + intent.rewritten.toLowerCase()));
    const date = typeof hit.publishedDate === 'string' ? Date.parse(hit.publishedDate) : NaN;
    const recent = intent.dateWindow && date >= intent.dateWindow[0] && date <= intent.dateWindow[1];
    const rank = coverage + matched.filter(word => titleMatches.has(word)).length / Math.max(1, intent.originalTerms.length)
        + (official ? 1 : 0) + (exact ? 2 : 0) + (recent && intent.category === 'fresh' ? 1 : 0);
    const relevant = Boolean(literal && (exact || coverage >= .45 || official && coverage >= .30));
    const highConfidence = literal && (exact || coverage >= .6 || official && coverage >= .45);
    const advisoryLead = !intent.explicitDates && trustedPublisher && !Number.isFinite(date) && intent.publisher[3]?.test(target.pathname);
    const sufficient = Boolean(highConfidence && (intent.category !== 'fresh' || official && recent || advisoryLead));
    // A documentation reference can omit the key detail from its search snippet.
    // Preserve it as a lead without letting it stop fallback or count as evidence.
    const documentationPath = /\/(?:doc|docs|reference)\//iu.test(target.pathname) && terms(target.pathname);
    const productMatch = documentationPath && terms(target.hostname.replace(/^www\./iu, '').split('.')[0])
        .some(word => intent.originalTerms.includes(word) && titleMatches.has(word));
    const documentationLead = !relevant && literal && productMatch &&
        ['general', 'documentation'].includes(intent.category) &&
        matched.some(word => documentationPath.includes(word));
    return {hit, rank, relevant, sufficient, documentationLead};
}

function resultKey(value) {
    const url = new URL(value);
    url.hash = '';
    for (const name of [...url.searchParams.keys()])
        if (/^(?:utm_|fbclid$|gclid$)/iu.test(name)) url.searchParams.delete(name);
    url.searchParams.sort();
    return url.href;
}

export async function searchInOrder(engines, budgetMs, minScore, query, send, hasInfobox, automated = false) {
    const site = requestedSite(query);
    // FreeSerp Global documents full-text queries. Enforce a single leading
    // site restriction locally even when sending only the topic to that engine.
    const freeSerpTopic = policy.adaptive && site && query.trim().replace(/^site:\S+\s*/iu, '');
    const intent = automated ? classifySearch(query) : null;
    const rescore = intent && (intent.publisher || site || intent.rewritten || intent.quoted.length);
    const candidates = new Map();
    let enough = false;
    let relevantResponses = 0;
    const deadline = performance.now() + budgetMs;
    const attempted = [];
    const failures = [];
    let cleanEmpty = false;
    let last = { results: [] };
    if (engines.length === 0) throw new MCPSearXNGError('No general search source has an active request budget in this profile.');
    for (const engine of engines) {
        const remaining = Math.floor(deadline - performance.now());
        if (remaining < 100) {
            failures.push([engine, 'shared search deadline exhausted before dispatch']);
            break;
        }
        const timeout = Math.min(policy.sources[engine]?.attempt_ms ?? policy.attempt_ms, remaining);
        const unavailable = reserveProjectSource(engine, timeout);
        if (unavailable) {
            failures.push([engine, unavailable]);
            continue;
        }
        try {
            const engineQuery = intent?.specialist === engine && intent.specialistQuery ||
                (engine === 'freeserp' && freeSerpTopic) || query;
            const data = await send(engine, timeout, engineQuery);
            const hits = data.results.filter(hit => usable(hit, minScore, site));
            const problems = (data.unresponsive_engines ?? []).filter(item =>
                Array.isArray(item) && item[0] === engine && typeof item[1] === 'string');
            const stops = problems.map(([, reason]) => stoppedBy(reason));
            const stop = stops.find(reason => reason === 'CAPTCHA' || reason === 'access denied') ||
                stops.find(reason => reason === 'throttled');
            pauseProjectSource(engine, stop, stop === 'throttled' ? retryAfter(data.retry_after) : 0);
            if (!stop) recordTransient(engine, problems.some(([, reason]) =>
                /\b(?:timeout|network|connection|server API error)\b/iu.test(reason)));
            failures.push(...problems);
            if (intent) {
                const ranked = hits.map((hit, sourceRank) => ({...assess(hit, intent), sourceRank}));
                for (const item of ranked.filter(item => item.relevant || item.documentationLead && item.sourceRank < 5)) {
                    const key = resultKey(item.hit.url);
                    const prior = candidates.get(key);
                    const sources = new Set([...(prior?.hit.engines ?? []), engine]);
                    const best = !prior || item.rank > prior.rank ? item : prior;
                    candidates.set(key, {...best, hit: {...best.hit, engines: [...sources]}});
                }
                const useful = ranked.some(item => item.sufficient);
                recordPerformanceSample(intent, engine, useful);
                enough ||= useful;
                relevantResponses += Number(ranked.some(item => item.relevant));
                attempted.push([engine, useful ? 'relevant leads' : hits.length ? 'insufficient evidence' : problems.length ? 'unavailable' : 'empty']);
                cleanEmpty ||= !problems.length;
                // Two weak matches can be enough for ordinary discovery. For a date-scoped
                // question, neither can replace an eligible source with in-window evidence.
                if (enough || (intent.category !== 'fresh' && relevantResponses >= 2)) break;
                continue;
            }
            const foundEvidence = hits.length > 0 || !site && hasInfobox?.(data);
            attempted.push([engine, foundEvidence ? 'results' : problems.length ? 'unavailable' : 'empty']);
            if (foundEvidence) {
                last = { ...data, results: hits };
                break;
            }
            cleanEmpty ||= problems.length === 0;
        } catch (error) {
            // Do not echo remote bodies, query strings or URLs into tool output.
            const reason = /abort|timeout|timed out/iu.test(error?.message ?? '') ? 'timeout' : 'search request failed';
            recordTransient(engine, true);
            if (intent) recordPerformanceSample(intent, engine, false);
            attempted.push([engine, reason]);
            failures.push([engine, reason]);
        }
    }
    if (intent) {
        const ordered = [...candidates.values()].sort((a, b) => rescore
            ? Number(b.sufficient) - Number(a.sufficient) || b.rank - a.rank
            : a.sourceRank - b.sourceRank || b.rank - a.rank);
        const index = intent.publisher?.[2];
        const indexInScope = index && (!site || usable({url: index, title: 'Publisher index'}, undefined, site));
        last = {results: ordered.map(item => item.hit),
            search_assessment: {intent: intent.category, status: enough ? 'relevant_leads' : candidates.size ? 'partial_leads' : 'insufficient_evidence',
                evidence_state: candidates.size ? 'candidate_leads' : cleanEmpty ? 'insufficient_evidence' : 'provider_unavailable',
                publisher_pages_verified: false, ...(intent.category === 'fresh' ? {publication_date_verified: false} : {}),
                ...(indexInScope && intent.advisory ? {publisher_index: index} : {})}};
    }
    return { data: { ...last, unresponsive_engines: failures, engine_attempts: attempted },
        servedBy: [], failedPages: [], hasCleanEmptyResponse: cleanEmpty };
}
