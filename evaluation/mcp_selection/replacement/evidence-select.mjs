// Optional bounded excerpt mode. Preserve source text and normalize aligned table padding.
const SEP = '\n\n[…]\n\n';
const PUBLICATION_QUERY = /\b(?:publication date|date of publication|issue date|release date|(?:date |when (?:was|were) .{1,80} )(?:issued|published))\b/i;
const RELEASE_QUERY = /\b(?:advisory|advisories|releases?|security updates?)\b/iu;
const DATE_SCOPE = /\b(?:recent|latest|newest|current|20\d{2}|(?:this|last|past) (?:\d+ )?(?:days?|weeks?|months?|years?))\b/iu;
const DATED_LABEL = /^(?:issued|published|announced|posted|publication date|issue date|release date)(?: on)?(?:[ \t]*:[ \t]*(?:\r?\n[ \t]*){0,2}|[ \t]*\r?\n(?:[ \t]*\r?\n)?[ \t]*|[ \t]+)(\d{4}-\d{2}-\d{2}|[a-z]{3,9}\.? \d{1,2}, \d{4})\b/imu;
const ADVISORY_HEADER_DATE = /^(?:#{1,6} )?[\w .-]{1,70} Security Advisory \[(\d{1,2})(?:st|nd|rd|th)? ([A-Za-z]{3,9}) (\d{4})\][ \t]*$/mu;

export function labelledPublicationDate(markdown) {
    const text = markdown.replaceAll('**', '');
    const label = DATED_LABEL.exec(text)?.[1];
    if (label) return label;
    const header = ADVISORY_HEADER_DATE.exec(text);
    return header ? `${header[2]} ${header[1]}, ${header[3]}` : null;
}
const CAVEAT_QUERY = /\b(?:caveats?|inconsisten\w*|limitations?|warnings?|exceptions?)\b/i;
const CAVEAT_TEXT = /\b(?:except|unless|inconsisten\w*|not (?:suitable|recommended|supported)|warning|caution)\b/i;
const sentences = new Intl.Segmenter('en', {granularity: 'sentence'});
const MAX_SENTENCE_BLOCK_CHARS = 16_384;
const MAX_TABLE_BLOCK_CHARS = 65_536;
const MAX_TABLE_ROWS = 256;
const STOP = new Set('a an and any are as at be by could did do does for from give how i in is it of on or should that the their this to was were what when where which who will with would you'.split(' '));
const undoubleEnding = stem => stem.replace(/([bcdfghjklmnpqrstvwxyz])\1$/u, '$1');
const words = (s) => Array.from(s.toLowerCase().matchAll(/[\p{L}\p{N}]+/gu), ([word]) => word)
    .filter(word => word.length > 1 && !STOP.has(word))
    .map(word => word.length > 8 && word.endsWith('ation') ? undoubleEnding(word.slice(0, -5))
        : word.length > 6 && word.endsWith('ing') ? word.slice(0, -3)
            : word.length > 5 && word.endsWith('ed') ? undoubleEnding(word.slice(0, -2))
                : word.length > 4 && /[es]$/.test(word) ? word.slice(0, -1) : word);

function definitionHeading(entries, query) {
    const symbols = new Set(query.match(/\b[A-Z][a-z0-9]+[A-Z]\w*\b/gu));
    if (symbols.size !== 1) return undefined;
    const headings = new Set();
    for (const {text, heading} of entries) {
        if (!heading) continue;
        const declared = /^`?(?:class|type|interface|function)\s+(?:[\w.]+\.)?([A-Z][a-z0-9]+[A-Z]\w*)\b/u.exec(text)?.[1];
        if (symbols.has(declared)) headings.add(heading);
    }
    return headings.size === 1 ? headings.values().next().value : undefined;
}

function addAcronymTerms(markdown, queryTerms) {
    const requested = new Set(queryTerms);
    for (const [, acronym, phrase] of markdown.matchAll(
        /\b([A-Z]{2,6}) (?:stands for|is (?:an acronym that stands for|short for)) ([^\n.!?]{4,160})/gu)) {
        const term = acronym.toLowerCase();
        if (!requested.has(term)) continue;
        const terms = phrase.replace(/,?\s+and\s+/gu, ',').split(',').map(term => term.trim());
        if (terms.length === acronym.length && terms.every((term, i) =>
            /^[a-z]+(?: [a-z]+){0,2}$/iu.test(term) && term[0].toUpperCase() === acronym[i])) {
            requested.delete(term);
            for (const expansion of words(terms.join(' '))) queryTerms.add(expansion);
        }
    }
}

function evidencePieces(text, heading, limit) {
    if (/^(?:[*+-]|\d+[.)])\s/u.test(text)) {
        // Score a long list item by item before its siblings take up most of the budget.
        return text.length > limit / 2 ? text.split(/\n(?=(?:[*+-]|\d+[.)])[ \t])/u) : [text];
    }
    const available = limit - (heading ? heading.length + 2 : 0);
    if (text.length > available && text.length <= MAX_TABLE_BLOCK_CHARS && text.startsWith('|')) {
        const [header, separator, ...rows] = text.split('\n');
        const row = /^\|[^\n]*\|\s*$/u;
        if (rows.length && rows.length <= MAX_TABLE_ROWS && row.test(header) &&
            /^\|(?:\s*:?-+:?\s*\|)+\s*$/u.test(separator ?? '')) {
            const columns = Array.from(separator.matchAll(/\|/gu), match => match.index);
            if ([header, ...rows].every(line => line.trimEnd().length === columns.at(-1) + 1 &&
                columns.every(index => line[index] === '|'))) {
                const compactRow = line => {
                    const cells = columns.slice(1).map((end, index) => line.slice(columns[index] + 1, end).trim());
                    return `| ${cells.join(' | ')} |`;
                };
                const labels = compactRow(header);
                const divider = compactRow(separator).replace(/-{4,}/gu, '---');
                return rows.filter(line => /[^|\s]/u.test(line)).map(line => `${labels}\n${divider}\n${compactRow(line)}`);
            }
        }
    }
    // Split bounded plain prose without breaking Markdown links, code blocks or tables.
    if (text.length <= available || text.length > MAX_SENTENCE_BLOCK_CHARS ||
        !/^\p{L}/u.test(text) || /[\n[\]*<>]/u.test(text)) return [text];
    const pieces = Array.from(sentences.segment(text), ({segment}) => segment.trim());
    return pieces.every(piece => (piece.match(/`/g)?.length ?? 0) % 2 === 0) ? pieces : [text];
}

function blocks(markdown, limit) {
    const result = [];
    let block = [], fence;
    const headings = [];
    const flush = () => {
        if (!block.length) return;
        const text = block.join('\n').trim();
        if (text) {
            const heading = headings.at(-1)?.line ?? '';
            const context = headings.map(h => h.line).join(' ');
            for (const piece of evidencePieces(text, heading, limit)) {
                const previous = result.at(-1);
                const sameShortBlock = previous?.heading === heading && previous.text.length < 85 && piece.length < 320;
                const joined = sameShortBlock && `${previous.text}\n\n${piece}`;
                if (joined && (previous.text.endsWith(':') ||
                    (!labelledPublicationDate(previous.text) && labelledPublicationDate(joined)))) {
                    previous.text = joined;
                } else {
                    result.push({ text: piece, heading, context });
                }
            }
        }
        block = [];
    };
    for (const line of markdown.split('\n')) {
        const marker = line.match(/^\s*(`{3,}|~{3,})/)?.[1];
        if (fence) {
            block.push(line);
            if (marker?.[0] === fence[0] && marker.length >= fence.length && line.trim() === marker) {
                fence = undefined;
                flush();
            }
        } else if (marker) {
            flush();
            block = [line];
            fence = marker;
        } else if (/^#{1,6}\s/.test(line)) {
            flush();
            const depth = line.indexOf(' ');
            while (headings.at(-1)?.depth >= depth) headings.pop();
            headings.push({ line, depth });
        } else if (!line.trim()) {
            flush();
        } else {
            block.push(line);
        }
    }
    flush();
    return result;
}

function selectRssEvidence(markdown, query, limit, fence) {
    const queryTerms = [...new Set(words(query))];
    const entries = [];
    let start = -1;
    for (const tag of markdown.matchAll(/<\/?item>/gi)) {
        if (tag[0][1] !== '/') {
            start = tag.index;
            continue;
        }
        if (start < 0) continue;
        const record = markdown.slice(start, tag.index + tag[0].length);
        start = -1;
        const recordTerms = new Set(words(record));
        const matches = queryTerms.filter(term => recordTerms.has(term)).length;
        if (matches) entries.push({record, matches});
    }
    entries.sort((left, right) => right.matches - left.matches);
    const selected = [];
    let remaining = limit - (2 * fence.length + 5);
    for (const {record} of entries) {
        if (selected.length === 18 || remaining <= 0) break;
        const divider = selected.length ? 2 : 0;
        if (record.length + divider > remaining) continue;
        selected.push(record);
        remaining -= record.length + divider;
    }
    return selected.length ? `${fence}xml\n${selected.join('\n\n')}\n${fence}`
        : 'No matching complete feed item within the requested limit.'.slice(0, limit);
}

export function datedCurlAdvisoryExcerpt(markdown, window, limit = Infinity) {
    const lines = markdown.split('\n');
    const cells = (line) => line.trim().slice(1, -1).split('|').map(cell => cell.replaceAll('**', '').trim());
    const header = lines.findIndex(line => /^\s*\|.*\|\s*$/u.test(line) && cells(line).includes('Vulnerability') &&
        cells(line).includes('Published'));
    if (header < 0 || !/^\s*\|[\s|:-]+\|\s*$/u.test(lines[header + 1] ?? '')) return '';
    const columns = cells(lines[header]);
    const disclosure = columns.indexOf('Vulnerability');
    const published = columns.indexOf('Published');
    const matching = [];
    for (const line of lines.slice(header + 2)) {
        if (!/^\s*\|.*\|\s*$/u.test(line)) break;
        const row = cells(line);
        if (row.length !== columns.length || !/\bCVE-\d{4}-\d{4,}\b/u.test(row[disclosure]) ||
            !/^\d{4}-\d{2}-\d{2}$/u.test(row[published])) continue;
        const date = Date.parse(row[published]);
        if (date >= window[0] && date <= window[1] && new Date(date).toISOString().startsWith(row[published]))
            matching.push({date, text: line});
    }
    const table = [lines[header], lines[header + 1]];
    let length = table.join('\n').length;
    for (const {text} of matching.sort((left, right) => right.date - left.date).slice(0, 4)) {
        if (length + text.length + 1 > limit) break;
        table.push(text);
        length += text.length + 1;
    }
    return table.length > 2 ? table.join('\n') : '';
}

export function selectEvidence(markdown, query, limit) {
    const rss = /^(`{3,})xml\r?\n[\s\S]{0,400}<rss\b/i.exec(markdown);
    if (rss) return selectRssEvidence(markdown, query, limit, rss[1]);
    const bulletin = /^(`{3,})(?:text|txt)?\r?\n([\s\S]+)\r?\n\1\s*$/u.exec(markdown);
    if (bulletin && ADVISORY_HEADER_DATE.test(bulletin[2].split(/\r?\n/u, 1)[0])) {
        return selectEvidence(bulletin[2], query, limit);
    }
    if (markdown.length <= limit) return markdown;
    const phrase = query.match(/`([^`]{2,80})`/g)?.map(s => s.slice(1, -1).toLowerCase()) ?? [];
    const literals = [...new Set([...phrase,
        ...Array.from(query.matchAll(/\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b/giu), match => match[0].toLowerCase()),
        ...Array.from(query.matchAll(/\b[A-Z][A-Z0-9_]*(?: [A-Z][A-Z0-9_]*)+\b/g), match => match[0].toLowerCase())])];
    const queryTerms = new Set(words(query));
    if (/\bsecurity (?:fix(?:es)?|releases?|advisor(?:y|ies)|updates?)\b/iu.test(query)) queryTerms.add('cve');
    if (/\b(?:what (?:does|is|are)|define|meaning|stands? for)\b/iu.test(query)) addAcronymTerms(markdown, queryTerms);
    const wantsExample = /\b(?:code|snippets?|import|constructor|syntax)\b/i.test(query);
    const wantsCaveat = CAVEAT_QUERY.test(query);
    if (!queryTerms.size) return 'No useful terms to select evidence.';
    const entries = blocks(markdown, limit);
    const exactHeading = definitionHeading(entries, query);
    const frequency = new Map();
    for (const block of entries) {
        const tokens = new Set(words(block.text));
        block.hits = [...queryTerms].filter(word => tokens.has(word));
        block.headingHits = new Set(words(block.heading));
        block.contextHits = new Set(words(block.context));
        for (const word of block.hits) frequency.set(word, (frequency.get(word) ?? 0) + 1);
    }
    const weight = (word) => Math.log1p(entries.length / (1 + (frequency.get(word) ?? 0)));
    const ranked = entries.map((block, index) => {
        const value = block.hits.reduce((sum, word) => sum + weight(word), 0);
        const lower = block.text.toLowerCase();
        const literalMatches = literals.filter(part => lower.includes(part)).length;
        const caveat = wantsCaveat && literalMatches && CAVEAT_TEXT.test(block.text) ? 5 : 0;
        const context = [...queryTerms].reduce((sum, word) => sum +
            (block.headingHits.has(word) ? .65 : block.contextHits.has(word) ? .3 : 0) * weight(word), 0);
        // Questions about exact code need literal examples as well as explanatory prose.
        const example = wantsExample && block.hits.length && /^(?:`{3,}|~{3,}|>>> )/m.test(block.text) ? 4 : 0;
        // Prefer material in a unique definition section over incidental references elsewhere.
        const definitionWeight = block.heading === exactHeading ? 3 : 1;
        // Avoid letting large lists crowd out short explanations and examples.
        return { index, value: definitionWeight * (value + 2 * literalMatches + context + example + caveat) / Math.sqrt(Math.max(1, block.text.length / 280)) };
    }).filter(row => row.value > 0).sort((a, b) => b.value - a.value || a.index - b.index);
    const chosen = new Set();
    const included = new Set();
    const output = () => [...chosen].sort((a, b) => a - b).map((index, i, all) => {
        const { text, heading } = entries[index];
        const previous = i ? all[i-1] : -1;
        const boundary = i && previous + 1 !== index ? SEP : i ? '\n\n' : '';
        const label = heading && (previous < 0 || entries[previous].heading !== heading) ? `${heading}\n\n` : '';
        return boundary + label + text;
    }).join('');
    const tryBlock = (index) => {
        if (chosen.has(index) || !entries[index]) return;
        const {context, text} = entries[index];
        const key = context + '\n' + text;
        if (included.has(key)) return;
        chosen.add(index);
        if (output().length > limit) chosen.delete(index);
        else included.add(key);
    };
    if (PUBLICATION_QUERY.test(query) || (RELEASE_QUERY.test(query) && DATE_SCOPE.test(query))) {
        // Metadata labels are not always the words used in the question (for example, "Issued:").
        tryBlock(entries.findIndex(block => labelledPublicationDate(block.text) || labelledPublicationDate(block.heading)));
    }
    for (const { index } of ranked) {
        if (chosen.size >= 18) break;
        tryBlock(index);
    }
    for (const index of [...chosen]) {
        if (chosen.size >= 18) break;
        // Keep eligible nearby context, never cross a section boundary.
        if (entries[index+1]?.heading === entries[index].heading) tryBlock(index+1);
    }
    return output() || 'No matching complete passage within the requested limit.';
}
