"""Render CLI selections from observed publisher excerpts and specialist links."""
from datetime import date, datetime
import json
import re
from urllib.parse import urlsplit


SELECTION_GUIDANCE = (
    'After using the tools, return one JSON object with the keys state and selections. '
    'For factual answers use state "evidence" and select one to four verbatim, contiguous quotations '
    'that directly answer the question. Every selection is an object with url and quote. Use the exact '
    'publisher_url from a structured publisher excerpt and copy the text as retrieved, including any '
    'markdown escapes. Keep enough context to answer the question. If a question specifies a behaviour, '
    'quantity, version, or condition, select an excerpt only if it directly addresses that detail. '
    'A quote about related behaviour alone is insufficient. For a link-only request use state '
    '"link" with a single selection containing the exact first-party record URL and an empty quote. '
    'If you cannot verify the requested facts from available evidence use state "insufficient" and an '
    'empty array. If you need the user to identify the subject, use state "clarify" and an empty array. '
    'Return just the object. Do not put your own facts or explanation in the quotations. '
    'Use responseFormat evidence for publisher reads and evidenceQuery for the facts needed.'
)
MARKDOWN_PUNCTUATION = re.compile(r'([\\`*_{}\[\]<>()#!|])')
PROSE_ESCAPE = re.compile(r'\\([.!_*#\[\]()])')
INLINE_CODE = re.compile(r'(`+[^`\n]+`+)')
INLINE_LINK = re.compile(r'(?<!!)\[([^\]\n]+)\]\([^\s()]+(?: "[^"\n]*")?\)')
CONTROL_CHARACTERS = re.compile(r'[\x00-\x1f\x7f]')
PUBLICATION_DATE = re.compile(r'\d{4}-\d{2}-\d{2}|[A-Za-z]{3,9}\.? \d{1,2}, \d{4}')
MISSING_PAGE = re.compile(r'🚫 Website Error \((404|410)\): [^\r\n]{1,100}')
ORDER_QUESTION = re.compile(r'\bwhich (?:one )?(?:came|was (?:published|released)) (first|earlier|last|later)\b', re.I)
SELECTION_SCHEMA = {
    'type': 'object', 'required': ['state', 'selections'], 'additionalProperties': False,
    'properties': {
        'state': {'type': 'string', 'enum': ['evidence', 'link', 'insufficient', 'clarify']},
        'selections': {
            'type': 'array', 'maxItems': 4,
            'items': {'type': 'object', 'required': ['url', 'quote'], 'additionalProperties': False,
                      'properties': {'url': {'type': 'string'}, 'quote': {'type': 'string'}}},
        },
    },
}


def parse_object(text):
    try:
        value = json.loads(text)
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def public_url(value):
    if not isinstance(value, str) or not value or re.search(r'[\s<>\\]', value) or CONTROL_CHARACTERS.search(value):
        return False
    try:
        url = urlsplit(value)
        return url.scheme == 'https' and bool(url.hostname) and url.username is None and url.password is None
    except ValueError:
        return False


def tool_results(timeline):
    calls = {}
    for message in timeline:
        for block in message['content']:
            if message['role'] == 'assistant' and block['type'] == 'tool_use':
                calls[block['id']] = block
            elif message['role'] == 'user' and block['type'] == 'tool_result':
                call = calls.get(block.get('tool_use_id'), {})
                text = block.get('content', '')
                if isinstance(text, list):
                    text = '\n'.join(part['text'] for part in text if part.get('type') == 'text')
                packet = parse_object(text)
                if block.get('is_error') is True and call.get('name') == 'mcp__searxng__web_url_read':
                    if missing := MISSING_PAGE.fullmatch(text):
                        packet = {'state': 'source_not_found', 'http_status': int(missing[1]),
                                  'publisher_url': call.get('input', {}).get('url')}
                yield call, packet


def normalise(text):
    return ' '.join(text.split())


def quote_markdown(text):
    if '`' not in text:
        text = PROSE_ESCAPE.sub(r'\1', text)
    return MARKDOWN_PUNCTUATION.sub(r'\\\1', text.replace('&', '&amp;'))


def source_quote(passage, quote):
    flattened = normalise(passage)
    if quote in flattened:
        return quote
    # Markdown conversion escapes punctuation in prose. Leave code literals untouched.
    if '`' not in flattened and '`' not in quote and quote in PROSE_ESCAPE.sub(r'\1', flattened):
        return quote
    if '```' in passage or '~~~' in passage:
        return None
    # A displayed link has the same text as its label. Match within one source
    # paragraph and render that original visible text, including its typography.
    def prose_apostrophes(text):
        return ''.join(part if index % 2 else part.replace('’', "'")
                       for index, part in enumerate(INLINE_CODE.split(text)))

    needle = prose_apostrophes(quote)
    for paragraph in passage.split('\n\n'):
        if not paragraph or not paragraph[0].isalpha():
            continue
        visible = ''.join(part if index % 2 else INLINE_LINK.sub(
            lambda match: PROSE_ESCAPE.sub(r'\1', match[1]), part)
            for index, part in enumerate(INLINE_CODE.split(paragraph)))
        if visible == paragraph:
            continue
        visible = normalise(visible)
        offset = prose_apostrophes(visible).find(needle)
        if offset >= 0:
            return visible[offset:offset + len(quote)]
    return None


def publication_order(prompt, dates):
    urls = r'https://[^\s<>()\[\]]+'
    question = re.sub(urls, '', prompt)
    order = ORDER_QUESTION.search(question)
    addresses = {url.rstrip('.,;:') for url in re.findall(urls, prompt)}
    if not order or not re.search(r'\b(?:dates?|published|released)\b', question, re.I):
        return ''
    if len(dates) != 2 or addresses != dates.keys():
        return ''
    parsed = {}
    for url, value in dates.items():
        try:
            if value[0].isdigit():
                parsed[url] = date.fromisoformat(value)
            else:
                month = value.split(' ', 1)[0]
                form = '%b %d, %Y' if len(month.rstrip('.')) == 3 else '%B %d, %Y'
                parsed[url] = datetime.strptime(value.replace('.', ''), form).date()
        except ValueError:
            return ''
    first, second = sorted(parsed, key=parsed.get)
    if parsed[first] == parsed[second]:
        return 'The two sources give the same calendar date.'
    if order[1].lower() in ('first', 'earlier'):
        return f'The earlier date is {parsed[first].isoformat()} on <{first}>.'
    return f'The later date is {parsed[second].isoformat()} on <{second}>.'


def render_selection(raw_answer, timeline, specialists, *, prompt=''):
    answer = raw_answer if isinstance(raw_answer, dict) else parse_object(raw_answer)
    excerpts, links, failed_reads = {}, set(), set()
    publication_dates = {}
    publisher_unavailable = False
    for call, result in tool_results(timeline):
        name = call.get('name')
        if name == 'mcp__searxng__searxng_web_search':
            for hit in result.get('results', []):
                if public_url(hit.get('url')) and set(hit.get('engines', [])) & specialists:
                    links.add(hit['url'])
            packet = result.get('publisher_evidence') or {}
        elif name == 'mcp__searxng__web_url_read':
            packet = result
            url = packet.get('publisher_url')
            if public_url(url) and packet.get('state') == 'source_not_found' and packet.get('http_status') in (404, 410):
                failed_reads.add((url, packet['http_status']))
            publisher_unavailable |= packet.get('state') == 'publisher_unavailable'
        else:
            continue
        url, passage = packet.get('publisher_url'), packet.get('excerpt')
        if packet.get('state') == 'publisher_excerpt' and public_url(url) and isinstance(passage, str) and passage.strip():
            excerpts.setdefault(url, []).append(passage)
            links.add(url)
            date = packet.get('publication_date')
            if isinstance(date, str) and PUBLICATION_DATE.fullmatch(date):
                publication_dates.setdefault(url, set()).add(date)

    selections = answer.get('selections')
    state = answer.get('state')
    if not isinstance(selections, list) or len(selections) > 4 or any(not isinstance(item, dict) for item in selections):
        return 'I couldn’t produce a verifiable answer from the retrieved evidence.', 'invalid_selection'
    if state == 'clarify' and not selections and not excerpts:
        return 'Which subject, product, or version should I verify?', 'clarification'
    if state == 'link' and len(selections) == 1:
        url, quote = selections[0].get('url'), selections[0].get('quote')
        if public_url(url) and url in links and quote == '':
            return url, 'verified_link'
    if state == 'evidence' and selections:
        verified = []
        for item in selections:
            url, quote = item.get('url'), item.get('quote')
            if not public_url(url) or not isinstance(quote, str) or not 12 <= len(quote) <= 1200:
                continue
            quote = normalise(quote)
            if not quote or CONTROL_CHARACTERS.search(quote):
                continue
            for passage in excerpts.get(url, []):
                if matched := source_quote(passage, quote):
                    verified.append((url, matched))
                    break
        if verified:
            rendered = []
            shown_dates = {}
            for url, quote in dict.fromkeys(verified):
                entry = f'> {quote_markdown(quote)}\n\n<{url}>'
                dates = publication_dates.get(url, set())
                if len(dates) == 1 and url not in shown_dates:
                    shown_dates[url] = next(iter(dates))
                    entry += f' · Published {shown_dates[url]}'
                rendered.append(entry)
            if comparison := publication_order(prompt, shown_dates):
                rendered.append(comparison)
            if len(verified) < len(selections):
                rendered.append('Some requested details could not be verified from the available evidence.')
            return '\n\n'.join(rendered), 'verified_excerpts'
    if not excerpts and len(failed_reads) == 1:
        url, status = next(iter(failed_reads))
        return f'The request for <{url}> returned HTTP {status}. I could not verify the requested record.', 'missing_address'
    if not excerpts and publisher_unavailable:
        return 'I couldn’t open the publisher page or verify the requested information.', 'publisher_unavailable'
    return 'I couldn’t verify the requested facts from the available publisher evidence.', 'insufficient_evidence'


def render_transcript(stdout, specialists, *, prompt=''):
    """Read once from Claude's JSON stream and expose only the verified answer."""
    timeline, result = [], {}
    for line in stdout.splitlines():
        event = parse_object(line)
        kind = event.get('type')
        if kind == 'result':
            result = event
        elif kind in ('assistant', 'user') and isinstance(event.get('message', {}).get('content'), list):
            timeline.append({'role': kind, 'content': event['message']['content']})
    if result.get('subtype') != 'success' or not result.get('structured_output'):
        return 'I couldn’t produce a verifiable answer from the retrieved evidence.', 'invalid_selection'
    return render_selection(result['structured_output'], timeline, specialists, prompt=prompt)
