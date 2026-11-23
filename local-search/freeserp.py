# SPDX-License-Identifier: AGPL-3.0-or-later
"""SearXNG adapter for FreeSerp's documented Global search API."""

import re
from datetime import datetime, timezone
from urllib.parse import quote_plus

from searx.exceptions import SearxEngineAPIException, SearxEngineCaptchaException
from searx.network import raise_for_httperror
from searx.utils import html_to_text

search_url = 'https://freeserp.ai/api.php?index=web&size=5&lang=en&q={query}'
paging = False
_PUBLICATION_DAY = re.compile(r'\d{4}-\d{2}-\d{2}', re.ASCII)


def publication_date(hit):
    value = hit.get('published_at')
    if not isinstance(value, str) or not _PUBLICATION_DAY.fullmatch(value):
        return None
    try:
        return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def request(query, params):
    params['url'] = search_url.format(query=quote_plus(query))
    params['allow_redirects'] = False
    params['raise_for_httperror'] = False
    params['headers'].update({'Accept': 'application/json', 'X-Agent': 'open-source-web-search/1.0'})
    return params


def response(resp):
    if resp.headers.get('cf-mitigated') == 'challenge':
        raise SearxEngineCaptchaException()
    raise_for_httperror(resp)
    try:
        payload = resp.json()
    except ValueError as error:
        raise SearxEngineAPIException('FreeSerp returned invalid JSON.') from error
    if not isinstance(payload, dict) or payload.get('ok') is not True or not isinstance(payload.get('results'), list):
        raise SearxEngineAPIException('FreeSerp Global results unavailable.')
    if payload.get('engine_fallback') is True:
        raise SearxEngineAPIException('FreeSerp Global unavailable. The provider returned site profiles.')
    if payload.get('index') != 'web':
        raise SearxEngineAPIException('FreeSerp returned an unexpected search index.')
    hits = []
    for hit in payload['results'][:5]:
        if isinstance(hit, dict) and all(isinstance(hit.get(key), str) and hit[key] for key in ('url', 'title')):
            snippet = hit.get('snippet')
            result = {'url': hit['url'], 'title': html_to_text(hit['title']),
                      'content': html_to_text(snippet) if isinstance(snippet, str) else ''}
            published = publication_date(hit)
            if published is not None:
                result['publishedDate'] = published
            hits.append(result)
    return hits
