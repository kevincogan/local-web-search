// Bounded, first-party Hugging Face lookups for named public accounts.
import { fetch } from 'undici';
import { reserveProjectSource, pauseProjectSource } from './engine-routing.mjs';
import { MCPSearXNGError, createNetworkError } from './error-handler.js';
import { createUrlReaderAgent } from './proxy.js';
import { readResponseBodyWithLimit } from './url-reader.js';

const ORIGIN = 'https://huggingface.co';
const ACCOUNT = /^[A-Za-z0-9][A-Za-z0-9_-]{0,53}$/;
const IDENTIFIER = /^[a-z\d][a-z\d._-]{0,95}\/[a-z\d][a-z\d._-]{0,95}$/i;
const TIMEOUT = 5000;
const MAX_BYTES = 512_000;

export const HF_CATALOG_TOOL = {
    name: 'huggingface_catalog',
    description: 'List public models or datasets for a named Hugging Face organization or account, with Hub creation or update timestamps and direct links. Use this first when asked what an organization recently published. Results are an inventory slice, not a statement of official release dates or which family is latest.',
    annotations: { readOnlyHint: true, openWorldHint: true },
    inputSchema: { type: 'object', properties: {
        owner: { type: 'string', description: 'Public Hugging Face account handle', pattern: ACCOUNT.source, maxLength: 54 },
        kind: { type: 'string', enum: ['models', 'datasets'], default: 'models' },
        order: { type: 'string', enum: ['created', 'updated'], default: 'created', description: 'Newest Hub records or most recently updated records' },
        search: { type: 'string', minLength: 1, maxLength: 64, description: 'Optional literal name filter within the account' },
        limit: { type: 'integer', minimum: 1, maximum: 10, default: 5 },
    }, required: ['owner'], additionalProperties: false },
};

export function validCatalogArgs(a) {
    return !!a && typeof a === 'object' && !Array.isArray(a) &&
        Object.keys(a).every(k => Object.hasOwn(HF_CATALOG_TOOL.inputSchema.properties, k)) &&
        typeof a.owner === 'string' && ACCOUNT.test(a.owner) &&
        (a.kind === undefined || ['models', 'datasets'].includes(a.kind)) &&
        (a.order === undefined || ['created', 'updated'].includes(a.order)) &&
        (a.search === undefined || (typeof a.search === 'string' && /^[a-z\d_. -]{1,64}$/i.test(a.search) && a.search.trim())) &&
        (a.limit === undefined || (Number.isInteger(a.limit) && a.limit >= 1 && a.limit <= 10));
}

function timestamp(value) {
    return typeof value === 'string' && /^\d{4}-\d\d-\d\dT[\d:.]+Z$/u.test(value) &&
        Number.isFinite(Date.parse(value)) ? value : null;
}

function retryAfter(value) {
    if (value === null) return 0;
    const n = /^\d{1,9}$/u.test(value) ? Date.now() + Number(value) * 1000 : Date.parse(value);
    return Number.isSafeInteger(n) ? n : 0;
}

export async function readHuggingFaceCatalog(args, signal, fetchImpl = fetch) {
    if (!validCatalogArgs(args)) throw new MCPSearXNGError('Invalid Hugging Face catalogue arguments.');
    const { owner, kind = 'models', order = 'created', search, limit = 5 } = args;
    const engine = kind === 'models' ? 'huggingface' : 'huggingface datasets';
    const key = order === 'created' ? 'createdAt' : 'lastModified';
    const url = new URL(`/api/${kind}`, ORIGIN);
    url.search = new URLSearchParams({
        author: owner, sort: key, direction: '-1', limit: String(limit),
        'expand[]': 'createdAt',
    });
    url.searchParams.append('expand[]', 'lastModified');
    if (search) url.searchParams.set('search', search.trim());
    signal?.throwIfAborted();
    const unavailable = reserveProjectSource(engine, TIMEOUT);
    if (unavailable === 'request budget cooling down')
        throw new MCPSearXNGError('Hugging Face local request cooldown (no upstream request).');
    if (unavailable) throw new MCPSearXNGError(`Hugging Face ${unavailable} (no upstream request).`);
    const deadline = AbortSignal.timeout(TIMEOUT);
    let response, payload;
    try {
        response = await fetchImpl(url, { method: 'GET', redirect: 'manual', headers: { Accept: 'application/json' },
            dispatcher: createUrlReaderAgent(), signal: signal ? AbortSignal.any([signal, deadline]) : deadline });
        const stop = response.status === 429 ? 'throttled' :
            response.headers.get('cf-mitigated') === 'challenge' ? 'CAPTCHA' :
            [401, 403].includes(response.status) ? 'access denied' : null;
        if (stop) {
            pauseProjectSource(engine, stop, retryAfter(response.headers.get('retry-after')));
            throw new MCPSearXNGError(`Hugging Face provider ${stop} (HTTP ${response.status}); no retry.`);
        }
        if (!response.ok) throw new MCPSearXNGError(`Hugging Face returned HTTP ${response.status}; no retry or redirect.`);
        if (!/^application\/json(?:;|$)/i.test(response.headers.get('content-type') ?? ''))
            throw new MCPSearXNGError('Hugging Face did not return a JSON inventory.');
        const read = await readResponseBodyWithLimit(response, MAX_BYTES, true);
        if (read.exceeded || read.hasNulInPrefix) throw new MCPSearXNGError('Hugging Face catalogue response exceeds the input policy.');
        try { payload = JSON.parse(read.text); }
        catch { throw new MCPSearXNGError('Hugging Face returned invalid catalogue JSON.'); }
    } catch (error) {
        if (error instanceof MCPSearXNGError) throw error;
        signal?.throwIfAborted();
        if (deadline.aborted) throw new MCPSearXNGError('Hugging Face catalogue timed out; no retry.');
        throw createNetworkError(error, { url: ORIGIN });
    } finally {
        if (response?.body && !response.bodyUsed) void response.body.cancel().catch(() => {});
    }
    if (!Array.isArray(payload)) throw new MCPSearXNGError('Hugging Face response is not an inventory.');
    const results = payload.filter(r => typeof r?.id === 'string' && IDENTIFIER.test(r.id) &&
        r.id.split('/')[0].toLowerCase() === owner.toLowerCase() && r.private !== true)
        .slice(0, limit).map(r => ({ id: r.id, url: `${ORIGIN}/${kind === 'datasets' ? 'datasets/' : ''}${r.id}`,
            createdAt: timestamp(r.createdAt), lastModified: timestamp(r.lastModified) }));
    if (payload.length && !results.length)
        throw new MCPSearXNGError('Hugging Face returned no verifiable records for the requested account.');
    return { source: url.href, owner, kind, order, results,
        dateMeaning: order === 'created' ? 'Hub repository creation date, not official release date' : 'Hub repository update date, not official release date' };
}
