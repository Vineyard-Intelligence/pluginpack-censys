// Censys (under testing, for research purpose) — Censys Platform API lookups and pivots for VINEYARD.
//
// TEMPORARY: added by the VINEYARD operator for thesis research (identifying origin servers from
// the TLS certificates and SSH host keys they expose). It may be removed without notice.
//
// KEY MODEL: the analyst's own Censys Personal Access Token, sent as `Authorization: Bearer` to
// api.platform.censys.io through the manifest's `network` allowlist. An organization ID is
// optional: without one Censys bills the request to the user's free account.
//
// TIERS (Censys docs, 2026-09):
//   free account  — host / certificate / web-property LOOKUPS only, 100 credits a month,
//                   1 credit per host, one request at a time.
//   Starter+      — search, 5 credits per page (8 with regex). A free account gets 403 there,
//                   so censys_pivot says so and stops instead of failing once per selected node.
//
// PLATFORM: desktop only. The API answers no CORS headers at all (its preflight is a 404), so
// the browser build cannot read a response; the desktop shell supplies the headers for origins
// a pack declares.
//
// Graph writes are STAGED: nothing reaches the project until the analyst reviews and applies.
import { definePlugin, definePluginPack } from './sdk';
import type {
    ConfigValue,
    GraphNode,
    GraphScope,
    HostContext,
    NetworkScope,
    PluginManifest,
    RunResult,
    VineyardPluginPack,
} from './sdk';

const API = 'https://api.platform.censys.io/v3/global';
const VERSION = '0.1.0';
const RESEARCH_NOTE =
    'Temporary plugin added by the VINEYARD operator for thesis research. Under testing — it may be removed soon.';
const INFRA = 'run.vineyard.typepacks.infrastructure';

const PLATFORMS: PluginManifest['platforms'] = {
    primary: 'desktop',
    web: { runtime: 'sandbox-js', entry: 'dist/pack.mjs' },
    desktop: { runtime: 'sandbox-js', entry: 'dist/pack.mjs', min_app_version: '0.1.0' },
};
const NET_SCOPE: NetworkScope[] = [
    {
        endpoint: API,
        methods: ['GET', 'POST'],
        purpose: "Censys Platform host lookups and searches — the analyst's own token via the Authorization header.",
    },
];
const CONFIG: ConfigValue[] = [
    { key: 'api_key', label: 'Censys Personal Access Token', type: 'string', secret: true, optional: false },
    { key: 'organization_id', label: 'Censys Organization ID (optional)', type: 'string', optional: true },
];
const GRAPH_SCOPES: GraphScope[] = ['node:read', 'node:create', 'node:update', 'edge:create'];
const LIFECYCLE: NonNullable<PluginManifest['lifecycle']> = {
    persistence: 'opt-in',
    controls: ['progress', 'cancel'],
    progress: 'determinate',
};

// ---- request plumbing ------------------------------------------------------------------------

const abortErr = () => new Error('cancelled');

const sleep = (ms: number, signal?: AbortSignal): Promise<void> =>
    new Promise((resolve, reject) => {
        const timer = setTimeout(done, ms);
        function done() {
            signal?.removeEventListener('abort', onAbort);
            resolve();
        }
        function onAbort() {
            clearTimeout(timer);
            reject(abortErr());
        }
        signal?.addEventListener('abort', onAbort, { once: true });
    });

/** A non-2xx answer that may be about one item rather than the whole run. */
class CensysError extends Error {
    constructor(
        readonly status: number,
        msg: string,
    ) {
        super(`${msg} (HTTP ${status})`);
    }
}

/**
 * One call with the analyst's token. 429 (the account's one-request-at-a-time limit) and 503 (the
 * per-IP rate limit) are retried with backoff; 401 ends the run, since every later call would fail
 * the same way. Everything else comes back as a CensysError for the caller to judge.
 */
async function censys(ctx: HostContext, method: 'GET' | 'POST', path: string, body?: unknown): Promise<any> {
    if (ctx.run?.platform && ctx.run.platform !== 'desktop') {
        throw new Error('Censys sends no CORS headers — this pack only works in the VINEYARD desktop app');
    }
    const token = ctx.config?.api_key;
    if (typeof token !== 'string' || !token.trim()) {
        throw new Error('Censys Personal Access Token is not set — configure it in the plugin settings first');
    }
    const headers: Record<string, string> = { Authorization: `Bearer ${token.trim()}`, Accept: 'application/json' };
    const org = ctx.config?.organization_id;
    if (typeof org === 'string' && org.trim()) headers['X-Organization-ID'] = org.trim();
    if (body !== undefined) headers['Content-Type'] = 'application/json';

    for (let attempt = 0; ; attempt++) {
        if (ctx.signal?.aborted) throw abortErr();
        const res = await ctx.net!.fetch!(API + path, {
            method,
            headers,
            body: body === undefined ? undefined : JSON.stringify(body),
        });
        if ((res.status === 429 || res.status === 503) && attempt < 3) {
            const wait = Math.min(30_000, 2_000 * 2 ** attempt);
            ctx.progress?.log?.(`Censys is throttling (HTTP ${res.status}) — retrying in ${wait / 1000}s`);
            await sleep(wait, ctx.signal);
            continue;
        }
        if (res.ok) return res.json();
        let msg = '';
        try {
            const j = (await res.json()) as any;
            msg = j?.error?.message ?? j?.message ?? j?.detail ?? '';
        } catch {
            /* non-JSON error body — the status line has to do */
        }
        if (res.status === 401) throw new Error('Censys rejected this Personal Access Token');
        throw new CensysError(res.status, msg || 'Censys error');
    }
}

/** Why this one item was skipped, or null when the error has to end the run. */
function itemMiss(e: unknown): string | null {
    if (!(e instanceof CensysError)) return null;
    if (e.status === 404) return 'no Censys record';
    if (e.status === 403) return `not visible to this Censys account — ${e.message}`;
    if (e.status === 400 || e.status === 422) return `rejected by Censys — ${e.message}`;
    return null;
}

// ---- graph helpers ---------------------------------------------------------------------------

const hex64 = (v: unknown): string | null =>
    typeof v === 'string' && /^[0-9a-fA-F]{64}$/.test(v.trim()) ? v.trim().toLowerCase() : null;

/** Drop empty values so a delta never overwrites a field with nothing. */
function compact(o: Record<string, unknown>): Record<string, unknown> {
    return Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined && v !== null && v !== ''));
}

async function selected(ctx: HostContext, types: string[]): Promise<GraphNode[]> {
    const out: GraphNode[] = [];
    for (const id of ctx.input.selection ?? []) {
        if (ctx.signal?.aborted) throw abortErr();
        const n = await ctx.graph?.get?.(id);
        if (n && types.includes(n.type)) out.push(n);
    }
    return out;
}

/** The leaf certificate a service presented, as typepack properties. */
function certData(svc: any): Record<string, unknown> | null {
    const fp = hex64(svc?.cert?.fingerprint_sha256) ?? hex64(svc?.tls?.fingerprint_sha256);
    if (!fp) return null;
    const p = svc?.cert?.parsed ?? {};
    const cn = Array.isArray(p.subject?.common_name) ? p.subject.common_name[0] : undefined;
    return compact({
        fingerprint_sha256: fp,
        subject_common_name: cn,
        issuer: p.issuer_dn,
        serial_number: p.serial_number,
        not_before: p.validity_period?.not_before,
        not_after: p.validity_period?.not_after,
    });
}

/**
 * The key algorithm, from which public key Censys parsed. `host_key_algorithm` is the negotiated
 * SIGNATURE algorithm, so an RSA key shows up there as rsa-sha2-256/512 — mapped back to ssh-rsa.
 */
function keyType(ssh: any): string | undefined {
    const hk = ssh?.server_host_key ?? {};
    const alg = ssh?.algorithm_selection?.host_key_algorithm;
    if (hk.ed25519_public_key) return 'ssh-ed25519';
    if (hk.rsa_public_key) return 'ssh-rsa';
    if (hk.dsa_public_key) return 'ssh-dss';
    if (hk.ecdsa_public_key) return typeof alg === 'string' && alg.startsWith('ecdsa-') ? alg : 'ecdsa';
    return typeof alg === 'string' && alg ? alg.replace(/^rsa-sha2-(256|512)$/, 'ssh-rsa') : undefined;
}

// =============================================================================================
// 1. censys_host — what an IP presents: TLS certificates and SSH host keys
// =============================================================================================
export const censysHost = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.censys_host',
        content_type: 'vineyard:plugin',
        name: 'Censys Host (under testing, for research purpose)',
        version: VERSION,
        description: `${RESEARCH_NOTE} For each selected IP Address, looks the host up on Censys and adds the TLS certificates ('presents certificate') and SSH host keys ('presents host key') its services present, and lists the open services on the IP. 1 credit per IP (a free Censys account has 100 a month). Desktop only.`,
        icon: 'server',
        platforms: PLATFORMS,
        io: {
            consumes: [{ typepack: INFRA, category: 'infrastructure', name: 'ip_address' }],
            produces: [
                { typepack: INFRA, category: 'infrastructure', name: 'certificate' },
                { typepack: INFRA, category: 'infrastructure', name: 'ssh_host_key' },
            ],
        },
        scopes: { graph: GRAPH_SCOPES, network: NET_SCOPE, config: CONFIG },
        lifecycle: LIFECYCLE,
    },
    async run(ctx): Promise<RunResult> {
        const nodes = await selected(ctx, ['infrastructure.ip_address']);
        const counts = { checked: 0, certificates: 0, host_keys: 0, misses: 0 };
        if (!nodes.length) return { summary: 'Select one or more IP Address nodes first', counts };
        for (let i = 0; i < nodes.length; i++) {
            if (ctx.signal?.aborted) throw abortErr();
            const n = nodes[i];
            const ip = String(n.data.ip_address ?? '').trim();
            ctx.progress?.set?.({ percent: Math.round((i / nodes.length) * 100), message: `Looking up ${ip}` });
            let host: any;
            try {
                host = (await censys(ctx, 'GET', `/asset/host/${encodeURIComponent(ip)}`))?.result?.resource;
            } catch (e) {
                const why = itemMiss(e);
                if (!why) throw e;
                counts.misses++;
                ctx.progress?.log?.(`${ip}: ${why}`);
                continue;
            }
            counts.checked++;
            const services: any[] = Array.isArray(host?.services) ? host.services : [];

            const listed = services
                .filter((s) => typeof s?.port === 'number')
                .map((s) => `${s.port}/${s.protocol || s.transport_protocol || '?'}`);
            if (listed.length) await ctx.graph!.updateNode!(n.id, { censys_services: listed.join(', ') });

            const seenCerts = new Set<string>();
            const seenKeys = new Set<string>();
            for (const svc of services) {
                const cert = certData(svc);
                if (cert && !seenCerts.has(cert.fingerprint_sha256 as string)) {
                    seenCerts.add(cert.fingerprint_sha256 as string);
                    const node = await ctx.graph!.createNode!({ type: 'infrastructure.certificate', data: cert });
                    await ctx.graph!.createEdge!({ from: n.id, to: node.id, label: 'presents certificate' });
                    counts.certificates++;
                }
                const fp = hex64(svc?.ssh?.server_host_key?.fingerprint_sha256);
                if (fp && !seenKeys.has(fp)) {
                    seenKeys.add(fp);
                    const node = await ctx.graph!.createNode!({
                        type: 'infrastructure.ssh_host_key',
                        data: compact({ fingerprint_sha256: fp, key_type: keyType(svc.ssh) }),
                    });
                    await ctx.graph!.createEdge!({ from: n.id, to: node.id, label: 'presents host key' });
                    counts.host_keys++;
                }
            }
        }
        ctx.progress?.set?.({ percent: 100 });
        const summary = `${counts.checked} of ${nodes.length} IP(s) found on Censys: ${counts.certificates} certificate(s), ${counts.host_keys} SSH host key(s)${counts.misses ? `, ${counts.misses} skipped` : ''}`;
        return { summary, counts };
    },
});

// =============================================================================================
// 2. censys_pivot — which other hosts present the same certificate or SSH host key
// =============================================================================================
const PIVOTS: Record<string, { field: string; label: string }> = {
    'infrastructure.certificate': { field: 'host.services.cert.fingerprint_sha256', label: 'presents certificate' },
    'infrastructure.ssh_host_key': {
        field: 'host.services.ssh.server_host_key.fingerprint_sha256',
        label: 'presents host key',
    },
};

export const censysPivot = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.censys_pivot',
        content_type: 'vineyard:plugin',
        name: 'Censys Pivot (under testing, for research purpose)',
        version: VERSION,
        description: `${RESEARCH_NOTE} For each selected TLS Certificate or SSH Host Key, searches Censys for the hosts that present it and links each one's IP Address. The total Censys found is recorded on the node as censys_host_count, so a key shared by thousands of hosts (a device default) is visible as such. Needs a paid Censys account (Starter or higher); each search costs credits. Desktop only.`,
        icon: 'route',
        platforms: PLATFORMS,
        params: {
            type: 'object',
            properties: {
                limit: {
                    type: 'integer',
                    title: 'Hosts per certificate or key',
                    description: 'At most this many IP addresses are added per selected node (1–100, default 25).',
                },
            },
        },
        io: {
            consumes: [
                { typepack: INFRA, category: 'infrastructure', name: 'certificate' },
                { typepack: INFRA, category: 'infrastructure', name: 'ssh_host_key' },
            ],
            produces: [{ typepack: INFRA, category: 'infrastructure', name: 'ip_address' }],
        },
        scopes: { graph: GRAPH_SCOPES, network: NET_SCOPE, config: CONFIG },
        lifecycle: LIFECYCLE,
    },
    async run(ctx): Promise<RunResult> {
        const nodes = await selected(ctx, Object.keys(PIVOTS));
        const counts = { searched: 0, hosts: 0, misses: 0 };
        if (!nodes.length) return { summary: 'Select one or more TLS Certificate or SSH Host Key nodes first', counts };
        const raw = Number(ctx.params?.limit);
        const limit = Number.isInteger(raw) && raw >= 1 ? Math.min(raw, 100) : 25;
        const capped: string[] = [];

        for (let i = 0; i < nodes.length; i++) {
            if (ctx.signal?.aborted) throw abortErr();
            const n = nodes[i];
            const fp = hex64(n.data.fingerprint_sha256);
            if (!fp) {
                counts.misses++;
                ctx.progress?.log?.(`${n.id}: no SHA-256 fingerprint to search for`);
                continue;
            }
            const pivot = PIVOTS[n.type];
            ctx.progress?.set?.({ percent: Math.round((i / nodes.length) * 100), message: `Searching ${fp.slice(0, 12)}…` });
            let result: any;
            try {
                result = (await censys(ctx, 'POST', '/search/query', { query: `${pivot.field}="${fp}"`, page_size: limit }))
                    ?.result;
            } catch (e) {
                // Search is a paid feature: on a free account every node would 403 the same way.
                if (e instanceof CensysError && e.status === 403) {
                    throw new Error(`Censys search needs a paid account (Starter or higher) — ${e.message}`);
                }
                const why = itemMiss(e);
                if (!why) throw e;
                counts.misses++;
                ctx.progress?.log?.(`${fp.slice(0, 12)}…: ${why}`);
                continue;
            }
            counts.searched++;
            const total = Number(result?.total_hits ?? 0);
            await ctx.graph!.updateNode!(n.id, { censys_host_count: total });

            const hits: any[] = Array.isArray(result?.hits) ? result.hits : [];
            const ips = [...new Set(hits.map((h) => h?.host_v1?.resource?.ip).filter((ip) => typeof ip === 'string' && ip))];
            for (const ip of ips) {
                const node = await ctx.graph!.createNode!({ type: 'infrastructure.ip_address', data: { ip_address: ip } });
                await ctx.graph!.createEdge!({ from: node.id, to: n.id, label: pivot.label });
                counts.hosts++;
            }
            if (total > ips.length) {
                capped.push(`${fp.slice(0, 12)}… ${ips.length} of ${total}`);
                ctx.progress?.log?.(`${fp.slice(0, 12)}…: added ${ips.length} of ${total} hosts`);
            }
        }
        ctx.progress?.set?.({ percent: 100 });
        const summary = `${counts.searched} search(es), ${counts.hosts} host(s) linked${capped.length ? ` — capped: ${capped.join('; ')}` : ''}${counts.misses ? `, ${counts.misses} skipped` : ''}`;
        return { summary, counts };
    },
});

const pack: VineyardPluginPack & {
    author: { name: string; url: string };
    license: string;
    icon: string;
    platforms: PluginManifest['platforms'];
} = {
    identifier: 'run.vineyard.pluginpacks.censys',
    content_type: 'vineyard:pluginpack',
    name: 'Censys (under testing, for research purpose)',
    version: VERSION,
    description: `${RESEARCH_NOTE} Censys Platform lookups with the analyst's own token: the TLS certificates and SSH host keys an IP presents, and the other hosts that present the same certificate or key. Desktop only.`,
    author: { name: 'VINEYARD', url: 'https://vineyard.run' },
    license: 'Apache-2.0',
    icon: 'scan-line',
    platforms: PLATFORMS,
    plugins: [censysHost, censysPivot],
};

export const censysPack = definePluginPack(pack);
export default censysPack;
