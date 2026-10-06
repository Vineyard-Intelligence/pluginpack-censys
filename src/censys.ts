// Censys (under testing) — Censys Platform API host lookup and search for VINEYARD.
//
// TEMPORARY: under testing, and it may change or be removed without notice.
//
// KEY MODEL: the analyst's own Censys Personal Access Token, sent as `Authorization: Bearer` to
// api.platform.censys.io through the manifest's `network` allowlist. An organization ID is
// optional: without one Censys bills the request to the user's free account.
//
// TIERS (Censys docs, 2026-09):
//   free account  — host / certificate / web-property LOOKUPS only, 100 credits a month,
//                   1 credit per host, one request at a time.
//   Starter+      — search, 5 credits per page (8 with regex). A free account gets 403 there
//                   ("requires an organization ID"; measured 2026-10-01), so censys_search says so
//                   and stops instead of failing once per selected node.
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
const VERSION = '0.3.1';
const TESTING_NOTE = 'Temporary plugin pack under testing — it may change or be removed.';
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
        purpose: 'Look up hosts and run searches on Censys.',
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
            // The Platform answers in problem+json: `detail` is one line ("Query error"), and the
            // `errors` list is where it says WHICH part of the request was wrong. Keeping only the
            // first line left an agent that had guessed a field name nothing to correct it from.
            // Bounded: the message goes into the agent's context and a toast as it is, and nothing
            // limits how many entries a body may carry.
            const head = j?.error?.message ?? j?.message ?? j?.detail ?? j?.title ?? '';
            const clip = (t: string) => (t.length > 300 ? `${t.slice(0, 300)}…` : t);
            const seen = new Set<string>([head]);
            const parts: string[] = [];
            let more = 0;
            for (const x of Array.isArray(j?.errors) ? j.errors : []) {
                const part = [x?.location, x?.message].filter((v) => typeof v === 'string' && v).join(': ');
                if (!part || seen.has(part)) continue;
                seen.add(part);
                if (parts.length < 5) parts.push(clip(part));
                else more++;
            }
            if (more) parts.push(`${more} more`);
            msg = [head, ...parts].filter(Boolean).join(' — ');
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

/** Suffixes no public certificate can name. Appliance default certificates carry them
 *  (`unifi.local`), and as nodes they would join every such device into one hub. */
const INTERNAL_SUFFIX = /\.(local|localdomain|localhost|internal|lan|home\.arpa)$/;
const DOMAIN_RE = /^[a-z0-9._-]+\.[a-z]{2,}$/;

/**
 * The public DNS names a service's certificate lists: the parsed SAN dNSNames, or Censys' `names`
 * (CN plus SANs) when those are absent. `*.` stripped (the wildcard's parent is the name the holder
 * controls), deduped; IP entries, single labels and internal names dropped.
 */
function certNames(svc: any): string[] {
    const raw = svc?.cert?.parsed?.extensions?.subject_alt_name?.dns_names ?? svc?.cert?.names;
    const out = new Set<string>();
    for (const v of Array.isArray(raw) ? raw : []) {
        if (typeof v !== 'string') continue;
        const name = v.trim().toLowerCase().replace(/\.$/, '').replace(/^\*\./, '');
        if (DOMAIN_RE.test(name) && !INTERNAL_SUFFIX.test(name)) out.add(name);
    }
    return [...out];
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
        // Hex, as VirusTotal writes it — both packs fill the same certificate node.
        serial_number: p.serial_number_hex ?? p.serial_number,
        not_before: p.validity_period?.not_before,
        not_after: p.validity_period?.not_after,
        // How many names it lists, kept even when they are too many to add (see addSanDomains).
        san_count: certNames(svc).length || undefined,
    });
}

/** More SAN names than this and none become nodes. */
const MAX_SANS = 25;

/**
 * A certificate's names as Domain nodes, linked certificate → domain by 'names domain' — not 'has
 * certificate', since a name a certificate lists may never have served it.
 *
 * Past MAX_SANS names nothing fans out. A list that long is a CDN or shared-hosting certificate
 * whose tenants have nothing to do with each other; the certificate node is already the point they
 * share, and san_count on it says how many there are. Returns how many were linked.
 *
 * Once per certificate per run (`done`): when several selected IPs present one certificate, its
 * names are the certificate's, and linking them again for each IP would only repeat the edges.
 */
async function addSanDomains(ctx: HostContext, certId: string, names: string[], who: string, done: Set<string>): Promise<number> {
    if (done.has(certId)) return 0;
    done.add(certId);
    if (names.length > MAX_SANS) {
        ctx.progress?.log?.(`${who}: a certificate lists ${names.length} names — over ${MAX_SANS}, so none were added (san_count is on the certificate)`);
        return 0;
    }
    for (const name of names) {
        if (ctx.signal?.aborted) throw abortErr();
        const node = await ctx.graph!.createNode!({ type: 'infrastructure.domain', data: { domain_name: name } });
        await ctx.graph!.createEdge!({ from: certId, to: node.id, label: 'names domain' });
    }
    return names.length;
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
// 1. censys_host_lookup — what an IP presents: TLS certificates and SSH host keys
// =============================================================================================
export const censysHostLookup = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.censys_host_lookup',
        content_type: 'vineyard:plugin',
        name: 'Censys Host Lookup',
        version: VERSION,
        description:
            "Looks up each selected IP Address on Censys and adds what its services present: TLS certificates (with subject CN, issuer, serial, validity and san_count) linked by 'presents certificate', the domain names each certificate lists as Domains linked from it by 'names domain' (only when it lists 25 or fewer), and SSH host keys (identified by the SHA-256 of the key) linked by 'presents host key'. Also lists the IP's open ports and protocols as censys_services. Use it to learn which certificate or SSH key a server exposes, for example before searching for other hosts that share it. Costs 1 Censys credit per IP; works on a free Censys account. Desktop only.",
        icon: 'server',
        platforms: PLATFORMS,
        io: {
            consumes: [{ typepack: INFRA, category: 'infrastructure', name: 'ip_address' }],
            produces: [
                { typepack: INFRA, category: 'infrastructure', name: 'certificate' },
                { typepack: INFRA, category: 'infrastructure', name: 'ssh_host_key' },
                { typepack: INFRA, category: 'infrastructure', name: 'domain' },
            ],
        },
        scopes: { graph: GRAPH_SCOPES, network: NET_SCOPE, config: CONFIG },
        lifecycle: LIFECYCLE,
    },
    async run(ctx): Promise<RunResult> {
        const nodes = await selected(ctx, ['infrastructure.ip_address']);
        const counts = { checked: 0, certificates: 0, cert_names: 0, host_keys: 0, misses: 0 };
        if (!nodes.length) return { summary: 'Select one or more IP Address nodes first', counts };
        const namedCerts = new Set<string>();
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
                    counts.cert_names += await addSanDomains(ctx, node.id, certNames(svc), ip, namedCerts);
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
        const summary = `${counts.checked} of ${nodes.length} IP(s) found on Censys: ${
            counts.certificates
        } certificate(s)${counts.cert_names ? ` naming ${counts.cert_names} domain(s)` : ''}, ${counts.host_keys} SSH host key(s)${
            counts.misses ? `, ${counts.misses} skipped` : ''
        }`;
        return { summary, counts };
    },
});

// =============================================================================================
// 2. censys_search — a CenQL query, and/or the hosts presenting a selected certificate or SSH key
// =============================================================================================
const BY_FINGERPRINT: Record<string, { field: string; label: string }> = {
    'infrastructure.certificate': { field: 'host.services.cert.fingerprint_sha256', label: 'presents certificate' },
    'infrastructure.ssh_host_key': {
        field: 'host.services.ssh.server_host_key.fingerprint_sha256',
        label: 'presents host key',
    },
};

const isIp = (v: string): boolean =>
    /^\d{1,3}(\.\d{1,3}){3}$/.test(v) || (v.includes(':') && /^[0-9a-fA-F:]+$/.test(v));

export const censysSearch = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.censys_search',
        content_type: 'vineyard:plugin',
        name: 'Censys Search',
        version: VERSION,
        description:
            "Searches Censys for hosts, two ways. With TLS Certificate or SSH Host Key nodes selected, it finds every host presenting that certificate or key, adds their IP Addresses linked by 'presents certificate' / 'presents host key', and records the total number of matching hosts on the node as censys_host_count (thousands usually means a shared device default, not one operator). With a Censys Query Language (CenQL) query in the Run dialog (syntax and common fields in the query parameter's description), it adds what the query matches: hosts as IP Addresses, certificates as TLS Certificates, web properties as Domains. Needs a paid Censys account (Starter or higher) and its organization ID; each search costs credits. Desktop only.",
        icon: 'search',
        platforms: PLATFORMS,
        params: {
            type: 'object',
            properties: {
                query: {
                    type: 'string',
                    title: 'CenQL query',
                    // A summary of https://docs.censys.com/docs/censys-query-language, carried here
                    // because an agent writing a query reads THIS, and the one example it used to
                    // hold was all it had: it guessed the rest from memory, mixed in Legacy Search
                    // forms, and lost whole pivots to 422s (2026-10-07 transcripts: 4 of 16 and 16
                    // of 34 free queries rejected, every one a field path that does not exist).
                    // Each field below resolves in the Platform's search OpenAPI schema.
                    description: [
                        'A Censys Query Language (CenQL) query, searched across hosts, certificates and web properties at once. Platform syntax, not Legacy Search: every full field path starts with host., cert. or web., and the prefix decides what matches (host.* finds hosts, cert.* certificates, web.* web properties); only the aliases below and the names inside a nested group are written without it. There is no unprefixed ip or services.* field: Legacy ip is host.ip, and Legacy services.tls.certificates.leaf_data.* is host.services.cert.* (host.services.tls.* still exists, for handshake data such as ja3s and ja4s). There is no …parsed.names and no …parsed.fingerprint_sha256.',
                        'Operators: field="v" exact and case-sensitive; field: "v" case-insensitive token match; field=~`regex`; > < >= <= for ranges, with numbers and dates in quotes; field: * any non-zero value (an empty string does not match). On cert.names and *.common_name, ":" also matches subdomains: cert.names: "example.com" finds certificates for example.com and any sub.example.com, and host.services.cert.names: "example.com" finds the hosts serving such a certificate. Part of a label, such as "example", does not match with ":"; use =~ for that. Combine with and / or / not and parentheses. host.services: (port="22" and protocol="SSH") requires both on the same service. Quote values with "…", \'…\' or `…` — always for hashes, IPs and CIDR blocks (an unquoted value must match [a-zA-Z][a-zA-Z0-9._-]*).',
                        'Common fields: host.ip (a CIDR block too: host.ip: "203.0.113.0/24"), host.services.port, host.services.protocol, host.autonomous_system.asn, host.dns.names, host.services.cert.fingerprint_sha256, host.services.cert.names (subject CN and SANs), host.services.cert.parsed.subject.common_name, host.services.cert.parsed.subject.organization, host.services.cert.parsed.issuer.organization, host.services.ssh.server_host_key.fingerprint_sha256, host.services.jarm.fingerprint, host.services.endpoints.http.html_title, host.services.endpoints.http.favicons.hash_sha256, web.hostname, cert.names, cert.fingerprint_sha256. Aliases search several fields at once, but not inside a nested group: sha256 (certificate fingerprints and HTTP body, favicon and banner hashes, not SSH host keys), org (WHOIS, AS and certificate subject or issuer organization).',
                        'Full reference: https://docs.censys.com/docs/censys-query-language. Runs alongside any selected certificates or SSH host keys; leave empty to search only those.',
                    ].join('\n'),
                },
                limit: {
                    type: 'integer',
                    title: 'Results per search',
                    description:
                        'Maximum results added per search (the query, and each selected certificate or SSH host key). 1–100, default 25.',
                },
            },
        },
        io: {
            // Empty on purpose: a typed query needs no selection, and a plugin that declares input
            // types is only offered when such nodes are selected. Selected certificates and SSH host
            // keys still reach run() and are searched for.
            consumes: [],
            produces: [
                { typepack: INFRA, category: 'infrastructure', name: 'ip_address' },
                { typepack: INFRA, category: 'infrastructure', name: 'certificate' },
                { typepack: INFRA, category: 'infrastructure', name: 'domain' },
            ],
        },
        scopes: { graph: GRAPH_SCOPES, network: NET_SCOPE, config: CONFIG },
        lifecycle: LIFECYCLE,
    },
    async run(ctx): Promise<RunResult> {
        const nodes = await selected(ctx, Object.keys(BY_FINGERPRINT));
        const query = typeof ctx.params?.query === 'string' ? ctx.params.query.trim() : '';
        const counts = { searches: 0, hosts: 0, certificates: 0, domains: 0, misses: 0 };
        if (!nodes.length && !query) {
            return { summary: 'Enter a CenQL query, or select TLS Certificate / SSH Host Key nodes', counts };
        }
        const raw = Number(ctx.params?.limit);
        const limit = Number.isInteger(raw) && raw >= 1 ? Math.min(raw, 100) : 25;
        const capped: string[] = [];

        /** One page of results. Search is a paid feature, so a 403 ends the run rather than an item. */
        const search = async (q: string): Promise<any> => {
            try {
                return (await censys(ctx, 'POST', '/search/query', { query: q, page_size: limit }))?.result;
            } catch (e) {
                if (e instanceof CensysError && e.status === 403) {
                    throw new Error(`Censys search needs a paid account (Starter or higher) — ${e.message}`);
                }
                throw e;
            }
        };
        const hitsOf = (result: any): any[] => (Array.isArray(result?.hits) ? result.hits : []);

        const steps = nodes.length + (query ? 1 : 0);
        let step = 0;

        if (query) {
            ctx.progress?.set?.({ percent: 0, message: 'Running the query' });
            let result: any;
            try {
                result = await search(query);
            } catch (e) {
                if (e instanceof CensysError && (e.status === 400 || e.status === 422)) {
                    // The corrections are the three wrong guesses the 2026-10-07 transcripts made
                    // over and over; the query parameter's description has the rest.
                    throw new Error(
                        `Censys rejected the query — ${e.message}. Check every field against the CenQL notes in this plugin's query parameter: ` +
                            'full field paths start with host., cert. or web. (host.ip, not ip); a certificate fingerprint is host.services.cert.fingerprint_sha256, not …cert.parsed.fingerprint_sha256; ' +
                            'certificate names are host.services.cert.names or cert.names, not …parsed.names.',
                    );
                }
                throw e;
            }
            counts.searches++;
            step++;
            const hits = hitsOf(result);
            for (const h of hits) {
                if (ctx.signal?.aborted) throw abortErr();
                const ip = h?.host_v1?.resource?.ip;
                const cert = h?.certificate_v1?.resource;
                const hostname = h?.webproperty_v1?.resource?.hostname;
                if (typeof ip === 'string' && ip) {
                    await ctx.graph!.createNode!({ type: 'infrastructure.ip_address', data: { ip_address: ip } });
                    counts.hosts++;
                } else if (cert) {
                    const data = certData({ cert });
                    if (data) {
                        await ctx.graph!.createNode!({ type: 'infrastructure.certificate', data });
                        counts.certificates++;
                    }
                } else if (typeof hostname === 'string' && hostname) {
                    const ipName = isIp(hostname);
                    await ctx.graph!.createNode!({
                        type: ipName ? 'infrastructure.ip_address' : 'infrastructure.domain',
                        data: ipName ? { ip_address: hostname } : { domain_name: hostname.toLowerCase() },
                    });
                    if (ipName) counts.hosts++;
                    else counts.domains++;
                }
            }
            const total = Number(result?.total_hits ?? 0);
            if (total > hits.length) capped.push(`query ${hits.length} of ${total}`);
        }

        for (const n of nodes) {
            if (ctx.signal?.aborted) throw abortErr();
            const fp = hex64(n.data.fingerprint_sha256);
            if (!fp) {
                counts.misses++;
                ctx.progress?.log?.(`${n.id}: no SHA-256 fingerprint to search for`);
                continue;
            }
            const by = BY_FINGERPRINT[n.type];
            ctx.progress?.set?.({
                percent: Math.round((step / steps) * 100),
                message: `Searching ${fp.slice(0, 12)}…`,
            });
            let result: any;
            try {
                result = await search(`${by.field}="${fp}"`);
            } catch (e) {
                const why = itemMiss(e);
                if (!why) throw e;
                counts.misses++;
                ctx.progress?.log?.(`${fp.slice(0, 12)}…: ${why}`);
                continue;
            }
            counts.searches++;
            step++;
            const total = Number(result?.total_hits ?? 0);
            await ctx.graph!.updateNode!(n.id, { censys_host_count: total });

            const ips = [
                ...new Set(
                    hitsOf(result)
                        .map((h) => h?.host_v1?.resource?.ip)
                        .filter((ip) => typeof ip === 'string' && ip),
                ),
            ];
            for (const ip of ips) {
                const node = await ctx.graph!.createNode!({
                    type: 'infrastructure.ip_address',
                    data: { ip_address: ip },
                });
                await ctx.graph!.createEdge!({ from: node.id, to: n.id, label: by.label });
                counts.hosts++;
            }
            if (total > ips.length) {
                capped.push(`${fp.slice(0, 12)}… ${ips.length} of ${total}`);
                ctx.progress?.log?.(`${fp.slice(0, 12)}…: added ${ips.length} of ${total} hosts`);
            }
        }
        ctx.progress?.set?.({ percent: 100 });
        const added = [
            `${counts.hosts} IP(s)`,
            counts.certificates ? `${counts.certificates} certificate(s)` : '',
            counts.domains ? `${counts.domains} domain(s)` : '',
        ].filter(Boolean);
        const summary = `${counts.searches} search(es), ${added.join(', ')}${
            capped.length ? ` — capped: ${capped.join('; ')}` : ''
        }${counts.misses ? `, ${counts.misses} skipped` : ''}`;
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
    name: 'Censys (under testing)',
    version: VERSION,
    description: `Censys Platform lookups and searches with the analyst's own Personal Access Token: the TLS certificates (and the domain names they list), SSH host keys and open services an IP presents, the other hosts presenting the same certificate or SSH key, and free Censys Query Language (CenQL) searches. Desktop only. ${TESTING_NOTE}`,
    author: { name: 'VINEYARD', url: 'https://vineyard.run' },
    license: 'Apache-2.0',
    icon: 'scan-line',
    platforms: PLATFORMS,
    plugins: [censysHostLookup, censysSearch],
};

export const censysPack = definePluginPack(pack);
export default censysPack;
