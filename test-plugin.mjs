// Functional test harness for pluginpack-censys/dist/pack.mjs (2 plugins).
// Run: node test-plugin.mjs
//
// Responses follow the shapes in the Censys Platform API reference (v3 global data): host lookup
// `result.resource.services[]`, search `result.{total_hits, hits[].host_v1.resource}`. A live run on
// a free account (2026-10-01) matched them for host lookup; search answered 403 there, as tested.
import pack from "./dist/pack.mjs";

const [hostPlugin, searchPlugin] = pack.plugins;
const ok = [];
const fail = [];
const check = (name, cond) => (cond ? ok : fail).push(name);

function makeGraph(nodeById) {
  const createdNodes = [];
  const createdEdges = [];
  const updates = [];
  return {
    createdNodes,
    createdEdges,
    updates,
    async get(id) {
      return nodeById[id] || null;
    },
    async createNode(draft) {
      const node = { id: `n${createdNodes.length + 1}`, type: draft.type, data: draft.data };
      createdNodes.push(node);
      return node;
    },
    async updateNode(id, data) {
      updates.push({ id, data });
    },
    async createEdge(edge) {
      createdEdges.push(edge);
    },
  };
}

function makeNet(respond) {
  const calls = [];
  return {
    calls,
    async fetch(url, init) {
      calls.push({ url, init });
      const { status, body, headers } = respond(url, init, calls.length);
      return {
        ok: status >= 200 && status < 300,
        status,
        headers: headers ?? {},
        async json() {
          return body;
        },
        async text() {
          return JSON.stringify(body);
        },
      };
    },
  };
}

function ctxFor({ nodes, selection, respond, platform = "desktop", config, params }) {
  const graph = makeGraph(nodes);
  const net = makeNet(respond);
  const logs = [];
  return {
    graph,
    net,
    logs,
    ctx: {
      run: { runId: "r1", projectId: "p1", pluginId: "x", grantedScopes: {}, platform },
      input: { selection },
      params: params ?? {},
      config: config ?? { api_key: " pat-token " },
      graph,
      net,
      progress: { set() {}, log: (m) => logs.push(m) },
      signal: undefined,
    },
  };
}

const CERT_FP = "AB".repeat(32);
// Censys writes its fingerprints in lowercase hex; uppercase here proves the pack folds them anyway.
const CERT_SHA1 = "C0FFEE".repeat(6) + "C0FF";
const ED_FP = "cd".repeat(32);
const RSA_FP = "ef".repeat(32);
const hostBody = {
  result: {
    resource: {
      ip: "198.51.100.7",
      services: [
        {
          port: 443,
          protocol: "HTTP",
          transport_protocol: "tcp",
          tls: { fingerprint_sha256: CERT_FP },
          cert: {
            fingerprint_sha256: CERT_FP,
            fingerprint_sha1: CERT_SHA1,
            parsed: {
              subject: { common_name: ["origin.example.com"] },
              issuer_dn: "C=US, O=CloudFlare, Inc., OU=CloudFlare Origin SSL Certificate Authority",
              serial_number: "1234567890",
              serial_number_hex: "499602d2",
              validity_period: { not_before: "2026-01-01T00:00:00Z", not_after: "2041-01-01T00:00:00Z" },
            },
          },
        },
        { port: 8443, protocol: "HTTP", tls: { fingerprint_sha256: CERT_FP }, cert: { fingerprint_sha256: CERT_FP } },
        {
          port: 22,
          protocol: "SSH",
          ssh: {
            server_host_key: { fingerprint_sha256: ED_FP, ed25519_public_key: { public_bytes: "x" } },
            algorithm_selection: { host_key_algorithm: "ssh-ed25519" },
          },
        },
        {
          port: 2222,
          protocol: "SSH",
          ssh: { server_host_key: { fingerprint_sha256: RSA_FP }, algorithm_selection: { host_key_algorithm: "rsa-sha2-512" } },
        },
        { port: 2200, protocol: "SSH", ssh: { server_host_key: { fingerprint_sha256: "not-a-hash" } } },
      ],
    },
  },
};

// ---- censys_host_lookup ---------------------------------------------------------------------------
{
  const { ctx } = ctxFor({ nodes: {}, selection: [], respond: () => ({ status: 200, body: {} }), platform: "web" });
  ctx.input.selection = ["ip1"];
  ctx.graph.get = async () => ({ id: "ip1", type: "infrastructure.ip_address", data: { ip_address: "1.2.3.4" } });
  const err = await hostPlugin.run(ctx).catch((e) => e);
  check("web build refuses with the CORS reason", err instanceof Error && /desktop app/.test(err.message));
}
{
  const t = ctxFor({
    nodes: { ip1: { id: "ip1", type: "infrastructure.ip_address", data: { ip_address: "198.51.100.7" } } },
    selection: ["ip1"],
    respond: () => ({ status: 200, body: hostBody }),
    config: { api_key: "tok", organization_id: " org-1 " },
  });
  const res = await hostPlugin.run(t.ctx);
  const call = t.net.calls[0];
  check("host lookup URL", call.url === "https://api.platform.censys.io/v3/global/asset/host/198.51.100.7");
  check("bearer token, trimmed", call.init.headers.Authorization === "Bearer tok");
  check("org id goes in X-Organization-ID", call.init.headers["X-Organization-ID"] === "org-1");
  const certs = t.graph.createdNodes.filter((n) => n.type === "infrastructure.certificate");
  check("one certificate across two ports", certs.length === 1);
  check("certificate fingerprint lowercased", certs[0]?.data.fingerprint_sha256 === CERT_FP.toLowerCase());
  // SSLBL lists certificates by SHA-1 only, and a SHA-256 cannot be turned into one.
  check("certificate SHA-1 kept, lowercased, as fingerprint_sha1", certs[0]?.data.fingerprint_sha1 === CERT_SHA1.toLowerCase());
  check("certificate CN/issuer/validity", certs[0]?.data.subject_common_name === "origin.example.com" && /CloudFlare Origin/.test(certs[0]?.data.issuer) && certs[0]?.data.not_after === "2041-01-01T00:00:00Z" && certs[0]?.data.serial_number === "499602d2");
  const keys = t.graph.createdNodes.filter((n) => n.type === "infrastructure.ssh_host_key");
  check("two valid host keys, bad one skipped", keys.length === 2);
  check("ed25519 key type", keys.find((k) => k.data.fingerprint_sha256 === ED_FP)?.data.key_type === "ssh-ed25519");
  check("rsa-sha2-512 maps to ssh-rsa", keys.find((k) => k.data.fingerprint_sha256 === RSA_FP)?.data.key_type === "ssh-rsa");
  check("edge labels", t.graph.createdEdges.filter((e) => e.label === "presents certificate" && e.from === "ip1").length === 1 && t.graph.createdEdges.filter((e) => e.label === "presents host key").length === 2);
  check("services listed on the IP", t.graph.updates[0]?.data.censys_services === "443/HTTP, 8443/HTTP, 22/SSH, 2222/SSH, 2200/SSH");
  check("summary counts", res.counts.certificates === 1 && res.counts.host_keys === 2);
}
{
  const t = ctxFor({
    nodes: {
      a: { id: "a", type: "infrastructure.ip_address", data: { ip_address: "192.0.2.1" } },
      b: { id: "b", type: "infrastructure.ip_address", data: { ip_address: "192.0.2.2" } },
    },
    selection: ["a", "b"],
    respond: (url) => (url.endsWith("192.0.2.1") ? { status: 404, body: { error: { code: 404, message: "Host not found" } } } : { status: 200, body: hostBody }),
  });
  const res = await hostPlugin.run(t.ctx);
  check("404 skips the item and continues", res.counts.misses === 1 && res.counts.checked === 1);
  check("404 reason logged", t.logs.some((l) => /192\.0\.2\.1: no Censys record/.test(l)));
  check("no org header when unset", !("X-Organization-ID" in t.net.calls[0].init.headers));
}
{
  const t = ctxFor({
    nodes: { a: { id: "a", type: "infrastructure.ip_address", data: { ip_address: "192.0.2.1" } } },
    selection: ["a"],
    respond: () => ({ status: 401, body: { message: "Access credentials are invalid" } }),
  });
  const err = await hostPlugin.run(t.ctx).catch((e) => e);
  check("401 ends the run", err instanceof Error && /rejected this Personal Access Token/.test(err.message));
}
{
  const t = ctxFor({
    nodes: { a: { id: "a", type: "infrastructure.ip_address", data: { ip_address: "192.0.2.1" } } },
    selection: ["a"],
    respond: (_u, _i, n) => (n === 1 ? { status: 429, body: {} } : { status: 200, body: hostBody }),
  });
  const res = await hostPlugin.run(t.ctx);
  check("429 is retried", t.net.calls.length === 2 && res.counts.checked === 1);
}

{
  // Certificate names. Censys parses the SAN extension into
  // cert.parsed.extensions.subject_alt_name.dns_names, and lists CN + SANs as cert.names
  // (host.services.cert.names in CenQL).
  const sharedNames = Array.from({ length: 30 }, (_, i) => `tenant${i}.example`);
  const body = {
    result: {
      resource: {
        ip: "198.51.100.8",
        services: [
          {
            port: 443,
            protocol: "HTTP",
            cert: {
              fingerprint_sha256: "11".repeat(32),
              names: ["example.com", "origin.example.com", "*.example.com"],
              parsed: {
                subject: { common_name: ["example.com"] },
                extensions: { subject_alt_name: { dns_names: ["origin.example.com", "*.example.com", "Example.com", "localhost", "nas.local"] } },
              },
            },
          },
          {
            port: 8443,
            protocol: "HTTP",
            cert: { fingerprint_sha256: "22".repeat(32), parsed: { extensions: { subject_alt_name: { dns_names: sharedNames } } } },
          },
          { port: 9443, protocol: "HTTP", cert: { fingerprint_sha256: "33".repeat(32), names: ["fallback.example.net"] } },
        ],
      },
    },
  };
  const t = ctxFor({
    nodes: { ip1: { id: "ip1", type: "infrastructure.ip_address", data: { ip_address: "198.51.100.8" } } },
    selection: ["ip1"],
    respond: () => ({ status: 200, body }),
  });
  const res = await hostPlugin.run(t.ctx);
  const nodeById = new Map(t.graph.createdNodes.map((n) => [n.id, n]));
  const certByFp = (fp) => t.graph.createdNodes.find((n) => n.type === "infrastructure.certificate" && n.data.fingerprint_sha256 === fp);
  const namedFrom = (cert) => t.graph.createdEdges.filter((e) => e.label === "names domain" && e.from === cert?.id).map((e) => nodeById.get(e.to)?.data.domain_name).sort();
  const own = certByFp("11".repeat(32));
  check("san: dns_names become Domains off the certificate, '*.' stripped, deduped, internal dropped", namedFrom(own).join() === "example.com,origin.example.com");
  check("san: san_count on the certificate", own?.data.san_count === 2);
  const shared = certByFp("22".repeat(32));
  check("san cap: a 30-name certificate adds no Domains", namedFrom(shared).length === 0);
  check("san cap: ...and records how many it lists", shared?.data.san_count === 30);
  check("san cap: ...and says why", t.logs.some((l) => /30 names — over 25/.test(l)));
  check("san: cert.names is the fallback when no parsed SAN", namedFrom(certByFp("33".repeat(32))).join() === "fallback.example.net");
  check("san: counted and summarised", res.counts.cert_names === 3 && /naming 3 domain\(s\)/.test(res.summary));
}
{
  // Two selected IPs presenting one certificate. The host merges createNode calls by identity
  // (imitated here), so both get the same certificate node — whose names are linked once, not per IP.
  const service = { port: 443, protocol: "HTTP", cert: { fingerprint_sha256: "44".repeat(32), names: ["a.example.com", "b.example.com"] } };
  const t = ctxFor({
    nodes: {
      ip1: { id: "ip1", type: "infrastructure.ip_address", data: { ip_address: "198.51.100.21" } },
      ip2: { id: "ip2", type: "infrastructure.ip_address", data: { ip_address: "198.51.100.22" } },
    },
    selection: ["ip1", "ip2"],
    respond: () => ({ status: 200, body: { result: { resource: { services: [service] } } } }),
  });
  const create = t.graph.createNode;
  const byIdentity = new Map();
  t.graph.createNode = async (d) => {
    const k = `${d.type}\0${d.data.fingerprint_sha256 ?? d.data.domain_name}`;
    if (!byIdentity.has(k)) byIdentity.set(k, await create(d));
    return byIdentity.get(k);
  };
  const res = await hostPlugin.run(t.ctx);
  check("san: a certificate shared by two selected IPs links its names once", t.graph.createdEdges.filter((e) => e.label === "names domain").length === 2 && res.counts.cert_names === 2);
  check("san: ...while each IP still presents it", t.graph.createdEdges.filter((e) => e.label === "presents certificate").length === 2);
}

// ---- censys_search: one CenQL query -----------------------------------------------------------
const searchBody = {
  result: {
    total_hits: 300,
    hits: [
      { host_v1: { resource: { ip: "203.0.113.5" } } },
      { host_v1: { resource: { ip: "203.0.113.6" } } },
      { host_v1: { resource: { ip: "203.0.113.5" } } },
      { webproperty_v1: { resource: { hostname: "x.example" } } },
    ],
  },
};
{
  const t = ctxFor({ nodes: {}, selection: [], respond: () => ({ status: 200, body: searchBody }), params: { query: 'host.services.port=8443', limit: 5 } });
  const res = await searchPlugin.run(t.ctx);
  const b = JSON.parse(t.net.calls[0].init.body);
  check("search endpoint and method", t.net.calls[0].url === "https://api.platform.censys.io/v3/global/search/query" && t.net.calls[0].init.method === "POST");
  check("the query is the only input", b.query === "host.services.port=8443" && t.net.calls.length === 1);
  check("limit param becomes page_size", b.page_size === 5);
  check("capped search reports what it added", /capped/.test(res.summary) && /4 of 300/.test(res.summary));
  check("search adds no edges", t.graph.createdEdges.length === 0);
}
{
  // Selecting a certificate must change nothing: the plugin reads its query, not the canvas.
  const cert = { id: "c1", type: "infrastructure.certificate", data: { fingerprint_sha256: CERT_FP } };
  const t = ctxFor({ nodes: { c1: cert }, selection: ["c1"], respond: () => ({ status: 200, body: searchBody }), params: { query: "host.ip=1.2.3.4" } });
  await searchPlugin.run(t.ctx);
  check("a selected certificate does not become an extra search", t.net.calls.length === 1 && JSON.parse(t.net.calls[0].init.body).query === "host.ip=1.2.3.4");
  const none = ctxFor({ nodes: { c1: cert }, selection: ["c1"], respond: () => ({ status: 200, body: searchBody }) });
  const res = await searchPlugin.run(none.ctx);
  check("with no query there is nothing to do", none.net.calls.length === 0 && none.graph.updates.length === 0 && /Enter a CenQL query/.test(res.summary));
}
{
  const t = ctxFor({ nodes: {}, selection: [], respond: () => ({ status: 200, body: { result: { total_hits: 0, hits: [] } } }), params: { query: "x", limit: 999 } });
  await searchPlugin.run(t.ctx);
  check("limit clamps to 100", JSON.parse(t.net.calls[0].init.body).page_size === 100);
  const d = ctxFor({ nodes: {}, selection: [], respond: () => ({ status: 200, body: { result: { total_hits: 0, hits: [] } } }), params: { query: "x" } });
  await searchPlugin.run(d.ctx);
  check("default limit 25", JSON.parse(d.net.calls[0].init.body).page_size === 25);
}
{
  const t = ctxFor({ nodes: {}, selection: [], respond: () => ({ status: 403, body: { error: { message: "Forbidden" } } }), params: { query: "x" } });
  const err = await searchPlugin.run(t.ctx).catch((e) => e);
  check("403 on search ends the run with the tier reason", err instanceof Error && /paid account/.test(err.message) && t.net.calls.length === 1);
}

{
  const body = {
    result: {
      total_hits: 3,
      hits: [
        { host_v1: { resource: { ip: "203.0.113.9" } } },
        { certificate_v1: { resource: { fingerprint_sha256: CERT_FP, fingerprint_sha1: CERT_SHA1, parsed: { subject: { common_name: ["a.example"] } } } } },
        { webproperty_v1: { resource: { hostname: "Shop.Example.com", port: 443 } } },
        { webproperty_v1: { resource: { hostname: "198.51.100.20", port: 8443 } } },
      ],
    },
  };
  const t = ctxFor({ nodes: {}, selection: [], respond: () => ({ status: 200, body }), params: { query: '  host.services.port=8443  ' } });
  const res = await searchPlugin.run(t.ctx);
  check("query runs with no selection", JSON.parse(t.net.calls[0].init.body).query === "host.services.port=8443");
  const types = t.graph.createdNodes.map((n) => `${n.type}:${JSON.stringify(n.data).slice(0, 40)}`);
  check("host hit -> IP", t.graph.createdNodes.some((n) => n.type === "infrastructure.ip_address" && n.data.ip_address === "203.0.113.9"));
  check("certificate hit -> certificate", t.graph.createdNodes.some((n) => n.type === "infrastructure.certificate" && n.data.subject_common_name === "a.example"));
  check("certificate hit keeps its SHA-1", t.graph.createdNodes.some((n) => n.type === "infrastructure.certificate" && n.data.fingerprint_sha1 === CERT_SHA1.toLowerCase()));
  check("web property hostname -> lowercased domain", t.graph.createdNodes.some((n) => n.type === "infrastructure.domain" && n.data.domain_name === "shop.example.com"));
  check("web property IP hostname -> IP", t.graph.createdNodes.some((n) => n.type === "infrastructure.ip_address" && n.data.ip_address === "198.51.100.20"));
  check("query adds no edges", t.graph.createdEdges.length === 0);
  check("query summary", res.counts.hosts === 2 && res.counts.certificates === 1 && res.counts.domains === 1);
}
{
  const t = ctxFor({ nodes: {}, selection: [], respond: () => ({ status: 200, body: {} }) });
  const res = await searchPlugin.run(t.ctx);
  check("nothing to search returns guidance without a request", t.net.calls.length === 0 && /CenQL query/.test(res.summary));
  const q = ctxFor({ nodes: {}, selection: [], respond: () => ({ status: 422, body: { error: { message: "invalid query" } } }), params: { query: "host.(" } });
  const err = await searchPlugin.run(q.ctx).catch((e) => e);
  check("a rejected query ends the run with Censys' reason", err instanceof Error && /rejected the query — invalid query/.test(err.message));
  // The Platform's problem+json: a one-line detail, and the field it objects to in errors[].
  const pj = ctxFor({ nodes: {}, selection: [], params: { query: 'host.services.cert.parsed.names="x.example"' }, respond: () => ({ status: 422, body: {
    title: "Unprocessable Entity", status: 422, detail: "Query error",
    errors: [{ location: "body.query", message: "unknown field host.services.cert.parsed.names", value: "host.services.cert.parsed.names" }],
  } }) });
  const pjErr = await searchPlugin.run(pj.ctx).catch((e) => e);
  check("a 422 passes Censys's errors[] through with the field it names", pjErr instanceof Error && /Query error — body\.query: unknown field host\.services\.cert\.parsed\.names \(HTTP 422\)/.test(pjErr.message));
  check("a rejected query points at the CenQL notes and the common corrections", /CenQL notes/.test(pjErr.message) && /host\.services\.cert\.names/.test(pjErr.message) && /host\.ip, not ip/.test(pjErr.message));
  // A body with hundreds of entries must not become a message of tens of thousands of characters.
  const flood = ctxFor({ nodes: {}, selection: [], params: { query: "host.x=1" }, respond: () => ({ status: 422, body: {
    detail: "Query error",
    errors: [
      ...Array.from({ length: 200 }, (_, i) => ({ location: "body.query", message: `unknown field host.f${i} ${"x".repeat(400)}` })),
      { location: "body.query", message: `unknown field host.f0 ${"x".repeat(400)}` },
    ],
  } }) });
  const floodErr = await searchPlugin.run(flood.ctx).catch((e) => e);
  check("a flood of errors[] is capped at five entries, clipped, deduplicated and counted", floodErr instanceof Error && floodErr.message.length < 2500 && /195 more/.test(floodErr.message) && (floodErr.message.match(/unknown field/g) || []).length === 5);
  const qd = searchPlugin.manifest.params.properties.query.description;
  check("the query is a required field", Array.isArray(searchPlugin.manifest.params.required) && searchPlugin.manifest.params.required.includes("query"));
  check("the query parameter carries the CenQL summary and the reference link", /Platform syntax, not Legacy Search/.test(qd) && /host\.services\.cert\.names/.test(qd) && /https:\/\/docs\.censys\.com\/docs\/censys-query-language/.test(qd));
  check("the plugin description stays within the catalog's 1024 characters", searchPlugin.manifest.description.length <= 1024);
}
// ---- raw results: ctx.retain (check:retain-feature-detect) --------------------------------------
// Invariants, from the plugin raw results spec (§5, §9-1, §12):
//   - Host Lookup keeps the FINAL answer for each IP on that IP's node, op "host": a 2xx, and the
//     404/403/400/422 item misses too (the analyst keeps error answers). A retried 429 is never kept,
//     and a run-ending error (401, throttling past the retries) keeps nothing.
//   - Search keeps nothing (analyst's decision, 2026-11-25): a hit cut out of a page is not the
//     answer Censys sent.
//   - Nothing handed to retain carries the token, the organization ID, a URL or an Authorization
//     header: the request never leaves the pack.
//   - A refusal object or a throw from retain never fails the run, and is logged once per reason.
//   - A host without ctx.retain (every desktop build before it) runs exactly as before.
const SECRET_PAT = "pat-SECRET-token-0123456789";
const SECRET_ORG = "org-SECRET-0123456789";
const SECRET_CONFIG = { api_key: SECRET_PAT, organization_id: SECRET_ORG };
const RESPONSE_HEADERS = { "content-type": "application/json", etag: '"r-1"', "x-request-id": "rq-1" };

function retainSpy(answer = async () => ({ kept: true })) {
  const calls = [];
  const fn = async (...args) => {
    calls.push(args);
    return answer(...args);
  };
  fn.calls = calls;
  return fn;
}

/** Everything a retain call was given, as one string to search for what must not be there. */
const dumped = (calls) => JSON.stringify(calls);
const leaks = (calls) => {
  const s = dumped(calls);
  return [SECRET_PAT, SECRET_ORG, "Bearer", "Authorization", "X-Organization-ID", "http://", "https://", "api.platform.censys.io"].filter((x) => s.includes(x));
};
const bodyOf = (call) => (typeof call?.[2]?.body === "string" ? JSON.parse(call[2].body) : call?.[2]?.body);

{
  const nodes = { ip1: { id: "ip1", type: "infrastructure.ip_address", data: { ip_address: "198.51.100.7" } } };
  const spy = retainSpy();
  const t = ctxFor({ nodes, selection: ["ip1"], config: SECRET_CONFIG, respond: () => ({ status: 200, body: hostBody, headers: RESPONSE_HEADERS }) });
  t.ctx.retain = spy;
  const res = await hostPlugin.run(t.ctx);
  check("retain host: one call, on the looked-up IP, op host", spy.calls.length === 1 && spy.calls[0][0] === "ip1" && spy.calls[0][1] === "host");
  check("retain host: status and the response's own headers", spy.calls[0]?.[2].status === 200 && spy.calls[0]?.[2].headers.etag === '"r-1"');
  check("retain host: the whole answer, as the text Censys sent", typeof spy.calls[0]?.[2].body === "string" && JSON.stringify(bodyOf(spy.calls[0])) === JSON.stringify(hostBody));
  check("retain host: a plain object, nothing a worker cannot post", spy.calls[0] && Object.keys(spy.calls[0][2]).sort().join() === "body,headers,status");
  check("retain host: no token, organization ID, URL or Authorization header", leaks(spy.calls).length === 0);
  check("retain host: the request really carried both secrets", t.net.calls[0].init.headers.Authorization === `Bearer ${SECRET_PAT}` && t.net.calls[0].init.headers["X-Organization-ID"] === SECRET_ORG);

  // The same run on a host without retain: same graph, same counts.
  const old = ctxFor({ nodes, selection: ["ip1"], config: SECRET_CONFIG, respond: () => ({ status: 200, body: hostBody, headers: RESPONSE_HEADERS }) });
  const oldRes = await hostPlugin.run(old.ctx);
  check("old host: no ctx.retain, the lookup runs as before", !("retain" in old.ctx) && JSON.stringify(oldRes) === JSON.stringify(res));
  check("old host: says nothing about raw results", !old.logs.some((l) => /not kept/.test(l)));
  check("old host: ...and stages the same graph", JSON.stringify(old.graph.createdNodes) === JSON.stringify(t.graph.createdNodes) && JSON.stringify(old.graph.updates) === JSON.stringify(t.graph.updates));
  const notFn = ctxFor({ nodes, selection: ["ip1"], respond: () => ({ status: 200, body: hostBody }) });
  notFn.ctx.retain = true;
  const notFnRes = await hostPlugin.run(notFn.ctx).catch((e) => e);
  check("old host: a retain that is not a function is left alone", !(notFnRes instanceof Error) && notFnRes.counts.checked === 1);
}
{
  const spy = retainSpy();
  const t = ctxFor({
    nodes: {
      a: { id: "a", type: "infrastructure.ip_address", data: { ip_address: "192.0.2.1" } },
      b: { id: "b", type: "infrastructure.ip_address", data: { ip_address: "192.0.2.2" } },
      c: { id: "c", type: "infrastructure.ip_address", data: { ip_address: "192.0.2.3" } },
    },
    selection: ["a", "b", "c"],
    config: SECRET_CONFIG,
    respond: (url) =>
      url.endsWith("192.0.2.1")
        ? { status: 404, body: { error: { code: 404, message: "Host not found" } } }
        : url.endsWith("192.0.2.3")
          ? { status: 403, body: { error: { message: "Forbidden" } } }
          : { status: 200, body: hostBody },
  });
  t.ctx.retain = spy;
  const res = await hostPlugin.run(t.ctx);
  check("retain host: item misses are kept too, on their own IP", spy.calls.map((c) => `${c[0]}:${c[1]}:${c[2].status}`).join() === "a:host:404,b:host:200,c:host:403");
  check("retain host: a 404 keeps Censys' own error body", bodyOf(spy.calls[0])?.error?.message === "Host not found");
  check("retain host: misses still skip the item", res.counts.misses === 2 && res.counts.checked === 1);
  check("retain host: no secret in a kept error answer either", leaks(spy.calls).length === 0);
}
{
  const spy = retainSpy();
  const t = ctxFor({
    nodes: { a: { id: "a", type: "infrastructure.ip_address", data: { ip_address: "192.0.2.1" } } },
    selection: ["a"],
    respond: () => ({ status: 401, body: { message: "Access credentials are invalid" } }),
  });
  t.ctx.retain = spy;
  await hostPlugin.run(t.ctx).catch(() => {});
  check("retain host: a 401 ends the run and keeps nothing", spy.calls.length === 0);

  const retried = retainSpy();
  const r = ctxFor({
    nodes: { a: { id: "a", type: "infrastructure.ip_address", data: { ip_address: "192.0.2.1" } } },
    selection: ["a"],
    respond: (_u, _i, n) => (n === 1 ? { status: 429, body: { throttled: true } } : { status: 200, body: hostBody }),
  });
  r.ctx.retain = retried;
  await hostPlugin.run(r.ctx);
  check("retain host: a retried 429 is not kept, only the final answer", retried.calls.length === 1 && retried.calls[0][2].status === 200);
}
{
  const spy = retainSpy();
  const t = ctxFor({ nodes: {}, selection: [], config: SECRET_CONFIG, respond: () => ({ status: 200, body: searchBody, headers: RESPONSE_HEADERS }), params: { query: "host.services.port=8443" } });
  t.ctx.retain = spy;
  const res = await searchPlugin.run(t.ctx);
  check("retain search: keeps nothing, not even a slice per hit", spy.calls.length === 0);
  check("retain search: still maps every hit", res.counts.hosts === 3 && t.graph.createdNodes.length === searchBody.result.hits.length);
}
{
  for (const status of [403, 422]) {
    const spy = retainSpy();
    const t = ctxFor({ nodes: {}, selection: [], respond: () => ({ status, body: { error: { message: "no" } } }), params: { query: "x" } });
    t.ctx.retain = spy;
    await searchPlugin.run(t.ctx).catch(() => {});
    check(`retain search: a run-ending ${status} keeps nothing`, spy.calls.length === 0);
  }
}
{
  // A refusal is an object, not a throw — and either way the run carries on.
  const refuse = retainSpy(async () => ({ kept: false, reason: "over this run's raw-result budget" }));
  const ips = { a: "192.0.2.1", b: "192.0.2.2", c: "192.0.2.3" };
  const t = ctxFor({
    nodes: Object.fromEntries(Object.entries(ips).map(([id, v]) => [id, { id, type: "infrastructure.ip_address", data: { ip_address: v } }])),
    selection: Object.keys(ips),
    respond: () => ({ status: 200, body: hostBody }),
  });
  t.ctx.retain = refuse;
  const res = await hostPlugin.run(t.ctx).catch((e) => e);
  check("retain refusal: the lookup still succeeds", !(res instanceof Error) && res.counts.checked === 3 && refuse.calls.length === 3);
  check("retain refusal: said once, not once per IP", t.logs.filter((l) => /Raw host result not kept — over this run's raw-result budget/.test(l)).length === 1);

  const thrower = retainSpy(async () => {
    throw new Error("host blew up");
  });
  const h = ctxFor({
    nodes: { ip1: { id: "ip1", type: "infrastructure.ip_address", data: { ip_address: "198.51.100.7" } } },
    selection: ["ip1"],
    respond: () => ({ status: 200, body: hostBody }),
  });
  h.ctx.retain = thrower;
  const hres = await hostPlugin.run(h.ctx).catch((e) => e);
  check("retain throw: the lookup still succeeds with everything mapped", !(hres instanceof Error) && hres.counts.checked === 1 && hres.counts.certificates === 1 && hres.counts.host_keys === 2);
  check("retain throw: logged without the host's message", h.logs.some((l) => /Raw host result not kept/.test(l)) && !h.logs.some((l) => /blew up/.test(l)));
}
{
  // The bundle is the source rebuilt: the version the update check compares moved, and only it.
  check("pack version is 0.7.0", pack.version === "0.7.0");
  check("member versions unchanged", hostPlugin.manifest.version === "0.4.0" && searchPlugin.manifest.version === "0.4.0");
}
for (const n of ok) console.log(`  ok   ${n}`);
for (const n of fail) console.log(`  FAIL ${n}`);
console.log(fail.length ? `\n${fail.length} FAILED` : `\nall ${ok.length} checks passed`);
if (fail.length) process.exit(1);
