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
      const { status, body } = respond(url, init, calls.length);
      return {
        ok: status >= 200 && status < 300,
        status,
        headers: {},
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

// ---- censys_search --------------------------------------------------------------------------
const certNode = { id: "c1", type: "infrastructure.certificate", data: { fingerprint_sha256: CERT_FP } };
const keyNode = { id: "k1", type: "infrastructure.ssh_host_key", data: { fingerprint_sha256: ED_FP } };
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
  const t = ctxFor({ nodes: { c1: certNode, k1: keyNode }, selection: ["c1", "k1"], respond: () => ({ status: 200, body: searchBody }), params: { limit: 5 } });
  const res = await searchPlugin.run(t.ctx);
  const [c, k] = t.net.calls;
  const cb = JSON.parse(c.init.body);
  const kb = JSON.parse(k.init.body);
  check("search endpoint and method", c.url === "https://api.platform.censys.io/v3/global/search/query" && c.init.method === "POST");
  check("cert query uses the lowercased fingerprint", cb.query === `host.services.cert.fingerprint_sha256="${CERT_FP.toLowerCase()}"`);
  check("ssh query field", kb.query === `host.services.ssh.server_host_key.fingerprint_sha256="${ED_FP}"`);
  check("limit param becomes page_size", cb.page_size === 5);
  check("host count recorded on the node", t.graph.updates.some((u) => u.id === "c1" && u.data.censys_host_count === 300));
  const ips = t.graph.createdNodes.filter((n) => n.type === "infrastructure.ip_address");
  check("distinct IPs only, web hits ignored", ips.length === 4); // 2 per searched node
  check("edges run IP -> pivot node", t.graph.createdEdges.some((e) => e.to === "c1" && e.label === "presents certificate") && t.graph.createdEdges.some((e) => e.to === "k1" && e.label === "presents host key"));
  check("cap reported", /capped/.test(res.summary) && /2 of 300/.test(res.summary));
}
{
  const t = ctxFor({ nodes: { c1: certNode }, selection: ["c1"], respond: () => ({ status: 200, body: { result: { total_hits: 0, hits: [] } } }), params: { limit: 999 } });
  await searchPlugin.run(t.ctx);
  check("limit clamps to 100", JSON.parse(t.net.calls[0].init.body).page_size === 100);
  const d = ctxFor({ nodes: { c1: certNode }, selection: ["c1"], respond: () => ({ status: 200, body: { result: { total_hits: 0, hits: [] } } }) });
  await searchPlugin.run(d.ctx);
  check("default limit 25", JSON.parse(d.net.calls[0].init.body).page_size === 25);
}
{
  const t = ctxFor({ nodes: { c1: certNode, k1: keyNode }, selection: ["c1", "k1"], respond: () => ({ status: 403, body: { error: { message: "Forbidden" } } }) });
  const err = await searchPlugin.run(t.ctx).catch((e) => e);
  check("403 on search ends the run with the tier reason", err instanceof Error && /paid account/.test(err.message) && t.net.calls.length === 1);
}

{
  const body = {
    result: {
      total_hits: 3,
      hits: [
        { host_v1: { resource: { ip: "203.0.113.9" } } },
        { certificate_v1: { resource: { fingerprint_sha256: CERT_FP, parsed: { subject: { common_name: ["a.example"] } } } } },
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
}
for (const n of ok) console.log(`  ok   ${n}`);
for (const n of fail) console.log(`  FAIL ${n}`);
console.log(fail.length ? `\n${fail.length} FAILED` : `\nall ${ok.length} checks passed`);
if (fail.length) process.exit(1);
