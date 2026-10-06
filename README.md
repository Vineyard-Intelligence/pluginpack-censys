# Censys (under testing)

> **Temporary.** This pack is under testing and may change or be removed — do not build workflows
> that depend on it.

Censys Platform host lookup and search for [VINEYARD](https://vineyard.run), using your own
Censys Personal Access Token: the TLS certificates and SSH host keys an IP presents, the other
hosts presenting the same certificate or key, and free CenQL queries.

## Plugins

| Plugin | Input | Adds | Censys account |
|---|---|---|---|
| **Censys Host Lookup** | selected IP Addresses | TLS Certificate (`presents certificate`) with `san_count`, the domain names it lists as Domains (`names domain`; none when it lists more than 25 — a CDN or shared-hosting certificate), SSH Host Key (`presents host key`), and the IP's open services as `censys_services` | Free works — 1 credit per IP (100 credits a month on a free account) |
| **Censys Search** | selected TLS Certificates / SSH Host Keys, and/or a CenQL query typed in the Run dialog | For a certificate or key: the IP Address of each host presenting it, and the total Censys found as `censys_host_count`. For a query: hosts as IP Addresses, certificates as TLS Certificates, web properties as Domains. Up to 100 results per search (default 25) | Paid (Starter or higher) with its organization ID — a free account is refused ("requires an organization ID"); each search costs credits |

A large `censys_host_count` usually means a shared or default certificate/key (an appliance
image, a hosting panel), not one operator's infrastructure.

Censys records one host key per SSH service — the one its scanner negotiated (often ECDSA) — so
a server's RSA or Ed25519 key seen by another source will not match it.

## Setup

1. Create a Personal Access Token at
   [accounts.censys.io → Personal Access Tokens](https://accounts.censys.io/settings/personal-access-tokens).
2. In VINEYARD, open **Run plugins**, pick a Censys plugin, and fill in its settings:
   - **Censys Personal Access Token** (required)
   - **Censys Organization ID** (optional) — set it to bill an organization's credits; leave it
     empty to use your free account (host lookup only).

**Desktop app only.** Censys sends no CORS headers, so the web build cannot read its responses.

Requires the Infrastructure Type Pack 2.5.0 or later (for the SSH Host Key type).

## Build

```sh
node build.mjs          # bundles src/censys.ts into dist/pack.mjs
node gen-manifest.mjs   # regenerates plugins/censys.manifest.json from the bundle
node test-plugin.mjs    # functional checks against recorded response shapes
```

## License

Apache-2.0. Data returned by Censys is subject to the
[Censys terms](https://censys.com/terms-of-service/).
