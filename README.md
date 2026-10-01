# Censys (under testing, for research purpose)

> **Temporary.** This pack was added by the VINEYARD operator for thesis research. It is under
> testing and may be removed soon — do not build workflows that depend on it.

Censys Platform lookups for [VINEYARD](https://vineyard.run), using your own Censys Personal
Access Token: the TLS certificates and SSH host keys an IP presents, and the other hosts that
present the same certificate or key.

## Plugins

| Plugin | Selected nodes | Adds | Censys account |
|---|---|---|---|
| **Censys Host** | IP Address | TLS Certificate (`presents certificate`), SSH Host Key (`presents host key`), and the IP's open services as `censys_services` | Free works — 1 credit per IP (100 credits a month on a free account) |
| **Censys Pivot** | TLS Certificate, SSH Host Key | IP Address of each host presenting it (up to 100 per node, default 25); the total Censys found as `censys_host_count` | Paid (Starter or higher) — search is not available to free accounts; each search costs credits |

A large `censys_host_count` usually means a shared or default certificate/key (an appliance
image, a hosting panel), not one operator's infrastructure.

## Setup

1. Create a Personal Access Token at
   [accounts.censys.io → Personal Access Tokens](https://accounts.censys.io/settings/personal-access-tokens).
2. In VINEYARD, open **Run plugins**, pick a Censys plugin, and fill in its settings:
   - **Censys Personal Access Token** (required)
   - **Censys Organization ID** (optional) — set it to bill an organization's credits; leave it
     empty to use your free account.

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
