# mark2

A multi-scanner home-network security pipeline. It combines several open-source
scanners into one agentic system that produces a **plain-English** security report for
non-technical users:

| Scanner | What it covers |
|---|---|
| **Nmap** | Open ports, service/version detection, CVE enrichment, IoT default-credential checks |
| **Trivy** | Local filesystem package vulnerabilities (Linux/macOS) |
| **Nuclei** | Web/network template-based vulnerability checks |
| **Lynis** / **Windows audit** | Host hardening audit (Linux/macOS via Lynis, Windows via a native PowerShell audit) |
| **ClamAV** / **Windows Defender** | Malware scan (ClamAV on Linux/macOS, Defender threat history on Windows) |

Each scanner has a parser and a self-contained [LangGraph](https://github.com/langchain-ai/langgraph)
subgraph. A deterministic orchestration layer (`agent.py`) runs the scanners in a fixed
order, flattens all findings into a single table, and uses an LLM **only** to reorder and
explain those findings — never to choose what to scan. See `CLAUDE.md` for the full
architecture.

## Requirements

- Python 3.10+
- The scanner binaries for your OS (see [Install the scanners](CONTRIBUTING_SCAN_DATA.md#install-the-scanners))
- **[Nmap](https://nmap.org/download.html), installed by you.** mark2 does not ship Nmap
  for licensing reasons (see [Licensing and Attributions](#licensing-and-attributions)).
  Install it from your package manager (`apt install nmap`, `brew install nmap`,
  `apk add nmap nmap-scripts`) or nmap.org, and make sure it is on `$PATH` — or point
  `NMAP_BINARY` at it. On Windows, LAN scans additionally need
  [Npcap](https://npcap.com/#download), also installed by you.
- An LLM backend: a local [Ollama](https://ollama.com) model (default) **or** an Anthropic API key

Without Nmap, mark2 still runs: the port/service, CVE-enrichment, and IoT default-credential
stages report `{"status": "unavailable"}` and the remaining scanners (Trivy, Nuclei, Lynis,
ClamAV) proceed normally. You lose the network findings, not the run.

```bash
pip install -r requirements.txt
```

## Running a diagnostic

```bash
# Scan your own machine (default target 127.0.0.1) with the default Ollama backend
python3 agent.py [--target IP] [--json]

# Use Anthropic instead of Ollama
LLM_PROVIDER=claude ANTHROPIC_API_KEY=sk-... python3 agent.py
```

You can also run any single scanner's subgraph standalone:

```bash
python3 nmap_subgraph.py [target]
python3 nuclei_subgraph.py [target]
python3 trivy_subgraph.py
python3 lynis_subgraph.py
python3 clamav_subgraph.py
```

### The CVE cache

CVE enrichment reads a local SQLite cache, `vulnerability_cache.db`. It's **~3.2 GB**, so
it is **not** in the repo — download the compressed copy (~126 MB) from the Releases page
and unpack it into the repo root:

```bash
gunzip -c vulnerability_cache.db.gz > vulnerability_cache.db
```

Without it, the pipeline creates an empty cache and syncs ~30 days of recent CVEs from NVD
on first run (slower, less complete). Set `NVD_API_KEY` for higher NVD rate limits.

## Docker

```bash
docker build -t mark2 .
docker run --rm --network host -e TARGET=192.168.1.1 mark2
```

The default image **does not contain Nmap** (see
[Licensing and Attributions](#licensing-and-attributions)), so the network-scan stages
report `unavailable`. To get them back, build an image with Nmap included **for your own
local use**:

```bash
docker build --build-arg INSTALL_NMAP=true -t mark2 .
```

An image built that way must not be pushed to a registry or otherwise redistributed —
that would require an [Nmap OEM license](https://nmap.org/oem/). Building it for yourself
is not redistribution.

`--network host` is needed on Linux so Nmap/Nuclei can reach hosts on your LAN. See
`CLAUDE.md` for the full set of environment variables and volume mounts (CVE cache,
ClamAV manifest, etc.).

## Contributing scan data

This project is collecting **real, anonymized** scan findings to improve the report
model. If you'd like to help, run one scan on a machine you own and submit a single
small JSON file via this [Google Form](https://docs.google.com/forms/d/e/1FAIpQLSfQIl3y1xTYoaWhLFSuIMLQh6TmnucyQUBe1x5bK01qFlD1zw/viewform).
It records only a findings summary (ports, versions, CVE IDs, hardening test IDs,
package names) — **never** file contents, credentials, or logs, and it makes you review
and consent before scanning.

👉 **See [CONTRIBUTING_SCAN_DATA.md](CONTRIBUTING_SCAN_DATA.md) for the full walkthrough.**

## Team

| Name | Role |
|---|---|
| Aditya Soni | Lead Developer & Architect |
| Andrew Macedo | Community Outreach |

## Licensing and Attributions

mark2 is licensed under the **GNU General Public License, version 2** (see [`LICENSE`](LICENSE)).

mark2 is an orchestration layer. **It ships no scanner binaries and redistributes no
third-party code.** You install the scanners yourself; mark2 invokes each as a separate
process via its documented command-line interface and reads only that process's output.
It does not contain, link against, or modify any scanner's source. All five remain the
copyright of their respective authors, under their own licenses, and all credit for the
actual scanning work belongs to them.

| Tool | Author / Maintainer | License | Role in mark2 |
|---|---|---|---|
| [Nmap](https://nmap.org) | Nmap Software LLC (Gordon "Fyodor" Lyon) | [Nmap Public Source License](https://nmap.org/npsl/) (NPSL, GPLv2-derived) | Port/service discovery, version detection, IoT default-credential NSE checks |
| [ClamAV](https://www.clamav.net) | Cisco Systems, Inc. / Talos | [GPL-2.0](https://github.com/Cisco-Talos/clamav/blob/main/COPYING.txt) | Malware scanning (`clamscan`) |
| [Lynis](https://cisofy.com/lynis/) | CISOfy / Michael Boelen | [GPL-3.0](https://github.com/CISOfy/lynis/blob/master/LICENSE) | Host hardening audit |
| [Trivy](https://trivy.dev) | Aqua Security | [Apache-2.0](https://github.com/aquasecurity/trivy/blob/main/LICENSE) | Filesystem package vulnerability scanning |
| [Nuclei](https://projectdiscovery.io) | ProjectDiscovery, Inc. | [MIT](https://github.com/projectdiscovery/nuclei/blob/main/LICENSE.md) | Template-based web/network vulnerability checks |

Nuclei templates are distributed separately by ProjectDiscovery under the
[MIT license](https://github.com/projectdiscovery/nuclei-templates/blob/main/LICENSE.md)
and are fetched at build/run time via `nuclei -update-templates`.

CVE data is retrieved from the [NVD](https://nvd.nist.gov/) (U.S. National Institute of
Standards and Technology). NVD data is in the public domain; NIST does not endorse this
project.

### Source availability (Docker image only)

mark2 is intended to run **natively** on the host — that is the only configuration in
which the scanners can see the real network and filesystem. Run that way, mark2
redistributes nothing, and no GPL source-offer obligation arises: you installed the
scanners, from their own maintainers.

The [`Dockerfile`](Dockerfile) in this repository is a development and testing convenience.
It installs unmodified upstream builds of ClamAV, Lynis, Trivy, and Nuclei (never Nmap, by
default). **If you publish an image built from it**, the GPL requires you to offer the
corresponding source for the GPL-licensed components, available upstream:

- ClamAV (GPL-2.0) — https://github.com/Cisco-Talos/clamav
- Lynis (GPL-3.0) — https://github.com/CISOfy/lynis

mark2 does not patch or fork either project.

### A note on Nmap, redistribution, and commercial use

Nmap is **not** distributed under a standard OSI-approved license. The
[NPSL](https://nmap.org/npsl/) is a modified GPLv2 whose definition of "derivative work"
is deliberately broader than the GPL's: it covers software that "is designed specifically
to execute Covered Software and parse the results," and software that redistributes Nmap
or its data files (`nmap-os-db`, `nmap-service-probes`, NSE scripts).

The NPSL also states that Nmap Software LLC "does not purport to control ... any software
which does not require the rights granted herein," and specifically names software that
executes an Nmap "that end user may have already installed on their system" and parses its
results. **The distinction that matters is therefore redistribution, not invocation.**

- **Running mark2 against your own systems, with Nmap installed by you, requires nothing
  from Nmap Software LLC.** This is how mark2 is meant to be run.
- **Redistributing Nmap** — shipping the binary inside an installer or image — exercises
  rights the NPSL grants, and brings the redistributed work under the NPSL's terms.

**mark2 therefore does not bundle Nmap.** You install Nmap yourself, and mark2 shells out
to it (`bin_resolver.resolve()` checks `$NMAP_BINARY`, then `$PATH`). The `Dockerfile`
ships no Nmap by default; `--build-arg INSTALL_NMAP=true` bakes it in for local use, but an
image built that way must not be published without an
[Nmap OEM license](https://nmap.org/oem/).

**If you ship mark2 (or a fork) inside a commercial or proprietary product *with the Nmap
binary bundled* — for example a Windows installer that provisions Nmap for the user — you
will likely need an Nmap OEM license** (`licensing@nmap.com`). Requiring the user to
install Nmap themselves avoids this entirely.

Two further constraints, relevant on Windows and in hosted deployments:

- **Npcap** (which Nmap needs for LAN scans on Windows) is **not open source and may not be
  redistributed** without separate written permission from Nmap Software LLC — independent
  of any Nmap OEM license (NPSL §10). Npcap's own license recommends that projects "ask
  your users to download and install Npcap themselves," which is what mark2 does. Note that
  **the free edition of Npcap is limited to roughly five systems**; organizations deploying
  mark2 more widely than that need an
  [Npcap OEM Internal-Use License](https://npcap.com/oem/internal.html). That obligation
  falls on the deploying organization, not on mark2.
- **Hosting mark2 as a service** that runs Nmap scans on behalf of users triggers NPSL §6
  ("External Deployment"): the system and its documentation must prominently state that it
  uses the Nmap Security Scanner, with a link to https://nmap.org/.

Nmap is a trademark of Nmap Software LLC. mark2 is not affiliated with, endorsed by, or
sponsored by Nmap Software LLC, Cisco Systems, CISOfy, Aqua Security, or ProjectDiscovery.

### Scope of use

mark2 runs active network and host scans. Only scan systems you own or have explicit
written authorization to test. Unauthorized scanning may be illegal in your jurisdiction.
