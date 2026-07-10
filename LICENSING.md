# Licensing — full analysis

This is the detailed companion to the short **License & attributions** section in
[`README.md`](README.md). You do **not** need to read this to *use* mark2 on your own systems
— that requires nothing from any of the tool authors (see below). This document exists for
anyone doing the less common things: packaging mark2 into a commercial or proprietary product,
hosting it as a service, bundling a scanner binary, or reviewing the project's IP for due
diligence.

mark2 itself is licensed under the **GNU General Public License, version 2** (see
[`LICENSE`](LICENSE)).

## Why using mark2 asks nothing of the tool authors

mark2 is an orchestration layer. **It ships no scanner binaries and redistributes no
third-party code.** You install the scanners yourself; mark2 invokes each as a separate
process via its documented command-line interface and reads only that process's output. It
does not contain, link against, or modify any scanner's source. Running a program as a
subprocess and parsing its output is *mere aggregation*, not a derivative work — so ClamAV's
GPLv2, Lynis's GPLv3, and Nmap's NPSL impose nothing on mark2's own code, and nothing on you
when you run it against your own systems. All five scanners remain the copyright of their
respective authors, under their own licenses, and all credit for the actual scanning work
belongs to them.

Full, unmodified copies of each tool's license are kept in
[`THIRD_PARTY_LICENSES/`](THIRD_PARTY_LICENSES/) for reference.

`LYNIS_TEST_CATALOG` in `lynis_subgraph.py` is original work by this project's author. It is
keyed by Lynis test ID but contains no text from Lynis.

## Attribution

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

## Source availability (Docker image only)

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

## A note on Nmap, redistribution, and commercial use

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

## Scope of use

mark2 runs active network and host scans. Only scan systems you own or have explicit
written authorization to test. Unauthorized scanning may be illegal in your jurisdiction.
