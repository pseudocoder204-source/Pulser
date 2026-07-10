# Third-party licenses

mark2 does **not** bundle any of these tools — it invokes each as a separate program that you
install yourself, and reads its output (see [`../LICENSING.md`](../LICENSING.md)). Running a
tool as a subprocess imposes none of its terms on mark2's own code.

These full, unmodified upstream license texts are kept here as a courtesy reference, and so that
any future distribution that *does* carry a scanner binary (e.g. a signed Windows bundle
shipping `nuclei.exe`/`trivy.exe`) already includes the notices the MIT and Apache-2.0 licenses
require.

| File | Tool | License | Upstream source |
|---|---|---|---|
| `Nmap-NPSL.txt` | Nmap | Nmap Public Source License (GPLv2-derived) | https://github.com/nmap/nmap/blob/master/LICENSE · https://nmap.org/npsl/ |
| `ClamAV-GPL-2.0.txt` | ClamAV | GPL-2.0 | https://github.com/Cisco-Talos/clamav/blob/main/COPYING.txt |
| `Lynis-GPL-3.0.txt` | Lynis | GPL-3.0 | https://github.com/CISOfy/lynis/blob/master/LICENSE |
| `Trivy-Apache-2.0.txt` + `Trivy-NOTICE.txt` | Trivy | Apache-2.0 | https://github.com/aquasecurity/trivy/blob/main/LICENSE · `/NOTICE` |
| `Nuclei-MIT.txt` | Nuclei | MIT | https://github.com/projectdiscovery/nuclei/blob/main/LICENSE.md |

CVE data is from the [NVD](https://nvd.nist.gov/) (public domain). Nuclei templates are
fetched at run time under their own [MIT license](https://github.com/projectdiscovery/nuclei-templates/blob/main/LICENSE.md).
