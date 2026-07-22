# SPDX-License-Identifier: GPL-2.0-only
"""Structured remediation facts for the report LLM (UpgradeTuning.txt Step 1).

`REMEDIATION_CATALOG` is keyed by *finding class* — a coarse category (e.g. "rce",
"default_creds"), not a CVE ID or exact finding — so a handful of entries cover the
whole space of findings a scanner can produce. Each entry is
`{fix_summary, steps_template, applies_to, provenance[, citations]}`; `steps_template` is a list of
step strings parameterized with `{service}`/`{package}`/`{fixed_version}`/`{port}`
placeholders. `fix_facts_for()` classifies an incoming finding row (as produced by
`agent.build_findings_table`) into a class, then fills those placeholders from the
finding's own fields. A step whose placeholders can't all be filled is dropped
entirely rather than falling back to generic "upgrade the software" filler — the
whole point of this layer is that `how_to_fix` names the actual affected thing.

`provenance` is one of:
  - "authored"          — written for this project, not checked against a citation.
  - "verified:citation"  — checked against an authoritative source (NIST/CISA guidance,
                           vendor security docs, OWASP WSTG, MITRE CWE) in the Step 2
                           grounding pass (2026-07-18); such entries carry a `citations`
                           list of the source URLs the steps were verified against.
  - "verified:execution" — reserved for the deferred vulhub execution-verification work;
                           no entries carry this tier yet.

Note on the CISA URLs: cisa.gov serves 403 to non-browser clients (bot protection), so
they can't be curl-verified from here — each one was confirmed live via search-engine
indexing (title + URL match) during the grounding pass instead.

Migrated from `finetune/label_batch.py` (`_VULN_CLASS_KEYWORDS`, `_PACKAGE_CATEGORY_*`,
`_MALWARE_TRANSLATIONS`, `_WEB_TRANSLATIONS`): the keyword/class *mappings* are reused,
but the prose here is a fresh, template-shaped rewrite — `label_batch.py`'s hand-written
strings were per-finding-description one-offs, not parameterized templates, and are
retired in favor of this catalog once the training-set rebuild (Step 3+) lands.

Wired into `agent.py`: `build_findings_table` attaches `fix_facts_for(row)` to every
findings-table row (Step 1), so these facts ride into the report prompt input.
"""

import platform
import re
from typing import Any, Dict, List, Optional, Union

from .priority import has_default_creds_finding
from .remediation_generated import GENERATED_REMEDIATION_ENTRIES

# --- Vulnerability-class keyword classifier for network/host_os/iot_defaults CVE
# findings — reused as-is from finetune/label_batch.py's _VULN_CLASS_KEYWORDS. Order
# matters: first match wins, most-severe-sounding classes checked first.
_VULN_CLASS_KEYWORDS = [
    ("rce", ["code execution", "execute arbitrary", "arbitrary code", "run arbitrary"]),
    ("downgrade", ["downgrade", "man-in-the-middle", "mitm", "protocol-downgrade"]),
    ("bypass", ["bypass", "spoof", "does not properly validate", "does not require",
                "authenticate", "without the need", "enumerate"]),
    ("privesc", ["privilege", "gain privileges", "elevat"]),
    ("infoleak", ["information disclosure", "obtain sensitive", "sensitive information",
                  "disclose", "read secret", "out-of-bounds read", "memory read",
                  "leak", "process memory"]),
    ("crash", ["denial of service", "crash", "use-after-free", "null pointer",
               "buffer overflow", "stack overflow", "segmentation fault",
               "memory consumption", "memory corruption", "uninitialized",
               "out of bound", "out-of-bounds write"]),
]

# --- Nuclei (web) template-class keyword classifier — reused from label_batch.py's
# fixed 6-template pool (_WEB_TRANSLATIONS), generalized to keyword matching so new
# templates in the same families classify without a catalog change. Order matters.
_WEB_CLASS_KEYWORDS = [
    ("rce_template", ["remote code execution", " rce", "struts"]),
    ("open_datastore", ["no auth", "unauthenticated", "open redis", "open database",
                        "open instance"]),
    ("default_creds", ["default credential", "default login", "default password"]),
    ("exposed_source", ["exposed .git", ".git directory", "source code exposed",
                        "exposed source"]),
    ("exposed_admin", ["admin login", "admin panel", "admin page"]),
    ("outdated_cms", ["outdated", "out of date", "out-of-date", "old version"]),
]

# --- Trivy (filesystem) package-category classifier — reused from label_batch.py's
# _PACKAGE_CATEGORY_PATTERNS. Checked in order; first match wins.
_PACKAGE_CATEGORY_PATTERNS = [
    ("kernel",         ("linux-headers", "linux-image", "linux-modules", "linux-libc-dev", "linux-tools", "linux-firmware")),
    ("crypto",         ("openssl", "libssl", "gnutls", "libgnutls", "ca-certificates")),
    ("network_client", ("curl", "libcurl", "wget")),
    ("remote_access",  ("openssh", "ssh")),
    ("web_server",     ("apache2", "nginx", "httpd", "lighttpd")),
    ("core_library",   ("glibc", "libc6", "libc-bin", "libc-dev")),
    ("runtime",        ("python", "perl", "ruby", "openjdk", "nodejs", "php")),
    ("system_service", ("systemd", "dbus", "udev", "polkit")),
]


# --- Citation sources (Step 2 grounding pass, 2026-07-18) --------------------------
# Named once here; referenced from entries' `citations` lists. What each grounds:
#
# _CITE_NIST_PATCH — NIST SP 800-40r4 "Guide to Enterprise Patch Management Planning":
#   patching/updating to the fixed version is the primary remediation for known
#   software vulnerabilities. Grounds every "update {service} to {fixed_version}" step.
_CITE_NIST_PATCH = "https://csrc.nist.gov/pubs/sp/800/40/r4/final"
# _CITE_CISA_KEV — CISA "Reducing the Significant Risk of Known Exploited
#   Vulnerabilities": prioritize immediate remediation of exploited vulns; remove the
#   product from the network if it can't be updated. Grounds the urgency framing on
#   rce/rce_template and the "take it offline until patched" steps.
_CITE_CISA_KEV = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog/reducing-significant-risk-known-exploited-vulnerabilities"
# _CITE_CISA_HOME_NET — CISA "Home Network Security": boundary firewall, don't expose
#   services to the internet, keep devices updated. Grounds the "restrict inbound
#   access at your router/firewall" and "don't expose to the internet" steps.
_CITE_CISA_HOME_NET = "https://www.cisa.gov/news-events/news/home-network-security"
# _CITE_CISA_WIRELESS — CISA "Securing Wireless Networks": strong Wi-Fi
#   passphrase/WPA3 keeps untrusted devices off the local network (the MITM
#   positioning prerequisite for downgrade attacks).
_CITE_CISA_WIRELESS = "https://www.cisa.gov/news-events/news/securing-wireless-networks"
# _CITE_NIST_TLS — NIST SP 800-52r2 TLS guidelines: obsolete protocol versions must be
#   retired/disabled (via software update/reconfiguration) to prevent downgrade to
#   weaker protection.
_CITE_NIST_TLS = "https://csrc.nist.gov/pubs/sp/800/52/r2/final"
# _CITE_CISA_DEFAULT_PW — CISA alert TA13-175A "Risks of Default Passwords on the
#   Internet": change default passwords to strong unique ones AND restrict network
#   access to the device.
_CITE_CISA_DEFAULT_PW = "https://www.cisa.gov/news-events/alerts/2013/06/24/risks-default-passwords-internet"
# _CITE_REDIS_SECURITY — Redis security docs (exemplar for the open-datastore class):
#   datastores are designed for trusted clients only — set an auth password and never
#   expose the port to the open internet.
_CITE_REDIS_SECURITY = "https://redis.io/docs/latest/operate/oss_and_stack/management/security/"
# _CITE_CWE_527 — MITRE CWE-527 "Exposure of Version-Control Repository to an
#   Unauthorized Control Sphere": block/remove the exposed repo dir from the web root;
#   exposed history can contain credentials, so rotate any that were in the code.
_CITE_CWE_527 = "https://cwe.mitre.org/data/definitions/527.html"
# _CITE_OWASP_ADMIN — OWASP WSTG-CONF-05 "Enumerate Infrastructure and Application
#   Admin Interfaces": admin interfaces must not be reachable/usable by unauthorized
#   users — strong auth, MFA, network-restrict the page.
_CITE_OWASP_ADMIN = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces"
# _CITE_WP_HARDENING — WordPress "Hardening WordPress" (exemplar for the outdated-CMS
#   class): keeping core + plugins + themes updated is the single most important
#   security measure; prefer sources that receive updates / enable auto-updates.
_CITE_WP_HARDENING = "https://developer.wordpress.org/advanced-administration/security/hardening/"
# _CITE_CISA_MALWARE — CISA "Recovering from Viruses, Worms, and Trojan Horses":
#   update AV definitions, run a full scan, remove/quarantine what's found, then
#   change passwords (the malware may have captured them).
_CITE_CISA_MALWARE = "https://www.cisa.gov/news-events/news/recovering-viruses-worms-and-trojan-horses"
# _CITE_CISA_MALWARE_PDF — Durkota & Dormann, "Recovering from a Trojan Horse or
#   Virus" (CISA/US-CERT paper): change passwords from a clean (different) computer,
#   since the infected one may still be capturing keystrokes.
_CITE_CISA_MALWARE_PDF = "https://www.cisa.gov/sites/default/files/publications/trojan-recovery.pdf"
# _CITE_LYNIS_UPSTREAM — Lynis's own test implementations (include/tests_*), the
#   "tool's own docs" ground for host_audit solutions: LYNIS_TEST_CATALOG's text was
#   fully verified against these upstream files on 2026-07-10 (see the PROVENANCE
#   comment in scanners/lynis/lynis_parser.py).
_CITE_LYNIS_UPSTREAM = "https://github.com/CISOfy/lynis/tree/master/include"


# --- REMEDIATION_CATALOG -----------------------------------------------------------
# Flat dict keyed by finding class. Vuln classes (rce/downgrade/bypass/privesc/
# infoleak/crash/cve_other) apply to network/host_os/iot_defaults; web classes
# (rce_template/open_datastore/default_creds/exposed_source/exposed_admin/
# outdated_cms/web_other) apply to web; "malware" applies to malware. filesystem and
# host_audit findings are resolved structurally in fix_facts_for() below, not via a
# catalog lookup — see the Step 1 note in UpgradeTuning.txt.

REMEDIATION_CATALOG: Dict[str, Dict[str, Any]] = {
    "rce": {
        "fix_summary": "Update {service} to close a remote-code-execution flaw.",
        "steps_template": [
            "Update {service} to version {fixed_version} or later.",
            "If no update is available yet, take {service} off the open internet and "
            "restrict it to your home network only.",
            "Restrict inbound access to port {port} at your router/firewall until it's patched.",
        ],
        "applies_to": ("network", "host_os", "iot_defaults"),
        "provenance": "verified:citation",
        "citations": [_CITE_NIST_PATCH, _CITE_CISA_KEV, _CITE_CISA_HOME_NET],
    },
    "downgrade": {
        "fix_summary": "Update {service} to stop its connection protection from being weakened.",
        "steps_template": [
            "Update {service} to version {fixed_version} or later.",
            "Make sure the network {service} runs on uses a strong Wi-Fi password so "
            "untrusted devices can't position themselves to intercept its traffic.",
        ],
        "applies_to": ("network", "host_os", "iot_defaults"),
        "provenance": "verified:citation",
        "citations": [_CITE_NIST_TLS, _CITE_CISA_WIRELESS],
    },
    "bypass": {
        "fix_summary": "Update {service} to close a flaw that could let a login/security check be skipped.",
        "steps_template": [
            "Update {service} to version {fixed_version} or later.",
            "Use a strong, unique password on {service} either way.",
        ],
        "applies_to": ("network", "host_os", "iot_defaults"),
        "provenance": "verified:citation",
        "citations": [_CITE_NIST_PATCH, _CITE_CISA_DEFAULT_PW],
    },
    "privesc": {
        "fix_summary": "Update {service} to close a flaw that could let another account gain more access.",
        "steps_template": [
            "Update {service} to version {fixed_version} or later.",
            "Make sure you recognize and trust every user account that has access to this device.",
        ],
        "applies_to": ("network", "host_os", "iot_defaults"),
        "provenance": "verified:citation",
        "citations": [_CITE_NIST_PATCH],
    },
    "infoleak": {
        "fix_summary": "Update {service} to stop it from leaking internal information.",
        "steps_template": [
            "Update {service} to version {fixed_version} or later.",
            "Avoid exposing {service} directly to the internet if you don't need to.",
            "Restrict inbound access to port {port} at your router/firewall.",
        ],
        "applies_to": ("network", "host_os", "iot_defaults"),
        "provenance": "verified:citation",
        "citations": [_CITE_NIST_PATCH, _CITE_CISA_HOME_NET],
    },
    "crash": {
        "fix_summary": "Update {service} to close a flaw that could crash or destabilize it.",
        "steps_template": [
            "Update {service} to version {fixed_version} or later.",
            "If you don't need {service}, consider turning it off.",
        ],
        "applies_to": ("network", "host_os", "iot_defaults"),
        "provenance": "verified:citation",
        "citations": [_CITE_NIST_PATCH, _CITE_CISA_HOME_NET],
    },
    "cve_other": {
        "fix_summary": "Update {service} to close a known security weakness.",
        "steps_template": [
            "Update {service} to version {fixed_version} or later.",
            "Review {service}'s settings to make sure it's configured securely.",
        ],
        "applies_to": ("network", "host_os", "iot_defaults"),
        "provenance": "verified:citation",
        "citations": [_CITE_NIST_PATCH],
    },
    "rce_template": {
        "fix_summary": "Update {service} immediately — this flaw could let an attacker run commands on it.",
        "steps_template": [
            "Update {service} to the latest version immediately.",
            "If you're not sure how, contact whoever manages this site/service for help.",
            "Consider taking {service} offline temporarily until it's updated.",
        ],
        "applies_to": ("web",),
        "provenance": "verified:citation",
        "citations": [_CITE_CISA_KEV, _CITE_NIST_PATCH],
    },
    "open_datastore": {
        "fix_summary": "Set a password on {service} and take it off the open internet.",
        "steps_template": [
            "Set a password on {service} immediately.",
            "Make sure {service} isn't reachable from the open internet — restrict it to "
            "your home network only.",
            "If you don't recognize {service}, find out what installed it and consider removing it.",
        ],
        "applies_to": ("web",),
        "provenance": "verified:citation",
        "citations": [_CITE_REDIS_SECURITY, _CITE_CISA_HOME_NET],
    },
    "default_creds": {
        "fix_summary": "Change {service}'s default login immediately.",
        "steps_template": [
            "Log into {service} and change the default username/password immediately — "
            "use a strong password you don't use anywhere else.",
            "Make sure {service}'s login page isn't reachable from the open internet — "
            "restrict it to your home network only.",
            "If you don't recognize or use {service}, consider taking it offline.",
        ],
        "applies_to": ("web", "network", "host_os", "iot_defaults"),
        "provenance": "verified:citation",
        "citations": [_CITE_CISA_DEFAULT_PW],
    },
    "exposed_source": {
        "fix_summary": "Block public access to the exposed source-control folder on {service}.",
        "steps_template": [
            "Remove or block public access to this folder on {service}.",
            "Review your deployment process so this folder isn't published again in the future.",
            "If passwords or keys were in that code, change them as a precaution.",
        ],
        "applies_to": ("web",),
        "provenance": "verified:citation",
        "citations": [_CITE_CWE_527],
    },
    "exposed_admin": {
        "fix_summary": "Lock down the publicly reachable admin login on {service}.",
        "steps_template": [
            "Make sure the admin login on {service} uses a strong, unique password.",
            "If possible, restrict access to this page to your home network only.",
            "Turn on two-factor authentication if it's supported.",
        ],
        "applies_to": ("web",),
        "provenance": "verified:citation",
        "citations": [_CITE_OWASP_ADMIN],
    },
    "outdated_cms": {
        "fix_summary": "Update {service} to the latest version.",
        "steps_template": [
            "Update {service}, along with its plugins and themes, to the latest version.",
            "Turn on automatic updates if your hosting provider supports it.",
        ],
        "applies_to": ("web",),
        "provenance": "verified:citation",
        "citations": [_CITE_WP_HARDENING],
    },
    # web_other is the catch-all for templates that match none of the classes above —
    # there's no single authoritative source to ground a class this heterogeneous, so
    # it stays "authored" (Step 2 rule: ungroundable entries keep conservative steps,
    # and deferring to the finding's own linked reference is as conservative as it gets).
    "web_other": {
        "fix_summary": "Review and remediate the flagged issue on {service}.",
        "steps_template": [
            "Review {service} against the linked reference and apply the recommended fix.",
        ],
        "applies_to": ("web",),
        "provenance": "authored",
    },
    "malware": {
        "fix_summary": "Quarantine the detected file and rescan the device.",
        "steps_template": [
            "Do not open the flagged file.",
            "Delete it or move it to quarantine using your antivirus software.",
            "Update your antivirus definitions, then run a full scan of the device to "
            "check for anything else related to it.",
            "Change your important passwords afterward, in case the file was already "
            "active — ideally from a different device you trust.",
        ],
        "applies_to": ("malware",),
        "provenance": "verified:citation",
        "citations": [_CITE_CISA_MALWARE, _CITE_CISA_MALWARE_PDF],
    },
}

# Overlay RAG-pipeline-exported entries (notes/RemediationRAGPlan.txt "Pipeline shape"
# step 5): for each finding class the offline pipeline has drafted+reviewed+
# AST-validated, replace fix_summary/steps_template/provenance/citations with the
# generated version, keeping applies_to (not tracked by the RAG DB -- it's a
# classifier-routing concept, not remediation content) from the hand-authored entry
# above. A class with no generated override is untouched.
for _cls, _generated in GENERATED_REMEDIATION_ENTRIES.items():
    if _cls in REMEDIATION_CATALOG:
        REMEDIATION_CATALOG[_cls] = {**REMEDIATION_CATALOG[_cls], **_generated}
    else:
        REMEDIATION_CATALOG[_cls] = _generated

# Package-category -> catalog class isn't a separate lookup table: filesystem findings
# resolve structurally in _fix_facts_filesystem() below (action/package/fixed_version
# straight from the Trivy finding, no class match needed).


_PLACEHOLDER_RE = re.compile(r"\{(\w+)\}")

# Preferred platform_key prefixes to try, in order, for the host mark2 itself is
# running on -- notes/RemediationRAGPlan.txt "Export" step: "fix_facts_for() gains a
# small platform lookup ... falls back to the step's prose alone if no command
# variant matches the host's platform." A step with no commands_template at all (the
# common case) or no entry for this host's platform stays prose-only.
_PLATFORM_KEY_PREFERENCE: Dict[str, tuple] = {
    "Linux": ("linux_apt", "linux_dnf", "linux_pacman"),
    "Darwin": ("darwin_brew",),
    "Windows": ("windows_powershell", "windows_winget"),
}


def _select_command_template(commands_template: Dict[str, str]) -> Optional[str]:
    for key in _PLATFORM_KEY_PREFERENCE.get(platform.system(), ()):
        if key in commands_template:
            return commands_template[key]
    return None


def _safe_format(template: str, values: Dict[str, Optional[str]]) -> Optional[str]:
    """Fill `template`'s placeholders from `values`; return None if any placeholder
    the template actually uses has no (truthy) value — the caller drops it rather
    than emitting half-filled or fallback-generic text."""
    needed = set(_PLACEHOLDER_RE.findall(template))
    if any(not values.get(name) for name in needed):
        return None
    return template.format(**values)


def _fill_steps(
    steps_template: List[Union[str, Dict[str, Any]]],
    values: Dict[str, Optional[str]],
) -> List[str]:
    """Fills each step's prose placeholders. A step may be a bare string (today's
    shape, no command) or a dict `{"text": ..., "commands_template": {platform_key:
    command_template}}` (RAG-pipeline-exported, see core/remediation_generated.py) --
    the matching command for this host's platform.system() is filled with the same
    `values` and appended, so a report can hand the user something to paste."""
    filled = []
    for step in steps_template:
        if isinstance(step, dict):
            text = _safe_format(step.get("text", ""), values)
            if text is None:
                continue
            command_template = _select_command_template(step.get("commands_template") or {})
            if command_template:
                command = _safe_format(command_template, values)
                if command:
                    text = f"{text}\n    $ {command}"
            filled.append(text)
        else:
            text = _safe_format(step, values)
            if text is not None:
                filled.append(text)
    return filled


# --- Best-effort service -> package-manager package name, used only to fill the
# {package} placeholder on RAG-pipeline-exported update commands (rce/downgrade/
# bypass/cve_other/privesc/infoleak/crash's update step in
# core/remediation_generated.py). nmap's "service" field on a network/host_os/
# iot_defaults finding is a generic protocol name (ssh, http, mysql, ...), not a
# package name, and several protocols map to more than one plausible package
# (http could be nginx/apache2/httpd/lighttpd) with no way to tell which from the
# service string alone -- those are deliberately left OUT of this map rather than
# guessed, so _package_for_service() returns None and the update-step's command
# variant is silently dropped (same "no filler" rule _safe_format already enforces
# for any unfillable placeholder), not a wrong package name someone pastes into a
# terminal. Only services with one obvious, stable package name across major distros
# are listed. Web-sourced findings (_fix_facts_web) don't carry a service name this
# specific either (site/CMS name, not a protocol) so this map isn't consulted there.
_SERVICE_PACKAGE_MAP: Dict[str, Dict[str, str]] = {
    "ssh":          {"linux_apt": "openssh-server", "linux_dnf": "openssh-server",
                      "linux_pacman": "openssh", "darwin_brew": "openssh",
                      "windows_winget": "Microsoft.OpenSSH.Beta"},
    "ftp":          {"linux_apt": "vsftpd", "linux_dnf": "vsftpd",
                      "linux_pacman": "vsftpd", "darwin_brew": "vsftpd"},
    "telnet":       {"linux_apt": "telnetd", "linux_dnf": "telnet-server",
                      "linux_pacman": "inetutils"},
    "domain":       {"linux_apt": "bind9", "linux_dnf": "bind",
                      "linux_pacman": "bind", "darwin_brew": "bind"},
    "smtp":         {"linux_apt": "postfix", "linux_dnf": "postfix",
                      "linux_pacman": "postfix", "darwin_brew": "postfix"},
    "mysql":        {"linux_apt": "mysql-server", "linux_dnf": "mysql-server",
                      "linux_pacman": "mysql", "darwin_brew": "mysql",
                      "windows_winget": "Oracle.MySQL"},
    "postgresql":   {"linux_apt": "postgresql", "linux_dnf": "postgresql-server",
                      "linux_pacman": "postgresql", "darwin_brew": "postgresql",
                      "windows_winget": "PostgreSQL.PostgreSQL"},
    "redis":        {"linux_apt": "redis-server", "linux_dnf": "redis",
                      "linux_pacman": "redis", "darwin_brew": "redis",
                      "windows_winget": "Redis.Redis"},
    "microsoft-ds": {"linux_apt": "samba", "linux_dnf": "samba",
                      "linux_pacman": "samba", "darwin_brew": "samba"},
    "netbios-ssn":  {"linux_apt": "samba", "linux_dnf": "samba",
                      "linux_pacman": "samba", "darwin_brew": "samba"},
    "snmp":         {"linux_apt": "snmpd", "linux_dnf": "net-snmp",
                      "linux_pacman": "net-snmp"},
}


def _package_for_service(service: Optional[str]) -> Optional[str]:
    if not service:
        return None
    entry = _SERVICE_PACKAGE_MAP.get(service.strip().lower())
    if entry is None:
        return None
    for key in _PLATFORM_KEY_PREFERENCE.get(platform.system(), ()):
        if key in entry:
            return entry[key]
    return None


def _classify_vuln(description: str) -> str:
    desc_l = (description or "").lower()
    for cls, keywords in _VULN_CLASS_KEYWORDS:
        if any(kw in desc_l for kw in keywords):
            return cls
    return "cve_other"


def _classify_web(text: str) -> str:
    text_l = (text or "").lower()
    for cls, keywords in _WEB_CLASS_KEYWORDS:
        if any(kw in text_l for kw in keywords):
            return cls
    return "web_other"


def _classify_package(pkg: str) -> str:
    p = (pkg or "").lower()
    for category, prefixes in _PACKAGE_CATEGORY_PATTERNS:
        if any(p.startswith(prefix) or prefix in p for prefix in prefixes):
            return category
    return "general"


_PORT_SERVICE_RE = re.compile(r"^Port\s+(\d+)\s+—\s+(\S+)")


def _network_service_and_port(finding: Dict[str, Any]):
    """(service, port) for a network/host_os/iot_defaults finding row. Prefers the
    explicit "service"/"port" fields build_findings_table puts on network/iot_defaults
    rows; falls back to regex-parsing the composed "affected" string (e.g. "Port 22 —
    ssh ...") for older-shaped rows that don't carry those fields directly. host_os
    rows have neither field — service is parsed off the "Operating system: ..." prefix
    on affected instead, and there's no port to speak of."""
    if finding.get("source") == "host_os":
        affected = finding.get("affected") or ""
        service = affected[len("Operating system:"):].strip() if affected.startswith("Operating system:") else None
        return (service or None), None
    service = finding.get("service")
    port = finding.get("port")
    if service:
        return service, (str(port) if port is not None else None)
    m = _PORT_SERVICE_RE.match(finding.get("affected") or "")
    if not m:
        return None, None
    port, service = m.group(1), m.group(2)
    return service, port


def _web_service(finding: Dict[str, Any]) -> Optional[str]:
    affected = finding.get("affected") or ""
    name = affected.split(" on ", 1)[0].strip()
    return name or None


def _http_refs(refs: Optional[List[Any]], limit: int = 2) -> List[str]:
    out = []
    for r in refs or []:
        if isinstance(r, str) and r.startswith("http"):
            out.append(r)
            if len(out) == limit:
                break
    return out


def _fix_facts_filesystem(finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Structural resolution for Trivy findings: action/package/fixed_version come
    straight from the finding itself, so the only thing to ground is the *shape* of
    the advice — "upgrade the package to the fixed version" — which is the canonical
    remediation per NIST SP 800-40r4 (_CITE_NIST_PATCH). Hence verified:citation."""
    affected = finding.get("affected") or ""
    package = affected[len("Package: "):].split(" ", 1)[0].strip() if affected.startswith("Package: ") else None
    if not package:
        return None
    refs = finding.get("remediation_refs") or []
    fixed_version = refs[0] if refs and isinstance(refs[0], str) else None
    facts: Dict[str, Any] = {"class": "filesystem", "action": "upgrade", "package": package}
    if fixed_version:
        facts["fixed_version"] = fixed_version
    category = _classify_package(package)
    facts["fix_summary"] = (
        f"Update {package} to version {fixed_version} or later."
        if fixed_version else
        f"Update {package} to the latest available version."
    )
    facts["category"] = category
    # Citations stay catalog/module-level (here: _CITE_NIST_PATCH, see docstring) —
    # they are provenance metadata, not per-finding references, and putting a generic
    # URL on every row would just bloat the prompt input.
    facts["provenance"] = "verified:citation"
    return facts


def _fix_facts_host_audit(finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Structural resolution for host-audit findings: the solution string in
    remediation_refs[0] is catalog text from LYNIS_TEST_CATALOG or
    WINDOWS_AUDIT_CATALOG, both of which carry their own citation-verified
    provenance — the Lynis catalog was verified against Lynis's own test sources
    (_CITE_LYNIS_UPSTREAM, 2026-07-10), and every WINDOWS_AUDIT_CATALOG solution
    was verified against Microsoft's documentation (2026-07-18; per-entry
    `citations` lists live on that catalog in
    scanners/windows/windows_audit_parser.py). Hence verified:citation."""
    refs = finding.get("remediation_refs") or []
    solution = refs[0] if refs and isinstance(refs[0], str) else None
    if not solution:
        return None
    return {
        "class": "host_audit",
        "action": "reconfigure",
        "solution": solution,
        "fix_summary": solution,
        "provenance": "verified:citation",
    }


def _fix_facts_network(finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    # A factory-default-credentials hit (from the iot_default_creds NSE scripts) is
    # its own class of problem, unrelated to whatever CVE the port's service might or
    # might not have — classifying by CVE description alone (below) would silently
    # miss it, since these findings routinely carry no CVE at all (empty description).
    cls = "default_creds" if has_default_creds_finding(finding) else _classify_vuln(finding.get("description"))
    entry = REMEDIATION_CATALOG.get(cls)
    if entry is None:
        return None
    service, port = _network_service_and_port(finding)
    refs = finding.get("remediation_refs") or []
    fixed_version = refs[0] if refs and isinstance(refs[0], str) and not refs[0].startswith("http") else None
    values = {"service": service, "port": port, "package": _package_for_service(service),
              "fixed_version": fixed_version}
    steps = _fill_steps(entry["steps_template"], values)
    if not steps:
        return None
    facts: Dict[str, Any] = {
        "class": cls,
        "steps": steps,
        "provenance": entry["provenance"],
    }
    fix_summary = _safe_format(entry["fix_summary"], values)
    if fix_summary:
        facts["fix_summary"] = fix_summary
    if fixed_version:
        facts["fixed_version"] = fixed_version
    patch_urls = _http_refs(refs)
    if patch_urls:
        facts["references"] = patch_urls
    return facts


def _fix_facts_malware(finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    entry = REMEDIATION_CATALOG["malware"]
    return {
        "class": "malware",
        "fix_summary": entry["fix_summary"],
        "steps": _fill_steps(entry["steps_template"], {}),
        "provenance": entry["provenance"],
    }


def _fix_facts_web(finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    cls = _classify_web(f"{finding.get('affected') or ''} {finding.get('description') or ''}")
    entry = REMEDIATION_CATALOG.get(cls)
    if entry is None:
        return None
    service = _web_service(finding)
    values = {"service": service, "port": None, "package": None, "fixed_version": None}
    steps = _fill_steps(entry["steps_template"], values)
    if not steps:
        return None
    facts: Dict[str, Any] = {
        "class": cls,
        "steps": steps,
        "provenance": entry["provenance"],
    }
    fix_summary = _safe_format(entry["fix_summary"], values)
    if fix_summary:
        facts["fix_summary"] = fix_summary
    references = _http_refs(finding.get("remediation_refs"))
    if references:
        facts["references"] = references
    return facts


def fix_facts_for(finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Per-source resolution of structured remediation facts for one findings-table
    row. Returns None when nothing grounded exists — callers (the label prompt /
    report prompt, once wired) must handle that case explicitly rather than treat
    None as an error."""
    source = finding.get("source")
    if source == "filesystem":
        return _fix_facts_filesystem(finding)
    if source == "host_audit":
        return _fix_facts_host_audit(finding)
    if source in ("network", "host_os", "iot_defaults"):
        return _fix_facts_network(finding)
    if source == "malware":
        return _fix_facts_malware(finding)
    if source == "web":
        return _fix_facts_web(finding)
    return None
