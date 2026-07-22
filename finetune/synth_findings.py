# SPDX-License-Identifier: GPL-2.0-only
"""Synthetic training-data generator for the report LoRA (see FinetuneGuide.txt PHASE 1B/1C,
UpgradeTuning.txt Step 3).

Replaces SecGen: instead of launching vulnerable VMs, this hand-assembles a worker-output
`results` dict per PHASE 1C's field contract, then runs it through the REAL
`build_findings_table` from agent.py + `priority.rank` — so every generated training
input is byte-identical in shape to what the live pipeline emits, including each row's
`fix_facts` (core/remediation.py, UpgradeTuning.txt Step 1). No model, no scan, no VM.

Profiles model "different user environments" as sampling configs over the six finding
sources (network, iot_defaults, filesystem, host_audit, malware, web), plus two
Windows-flavored profiles and a scripted set of edge cases (FinetuneGuide Step 7).
`_sample_table_size()` gives the multi-device profiles a `table_size` dimension spanning
0-40 findings, rather than the fixed small ranges the original 6 profiles used — the
`_REPORT_CHUNK_SIZE=10` stopgap in agent.py exists because >10-finding tables were
out-of-distribution, and this is what fixes that at the data level.

Real vocabulary is sampled from vulnerability_cache.db's own CPE/CVE rows (services,
filesystem packages, OS platforms) rather than a handful of hand-picked versions, so
labels drafted later stay grounded in real product/version/CVE facts and don't just
memorize "OpenSSH 7.4" as a fixed string. Nuclei templates and ClamAV signatures have no
local database to mine, so their pools are hand-curated from real, publicly documented
template/signature families instead.

Usage:
    python3 finetune/synth_findings.py --db trainset.db --per-profile 45
    python3 finetune/synth_findings.py --db trainset.db --profile clean_healthy --per-profile 10
"""

import argparse
import json
import random
import re
import sqlite3
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent import build_findings_table
from scanners.lynis.lynis_subgraph import LYNIS_TEST_CATALOG
from scanners.windows.windows_audit_parser import WINDOWS_AUDIT_CATALOG
from core.priority import ordered_refs, rank

_VULN_DB_PATH = "vulnerability_cache.db"
_TRAINSET_SCHEMA = """
CREATE TABLE IF NOT EXISTS examples (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    source        TEXT,                   -- 'synth' | 'real'
    profile       TEXT,                   -- profile name, or NULL for real anchors
    ordered_facts TEXT NOT NULL,           -- json.dumps(ordered_facts) — the model input
    label         TEXT,                   -- json.dumps(report) — NULL until labeled
    status        TEXT DEFAULT 'pending', -- pending -> labeled -> validated | rejected | superseded
    platform      TEXT                    -- 'linux' | 'windows' | 'darwin'
)
"""

# --- Real-vocabulary pools, mined from vulnerability_cache.db ----------------------
# Each *_META entry names a real product's NVD cpe_base; concrete (version, CVE) facts
# are pulled live from the cache so the pool reflects actual recorded vulnerabilities
# rather than invented ones. Built once per run (see _get_services_pool/_get_package_pool)
# and cached at module level — re-querying per row would be wasteful at 1000+ rows.

_SERVICE_META: List[Tuple[int, str, str, str]] = [
    # (port, service label, product display name, NVD cpe_base)
    (22, "ssh", "OpenSSH", "cpe:2.3:a:openbsd:openssh"),
    (22, "ssh", "Dropbear SSH", "cpe:2.3:a:dropbear_ssh_project:dropbear_ssh"),
    (80, "http", "Apache httpd", "cpe:2.3:a:apache:http_server"),
    (80, "http", "lighttpd", "cpe:2.3:a:lighttpd:lighttpd"),
    (443, "https", "nginx", "cpe:2.3:a:f5:nginx"),
    (445, "smb", "Samba", "cpe:2.3:a:samba:samba"),
    (8080, "http-proxy", "Jetty", "cpe:2.3:a:eclipse:jetty"),
    (8080, "http-proxy", "Apache Tomcat", "cpe:2.3:a:apache:tomcat"),
    (3306, "mysql", "MySQL", "cpe:2.3:a:mysql:mysql"),
    (3306, "mysql", "MariaDB", "cpe:2.3:a:mariadb:mariadb"),
    (5432, "postgresql", "PostgreSQL", "cpe:2.3:a:postgresql:postgresql"),
    (6379, "redis", "Redis", "cpe:2.3:a:redis:redis"),
    (27017, "mongodb", "MongoDB", "cpe:2.3:a:mongodb:mongodb"),
    (23, "telnet", "BusyBox telnetd", "cpe:2.3:a:busybox:busybox"),
    (1900, "upnp", "MiniUPnPd", "cpe:2.3:a:miniupnp_project:miniupnpd"),
    (21, "ftp", "vsftpd", "cpe:2.3:a:redhat:vsftpd"),
    (21, "ftp", "ProFTPD", "cpe:2.3:a:proftpd:proftpd"),
    (25, "smtp", "Exim", "cpe:2.3:a:exim:exim"),
    (25, "smtp", "Postfix", "cpe:2.3:a:postfix:postfix"),
    (143, "imap", "Dovecot", "cpe:2.3:a:dovecot:dovecot"),
    (53, "domain", "ISC BIND", "cpe:2.3:a:isc:bind"),
    (53, "domain", "dnsmasq", "cpe:2.3:a:thekelleys:dnsmasq"),
    (1194, "openvpn", "OpenVPN", "cpe:2.3:a:openvpn:openvpn"),
    (11211, "memcache", "memcached", "cpe:2.3:a:memcached:memcached"),
    (9200, "http", "Elasticsearch", "cpe:2.3:a:elastic:elasticsearch"),
    (5984, "couchdb", "Apache CouchDB", "cpe:2.3:a:apache:couchdb"),
    (5672, "amqp", "RabbitMQ", "cpe:2.3:a:pivotal_software:rabbitmq"),
    (2375, "docker", "Docker", "cpe:2.3:a:docker:docker"),
    (8081, "http-alt", "Node.js", "cpe:2.3:a:nodejs:node.js"),
    (80, "http", "Synology DSM", "cpe:2.3:o:synology:diskstation_manager"),
    (80, "http", "QNAP QTS", "cpe:2.3:o:qnap:qts"),
    (80, "http", "NETGEAR router firmware", "cpe:2.3:o:netgear:r7800_firmware"),
    (80, "http", "TP-Link router firmware", "cpe:2.3:o:tp-link:tapo_c200_firmware"),
    (80, "http", "D-Link router firmware", "cpe:2.3:o:dlink:dir-816_firmware"),
    (161, "snmp", "Net-SNMP", "cpe:2.3:a:net-snmp:net-snmp"),
]

_TRIVY_PACKAGE_META: List[Tuple[str, str]] = [
    # (Debian/Ubuntu package name, NVD cpe_base for the upstream project)
    ("openssl", "cpe:2.3:a:openssl:openssl"),
    ("libssl1.1", "cpe:2.3:a:openssl:openssl"),
    ("curl", "cpe:2.3:a:haxx:curl"),
    ("libcurl4", "cpe:2.3:a:haxx:curl"),
    ("libxml2", "cpe:2.3:a:xmlsoft:libxml2"),
    ("zlib1g", "cpe:2.3:a:zlib:zlib"),
    ("python3.8", "cpe:2.3:a:python:python"),
    ("python3.10", "cpe:2.3:a:python:python"),
    ("bash", "cpe:2.3:a:gnu:bash"),
    ("sudo", "cpe:2.3:a:sudo_project:sudo"),
    ("openssh-server", "cpe:2.3:a:openbsd:openssh"),
    ("apache2", "cpe:2.3:a:apache:http_server"),
    ("nginx", "cpe:2.3:a:f5:nginx"),
    ("systemd", "cpe:2.3:a:systemd_project:systemd"),
    ("libc6", "cpe:2.3:a:gnu:glibc"),
    ("tar", "cpe:2.3:a:gnu:tar"),
    ("gzip", "cpe:2.3:a:gnu:gzip"),
    ("libsqlite3-0", "cpe:2.3:a:sqlite:sqlite"),
    ("libexpat1", "cpe:2.3:a:libexpat_project:libexpat"),
    ("perl", "cpe:2.3:a:perl:perl"),
    ("ruby", "cpe:2.3:a:ruby-lang:ruby"),
    ("php", "cpe:2.3:a:php:php"),
    ("nodejs", "cpe:2.3:a:nodejs:node.js"),
    ("samba", "cpe:2.3:a:samba:samba"),
    ("postgresql", "cpe:2.3:a:postgresql:postgresql"),
    ("docker.io", "cpe:2.3:a:docker:docker"),
    ("git", "cpe:2.3:a:git:git"),
    ("vim", "cpe:2.3:a:vim:vim"),
    ("cups-daemon", "cpe:2.3:a:apple:cups"),
    ("dbus", "cpe:2.3:a:freedesktop:dbus"),
    ("grub-common", "cpe:2.3:a:gnu:grub2"),
    ("wget", "cpe:2.3:a:gnu:wget"),
    ("linux-image-generic", "cpe:2.3:o:linux:linux_kernel"),
]

# Package-category classifier input reused by core/remediation.py's own
# _PACKAGE_CATEGORY_PATTERNS — not duplicated here; the category tag on filesystem
# findings is inferred downstream from the package name, not carried in this pool.

_OS_CPES: List[Tuple[str, str]] = [
    ("cpe:2.3:o:linux:linux_kernel", "Linux (kernel 4.15)"),
    ("cpe:2.3:o:microsoft:windows_10", "Windows 10"),
    ("cpe:2.3:o:windriver:vxworks", "VxWorks (embedded/router firmware)"),
    ("cpe:2.3:o:apple:mac_os_x", "macOS"),
    ("cpe:2.3:o:debian:debian_linux", "Debian Linux"),
    ("cpe:2.3:o:microsoft:windows_7", "Windows 7 (end-of-life, no longer receives security updates)"),
]

# --- Hand-curated pools (no local DB/catalog to mine from) --------------------------
# Real, publicly documented ClamAV signature families and nuclei-templates classes —
# genuine vocabulary, not invented strings, since the label-writer needs authentic
# product/finding names to draft from later.

# Malware file_path diversity: every finding must combine an independently-sampled
# location AND filename (not a fixed template with just a counter) — a constant
# "/home/user/downloads/file_N.bin" across every single malware row in the training
# set would teach the model "malware lives in Downloads" as a memorized fact rather
# than something it reads off the actual finding. Locations mirror ClamAV's real
# _DEFAULT_SCAN_PATHS scope (scanners/clamav/clamav_parser.py) so they stay plausible.
_MALWARE_LOCATIONS_LINUX = [
    "/home/user/Downloads", "/home/user/Desktop", "/home/user/.cache",
    "/tmp", "/var/tmp", "/opt/staging", "/srv/backups", "/root",
    "/var/www/html/uploads",
]
_MALWARE_FILENAMES_LINUX = [
    "setup.bin", "update_tool.elf", "keygen_crack.bin", "installer.sh",
    "media_player.appimage", "codec_pack.bin", "torrent_client.bin",
    "backup_script.sh", "flash_update.bin", "invoice_2026.pdf.sh",
]
_MALWARE_LOCATIONS_WINDOWS = [
    "C:\\Users\\user\\Downloads", "C:\\Users\\user\\Desktop",
    "C:\\Users\\user\\AppData\\Local\\Temp", "C:\\Users\\user\\Documents",
    "C:\\ProgramData\\Temp",
]
_MALWARE_FILENAMES_WINDOWS = [
    "invoice_2026.pdf.exe", "setup_installer.exe", "keygen_crack.exe",
    "steam_update.exe", "photo_editor_setup.exe", "flash_player_update.exe",
    "game_patch.exe", "driver_update.exe", "resume_2026.doc.exe", "zoom_installer.exe",
]

_CLAMAV_SIGNATURES = [
    ("Win.Trojan.Agent-123456", "high"),
    ("Win.Ransomware.WannaCry-9954", "high"),
    ("Win.Ransomware.GandCrab-7712", "high"),
    ("Unix.Trojan.Mirai-4432", "high"),
    ("Unix.Malware.Gafgyt-2201", "high"),
    ("Unix.Trojan.Generic-1234", "high"),
    ("Unix.Exploit.CVE_2016_3714-1", "high"),
    ("Win.Trojan.Zeus-3391", "high"),
    ("Win.Downloader.Emotet-5521", "high"),
    ("Win.Trojan.Kovter-8871", "medium"),
    ("PUA.Win.Adware.InstallCore-1", "medium"),
    ("PUA.Script.Coinminer-4521", "medium"),
    ("JS.Trojan.Agent-771", "medium"),
    ("Doc.Malware.Emotet-221", "high"),
    ("Unix.Backdoor.Small-90", "high"),
    ("Win.Trojan.Downloader-771", "high"),
    ("PUA.Win.Packer.UPX-2", "medium"),
    ("Unix.Trojan.Ddostf-1123", "high"),
]

# (name, severity, cve_id-or-None, cvss-or-None). Named to genuinely trigger the right
# class in core.remediation._classify_web (matched against "affected"/"name" text) —
# real templates in these families use this same kind of phrasing.
_NUCLEI_TEMPLATES = [
    # rce_template
    ("Apache Struts RCE", "critical", "CVE-2017-5638", 10.0),
    ("Apache Log4j2 Remote Code Execution (Log4Shell)", "critical", "CVE-2021-44228", 10.0),
    ("Spring Cloud Function RCE", "critical", "CVE-2022-22963", 9.8),
    ("Atlassian Confluence OGNL RCE", "critical", "CVE-2022-26134", 9.8),
    ("VMware vCenter RCE", "critical", "CVE-2021-21972", 9.8),
    ("F5 BIG-IP iControl REST RCE", "critical", "CVE-2022-1388", 9.8),
    ("Fortinet FortiOS RCE", "critical", "CVE-2022-40684", 9.8),
    ("GitLab CE/EE Remote Code Execution", "critical", "CVE-2021-22205", 9.9),
    ("Oracle WebLogic Server RCE", "critical", "CVE-2020-14882", 9.8),
    ("PHP-CGI Remote Code Execution", "critical", "CVE-2024-4577", 9.8),
    # open_datastore
    ("Open Redis instance (no auth)", "critical", None, 9.8),
    ("Open MongoDB instance (no auth)", "high", None, 8.2),
    ("Open Elasticsearch instance (unauthenticated)", "high", None, 7.5),
    ("Open Memcached instance (no auth)", "medium", None, 5.3),
    ("Unauthenticated Kibana dashboard access", "medium", None, 5.9),
    ("Open Docker API (unauthenticated)", "critical", None, 9.1),
    ("Open Kubernetes API (unauthenticated)", "critical", None, 9.1),
    ("Unauthenticated Jupyter Notebook access", "high", None, 8.8),
    ("Open CouchDB instance (no auth)", "high", None, 7.5),
    # default_creds
    ("Jenkins default credentials", "high", None, 8.1),
    ("Tomcat Manager default login", "high", None, 7.5),
    ("phpMyAdmin default login", "medium", None, 6.5),
    ("Grafana default credentials", "medium", None, 6.5),
    ("RabbitMQ Management default login", "medium", None, 6.5),
    ("MinIO default credentials", "high", None, 8.1),
    ("Zabbix default login", "medium", None, 6.5),
    ("Nagios XI default credentials", "high", None, 7.5),
    # exposed_source
    ("Exposed .git directory", "medium", None, None),
    ("Exposed .svn directory", "medium", None, None),
    ("Exposed .env configuration file", "high", None, 7.5),
    ("Backup file exposing source code (.bak)", "medium", None, None),
    ("Exposed .DS_Store revealing directory structure", "low", None, None),
    # exposed_admin
    ("Default admin login page", "medium", None, None),
    ("WordPress admin login page exposed", "low", None, None),
    ("cPanel admin panel exposed", "medium", None, None),
    ("pgAdmin admin panel exposed", "medium", None, None),
    # outdated_cms
    ("WordPress outdated core version", "high", "CVE-2022-21661", 7.5),
    ("Joomla outdated core version", "high", None, 7.2),
    ("Drupal outdated core version (Drupalgeddon2)", "critical", "CVE-2018-7600", 9.8),
    ("WordPress plugin out of date: Elementor", "medium", None, 6.1),
    ("Outdated jQuery version with known vulnerabilities", "medium", None, 5.4),
    # web_other (no keyword match — exercises the catch-all class)
    ("Swagger UI exposed", "low", None, None),
    ("GraphQL introspection enabled", "medium", None, None),
    ("Cross-site scripting in search parameter", "medium", None, 6.1),
    ("Missing HTTP security headers", "low", None, None),
    ("TLS certificate expired", "medium", None, None),
]

# Each iot_default_creds NSE script only ever fires against the protocol it actually
# checks: http-default-accounts probes a web login page, upnp-info a UPnP/SSDP
# responder, snmp-info an SNMP agent. Keeping these as one flat pool (as this used to
# be) let a caller pair, say, an http-default-accounts hit with a plain FTP port — a
# combination no real scan could ever produce, since that NSE script never even runs
# against a non-HTTP port. Split by script class, and paired with
# _SERVICE_LABELS_BY_SCRIPT_CLASS below, so a script only ever lands on a service
# whose protocol it's actually capable of checking.
_HTTP_DEFAULT_CREDS_OUTPUTS = [
    {"id": "http-default-accounts", "output": "Found default credentials admin:admin at path /login"},
    {"id": "http-default-accounts", "output": "Found default credentials admin:1234 at path /cgi-bin/luci"},
    {"id": "http-default-accounts", "output": "Found default credentials root:root at path /admin/login.cgi"},
]
_UPNP_INFO_OUTPUTS = [
    {"id": "upnp-info", "output": "Server: Linux/3.10 UPnP/1.0 MiniUPnPd/1.9 — external port mapping open"},
    {"id": "upnp-info", "output": "Server: Linux/4.4 UPnP/1.0 MiniUPnPd/2.1 — external port mapping open, WAN access unrestricted"},
]
_SNMP_INFO_OUTPUTS = [
    {"id": "snmp-info", "output": "SNMP community string 'public' accepted (read access)"},
    {"id": "snmp-info", "output": "SNMP community string 'private' accepted (read-write access)"},
]
_HTTP_LIKE_SERVICE_LABELS = {"http", "https", "http-proxy", "http-alt"}
_SCRIPT_CLASSES = ("http_default_creds", "upnp_info", "snmp_info")

_VERSION_RE = re.compile(r"^[0-9]+(\.[0-9]+){0,4}[a-z0-9]*$")
_LAST_DIGITS_RE = re.compile(r"(\d+)(?!.*\d)")

_services_pool_cache: Optional[List[Tuple[int, str, str, str, str]]] = None
_package_pool_cache: Optional[List[Tuple[str, str, str, str]]] = None


def _real_versions_for_cpe(conn: sqlite3.Connection, cpe_base: str, limit: int) -> List[str]:
    """Distinct plausible version strings actually recorded against `cpe_base` in the
    cache (filters out NVD's '*'/range-only rows) — real vocabulary, not invented."""
    cur = conn.cursor()
    cur.execute(
        "SELECT DISTINCT vulnerable_version FROM local_cves WHERE cpe_base = ? "
        "AND vulnerable_version NOT IN ('*', '', '-') LIMIT 300",
        (cpe_base,),
    )
    versions = [v for (v,) in cur.fetchall() if v and _VERSION_RE.match(v)]
    random.shuffle(versions)
    return versions[:limit] or ["1.0"]


def _bump_version(version: str) -> str:
    """Increment the last digit run in `version` — a plausible "next patch" string for
    a synthetic fixed_version (Trivy's real distro-patched strings aren't in NVD data,
    so this stands in for e.g. "1.1.1f" -> "1.1.2f")."""
    m = _LAST_DIGITS_RE.search(version)
    if not m:
        return version
    return version[:m.start(1)] + str(int(m.group(1)) + 1) + version[m.end(1):]


def _build_services_pool(conn: sqlite3.Connection) -> List[Tuple[int, str, str, str, str]]:
    pool = []
    for port, service, product, cpe_base in _SERVICE_META:
        for version in _real_versions_for_cpe(conn, cpe_base, limit=6):
            pool.append((port, service, product, version, f"{cpe_base}:{version}"))
    return pool


def _get_services_pool(conn: sqlite3.Connection) -> List[Tuple[int, str, str, str, str]]:
    global _services_pool_cache
    if _services_pool_cache is None:
        _services_pool_cache = _build_services_pool(conn)
    return _services_pool_cache


def _build_package_pool(conn: sqlite3.Connection) -> List[Tuple[str, str, str, str]]:
    """(package, installed_version, fixed_version, cpe_base) — installed_version is a
    real recorded vulnerable version, fixed_version a plausible next-patch bump."""
    pool = []
    for package, cpe_base in _TRIVY_PACKAGE_META:
        for installed in _real_versions_for_cpe(conn, cpe_base, limit=4):
            pool.append((package, installed, _bump_version(installed), cpe_base))
    return pool


def _get_package_pool(conn: sqlite3.Connection) -> List[Tuple[str, str, str, str]]:
    global _package_pool_cache
    if _package_pool_cache is None:
        _package_pool_cache = _build_package_pool(conn)
    return _package_pool_cache


def _cve_rows_for_cpe_prefix(conn: sqlite3.Connection, prefix: str, limit: int) -> List[Dict[str, Any]]:
    """Real CVE rows from vulnerability_cache.db, matching PHASE 1C's nmap CVE-dict shape."""
    cur = conn.cursor()
    cur.execute(
        """SELECT cve_id, cvss_score, severity, description, patch_links
           FROM local_cves WHERE cpe_base LIKE ? AND cvss_score > 0 ORDER BY RANDOM() LIMIT ?""",
        (prefix + "%", limit),
    )
    out = []
    for cve_id, cvss, severity, desc, links_s in cur.fetchall():
        links = [l.strip() for l in (links_s or "").split(",") if l.strip()]
        out.append({
            "cve_id": cve_id,
            "cvss_score": float(cvss) if cvss else 0.0,
            "severity": severity or "UNKNOWN",
            "description": desc or "No description provided.",
            "links": links[:2],
        })
    return out


def _service_record(
    conn: sqlite3.Connection, with_cves: bool, script_findings: Optional[list] = None,
    choice: Optional[Tuple[int, str, str, str, str]] = None,
) -> Dict[str, Any]:
    port, service, product, version, cpe = choice or random.choice(_get_services_pool(conn))
    cves = _cve_rows_for_cpe_prefix(conn, cpe.rsplit(":", 1)[0], random.randint(1, 3)) if with_cves else []
    max_cvss = max((c["cvss_score"] for c in cves), default=0.0)
    critical = sum(1 for c in cves if c["severity"] == "CRITICAL")
    high = sum(1 for c in cves if c["severity"] == "HIGH")
    return {
        "port": port,
        "service": service,
        "product": product,
        "version": version,
        "cpe": cpe,
        "risk_metrics": {
            "max_cvss_score": max_cvss,
            "total_critical_cves_found": critical,
            "total_high_cves_found": high,
        },
        "priority_vulnerabilities": cves[:5],
        "verified_patch_urls": [l for c in cves for l in c["links"]][:4],
        "script_findings": script_findings or [],
    }


def _service_records(
    conn: sqlite3.Connection, count: int, with_cves: bool, script_findings: Optional[list] = None,
    exclude_ports: Optional[set] = None,
) -> List[Dict[str, Any]]:
    """`count` service records with distinct ports — build_findings_table dedups
    same-port findings across sources, so same-port collisions within one profile
    would silently shrink the table below what the profile intended. `exclude_ports`
    lets a caller top up a set of records already picked elsewhere (e.g. an
    iot_defaults record chosen via _pick_iot_service_and_script) without risking a
    duplicate port between the two calls."""
    if count <= 0:
        return []
    pool = list(_get_services_pool(conn))
    random.shuffle(pool)
    seen_ports: set = set(exclude_ports or ())
    picks = []
    for tup in pool:
        if tup[0] in seen_ports:
            continue
        seen_ports.add(tup[0])
        picks.append(tup)
        if len(picks) == count:
            break
    return [_service_record(conn, with_cves, script_findings=script_findings, choice=tup) for tup in picks]


def _pick_iot_service_and_script(conn: sqlite3.Connection, with_cves: bool) -> Dict[str, Any]:
    """One iot_defaults service record carrying an NSE script result that's actually
    compatible with that service's protocol. Picks the script class first, then picks
    a service from only the ports capable of producing that class of result — the
    reverse order (service first, script second) is how this used to work and is what
    let e.g. an http-default-accounts hit land on a plain FTP port."""
    pool = _get_services_pool(conn)
    script_class = random.choice(_SCRIPT_CLASSES)
    if script_class == "http_default_creds":
        candidates = [t for t in pool if t[1] in _HTTP_LIKE_SERVICE_LABELS]
        output = random.choice(_HTTP_DEFAULT_CREDS_OUTPUTS)
    elif script_class == "upnp_info":
        candidates = [t for t in pool if t[1] == "upnp"]
        output = random.choice(_UPNP_INFO_OUTPUTS)
    else:
        candidates = [t for t in pool if t[1] == "snmp"]
        output = random.choice(_SNMP_INFO_OUTPUTS)
    choice = random.choice(candidates)
    return _service_record(conn, with_cves, script_findings=[output], choice=choice)


def _host_os_record(conn: sqlite3.Connection) -> Dict[str, Any]:
    cpe, os_name = random.choice(_OS_CPES)
    cves = _cve_rows_for_cpe_prefix(conn, cpe.rsplit(":", 1)[0], random.randint(0, 2))
    max_cvss = max((c["cvss_score"] for c in cves), default=0.0)
    critical = sum(1 for c in cves if c["severity"] == "CRITICAL")
    high = sum(1 for c in cves if c["severity"] == "HIGH")
    return {
        "finding_type": "host_os",
        "cpe": cpe,
        "os_name": os_name,
        "risk_metrics": {
            "max_cvss_score": max_cvss,
            "total_critical_cves_found": critical,
            "total_high_cves_found": high,
        },
        "priority_vulnerabilities": cves[:5],
        "verified_patch_urls": [l for c in cves for l in c["links"]][:4],
    }


def _filesystem_payload(conn: sqlite3.Connection, n: int) -> Dict[str, Any]:
    pool = _get_package_pool(conn)
    seen_pkgs: set = set()
    picks = []
    shuffled = list(pool)
    random.shuffle(shuffled)
    for tup in shuffled:
        if tup[0] in seen_pkgs:
            continue
        seen_pkgs.add(tup[0])
        picks.append(tup)
        if len(picks) == n:
            break

    findings = []
    for package, installed, fixed, cpe_base in picks:
        cves = _cve_rows_for_cpe_prefix(conn, cpe_base, 1)
        if cves:
            cve = cves[0]
            cve_id, severity, description = cve["cve_id"], cve["severity"].upper(), cve["description"]
        else:
            cve_id, severity = f"CVE-UNKNOWN-{package}", "MEDIUM"
            description = f"{package} {installed} has a known vulnerability, fixed in {fixed}."
        if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            severity = "MEDIUM"
        findings.append({
            "cve_id": cve_id,
            "package": package,
            "installed_version": installed,
            "fixed_version": fixed,
            "severity": severity,
            "title": f"{package} vulnerability",
            "description": description,
        })
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f["severity"].lower()] = counts.get(f["severity"].lower(), 0) + 1
    return {
        "host_node": "production_target_host",
        "risk_summary": {
            "critical_count": counts["critical"], "high_count": counts["high"],
            "medium_count": counts["medium"], "low_count": counts["low"],
            "total_actionable": len(findings),
        },
        "priority_findings": findings[:10],
    }


def _host_audit_payload(n: int) -> Dict[str, Any]:
    test_ids = random.sample(list(LYNIS_TEST_CATALOG), min(n, len(LYNIS_TEST_CATALOG)))
    findings = []
    for tid in test_ids:
        meta = LYNIS_TEST_CATALOG[tid]
        severity = random.choice(["HIGH", "MEDIUM"])
        findings.append({
            "test_id": tid,
            "severity": severity,
            "description": meta["description"],
            "details": "",
            "solution": meta["solution"],
        })
    high = sum(1 for f in findings if f["severity"] == "HIGH")
    medium = len(findings) - high
    return {
        "scan_target": "localhost",
        "lynis_version": "3.0.9",
        "os": "Linux",
        "hardening_index": random.randint(50, 85),
        "risk_summary": {
            "critical_count": 0, "high_count": high, "medium_count": medium,
            "low_count": 0, "total_actionable": len(findings),
        },
        "priority_findings": findings[:10],
    }


# Windows checks that read as elevation-sensitive/severe are worth weighting HIGH more
# often in synthetic data — matches how WINDOWS_AUDIT_CATALOG's own severities skew.
_WINDOWS_HIGH_TESTS = {"DEFENDER-RTP", "SMB1-ENABLED", "UAC-DISABLED", "BITLOCKER-OFF", "RDP-NLA"}


def _windows_audit_payload(n: int) -> Dict[str, Any]:
    test_ids = random.sample(list(WINDOWS_AUDIT_CATALOG), min(n, len(WINDOWS_AUDIT_CATALOG)))
    findings = []
    for tid in test_ids:
        meta = WINDOWS_AUDIT_CATALOG[tid]
        severity = "HIGH" if tid in _WINDOWS_HIGH_TESTS else "MEDIUM"
        findings.append({
            "test_id": tid,
            "severity": severity,
            "description": meta["description"],
            "details": "",
            "solution": meta["solution"],
        })
    high = sum(1 for f in findings if f["severity"] == "HIGH")
    medium = len(findings) - high
    return {
        "scan_target": "DESKTOP-HOME01",
        "os": "Windows 11 Pro",
        "hardening_index": random.randint(50, 90),
        "risk_summary": {
            "critical_count": 0, "high_count": high, "medium_count": medium,
            "low_count": 0, "total_actionable": len(findings),
        },
        "priority_findings": findings[:10],
    }


def _malware_file_path(location: str, filename: str) -> str:
    return f"{location}/{filename}"


def _windows_malware_file_path(location: str, filename: str) -> str:
    return f"{location}\\{filename}"


def _malware_payload(n: int) -> Dict[str, Any]:
    picks = random.sample(_CLAMAV_SIGNATURES, min(n, len(_CLAMAV_SIGNATURES)))
    findings = [
        {
            "file_path": _malware_file_path(random.choice(_MALWARE_LOCATIONS_LINUX), random.choice(_MALWARE_FILENAMES_LINUX)),
            "signature": sig, "severity": sev.upper(),
        }
        for sig, sev in picks
    ]
    high = sum(1 for f in findings if f["severity"] == "HIGH")
    medium = len(findings) - high
    return {
        "scan_target": ["/home", "/tmp", "/var/tmp", "/opt", "/srv", "/root", "/var/www"],
        "engine": "ClamAV",
        "scan_mode": "incremental",
        "risk_summary": {
            "critical_count": 0, "high_count": high, "medium_count": medium, "low_count": 0,
            "total_actionable": len(findings), "scanned_files": 5000, "infected_files": len(findings),
        },
        "priority_findings": findings[:10],
    }


def _windows_malware_payload(n: int) -> Dict[str, Any]:
    picks = random.sample(_CLAMAV_SIGNATURES, min(n, len(_CLAMAV_SIGNATURES)))
    findings = [
        {
            "file_path": _windows_malware_file_path(random.choice(_MALWARE_LOCATIONS_WINDOWS), random.choice(_MALWARE_FILENAMES_WINDOWS)),
            "signature": sig, "severity": sev.upper(),
        }
        for sig, sev in picks
    ]
    high = sum(1 for f in findings if f["severity"] == "HIGH")
    medium = len(findings) - high
    return {
        "scan_target": "local host (Windows Defender threat history)",
        "engine": "Windows Defender",
        "scan_mode": "history",
        "risk_summary": {
            "critical_count": 0, "high_count": high, "medium_count": medium, "low_count": 0,
            "total_actionable": len(findings), "infected_files": len(findings),
        },
        "priority_findings": findings[:10],
    }


def _pending_malware_payload() -> Dict[str, Any]:
    return {"status": "pending"}


def _web_payload(n: int) -> Dict[str, Any]:
    picks = random.sample(_NUCLEI_TEMPLATES, min(n, len(_NUCLEI_TEMPLATES)))
    findings = []
    for name, sev, cve_id, cvss in picks:
        findings.append({
            "template_id": name.lower().replace(" ", "-"),
            "name": name,
            "severity": sev.upper(),
            "host": "192.168.1.50",
            "matched_at": f"http://192.168.1.50/{name.lower().replace(' ', '-')}",
            "cve_id": cve_id,
            "cvss_score": cvss,
            "description": f"{name} was detected during a template-based web scan.",
            "references": [],
        })
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f["severity"].lower()] = counts.get(f["severity"].lower(), 0) + 1
    return {
        "scan_target": "192.168.1.50",
        "risk_summary": {**counts, "info_count": 0, "total_actionable": len(findings)},
        "priority_findings": findings[:10],
    }


# --- Table-size dimension -------------------------------------------------------
# Weighted sample across 0-40 findings. The original 6 profiles clustered small
# (1-8 findings); >10-finding tables were out-of-distribution, which is exactly what
# forced the _REPORT_CHUNK_SIZE=10 stopgap in agent.py. Applied to the "wide" multi-
# device profiles below (small_office, family_smarthome, windows_office_pc) rather
# than added as separate profiles, per UpgradeTuning.txt Step 3.

def _sample_table_size() -> int:
    r = random.random()
    if r < 0.35:
        return random.randint(0, 3)
    if r < 0.65:
        return random.randint(4, 10)
    if r < 0.88:
        return random.randint(11, 25)
    return random.randint(26, 40)


# --- Profiles -----------------------------------------------------------------
# Each profile returns a `results` dict shaped exactly like agent.py's worker spine
# output (the dict build_findings_table consumes).

def _profile_elderly_minimal(conn: sqlite3.Connection) -> Dict[str, Any]:
    network = _service_records(conn, 1, with_cves=False)
    iot = [_pick_iot_service_and_script(conn, with_cves=False)]
    return {
        "network": network, "iot_defaults": iot,
        "filesystem": {"priority_findings": []},
        "host_audit": {"priority_findings": []},
        "malware": _pending_malware_payload(),
        "web": {"priority_findings": []},
    }


def _profile_family_smarthome(conn: sqlite3.Connection) -> Dict[str, Any]:
    network = _service_records(conn, random.randint(2, 4), with_cves=True)
    iot_with_cves = random.random() < 0.5
    # One device gets an NSE hit compatible with its own protocol; if a second
    # iot-scanned device is included, it gets no script finding at all (a scanned
    # device that simply didn't trigger any of the three checks), rather than
    # duplicating the first device's script result onto a second, unrelated service.
    iot = [_pick_iot_service_and_script(conn, with_cves=iot_with_cves)]
    if random.randint(1, 2) == 2:
        iot.extend(_service_records(conn, 1, with_cves=iot_with_cves, exclude_ports={iot[0]["port"]}))
    return {
        "network": network, "iot_defaults": iot,
        "filesystem": {"priority_findings": []},
        "host_audit": {"priority_findings": []},
        "malware": _pending_malware_payload(),
        "web": {"priority_findings": []},
    }


def _profile_freelancer_laptop(conn: sqlite3.Connection) -> Dict[str, Any]:
    return {
        "network": _service_records(conn, 1, with_cves=False),
        "iot_defaults": [],
        "filesystem": _filesystem_payload(conn, random.randint(3, 5)),
        "host_audit": _host_audit_payload(random.randint(4, 8)),
        "malware": _pending_malware_payload(),
        "web": {"priority_findings": []},
    }


def _profile_compromised_machine(conn: sqlite3.Connection) -> Dict[str, Any]:
    return {
        "network": _service_records(conn, 1, with_cves=True),
        "iot_defaults": [],
        "filesystem": {"priority_findings": []},
        "host_audit": {"priority_findings": []},
        "malware": _malware_payload(1),
        "web": {"priority_findings": []},
    }


def _profile_small_office(conn: sqlite3.Connection) -> Dict[str, Any]:
    target = _sample_table_size()
    n_network = max(1, round(target * 0.45))
    n_web = round(target * 0.25)
    n_fs = round(target * 0.15)
    n_audit = round(target * 0.15)
    network = _service_records(conn, n_network, with_cves=True)
    if random.random() < 0.5:
        network.append(_host_os_record(conn))
    return {
        "network": network, "iot_defaults": [],
        "filesystem": _filesystem_payload(conn, n_fs),
        "host_audit": _host_audit_payload(n_audit),
        "malware": _pending_malware_payload(),
        "web": _web_payload(n_web),
    }


def _profile_clean_healthy(conn: sqlite3.Connection) -> Dict[str, Any]:
    return {
        "network": _service_records(conn, random.randint(1, 3), with_cves=False),
        "iot_defaults": [],
        "filesystem": {"priority_findings": []},
        "host_audit": {"priority_findings": []},
        "malware": _pending_malware_payload(),
        "web": {"priority_findings": []},
    }


def _profile_windows_home_user(conn: sqlite3.Connection) -> Dict[str, Any]:
    """A typical home Windows PC: Trivy skipped, a handful of hardening checks (not a
    dozen — most home users have Defender/firewall on by default), malware read from
    Defender's own history rather than ClamAV."""
    return {
        "network": _service_records(conn, 1, with_cves=False) if random.random() < 0.3 else [],
        "iot_defaults": [],
        "filesystem": {"status": "skipped"},
        "host_audit": _windows_audit_payload(random.randint(1, 3)),
        "malware": _windows_malware_payload(1) if random.random() < 0.2 else _pending_malware_payload(),
        "web": {"priority_findings": []},
    }


def _profile_windows_office_pc(conn: sqlite3.Connection) -> Dict[str, Any]:
    """A managed-but-imperfect office Windows PC: more hardening gaps (RDP/SMB/firewall
    misconfig is the common office-network failure mode) and occasional malware."""
    target = _sample_table_size()
    n_audit = min(max(2, round(target * 0.6)), len(WINDOWS_AUDIT_CATALOG))
    n_network = round(target * 0.3)
    return {
        "network": _service_records(conn, n_network, with_cves=True),
        "iot_defaults": [],
        "filesystem": {"status": "skipped"},
        "host_audit": _windows_audit_payload(n_audit),
        "malware": _windows_malware_payload(random.randint(1, 2)) if random.random() < 0.3 else _pending_malware_payload(),
        "web": {"priority_findings": []},
    }


def _profile_no_fix_available(conn: sqlite3.Connection) -> Dict[str, Any]:
    """Findings whose service nmap couldn't fingerprint (a real, if uncommon, scan
    outcome) — core.remediation.fix_facts_for legitimately has nothing to name a fix
    for, so this exercises the report prompt's "fix_facts is null" branch
    (UpgradeTuning.txt Step 1/3). Both service AND product/version must be blank: any
    one of them surviving into "affected" gives _network_service_and_port's regex
    fallback something to latch onto, defeating the point."""
    network = []
    for port in random.sample([22, 8443, 9000, 5000, 6000], random.randint(1, 3)):
        _, _, _, _, cpe = random.choice(_get_services_pool(conn))
        cves = _cve_rows_for_cpe_prefix(conn, cpe.rsplit(":", 1)[0], 1)
        network.append({
            "port": port, "service": "", "product": "", "version": "",
            "cpe": None,
            "risk_metrics": {
                "max_cvss_score": max((c["cvss_score"] for c in cves), default=6.5),
                "total_critical_cves_found": 0,
                "total_high_cves_found": 1 if cves else 0,
            },
            "priority_vulnerabilities": cves[:1] or [{
                "cve_id": None,
                "description": "An unidentified service responded on this port but its banner could not be fingerprinted.",
            }],
            "verified_patch_urls": [],
            "script_findings": [],
        })
    return {
        "network": network, "iot_defaults": [],
        "filesystem": {"priority_findings": []},
        "host_audit": {"priority_findings": []},
        "malware": _pending_malware_payload(),
        "web": {"priority_findings": []},
    }


def _profile_edge_empty(conn: sqlite3.Connection) -> Dict[str, Any]:
    """Scripted edge case: a fully clean scan, zero findings of any kind."""
    return {
        "network": [], "iot_defaults": [],
        "filesystem": {"priority_findings": []},
        "host_audit": {"priority_findings": []},
        "malware": _pending_malware_payload(),
        "web": {"priority_findings": []},
    }


def _profile_edge_all_good(conn: sqlite3.Connection) -> Dict[str, Any]:
    """Scripted edge case: several services scanned, all clean (no CVEs matched) —
    distinct from clean_healthy's smaller 1-3 count, for wider "all good" coverage."""
    return {
        "network": _service_records(conn, random.randint(4, 7), with_cves=False),
        "iot_defaults": [],
        "filesystem": {"priority_findings": []},
        "host_audit": {"priority_findings": []},
        "malware": _pending_malware_payload(),
        "web": {"priority_findings": []},
    }


def _profile_edge_single_critical(conn: sqlite3.Connection) -> Dict[str, Any]:
    """Scripted edge case: exactly one finding, forced critical — the smallest possible
    non-empty table, at the opposite severity extreme from edge_all_good."""
    rec = _service_records(conn, 1, with_cves=False)[0]
    rec["priority_vulnerabilities"] = [{
        "cve_id": "CVE-2021-44228", "cvss_score": 10.0, "severity": "CRITICAL",
        "description": "Remote attackers can execute arbitrary code via crafted input; exploitation requires no authentication.",
        "links": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
    }]
    rec["risk_metrics"] = {"max_cvss_score": 10.0, "total_critical_cves_found": 1, "total_high_cves_found": 0}
    rec["verified_patch_urls"] = ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]
    return {
        "network": [rec], "iot_defaults": [],
        "filesystem": {"priority_findings": []},
        "host_audit": {"priority_findings": []},
        "malware": _pending_malware_payload(),
        "web": {"priority_findings": []},
    }


def _profile_edge_all_same_severity(conn: sqlite3.Connection) -> Dict[str, Any]:
    """Scripted edge case: multiple findings all at the same (medium) severity tier —
    tests that triage/report ordering doesn't depend on severity variance existing."""
    recs = _service_records(conn, random.randint(5, 8), with_cves=False)
    for rec in recs:
        rec["priority_vulnerabilities"] = [{
            "cve_id": None, "cvss_score": 5.5, "severity": "MEDIUM",
            "description": "A known weakness allows information disclosure under specific conditions.",
            "links": [],
        }]
        rec["risk_metrics"] = {"max_cvss_score": 5.5, "total_critical_cves_found": 0, "total_high_cves_found": 0}
    return {
        "network": recs, "iot_defaults": [],
        "filesystem": {"priority_findings": []},
        "host_audit": {"priority_findings": []},
        "malware": _pending_malware_payload(),
        "web": {"priority_findings": []},
    }


_PROFILES = {
    "elderly_minimal": _profile_elderly_minimal,
    "family_smarthome": _profile_family_smarthome,
    "freelancer_laptop": _profile_freelancer_laptop,
    "compromised_machine": _profile_compromised_machine,
    "small_office": _profile_small_office,
    "clean_healthy": _profile_clean_healthy,
    "windows_home_user": _profile_windows_home_user,
    "windows_office_pc": _profile_windows_office_pc,
    "no_fix_available": _profile_no_fix_available,
    "edge_empty": _profile_edge_empty,
    "edge_all_good": _profile_edge_all_good,
    "edge_single_critical": _profile_edge_single_critical,
    "edge_all_same_severity": _profile_edge_all_same_severity,
}

_WINDOWS_PROFILES = {"windows_home_user", "windows_office_pc"}


def _platform_for_profile(profile: str) -> str:
    return "windows" if profile in _WINDOWS_PROFILES else "linux"


def generate_ordered_facts(profile: str, conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    """Assemble a synthetic `results` dict for `profile`, run it through the real
    build_findings_table + priority.rank, and return ordered_facts — identical in
    shape to what run_report's _log_training_input logs in production."""
    results = _PROFILES[profile](conn)
    table = build_findings_table(results)
    order = ordered_refs(rank(table))
    by_ref = {f["ref"]: f for f in table}
    return [by_ref[r] for r in order if r in by_ref]


def _ensure_platform_column(conn: sqlite3.Connection) -> None:
    cols = {row[1] for row in conn.execute("PRAGMA table_info(examples)")}
    if "platform" not in cols:
        conn.execute("ALTER TABLE examples ADD COLUMN platform TEXT")
        conn.commit()


def _supersede_old_format_rows(conn: sqlite3.Connection) -> int:
    """Mark every non-superseded row (synth AND real — 'real' rows predate the
    fix_facts contract exactly as much as the original synth rows do) whose
    ordered_facts lacks a fix_facts key as 'superseded'. Leaves synth_triage alone —
    that source trains a different (deterministic-triage) task, not the report LLM,
    and never carried fix_facts to begin with. Rows with an empty ordered_facts list
    can't be classified either way from content alone, so they're left untouched —
    harmless either way since an empty table renders identically regardless of when
    it was generated."""
    cur = conn.cursor()
    cur.execute("SELECT id, ordered_facts FROM examples WHERE source != 'synth_triage' AND status != 'superseded'")
    stale_ids = []
    for row_id, facts_json in cur.fetchall():
        try:
            facts = json.loads(facts_json)
        except (TypeError, json.JSONDecodeError):
            continue
        if isinstance(facts, list) and any(isinstance(f, dict) and "fix_facts" not in f for f in facts):
            stale_ids.append(row_id)
    if stale_ids:
        cur.executemany("UPDATE examples SET status = 'superseded' WHERE id = ?", [(i,) for i in stale_ids])
        conn.commit()
    return len(stale_ids)


def _init_trainset_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute(_TRAINSET_SCHEMA)
    conn.commit()
    _ensure_platform_column(conn)
    return conn


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", default="trainset.db", help="path to the trainset working store")
    ap.add_argument("--vuln-db", default=_VULN_DB_PATH, help="path to vulnerability_cache.db")
    ap.add_argument("--profile", choices=list(_PROFILES), help="generate only this profile (default: all)")
    ap.add_argument("--per-profile", type=int, default=45, help="rows to generate per profile")
    ap.add_argument("--seed", type=int, default=None, help="random seed for reproducibility")
    ap.add_argument("--skip-supersede", action="store_true",
                     help="don't mark old-format (pre-fix_facts) rows as superseded before inserting")
    args = ap.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    vuln_conn = sqlite3.connect(args.vuln_db)
    trainset_conn = _init_trainset_db(args.db)

    if not args.skip_supersede:
        superseded = _supersede_old_format_rows(trainset_conn)
        print(f"[synth_findings] superseded {superseded} pre-fix_facts rows")

    profiles = [args.profile] if args.profile else list(_PROFILES)
    inserted = 0
    for profile in profiles:
        platform = _platform_for_profile(profile)
        for _ in range(args.per_profile):
            ordered_facts = generate_ordered_facts(profile, vuln_conn)
            trainset_conn.execute(
                "INSERT INTO examples (source, profile, ordered_facts, status, platform) VALUES (?, ?, ?, 'pending', ?)",
                ("synth", profile, json.dumps(ordered_facts), platform),
            )
            inserted += 1
        trainset_conn.commit()
        print(f"[synth_findings] {profile}: {args.per_profile} rows")

    print(f"[synth_findings] inserted {inserted} pending rows into {args.db}")
    vuln_conn.close()
    trainset_conn.close()


if __name__ == "__main__":
    main()
