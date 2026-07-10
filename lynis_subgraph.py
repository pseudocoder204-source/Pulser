# SPDX-License-Identifier: GPL-2.0-only
"""
lynis_subgraph.py — LangGraph subgraph edition of the Lynis host-security-audit pipeline.

Four stages, each modelled as a LangGraph node:

    [scan_node] → [parse_node] → [enrich_node] → [build_node] → END
          ↓              ↓               ↓               ↓
         END            END             END             END   (on error)

The extra enrich_node is unique to Lynis: it cross-references each test_id against
LYNIS_TEST_CATALOG — a mapping of Lynis test IDs to human-readable descriptions and
remediation steps, written for this project. This fills in the description/solution
fields that the machine-readable report file omits (it stores test_id and severity only).

See the WARNING above LYNIS_TEST_CATALOG: most of its descriptions do not match what
the corresponding upstream Lynis test actually checks.

Usage — standalone:
    python3 lynis_subgraph.py

Usage — as a subgraph node inside a parent graph:
    from lynis_subgraph import build_lynis_subgraph
    parent.add_node("lynis", build_lynis_subgraph())

    No inputs required — Lynis always audits the local host.
    On completion the subgraph writes back: raw_report, parsed_report, payload, error.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Optional

from typing_extensions import TypedDict

from langgraph.graph import END, StateGraph
from display_graph import display_graph

from lynis_parser import (
    build_llm_payload_from_lynis,
    parse_lynis_report,
    run_lynis_audit,
)

# ── Lynis test catalog ─────────────────────────────────────────────────────────
# Maps test_id → {category, description, solution} so the enrich_node can fill in
# the fields that the machine-readable report file omits.
#
# Original text, not copied from Lynis. Keep it that way: Lynis is GPL-3.0 and this
# project is GPL-2.0-only, so pasting upstream text in here would be a license conflict.
#
# WARNING — UNVERIFIED MAPPINGS. As of 2026-07-09 these descriptions were compared
# against all 43 include/tests_* files in CISOfy/lynis@master. Of 80 entries, 71
# describe something *different* from what that test ID actually checks upstream, and
# 2 IDs (incl. SSH-7408) do not exist upstream at all. Example: AUTH-9204 upstream is
# "Check users with an UID of zero", not the passwordless-account check claimed below.
# These strings reach end users via enrich_node and seed synth_findings.py's training
# rows, so a wrong mapping is a wrong report and a poisoned training example.
# Do not add entries without checking the ID against upstream first.

LYNIS_TEST_CATALOG: Dict[str, Dict[str, str]] = {
    # ── AUTH — Authentication ──────────────────────────────────────────────────
    "AUTH-9204": {
        "category":    "Authentication",
        "description": "Check user accounts in /etc/passwd without a password field set",
        "solution":    "Lock or remove password-less accounts: passwd -l <user>.",
    },
    "AUTH-9208": {
        "category":    "Authentication",
        "description": "Check default umask in /etc/login.defs",
        "solution":    "Set UMASK to 027 or stricter in /etc/login.defs.",
    },
    "AUTH-9218": {
        "category":    "Authentication",
        "description": "Check for locked/expired system accounts",
        "solution":    "Remove or lock unused system accounts with usermod -L <user>.",
    },
    "AUTH-9228": {
        "category":    "Authentication",
        "description": "Check password hashing algorithm in /etc/pam.d/ (should be SHA-512)",
        "solution":    "Configure PAM to use SHA-512: add 'sha512' to pam_unix in /etc/pam.d/common-password.",
    },
    "AUTH-9234": {
        "category":    "Authentication",
        "description": "Check for non-unique UIDs in /etc/passwd",
        "solution":    "Ensure each user account has a unique UID.",
    },
    "AUTH-9252": {
        "category":    "Authentication",
        "description": "Check password aging / maximum days between password changes",
        "solution":    "Set PASS_MAX_DAYS=90 in /etc/login.defs; apply per-account with chage -M 90 <user>.",
    },
    "AUTH-9262": {
        "category":    "Authentication",
        "description": "Check minimum password age to prevent immediate recycling",
        "solution":    "Set PASS_MIN_DAYS=1 in /etc/login.defs.",
    },
    "AUTH-9266": {
        "category":    "Authentication",
        "description": "Check PAM password complexity requirements",
        "solution":    "Enable pam_pwquality with minlen=12, dcredit=-1, ucredit=-1 in /etc/pam.d/common-password.",
    },
    "AUTH-9268": {
        "category":    "Authentication",
        "description": "Check maximum password expiry for active user accounts",
        "solution":    "Apply per-account expiry: chage -M 90 <user> for all interactive accounts.",
    },
    "AUTH-9282": {
        "category":    "Authentication",
        "description": "Check whether the sudo binary is available",
        "solution":    "Install sudo (apt install sudo) and restrict its use via /etc/sudoers.",
    },
    "AUTH-9286": {
        "category":    "Authentication",
        "description": "Check sudo configuration for security weaknesses",
        "solution":    "Use visudo to review sudoers; avoid NOPASSWD for privileged commands.",
    },
    "AUTH-9288": {
        "category":    "Authentication",
        "description": "Check LDAP authentication module configuration",
        "solution":    "Secure LDAP connections with LDAPS or STARTTLS; do not transmit credentials in cleartext.",
    },

    # ── BOOT — Bootloader ──────────────────────────────────────────────────────
    "BOOT-5122": {
        "category":    "Boot",
        "description": "Check for password protection on the GRUB bootloader",
        "solution":    "Set a GRUB superuser password (grub-mkpasswd-pbkdf2) to prevent boot-time tampering.",
    },
    "BOOT-5180": {
        "category":    "Boot",
        "description": "Check systemd service unit hardening options",
        "solution":    "Add PrivateTmp=yes, NoNewPrivileges=yes, ProtectSystem=strict to service unit files.",
    },

    # ── CONT — Containers ─────────────────────────────────────────────────────
    "CONT-8004": {
        "category":    "Containers",
        "description": "Docker daemon is running; check security configuration",
        "solution":    "Enable Docker Content Trust (DOCKER_CONTENT_TRUST=1); use rootless Docker where possible.",
    },
    "CONT-8102": {
        "category":    "Containers",
        "description": "Check for Docker containers running as root",
        "solution":    "Add a non-root USER directive in all Dockerfiles; use --user flag at runtime.",
    },

    # ── CRYP — Cryptography ───────────────────────────────────────────────────
    "CRYP-7902": {
        "category":    "Cryptography",
        "description": "Check for expired SSL/TLS certificates",
        "solution":    "Renew expired certificates immediately; automate renewal with certbot --renew.",
    },
    "CRYP-7930": {
        "category":    "Cryptography",
        "description": "Check SSL/TLS certificate expiring within 90 days",
        "solution":    "Automate certificate renewal with an ACME client (certbot, acme.sh).",
    },
    "CRYP-8002": {
        "category":    "Cryptography",
        "description": "Check for adequate entropy source (haveged or rng-tools)",
        "solution":    "Install haveged (apt install haveged; systemctl enable haveged) to ensure sufficient entropy.",
    },

    # ── FILE — File permissions ────────────────────────────────────────────────
    "FILE-6310": {
        "category":    "File Permissions",
        "description": "Check default umask in shell configuration files (/etc/profile, /etc/bash.bashrc)",
        "solution":    "Set 'umask 027' in /etc/profile and /etc/bash.bashrc.",
    },
    "FILE-6362": {
        "category":    "File Permissions",
        "description": "Check sticky bit on /tmp directory",
        "solution":    "Set the sticky bit: chmod +t /tmp.",
    },
    "FILE-6374": {
        "category":    "File Permissions",
        "description": "Check /tmp mounted with nodev, noexec, nosuid options",
        "solution":    "Add 'nodev,noexec,nosuid' to the /tmp entry in /etc/fstab and remount.",
    },
    "FILE-6430": {
        "category":    "File Permissions",
        "description": "Check for disabled unused filesystem kernel modules (cramfs, hfs, jffs2, udf, etc.)",
        "solution":    "Blacklist modules in /etc/modprobe.d/: e.g., 'install cramfs /bin/true'.",
    },

    # ── FINT — File Integrity ─────────────────────────────────────────────────
    "FINT-4350": {
        "category":    "File Integrity",
        "description": "No file integrity monitoring (FIM) tool detected",
        "solution":    "Install AIDE (apt install aide) and initialise a baseline: aideinit; schedule daily aide --check via cron.",
    },
    "FINT-4402": {
        "category":    "File Integrity",
        "description": "Check AIDE configuration for strong hash algorithms (SHA-256/SHA-512)",
        "solution":    "Configure AIDE rules to use sha256 or sha512; remove md5 from the hash list.",
    },

    # ── FIRE — Firewall ───────────────────────────────────────────────────────
    "FIRE-4512": {
        "category":    "Firewall",
        "description": "iptables ruleset is empty — no firewall rules active",
        "solution":    "Define a default-deny policy and add explicit ACCEPT rules for required services.",
    },
    "FIRE-4590": {
        "category":    "Firewall",
        "description": "No active firewall (iptables, nftables, or ufw) detected",
        "solution":    "Enable ufw (ufw enable) or start nftables and load a hardened ruleset.",
    },

    # ── HOME — Home directories ───────────────────────────────────────────────
    "HOME-9304": {
        "category":    "Home Directories",
        "description": "Check home directory permissions (should be 750 or stricter)",
        "solution":    "Restrict home directories: chmod 750 /home/<user> for each interactive account.",
    },
    "HOME-9310": {
        "category":    "Home Directories",
        "description": "Check for history file symlink attacks (e.g., .bash_history → /dev/null)",
        "solution":    "Remove symlinks from history files; set HISTFILE=/dev/null only in approved admin configs.",
    },

    # ── HRDN — Hardening ──────────────────────────────────────────────────────
    "HRDN-7222": {
        "category":    "Hardening",
        "description": "Compiler binaries are world-accessible — restrict to root/admin group",
        "solution":    "Restrict compiler access: chmod 750 /usr/bin/gcc; chown root:adm /usr/bin/gcc.",
    },
    "HRDN-7230": {
        "category":    "Hardening",
        "description": "No malware scanner installed on this host",
        "solution":    "Install ClamAV (apt install clamav clamav-daemon) and configure freshclam for signature updates.",
    },

    # ── HTTP — Web servers ────────────────────────────────────────────────────
    "HTTP-6640": {
        "category":    "Web Servers",
        "description": "Apache mod_evasive (DDoS/brute-force protection) not installed",
        "solution":    "Install libapache2-mod-evasive and configure DOSPageCount, DOSSiteCount thresholds.",
    },
    "HTTP-6643": {
        "category":    "Web Servers",
        "description": "Apache mod_security (WAF) not installed",
        "solution":    "Install libapache2-mod-security2 and enable the OWASP ModSecurity Core Rule Set.",
    },
    "HTTP-6660": {
        "category":    "Web Servers",
        "description": "Apache TraceEnable directive is not disabled (HTTP TRACE method active)",
        "solution":    "Add 'TraceEnable Off' to Apache's main config or VirtualHost block.",
    },

    # ── INSE — Insecure services ──────────────────────────────────────────────
    "INSE-8016": {
        "category":    "Insecure Services",
        "description": "Insecure service (telnet, rsh, rlogin) detected via inetd/xinetd",
        "solution":    "Remove insecure service entries from /etc/inetd.conf; disable inetd or replace with SSH.",
    },
    "INSE-8300": {
        "category":    "Insecure Services",
        "description": "rsh (remote shell) service is installed",
        "solution":    "Remove rsh-server: apt purge rsh-server; use SSH for all remote access.",
    },
    "INSE-8322": {
        "category":    "Insecure Services",
        "description": "Telnet server is installed and/or running",
        "solution":    "Remove telnetd: apt purge telnetd; use SSH instead.",
    },

    # ── KRNL — Kernel ────────────────────────────────────────────────────────
    "KRNL-5820": {
        "category":    "Kernel",
        "description": "Kernel core dumps are not disabled",
        "solution":    "Add 'fs.suid_dumpable=0' to /etc/sysctl.d/99-hardening.conf; set 'ulimit -c 0' in /etc/profile.",
    },
    "KRNL-5830": {
        "category":    "Kernel",
        "description": "System requires a reboot to activate a newly installed kernel",
        "solution":    "Schedule a maintenance window and reboot: shutdown -r now.",
    },
    "KRNL-6000": {
        "category":    "Kernel",
        "description": "One or more sysctl hardening parameters are not set to the recommended value",
        "solution":    "Apply kernel hardening in /etc/sysctl.d/99-hardening.conf: kernel.randomize_va_space=2, "
                       "net.ipv4.conf.all.rp_filter=1, net.ipv4.conf.all.accept_redirects=0, "
                       "kernel.dmesg_restrict=1; run sysctl --system.",
    },

    # ── LDAP — LDAP ───────────────────────────────────────────────────────────
    "LDAP-2240": {
        "category":    "LDAP",
        "description": "LDAP rootdn password is stored in plaintext in slapd.conf",
        "solution":    "Hash the password with slappasswd and replace the plaintext value in slapd.conf.",
    },
    "LDAP-2244": {
        "category":    "LDAP",
        "description": "LDAP is not configured to use TLS/LDAPS",
        "solution":    "Configure STARTTLS or LDAPS; set 'security tls=1' in slapd.conf.",
    },

    # ── LOGG — Logging ────────────────────────────────────────────────────────
    "LOGG-2154": {
        "category":    "Logging",
        "description": "No remote syslog server configured",
        "solution":    "Configure rsyslog/syslog-ng to forward logs to a central log server or SIEM.",
    },
    "LOGG-2190": {
        "category":    "Logging",
        "description": "Open log file handles detected for deleted files (log rotation gap)",
        "solution":    "Restart daemons with deleted log handles: systemctl restart <service>; run logrotate.",
    },

    # ── MACF — MAC Frameworks ─────────────────────────────────────────────────
    "MACF-6208": {
        "category":    "MAC Frameworks",
        "description": "AppArmor is not enabled or not in enforcing mode",
        "solution":    "Enable AppArmor: aa-enforce /etc/apparmor.d/*; add security=apparmor to kernel cmdline.",
    },
    "MACF-6234": {
        "category":    "MAC Frameworks",
        "description": "SELinux is not enabled or not in enforcing mode",
        "solution":    "Set SELINUX=enforcing in /etc/selinux/config and relabel the filesystem (touch /.autorelabel).",
    },
    "MACF-6290": {
        "category":    "MAC Frameworks",
        "description": "No mandatory access control (MAC) framework is active on this system",
        "solution":    "Install and enforce AppArmor (Debian/Ubuntu) or SELinux (RHEL/CentOS) for kernel-level access control.",
    },

    # ── MAIL — Mail ───────────────────────────────────────────────────────────
    "MAIL-8818": {
        "category":    "Mail",
        "description": "Postfix SMTP banner reveals version or OS information",
        "solution":    "Set 'smtpd_banner = $myhostname ESMTP' in /etc/postfix/main.cf; reload postfix.",
    },
    "MAIL-8820": {
        "category":    "Mail",
        "description": "SMTP VRFY command is enabled — allows user enumeration",
        "solution":    "Disable VRFY in Postfix: set 'disable_vrfy_command = yes' in main.cf.",
    },

    # ── MALW — Malware ────────────────────────────────────────────────────────
    "MALW-3280": {
        "category":    "Malware",
        "description": "No anti-virus or anti-malware scanner is installed",
        "solution":    "Install ClamAV: apt install clamav clamav-daemon; enable freshclam for daily signature updates.",
    },
    "MALW-3286": {
        "category":    "Malware",
        "description": "freshclam anti-virus signature update daemon is not running",
        "solution":    "Enable freshclam: systemctl enable --now clamav-freshclam.",
    },

    # ── NAME — Name services ───────────────────────────────────────────────────
    "NAME-4210": {
        "category":    "Name Services",
        "description": "BIND nameserver version is exposed in DNS responses",
        "solution":    "Hide BIND version: set 'version \"none\";' inside the options block of named.conf.",
    },
    "NAME-4304": {
        "category":    "Name Services",
        "description": "NIS (YP) is in use — transmits credentials in cleartext",
        "solution":    "Migrate from NIS to LDAP with TLS or Kerberos for secure directory services.",
    },

    # ── NETW — Networking ─────────────────────────────────────────────────────
    "NETW-3015": {
        "category":    "Networking",
        "description": "A network interface is in promiscuous mode — possible packet sniffing",
        "solution":    "Investigate the interface: ip link show; disable promiscuous mode: ip link set <iface> promisc off.",
    },
    "NETW-3032": {
        "category":    "Networking",
        "description": "No ARP monitoring tool installed — ARP spoofing attacks undetected",
        "solution":    "Install arpwatch: apt install arpwatch; systemctl enable --now arpwatch.",
    },
    "NETW-3200": {
        "category":    "Networking",
        "description": "Uncommon/unused network protocols (dccp, sctp, rds, tipc) are not disabled",
        "solution":    "Blacklist protocols in /etc/modprobe.d/disable-net-protocols.conf: 'install dccp /bin/true'.",
    },

    # ── PHP — PHP ─────────────────────────────────────────────────────────────
    "PHP-2320": {
        "category":    "PHP",
        "description": "Dangerous PHP functions (exec, passthru, shell_exec, system) are enabled",
        "solution":    "Add to php.ini: disable_functions = exec,passthru,shell_exec,system,popen,proc_open.",
    },
    "PHP-2372": {
        "category":    "PHP",
        "description": "PHP expose_php is On — version disclosed in HTTP headers",
        "solution":    "Set 'expose_php = Off' in php.ini.",
    },
    "PHP-2376": {
        "category":    "PHP",
        "description": "PHP allow_url_fopen is On — enables remote file inclusion (RFI) risk",
        "solution":    "Set 'allow_url_fopen = Off' in php.ini.",
    },

    # ── PKGS — Packages ───────────────────────────────────────────────────────
    "PKGS-7346": {
        "category":    "Packages",
        "description": "Packages in rc state have residual config files that were not purged",
        "solution":    "Purge residual configs: dpkg --purge $(dpkg -l | awk '/^rc/{print $2}').",
    },
    "PKGS-7392": {
        "category":    "Packages",
        "description": "Pending Debian/Ubuntu security updates available",
        "solution":    "Apply security patches immediately: apt-get update && apt-get upgrade.",
    },
    "PKGS-7420": {
        "category":    "Packages",
        "description": "Automatic security updates are not configured",
        "solution":    "Install and enable unattended-upgrades: apt install unattended-upgrades; dpkg-reconfigure unattended-upgrades.",
    },

    # ── PRNT — Printing ───────────────────────────────────────────────────────
    "PRNT-2307": {
        "category":    "Printing",
        "description": "CUPS configuration file has insecure permissions",
        "solution":    "Restrict permissions: chmod 640 /etc/cups/cupsd.conf; chown root:lp /etc/cups/cupsd.conf.",
    },
    "PRNT-2308": {
        "category":    "Printing",
        "description": "CUPS is listening on a network interface (not restricted to localhost)",
        "solution":    "Restrict CUPS: set 'Listen 127.0.0.1:631' in /etc/cups/cupsd.conf; restart CUPS.",
    },

    # ── PROC — Processes ──────────────────────────────────────────────────────
    "PROC-3612": {
        "category":    "Processes",
        "description": "Zombie processes detected — child processes not reaped by parent",
        "solution":    "Identify zombie parents with ps aux | grep Z; restart or fix the parent process.",
    },
    "PROC-3614": {
        "category":    "Processes",
        "description": "High I/O wait detected — possible disk bottleneck or failing drive",
        "solution":    "Diagnose with iostat -x 1 10; check for failing drives with smartctl -a /dev/sdX.",
    },

    # ── SCHD — Scheduling ────────────────────────────────────────────────────
    "SCHD-7704": {
        "category":    "Scheduling",
        "description": "Crontab or cron directory files have insecure permissions",
        "solution":    "Restrict crontab: chmod 600 /etc/crontab; ensure /etc/cron.d/ files are owned by root:root.",
    },

    # ── SHLL — Shell ─────────────────────────────────────────────────────────
    "SHLL-6220": {
        "category":    "Shell",
        "description": "No idle session timeout (TMOUT) configured — sessions remain open indefinitely",
        "solution":    "Add 'readonly TMOUT=900; export TMOUT' to /etc/profile.d/tmout.sh.",
    },
    "SHLL-6230": {
        "category":    "Shell",
        "description": "Default shell umask is not set to a restrictive value",
        "solution":    "Set 'umask 027' in /etc/profile and /etc/bash.bashrc.",
    },

    # ── SNMP — SNMP ───────────────────────────────────────────────────────────
    "SNMP-3306": {
        "category":    "SNMP",
        "description": "SNMP is configured with default community strings (public/private)",
        "solution":    "Change default community strings to unique values; migrate to SNMPv3 with authPriv security level.",
    },

    # ── SSH — SSH ─────────────────────────────────────────────────────────────
    "SSH-7408": {
        "category":    "SSH",
        "description": "SSH server configuration has one or more insecure settings "
                       "(e.g., PermitRootLogin, PasswordAuthentication, Protocol version, MaxAuthTries)",
        "solution":    "Harden /etc/ssh/sshd_config: PermitRootLogin no, Protocol 2, "
                       "PasswordAuthentication no, MaxAuthTries 3, "
                       "ClientAliveInterval 300, ClientAliveCountMax 2, "
                       "AllowTcpForwarding no, X11Forwarding no; reload: systemctl reload sshd.",
    },
    "SSH-7440": {
        "category":    "SSH",
        "description": "SSH does not restrict access with AllowUsers or AllowGroups",
        "solution":    "Add 'AllowUsers <user1> <user2>' or 'AllowGroups sshusers' to /etc/ssh/sshd_config; reload sshd.",
    },

    # ── STRG — Storage ────────────────────────────────────────────────────────
    "STRG-1846": {
        "category":    "Storage",
        "description": "FireWire kernel module is loaded — susceptible to DMA-based memory attacks",
        "solution":    "Blacklist FireWire: add 'blacklist firewire-core' to /etc/modprobe.d/blacklist.conf; unload: rmmod firewire-core.",
    },
    "STRG-1930": {
        "category":    "Storage",
        "description": "NFS export access controls are too permissive",
        "solution":    "Restrict NFS exports in /etc/exports: add root_squash, nosuid, noexec options per export.",
    },

    # ── TIME — Time/NTP ───────────────────────────────────────────────────────
    "TIME-3104": {
        "category":    "Time/NTP",
        "description": "No NTP daemon (chronyd, ntpd, timesyncd) is running — clock may drift",
        "solution":    "Enable NTP synchronisation: systemctl enable --now chronyd (or ntpd/systemd-timesyncd).",
    },
    "TIME-3116": {
        "category":    "Time/NTP",
        "description": "NTP stratum is 16 — clock is not synchronised to any time source",
        "solution":    "Configure NTP servers in /etc/chrony.conf (e.g., pool pool.ntp.org iburst); restart chronyd.",
    },

    # ── TOOL — Tooling / IDS ──────────────────────────────────────────────────
    "TOOL-5102": {
        "category":    "Tooling",
        "description": "Fail2ban intrusion prevention is not installed",
        "solution":    "Install Fail2ban: apt install fail2ban; configure /etc/fail2ban/jail.local for SSH and web services.",
    },
    "TOOL-5190": {
        "category":    "Tooling",
        "description": "No IDS/IPS (Snort, Suricata, OSSEC/Wazuh) installed",
        "solution":    "Install Suricata (apt install suricata) or Wazuh for host-based and network intrusion detection.",
    },

    # ── USB — USB ─────────────────────────────────────────────────────────────
    "USB-1000": {
        "category":    "USB",
        "description": "USB storage kernel module is not disabled — external drives can be mounted",
        "solution":    "Blacklist USB storage: add 'blacklist usb-storage' to /etc/modprobe.d/blacklist.conf.",
    },
    "USB-3000": {
        "category":    "USB",
        "description": "USBGuard is not installed — no USB device whitelist enforced",
        "solution":    "Install USBGuard: apt install usbguard; run usbguard generate-policy > /etc/usbguard/rules.conf.",
    },
}

# ── State ──────────────────────────────────────────────────────────────────────

class LynisSubgraphState(TypedDict):
    # Optional input — override via env var LYNIS_REPORT_FILE or pass directly
    report_file: str

    # Stage outputs — populated as the pipeline progresses
    raw_report:    str              # Stage 1: raw Lynis report file content
    parsed_report: Dict[str, Any]  # Stage 2: structured warnings/suggestions/metadata
    payload:       Dict[str, Any]  # Stage 4: condensed LLM-ready payload

    # Set by any node on failure; causes the graph to route to END early
    error: Optional[str]

# ── Nodes ──────────────────────────────────────────────────────────────────────

def _scan_node(state: LynisSubgraphState) -> Dict[str, Any]:
    """Stage 1 — Run the Lynis host-security audit and capture the report file."""
    report_file = state.get("report_file") or "/tmp/lynis-report.dat"
    print(f"[lynis/scan]   launching audit (report → {report_file!r})...", file=sys.stderr)
    try:
        raw_report = run_lynis_audit(report_file=report_file)
        if not raw_report:
            return {"error": "Lynis audit produced an empty report — is lynis installed?"}
        lines = raw_report.count("\n")
        print(f"[lynis/scan]   captured {lines} report lines.", file=sys.stderr)
        return {"raw_report": raw_report}
    except Exception as exc:
        return {"error": str(exc)}


def _parse_node(state: LynisSubgraphState) -> Dict[str, Any]:
    """Stage 2 — Parse the key=value report file into structured dicts."""
    print("[lynis/parse]  parsing report file...", file=sys.stderr)
    try:
        parsed = parse_lynis_report(state["raw_report"])
        w = len(parsed.get("warnings", []))
        s = len(parsed.get("suggestions", []))
        print(f"[lynis/parse]  {w} warning(s), {s} suggestion(s) extracted.", file=sys.stderr)
        return {"parsed_report": parsed}
    except Exception as exc:
        return {"error": str(exc)}


def _enrich_node(state: LynisSubgraphState) -> Dict[str, Any]:
    """Stage 3 — Cross-reference each test_id against LYNIS_TEST_CATALOG.

    Lynis's machine-readable report file stores only test_id and severity;
    the human-readable description and remediation steps are in the catalog.
    This node fills in any empty description/solution fields and attaches
    a category tag to every finding.
    """
    print("[lynis/enrich] enriching findings from test catalog...", file=sys.stderr)
    try:
        parsed = state["parsed_report"]

        def _enrich_list(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
            enriched = []
            for f in findings:
                tid  = f.get("test_id", "")
                meta = LYNIS_TEST_CATALOG.get(tid, {})
                entry = dict(f)
                entry["category"] = meta.get("category", _infer_category(tid))
                # Only fill description/solution if the report left them blank or as "-"
                if not entry.get("description") or entry["description"] in ("-", ""):
                    entry["description"] = meta.get("description", "")
                if not entry.get("solution") or entry["solution"] in ("-", ""):
                    entry["solution"] = meta.get("solution", "")
                enriched.append(entry)
            return enriched

        enriched_parsed = dict(parsed)
        enriched_parsed["warnings"]    = _enrich_list(parsed.get("warnings", []))
        enriched_parsed["suggestions"] = _enrich_list(parsed.get("suggestions", []))

        catalog_hits = sum(
            1 for f in enriched_parsed["warnings"] + enriched_parsed["suggestions"]
            if f.get("test_id", "") in LYNIS_TEST_CATALOG
        )
        print(
            f"[lynis/enrich] {catalog_hits} test ID(s) matched in catalog "
            f"({len(LYNIS_TEST_CATALOG)} entries).",
            file=sys.stderr,
        )
        return {"parsed_report": enriched_parsed}
    except Exception as exc:
        return {"error": str(exc)}


def _infer_category(test_id: str) -> str:
    """Derive a human-readable category from the test_id prefix when not in catalog."""
    _PREFIX_MAP = {
        "AUTH": "Authentication", "BOOT": "Boot",    "CONT": "Containers",
        "CRYP": "Cryptography",  "DBS":  "Databases","DNS":  "DNS",
        "FILE": "File Permissions", "FINT": "File Integrity", "FIRE": "Firewall",
        "HOME": "Home Directories", "HRDN": "Hardening", "HTTP": "Web Servers",
        "INSE": "Insecure Services", "KRB":  "Kerberos", "KRNL": "Kernel",
        "LDAP": "LDAP",  "LOGG": "Logging", "MACF": "MAC Frameworks",
        "MAIL": "Mail",  "MALW": "Malware", "NAME": "Name Services",
        "NETW": "Networking", "PHP": "PHP", "PKGS": "Packages",
        "PRNT": "Printing", "PROC": "Processes", "RBAC": "RBAC",
        "SCHD": "Scheduling", "SHLL": "Shell", "SINT": "System Integrity",
        "SNMP": "SNMP",  "SQD":  "Squid Proxy", "SSH":  "SSH",
        "STRG": "Storage", "TIME": "Time/NTP", "TOOL": "Tooling",
        "USB":  "USB",   "VIRT": "Virtualization",
    }
    prefix = test_id.split("-")[0] if "-" in test_id else test_id[:4]
    return _PREFIX_MAP.get(prefix, "General")


def _build_node(state: LynisSubgraphState) -> Dict[str, Any]:
    """Stage 4 — Condense the enriched parsed report into a ranked LLM-ready payload."""
    print("[lynis/build]  condensing findings for LLM context...", file=sys.stderr)
    try:
        payload = build_llm_payload_from_lynis(state["parsed_report"])
        total   = payload.get("risk_summary", {}).get("total_actionable", 0)
        idx     = payload.get("hardening_index")
        print(
            f"[lynis/build]  enrichment complete — {total} actionable finding(s), "
            f"hardening index: {idx}/100.",
            file=sys.stderr,
        )
        return {"payload": payload}
    except Exception as exc:
        return {"error": str(exc)}

# ── Routing ────────────────────────────────────────────────────────────────────

def _route(state: LynisSubgraphState) -> str:
    """Continue to the next node unless a previous node set an error."""
    return "error" if state.get("error") else "ok"

# ── Graph factory ──────────────────────────────────────────────────────────────

def build_lynis_subgraph():
    """Build and compile the Lynis parser subgraph.

    Returns a compiled CompiledStateGraph that can be:
      • Invoked directly:  app.invoke({...})  / app.stream({...})
      • Embedded as a node in a parent graph via parent.add_node("lynis", build_lynis_subgraph())

    No inputs are required — Lynis always audits the local host.
    On completion the subgraph populates:
        raw_report, parsed_report, payload, error
    """
    graph = StateGraph(LynisSubgraphState)

    graph.add_node("scan",   _scan_node)
    graph.add_node("parse",  _parse_node)
    graph.add_node("enrich", _enrich_node)
    graph.add_node("build",  _build_node)

    graph.set_entry_point("scan")

    graph.add_conditional_edges("scan",   _route, {"ok": "parse",  "error": END})
    graph.add_conditional_edges("parse",  _route, {"ok": "enrich", "error": END})
    graph.add_conditional_edges("enrich", _route, {"ok": "build",  "error": END})
    graph.add_conditional_edges("build",  _route, {"ok": END,      "error": END})

    return graph.compile()

# ── Convenience wrapper ────────────────────────────────────────────────────────

def run_pipeline(report_file: str = "/tmp/lynis-report.dat") -> Dict[str, Any]:
    """Run the full scan → parse → enrich → build pipeline.

    Mirrors the original lynis_parser.py interface so this module can be swapped
    in wherever build_llm_payload_from_lynis output is expected.

    Raises RuntimeError if any stage fails.
    """
    app = build_lynis_subgraph()
    display_graph(app)
    final_state = app.invoke({
        "report_file":   report_file,
        "raw_report":    "",
        "parsed_report": {},
        "payload":       {},
        "error":         None,
    })
    if final_state.get("error"):
        raise RuntimeError(f"Lynis pipeline failed: {final_state['error']}")
    return final_state["payload"]

# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    report_file = os.environ.get("LYNIS_REPORT_FILE", "/tmp/lynis-report.dat")
    print("[lynis_subgraph] auditing local host...", file=sys.stderr)
    try:
        payload = run_pipeline(report_file=report_file)
        print(json.dumps(payload, indent=2))
    except RuntimeError as exc:
        print(f"[lynis_subgraph] {exc}", file=sys.stderr)
        sys.exit(1)
