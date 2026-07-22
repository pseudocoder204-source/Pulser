# SPDX-License-Identifier: GPL-2.0-only
"""Seed list for `ingest_vendor_advisories.py`.

These are the same URLs already cited by `core/remediation.py`'s `_CITE_*`
constants — reused here rather than invented, so this corpus starts from
sources the catalog already trusts instead of a speculative new list. Review
and edit this list freely; it's meant to grow (distro patch-notes feeds,
vendor security-advisory pages) as the CVE-driven finding classes
(`rce`/`downgrade`/`bypass`/`privesc`/`infoleak`/`crash`) need better-grounded
steps, per notes/RemediationRAGPlan.txt "Sources" (NVD/KEV/vendor advisories
are unchanged by the ComplianceAsCode/mSCP decision, but weren't chunked into
a queryable corpus before now).

Each entry:
    title               human-readable document title
    url                 fetched verbatim; must be publicly reachable, no auth
    publisher           org name for sources.publisher
    corpus              'vendor_advisory' | 'distro_patchnotes'
    platform            'linux' | 'windows' | 'darwin' | None (agnostic)
    finding_class_hint  pre-tag matching core/remediation.py's REMEDIATION_CATALOG
                         keys, taken from the citation's existing usage there
    license             best-effort; these are U.S. government works (public
                         domain) or vendor docs pages (fair-use excerpt only —
                         ingest short chunks, not whole pages, for the latter)
"""
from typing import List, TypedDict


class VendorAdvisorySource(TypedDict):
    title: str
    url: str
    publisher: str
    corpus: str
    platform: str | None
    finding_class_hint: str | None
    license: str


VENDOR_ADVISORY_SOURCES: List[VendorAdvisorySource] = [
    {
        "title": "SP 800-40r4: Guide to Enterprise Patch Management Planning",
        "url": "https://csrc.nist.gov/pubs/sp/800/40/r4/final",
        "publisher": "NIST",
        "corpus": "vendor_advisory",
        "platform": None,
        "finding_class_hint": "cve_other",
        "license": "public_domain",
    },
    {
        "title": "Reducing the Significant Risk of Known Exploited Vulnerabilities",
        "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog/reducing-significant-risk-known-exploited-vulnerabilities",
        "publisher": "CISA",
        "corpus": "vendor_advisory",
        "platform": None,
        "finding_class_hint": "cve_other",
        "license": "public_domain",
    },
    {
        "title": "Home Network Security",
        "url": "https://www.cisa.gov/news-events/news/home-network-security",
        "publisher": "CISA",
        "corpus": "vendor_advisory",
        "platform": None,
        "finding_class_hint": "rce",
        "license": "public_domain",
    },
    {
        "title": "Securing Wireless Networks",
        "url": "https://www.cisa.gov/news-events/news/securing-wireless-networks",
        "publisher": "CISA",
        "corpus": "vendor_advisory",
        "platform": None,
        "finding_class_hint": "downgrade",
        "license": "public_domain",
    },
    {
        "title": "SP 800-52r2: Guidelines for the Selection, Configuration, and Use of TLS",
        "url": "https://csrc.nist.gov/pubs/sp/800/52/r2/final",
        "publisher": "NIST",
        "corpus": "vendor_advisory",
        "platform": None,
        "finding_class_hint": "downgrade",
        "license": "public_domain",
    },
    # Added 2026-07-20 -- the NIST SP 800-52 page above only ingests as its
    # HTML landing page (abstract + metadata, ~3K chars across 4 chunks); the
    # actual guideline is a linked PDF this ingest doesn't fetch. OWASP's TLS
    # Cheat Sheet gives concrete, actionable "which versions/ciphers to
    # disable" content instead of an abstract -- same CC BY-SA 4.0 license
    # tier already used for CWE-527/WSTG below.
    {
        "title": "Transport Layer Security Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
        "publisher": "OWASP",
        "corpus": "vendor_advisory",
        "platform": None,
        "finding_class_hint": "downgrade",
        "license": "cc_by_sa_4_0",
    },
    {
        "title": "TA13-175A: Risks of Default Passwords on the Internet",
        "url": "https://www.cisa.gov/news-events/alerts/2013/06/24/risks-default-passwords-internet",
        "publisher": "CISA",
        "corpus": "vendor_advisory",
        "platform": None,
        "finding_class_hint": "bypass",
        "license": "public_domain",
    },
    {
        "title": "Redis Security",
        "url": "https://redis.io/docs/latest/operate/oss_and_stack/management/security/",
        "publisher": "Redis",
        "corpus": "vendor_advisory",
        "platform": None,
        "finding_class_hint": "open_datastore",
        "license": "vendor_docs_excerpt_only",
    },
    {
        "title": "CWE-527: Exposure of Version-Control Repository to an Unauthorized Control Sphere",
        "url": "https://cwe.mitre.org/data/definitions/527.html",
        "publisher": "MITRE",
        "corpus": "vendor_advisory",
        "platform": None,
        "finding_class_hint": "exposed_source",
        "license": "cc_by_sa_4_0",
    },
    {
        "title": "WSTG-CONF-05: Enumerate Infrastructure and Application Admin Interfaces",
        "url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces",
        "publisher": "OWASP",
        "corpus": "vendor_advisory",
        "platform": None,
        "finding_class_hint": "exposed_admin",
        "license": "cc_by_sa_4_0",
    },
    {
        "title": "Hardening WordPress",
        "url": "https://developer.wordpress.org/advanced-administration/security/hardening/",
        "publisher": "WordPress",
        "corpus": "vendor_advisory",
        "platform": None,
        "finding_class_hint": "outdated_cms",
        "license": "vendor_docs_excerpt_only",
    },
    {
        "title": "Recovering from Viruses, Worms, and Trojan Horses",
        "url": "https://www.cisa.gov/news-events/news/recovering-viruses-worms-and-trojan-horses",
        "publisher": "CISA",
        "corpus": "vendor_advisory",
        "platform": None,
        "finding_class_hint": "malware",
        "license": "public_domain",
    },
    # --- Windows audit-check grounding (2026-07-19) -------------------------------
    # See project_windows_remediation_source memory: DISA/MITRE Windows STIGs and
    # CIS Windows benchmarks were considered and rejected (enterprise/DoD-shaped,
    # non-redistributable or provenance-heavy license respectively); Microsoft's own
    # Learn/Support docs were chosen instead as the Windows-side counterpart to the
    # ComplianceAsCode corpus (see ingest_complianceascode.py, Linux-only upstream).
    #
    # These are the exact same 12 URLs already cited per-entry in
    # scanners/windows/windows_audit_parser.py's WINDOWS_AUDIT_CATALOG (verified live
    # again here 2026-07-19) -- reused rather than re-picked, so the runtime citation
    # list and this ingest corpus stay pointed at one set of sources. finding_class_hint
    # uses WINDOWS_AUDIT_CATALOG's test_id keys (not a REMEDIATION_CATALOG class --
    # host_audit findings resolve via that catalog, not REMEDIATION_CATALOG, see
    # core/remediation.py's _fix_facts_host_audit); a shared "FIREWALL-PROFILE" tag
    # covers FIREWALL-DOMAIN/PRIVATE/PUBLIC since Windows Firewall's docs don't split
    # by profile the way the three check IDs do.
    {
        "title": "Virus and threat protection in the Windows Security app",
        "url": "https://support.microsoft.com/en-us/windows/virus-and-threat-protection-in-the-windows-security-app-1362f4cd-d71a-b52a-0b66-c2820032b65e",
        "publisher": "Microsoft",
        "corpus": "vendor_advisory",
        "platform": "windows",
        "finding_class_hint": "DEFENDER-RTP",
        "license": "vendor_docs_excerpt_only",
    },
    # Added 2026-07-21 -- the Virus/threat-protection page above describes
    # the GUI toggle only; this is Microsoft's own Set-MpPreference cmdlet
    # reference, which grounds the actual DisableRealtimeMonitoring command.
    {
        "title": "Set-MpPreference (Defender)",
        "url": "https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=windowsserver2022-ps",
        "publisher": "Microsoft",
        "corpus": "vendor_advisory",
        "platform": "windows",
        "finding_class_hint": "DEFENDER-RTP",
        "license": "vendor_docs_excerpt_only",
    },
    {
        "title": "Set-NetFirewallProfile (NetSecurity)",
        "url": "https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile",
        "publisher": "Microsoft",
        "corpus": "vendor_advisory",
        "platform": "windows",
        "finding_class_hint": "FIREWALL-PROFILE",
        "license": "vendor_docs_excerpt_only",
    },
    {
        "title": "Windows Firewall overview",
        "url": "https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/",
        "publisher": "Microsoft",
        "corpus": "vendor_advisory",
        "platform": "windows",
        "finding_class_hint": "FIREWALL-PROFILE",
        "license": "vendor_docs_excerpt_only",
    },
    {
        "title": "Detect, enable, and disable SMBv1, SMBv2, and SMBv3 in Windows",
        "url": "https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3",
        "publisher": "Microsoft",
        "corpus": "vendor_advisory",
        "platform": "windows",
        "finding_class_hint": "SMB1-ENABLED",
        "license": "vendor_docs_excerpt_only",
    },
    {
        "title": "Enable Remote Desktop on your PC",
        "url": "https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/remotepc/remote-desktop-allow-access",
        "publisher": "Microsoft",
        "corpus": "vendor_advisory",
        "platform": "windows",
        "finding_class_hint": "RDP-ENABLED",
        "license": "vendor_docs_excerpt_only",
    },
    # Added 2026-07-21 -- "Enable Remote Desktop on your PC" above covers the
    # GUI toggle-on path but never states the underlying registry value for
    # the reverse (disable when not needed, per that same page's own "if you
    # only need to use your PC locally, there's no need to enable Remote
    # Desktop" line); this is Microsoft's own fDenyTSConnections setting
    # reference, the unattend-XML equivalent of the live registry value.
    {
        "title": "fDenyTSConnections setting",
        "url": "https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-terminalservices-localsessionmanager-fdenytsconnections",
        "publisher": "Microsoft",
        "corpus": "vendor_advisory",
        "platform": "windows",
        "finding_class_hint": "RDP-ENABLED",
        "license": "vendor_docs_excerpt_only",
    },
    {
        "title": "RemoteDesktopServices Policy CSP",
        "url": "https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-remotedesktopservices",
        "publisher": "Microsoft",
        "corpus": "vendor_advisory",
        "platform": "windows",
        "finding_class_hint": "RDP-NLA",
        "license": "vendor_docs_excerpt_only",
    },
    # Added 2026-07-21 -- the Policy CSP page above explains NLA's *why* but
    # never states the underlying registry key; this page is Microsoft's own
    # UserAuthentication setting reference (the RDP-Tcp\UserAuthentication
    # value the CSP maps onto under the hood) and is what actually grounds
    # the command, not just the rationale.
    {
        "title": "UserAuthentication setting",
        "url": "https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-terminalservices-rdp-winstationextensions-userauthentication",
        "publisher": "Microsoft",
        "corpus": "vendor_advisory",
        "platform": "windows",
        "finding_class_hint": "RDP-NLA",
        "license": "vendor_docs_excerpt_only",
    },
    {
        "title": "User Account Control settings and configuration",
        "url": "https://learn.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings",
        "publisher": "Microsoft",
        "corpus": "vendor_advisory",
        "platform": "windows",
        "finding_class_hint": "UAC-DISABLED",
        "license": "vendor_docs_excerpt_only",
    },
    {
        "title": "Device encryption in Windows",
        "url": "https://support.microsoft.com/en-us/windows/device-encryption-in-windows-cf7e2b6f-3e70-4882-9532-18633605b7df",
        "publisher": "Microsoft",
        "corpus": "vendor_advisory",
        "platform": "windows",
        "finding_class_hint": "BITLOCKER-OFF",
        "license": "vendor_docs_excerpt_only",
    },
    # Added 2026-07-20 -- the FAQ above is a short (~2.5K char) support
    # article; this Learn doc covers TPM requirements, the non-TPM fallback,
    # and actual deployment mechanics BitLocker's own remediation steps need.
    {
        "title": "BitLocker overview",
        "url": "https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/",
        "publisher": "Microsoft",
        "corpus": "vendor_advisory",
        "platform": "windows",
        "finding_class_hint": "BITLOCKER-OFF",
        "license": "vendor_docs_excerpt_only",
    },
    {
        "title": "Manage additional Windows Update settings",
        "url": "https://learn.microsoft.com/en-us/windows/deployment/update/waas-wu-settings",
        "publisher": "Microsoft",
        "corpus": "vendor_advisory",
        "platform": "windows",
        "finding_class_hint": "WU-AUTOUPDATE",
        "license": "vendor_docs_excerpt_only",
    },
    {
        "title": "Install Windows updates",
        "url": "https://support.microsoft.com/en-us/windows/deployment/updates-lifecycle/install-windows-updates",
        "publisher": "Microsoft",
        "corpus": "vendor_advisory",
        "platform": "windows",
        "finding_class_hint": "WU-STALE",
        "license": "vendor_docs_excerpt_only",
    },
    # Added 2026-07-20 -- the lifecycle page above is short (~2.8K chars);
    # this FAQ covers restart scheduling/deferral and staleness causes, the
    # actual "why hasn't this device updated" grounding WU-STALE needs.
    {
        "title": "Windows Update FAQ",
        "url": "https://support.microsoft.com/en-us/windows/windows-update-faq-8a903416-6f45-0718-f5c7-375e92dddeb2",
        "publisher": "Microsoft",
        "corpus": "vendor_advisory",
        "platform": "windows",
        "finding_class_hint": "WU-STALE",
        "license": "vendor_docs_excerpt_only",
    },
    {
        "title": "Local accounts",
        "url": "https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts",
        "publisher": "Microsoft",
        "corpus": "vendor_advisory",
        "platform": "windows",
        "finding_class_hint": "GUEST-ENABLED",
        "license": "vendor_docs_excerpt_only",
    },
    {
        "title": "about_Execution_Policies",
        "url": "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies",
        "publisher": "Microsoft",
        "corpus": "vendor_advisory",
        "platform": "windows",
        "finding_class_hint": "PS-EXECPOLICY",
        "license": "vendor_docs_excerpt_only",
    },
]
