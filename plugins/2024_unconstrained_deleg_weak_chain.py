"""
Plugin 2024: Computer With Unconstrained Delegation Is Also Unsupported or Dormant

The classic real-world unconstrained-delegation attack scenario: an old,
neglected legacy server (unpatched, likely running end-of-support
software) that nobody has gotten around to reconfiguring or
decommissioning, still holding unconstrained delegation from an older,
less security-conscious era of the domain's history. These machines are
disproportionately likely to have other exploitable weaknesses on top of
the delegation setting itself, making them an efficient target: easy to
compromise, and highly valuable once compromised.

[v1.3] Disabled accounts are no longer rated like enabled ones: a
disabled computer cannot obtain or receive Kerberos tickets, so its
unconstrained delegation is not exploitable until someone re-enables it.
Such rows are now 'warn'/medium with "(account disabled)" appended to the
summary (enabled accounts stay 'fail'/critical, summary unchanged), and
detail carries is_enabled. The unsupported-OS list no longer matches
Windows 10 Enterprise LTSC (2019/2021 and IoT LTSC are still in support)
and now includes Windows 2000 and Windows NT. Summary is NULL-safe.
"""

PLUGIN = {
    "plugin_id": 2024,
    "category": "Computer Accounts",
    "name": "Computer With Unconstrained Delegation Is Also Unsupported or Dormant",
    "version": "1.3",
    "revision_date": "2026-10-04",
    "remediation": (
        "Prioritize for remediation or decommissioning over an ordinary "
        "unconstrained-delegation finding -- this specific machine "
        "combines a severe delegation misconfiguration with an "
        "independent weakness that makes it an efficient target. If "
        "still needed, patch/upgrade or replace it AND migrate off "
        "unconstrained delegation (see plugin 2001's remediation). If "
        "dormant and unsupported, decommissioning is very likely the "
        "right answer rather than trying to fix both issues on an "
        "abandoned asset. A disabled account (reported at medium) is "
        "not exploitable while disabled, but clear its delegation flag "
        "or delete it rather than leave it to be re-enabled."
    ),
    "control_id": "CHAIN-202",
    "framework_tags": [
        "NIST-800-53-AC-3",
        "NIST-800-53-AC-6",
        "NIST-800-53-AC-6(1)",
        "NIST-800-53-SI-2",
        "NIST-800-53-RA-5",
        "NIST-800-53-SA-22",
        "NIST-800-53-AC-2",
        "NIST-800-53-AC-2(3)",
        "NIST-CSF-2.0-PR.AA-05",
        "NIST-CSF-2.0-ID.RA-01",
        "NIST-CSF-2.0-PR.PS-02",
        "NIST-CSF-2.0-PR.AA-01",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.2",
        "PCI-DSS-4.0-6.3.3",
        "PCI-DSS-4.0-12.3.4",
        "PCI-DSS-4.0-8.2.6",
        "CIS-CSC-8-3.3",
        "CIS-CSC-8-6.8",
        "CIS-CSC-8-2.2",
        "CIS-CSC-8-7.3",
        "CIS-CSC-8-5.3",
        "ISO-27001-2022-A.5.15",
        "ISO-27001-2022-A.8.3",
        "ISO-27001-2022-A.8.8",
        "ISO-27001-2022-A.5.18",
        "SOC2-CC6.3",
        "SOC2-CC7.1",
        "SOC2-CC6.2",
        "HIPAA-164.312(a)(1)",
        "HIPAA-164.308(a)(3)(ii)(C)",
        "DISA-STIG",
        "MITRE-ATTCK-T1550.003",
    ],
    "references": [
        {"title": "MITRE ATT&CK T1558: Steal or Forge Kerberos Tickets",
         "url": "https://attack.mitre.org/techniques/T1558/"},
    ],
    "description": (
        "Chains plugin 2001 (unconstrained delegation) with an "
        "independent weakness: this computer is also running an "
        "unsupported/end-of-support operating system (plugin 2003) or "
        "has not logged on in 90+ days (plugin 2006). The classic "
        "real-world scenario this catches: an old, neglected legacy "
        "server nobody has reconfigured since a less security-conscious "
        "era of the domain's history, disproportionately likely to have "
        "other exploitable weaknesses on top of the delegation setting "
        "itself."
    ),
    "base_severity": "critical",
    "query": """
        SELECT
            CASE WHEN c.is_enabled IS FALSE THEN 'warn' ELSE 'fail' END AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN c.is_enabled IS FALSE THEN 'medium' ELSE 'critical' END AS fd_severity,
            'Computer Account ' || COALESCE(c.sam_account_name, c.object_guid::text)
                || ' has unconstrained Kerberos delegation enabled AND is independently weak: '
                || (SELECT string_agg(x, ', ') FROM (VALUES
                        (CASE WHEN (c.operating_system ILIKE '%%windows 10%%' AND c.operating_system NOT ILIKE '%%LTSC%%') OR c.operating_system ILIKE '%%server 2012%%'
                              OR c.operating_system ILIKE '%%server 2008%%' OR c.operating_system ILIKE '%%server 2003%%'
                              OR c.operating_system ILIKE '%%windows 7%%' OR c.operating_system ILIKE '%%windows 8%%'
                              OR c.operating_system ILIKE '%%windows xp%%' OR c.operating_system ILIKE '%%windows vista%%'
                              OR c.operating_system ILIKE '%%windows 2000%%' OR c.operating_system ILIKE '%%windows nt%%'
                              THEN 'unsupported OS (' || c.operating_system || ')' END),
                        (CASE WHEN c.last_logon_timestamp IS NULL OR c.last_logon_timestamp < now() - interval '90 days'
                              THEN 'dormant' END)
                    ) AS v(x) WHERE x IS NOT NULL)
                || (CASE WHEN c.is_enabled IS FALSE THEN ' (account disabled)' ELSE '' END) AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'operating_system', c.operating_system,
                'last_logon_timestamp', c.last_logon_timestamp,
                'is_enabled', c.is_enabled
            ) AS detail
        FROM ad_computer c
        WHERE c.valid_to IS NULL
          AND c.client_id = %(client_id)s
          AND c.unconstrained_delegation
          AND NOT c.is_domain_controller
          AND (
                (c.operating_system ILIKE '%%windows 10%%' AND c.operating_system NOT ILIKE '%%LTSC%%') OR c.operating_system ILIKE '%%server 2012%%'
                OR c.operating_system ILIKE '%%server 2008%%' OR c.operating_system ILIKE '%%server 2003%%'
                OR c.operating_system ILIKE '%%windows 7%%' OR c.operating_system ILIKE '%%windows 8%%'
                OR c.operating_system ILIKE '%%windows xp%%' OR c.operating_system ILIKE '%%windows vista%%'
                OR c.operating_system ILIKE '%%windows 2000%%' OR c.operating_system ILIKE '%%windows nt%%'
                OR c.last_logon_timestamp IS NULL OR c.last_logon_timestamp < now() - interval '90 days'
              )
    """,
}
