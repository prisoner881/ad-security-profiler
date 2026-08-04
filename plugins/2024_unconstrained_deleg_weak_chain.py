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
"""

PLUGIN = {
    "plugin_id": 2024,
    "category": "Computer Accounts",
    "name": "Computer With Unconstrained Delegation Is Also Unsupported or Dormant",
    "version": "1.2",
    "revision_date": "2026-07-17",
    "remediation": (
        "Prioritize for remediation or decommissioning over an ordinary "
        "unconstrained-delegation finding -- this specific machine "
        "combines a severe delegation misconfiguration with an "
        "independent weakness that makes it an efficient target. If "
        "still needed, patch/upgrade or replace it AND migrate off "
        "unconstrained delegation (see plugin 2001's remediation). If "
        "dormant and unsupported, decommissioning is very likely the "
        "right answer rather than trying to fix both issues on an "
        "abandoned asset."
    ),
    "control_id": "CHAIN-202",
    "framework_tags": [],
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
            'fail' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'critical' AS fd_severity,
            'Computer Account ' || c.sam_account_name
                || ' has unconstrained Kerberos delegation enabled AND is independently weak: '
                || (SELECT string_agg(x, ', ') FROM (VALUES
                        (CASE WHEN c.operating_system ILIKE '%%windows 10%%' OR c.operating_system ILIKE '%%server 2012%%'
                              OR c.operating_system ILIKE '%%server 2008%%' OR c.operating_system ILIKE '%%server 2003%%'
                              OR c.operating_system ILIKE '%%windows 7%%' OR c.operating_system ILIKE '%%windows 8%%'
                              OR c.operating_system ILIKE '%%windows xp%%' OR c.operating_system ILIKE '%%windows vista%%'
                              THEN 'unsupported OS (' || c.operating_system || ')' END),
                        (CASE WHEN c.last_logon_timestamp IS NULL OR c.last_logon_timestamp < now() - interval '90 days'
                              THEN 'dormant' END)
                    ) AS v(x) WHERE x IS NOT NULL) AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'operating_system', c.operating_system,
                'last_logon_timestamp', c.last_logon_timestamp
            ) AS detail
        FROM ad_computer c
        WHERE c.valid_to IS NULL
          AND c.client_id = %(client_id)s
          AND c.unconstrained_delegation
          AND NOT c.is_domain_controller
          AND (
                c.operating_system ILIKE '%%windows 10%%' OR c.operating_system ILIKE '%%server 2012%%'
                OR c.operating_system ILIKE '%%server 2008%%' OR c.operating_system ILIKE '%%server 2003%%'
                OR c.operating_system ILIKE '%%windows 7%%' OR c.operating_system ILIKE '%%windows 8%%'
                OR c.operating_system ILIKE '%%windows xp%%' OR c.operating_system ILIKE '%%windows vista%%'
                OR c.last_logon_timestamp IS NULL OR c.last_logon_timestamp < now() - interval '90 days'
              )
    """,
}
