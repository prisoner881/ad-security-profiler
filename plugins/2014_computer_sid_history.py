"""
Plugin 2014: Computer Account Has SID History

Same technique as user-account plugin 1008, applied to computer objects.
Legitimate during domain/forest migrations, but also a well-documented
persistence and privilege-escalation mechanism.
"""

PLUGIN = {
    "plugin_id": 2014,
    "category": "Computer Accounts",
    "name": "Computer Account Has SID History",
    "version": "1.2",
    "revision_date": "2026-07-15",
    "remediation": (
        "Investigate and confirm whether this is legitimate residue from "
        "a completed domain/forest migration. If migration is fully "
        "complete and SID history is no longer needed, clear it "
        "(`Set-ADComputer -Clear SIDHistory`). If found on a computer "
        "object with no known migration history, treat it as a probable "
        "compromise indicator and escalate to incident response rather "
        "than clearing it first."
    ),
    "control_id": "PRIV-202",
    "framework_tags": ["MITRE-ATTCK-T1134.005"],
    "references": [
        {"title": "MITRE ATT&CK T1134.005: Access Token Manipulation -- SID-History Injection",
         "url": "https://attack.mitre.org/techniques/T1134/005/"},
        {"title": "Microsoft Defender for Identity: Unsecure SID-History attribute",
         "url": "https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-unsecure-sid-history-attribute"},
    ],
    "description": (
        "sIDHistory is legitimately populated during domain/forest "
        "migrations, but is also a well-documented persistence and "
        "privilege-escalation technique (MITRE ATT&CK T1134.005) -- the "
        "same reasoning as user-account plugin 1008, applied here to "
        "computer objects. NOT downgraded when the computer account is "
        "disabled: sIDHistory is a persistent configuration on the "
        "object itself and survives disablement untouched, reactivating "
        "immediately if the account is ever re-enabled."
    ),
    "base_severity": "high",
    "query": """
        SELECT
            'fail' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN c.is_domain_controller THEN 'critical' ELSE 'high' END AS fd_severity,
            (CASE WHEN c.is_domain_controller THEN 'Domain Controller ' ELSE '' END)
                || 'Computer Account ' || c.sam_account_name
                || ' has SID history populated (' || array_length(c.sid_history, 1)
                || ' entrie(s))' AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'dns_hostname', c.dns_hostname,
                'sid_history', c.sid_history,
                'is_enabled', c.is_enabled,
                'is_domain_controller', c.is_domain_controller
            ) AS detail
        FROM ad_computer c
        WHERE c.valid_to IS NULL
          AND c.client_id = %(client_id)s
          AND c.sid_history IS NOT NULL
          AND array_length(c.sid_history, 1) > 0
    """,
}
