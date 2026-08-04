"""
Plugin 1008: SID History Present on Enabled Account

sIDHistory is legitimately used during domain/forest migrations to
preserve access during a transition, but it's also a well-known
persistence and privilege-escalation mechanism (MITRE ATT&CK T1134.005,
SID-History Injection) -- an account with SID history matching a
privileged SID can inherit that privilege without any visible group
membership showing why.
"""

PLUGIN = {
    "plugin_id": 1008,
    "category": "User Accounts",
    "name": "User Account Has SID History",
    "version": "1.4",
    "revision_date": "2026-07-15",
    "remediation": (
    'Investigate and confirm whether this is legitimate residue from a '
    'completed domain/forest migration. If migration is fully complete and SID '
    'history is no longer needed for resource access, clear it (`Set-ADUser '
    '-Clear SIDHistory`, which requires elevated rights and may require a DC '
    'restart in some configurations). If found on an account with no known '
    'migration history, treat it as a probable compromise indicator and '
    'escalate to incident response immediately rather than clearing it -- '
    'clearing first may destroy evidence of how it was set.'
),
    "control_id": "PRIV-103",
    "framework_tags": ["MITRE-ATTCK-T1134.005"],
    "references": [
        {"title": "MITRE ATT&CK T1134.005: Access Token Manipulation -- SID-History Injection",
         "url": "https://attack.mitre.org/techniques/T1134/005/"},
        {"title": "Microsoft Defender for Identity: Unsecure SID-History attribute",
         "url": "https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-unsecure-sid-history-attribute"},
    ],
    "description": (
        "sIDHistory is legitimately populated during domain/forest "
        "migrations to preserve access during a transition, but is also "
        "a well-documented persistence and privilege-escalation "
        "technique (MITRE ATT&CK T1134.005, SID-History Injection) -- an "
        "account with a privileged SID in its history can inherit that "
        "privilege without it appearing as ordinary group membership. "
        "Any finding here, especially outside a known, recent, "
        "in-progress migration, warrants direct investigation rather "
        "than being assumed benign. NOT downgraded when the account is "
        "disabled: sIDHistory is a persistent configuration on the "
        "object itself, not something that requires the account to "
        "currently be usable -- it survives disablement untouched and "
        "reactivates immediately if the account is ever re-enabled by "
        "anyone, including whoever set up the persistence in the first place."
    ),
    "base_severity": "high",
    "query": """
        SELECT
            'fail' AS status,
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'User Account ' || COALESCE(u.user_principal_name, u.sam_account_name)
                || ' has SID history populated (' || array_length(u.sid_history, 1)
                || ' entrie(s))' AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'user_principal_name', u.user_principal_name,
                'is_enabled', u.is_enabled,
                'sid_history', u.sid_history
            ) AS detail
        FROM ad_user u
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          AND u.sid_history IS NOT NULL
          AND array_length(u.sid_history, 1) > 0
    """,
}
