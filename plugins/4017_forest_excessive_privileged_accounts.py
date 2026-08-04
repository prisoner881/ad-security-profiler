"""
Plugin 4017: Forest Contains an Excessive Number of Privileged Accounts

A simple count of every user and group carrying the AdminSDHolder
protection marker (admin_count=1) -- the same population every other
admin_count-based plugin in this project already reasons about
individually. Considered in aggregate rather than one object at a
time: the more privileged accounts and groups exist domain-wide, the
larger the attack surface for privilege escalation, since each one is
an independent path an attacker could compromise to reach Tier-0
access. Confirmed against Purple Knight's own equivalent check and
threshold (50).
"""

PLUGIN = {
    "plugin_id": 4017,
    "category": "Domain",
    "name": "Forest Contains an Excessive Number of Privileged Accounts",
    "version": "1.0",
    "revision_date": "2026-07-18",
    "remediation": (
        "Review the full list of privileged users and groups (every "
        "object with admin_count=1) and identify which ones genuinely "
        "need standing privileged access versus which could move to a "
        "just-in-time or time-limited privileged access model instead. "
        "A large, flat population of always-on privileged accounts is "
        "harder to monitor effectively than a smaller, well-understood "
        "set -- reducing the count is itself a meaningful hardening "
        "step, independent of any individual account's own "
        "configuration."
    ),
    "control_id": "PRIV-401",
    "framework_tags": [],
    "references": [],
    "description": (
        "Counts every user and group carrying the AdminSDHolder "
        "protection marker (admin_count=1) domain-wide. Considered in "
        "aggregate: the more privileged accounts and groups exist, the "
        "larger the attack surface for privilege escalation, since "
        "each one is an independent path to Tier-0 access. Confirmed "
        "against Purple Knight's own equivalent check and threshold "
        "(50)."
    ),
    "base_severity": "medium",
    "query": """
        SELECT
            'warn' AS status,
            d.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Forest has ' || (
                (SELECT count(*) FROM ad_user u WHERE u.valid_to IS NULL AND u.client_id = %(client_id)s AND u.admin_count = 1)
                +
                (SELECT count(*) FROM ad_group g WHERE g.valid_to IS NULL AND g.client_id = %(client_id)s AND g.admin_count = 1)
            ) || ' privileged (admin_count=1) user(s) and group(s), exceeding the 50-account threshold' AS summary,
            jsonb_build_object(
                'privileged_account_and_group_count',
                (SELECT count(*) FROM ad_user u WHERE u.valid_to IS NULL AND u.client_id = %(client_id)s AND u.admin_count = 1)
                +
                (SELECT count(*) FROM ad_group g WHERE g.valid_to IS NULL AND g.client_id = %(client_id)s AND g.admin_count = 1)
            ) AS detail
        FROM ad_domain d
        WHERE d.valid_to IS NULL
          AND d.client_id = %(client_id)s
          AND (
                (SELECT count(*) FROM ad_user u WHERE u.valid_to IS NULL AND u.client_id = %(client_id)s AND u.admin_count = 1)
                +
                (SELECT count(*) FROM ad_group g WHERE g.valid_to IS NULL AND g.client_id = %(client_id)s AND g.admin_count = 1)
              ) > 50
    """,
}
