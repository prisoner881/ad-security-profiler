"""
Plugin 7004: Disabled Trust Relationship Object Still Present

trustDirection=0 ("Disabled") means the trust relationship object
(TDO) is administratively deactivated but has not actually been
removed. A lingering, disabled TDO is stale-object hygiene debt in the
same spirit as this project's other dormant/stale findings (plugins
1007/2006 for accounts, 3007 for empty groups): it doesn't grant
active privilege by itself, but it's unmanaged configuration surface
that can be forgotten about, misread during an incident response
trust inventory, or accidentally re-enabled without anyone noticing
it was ever there.
"""

PLUGIN = {
    "plugin_id": 7004,
    "category": "Trusts",
    "name": "Disabled Trust Relationship Object Still Present",
    "version": "1.0",
    "revision_date": "2026-07-18",
    "remediation": (
        "If this trust relationship is genuinely no longer needed, "
        "remove the Trusted Domain Object entirely rather than leaving "
        "it in a disabled state (Active Directory Domains and Trusts -> "
        "right-click the domain -> Properties -> Trusts tab -> select "
        "the trust -> Remove, or `netdom trust <TrustingDomain> "
        "/domain:<TrustedDomain> /remove`). If it's disabled "
        "intentionally but expected to be re-enabled later, document "
        "why and by whom, since a disabled trust is easy to overlook "
        "during a security review that only checks for active trusts."
    ),
    "control_id": "TRUST-104",
    "framework_tags": [],
    "references": [],
    "description": (
        "trustDirection=0 means this Trusted Domain Object (TDO) is "
        "administratively disabled but still exists in the directory. "
        "This mirrors the same stale-object reasoning already applied "
        "elsewhere in this project (dormant user/computer accounts, "
        "empty security groups): a lingering disabled trust doesn't "
        "grant active privilege, but it's unmanaged configuration "
        "surface -- easy to forget about, easy to misread during an "
        "incident response trust inventory, and a candidate for being "
        "accidentally re-enabled without review."
    ),
    "base_severity": "low",
    "query": """
        SELECT
            'warn' AS status,
            t.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'Disabled trust relationship with "' || COALESCE(t.trust_partner, '(unknown)')
                || '" is still present' AS summary,
            jsonb_build_object(
                'trust_partner', t.trust_partner,
                'trust_type', t.trust_type,
                'trust_attributes', t.trust_attributes
            ) AS detail
        FROM ad_trust t
        WHERE t.valid_to IS NULL
          AND t.client_id = %(client_id)s
          AND t.trust_direction = 0
    """,
}
