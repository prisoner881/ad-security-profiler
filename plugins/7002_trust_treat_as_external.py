"""
Plugin 7002: Trust Explicitly Relaxes SID Filtering (TREAT_AS_EXTERNAL)

TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL (trustAttributes bit 0x00000040,
confirmed against Microsoft's own [MS-ADTS] specification) deliberately
downgrades a cross-forest trust's SID filtering from the stricter
cross-forest ruleset to the more permissive external-trust ruleset.
Unlike plugin 7001 (which can have a legacy-artifact explanation), this
bit is never set by accident or as a side effect of domain age -- it is
an explicit, deliberate administrative relaxation of an otherwise-
stricter default, and is only ever evaluated on forest-transitive
trusts that already have SID filtering active in the first place.
"""

PLUGIN = {
    "plugin_id": 7002,
    "category": "Trusts",
    "name": "Trust Explicitly Relaxes SID Filtering (TREAT_AS_EXTERNAL)",
    "version": "1.0",
    "revision_date": "2026-07-18",
    "remediation": (
        "Confirm this relaxation was a deliberate, documented decision -- "
        "typically done to allow SID history from a specific, trusted "
        "migration source to cross an otherwise cross-forest-filtered "
        "boundary. If not intentional or no longer needed, remove the "
        "TREAT_AS_EXTERNAL setting to restore the stricter, default "
        "cross-forest SID filtering behavior: `netdom trust "
        "<TrustingDomain> /domain:<TrustedDomain> /EnableSIDHistory:no` "
        "(the TreatAsExternal setting is managed alongside SID history "
        "settings via netdom or the Active Directory Domains and Trusts "
        "console's trust properties)."
    ),
    "control_id": "TRUST-102",
    "framework_tags": [],
    "references": [
        {"title": "dirkjanm.io: Active Directory forest trusts -- How does SID filtering work?",
         "url": "https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/"},
    ],
    "description": (
        "TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL (trustAttributes bit "
        "0x00000040, confirmed against Microsoft's own [MS-ADTS] "
        "specification) deliberately downgrades a cross-forest trust's "
        "SID filtering to the more permissive external-trust ruleset. "
        "Unlike plugin 7001, this bit is never set as a side effect of "
        "domain age or a legacy artifact -- it only applies to forest-"
        "transitive trusts that already have SID filtering active, and "
        "represents an explicit administrative choice to relax it, "
        "typically to permit SID history from a specific known source "
        "to cross the boundary."
    ),
    "base_severity": "medium",
    "query": """
        SELECT
            'warn' AS status,
            t.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Trust with "' || COALESCE(t.trust_partner, '(unknown)')
                || '" has TREAT_AS_EXTERNAL set, relaxing its SID filtering' AS summary,
            jsonb_build_object(
                'trust_partner', t.trust_partner,
                'trust_direction', t.trust_direction,
                'trust_type', t.trust_type,
                'trust_attributes', t.trust_attributes
            ) AS detail
        FROM ad_trust t
        WHERE t.valid_to IS NULL
          AND t.client_id = %(client_id)s
          AND (COALESCE(t.trust_attributes, 0) & 64) != 0
    """,
}
