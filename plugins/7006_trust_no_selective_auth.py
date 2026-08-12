"""
Plugin 7006: Outgoing Forest Trust Does Not Have Selective Authentication Enabled

Directly cited against DISA Active Directory Domain STIG V-243485
(CAT II): "If the 'Selective Authentication' option is not selected on
every outgoing forest trust, this is a finding." Confirmed against the
current STIG text (V3R7) directly.

TRUST_ATTRIBUTE_CROSS_ORGANIZATION (0x00000010) is the trustAttributes
bit corresponding to Selective Authentication -- confirmed against
[MS-ADTS] and cross-checked against four independent technical
sources before writing this query, not assumed from the bit's name
alone. Mirrors the exact bitwise-check pattern already used and
proven in plugins 7001 (SID filtering, bit 32) and 7002 (Treat as
External, bit 64) -- same trust_attributes column, same style of
check, just a different, newly-verified bit.

Scoped specifically to FOREST trusts in the outgoing direction,
matching the STIG's own scope exactly. Confirmed precisely, not
assumed: forest-trust scope comes from trust_attributes bit 8
(TRUST_ATTRIBUTE_FOREST_TRANSITIVE) -- trust_type only distinguishes
legacy (Downlevel) trusts from modern AD-native (Uplevel) ones and
says nothing about domain-vs-forest scope, so filtering on trust_type
alone would have silently matched ordinary domain trusts too.
"Outgoing" means trustDirection has the Outbound bit set (value 2 or
3, Outbound or Bidirectional) -- confirmed against [MS-ADTS]'s own
trustDirection definition directly, not assumed from convention.
"""

PLUGIN = {
    "plugin_id": 7006,
    "category": "Trusts",
    "name": "Outgoing Forest Trust Does Not Have Selective Authentication Enabled",
    "version": "1.0",
    "revision_date": "2026-08-12",
    "remediation": (
        "Enable Selective Authentication on the trust: open \"Active "
        "Directory Domains and Trusts\", right-click the domain, "
        "Properties, Trusts tab, select the outgoing forest trust, "
        "Properties, Authentication tab, select \"Selective "
        "Authentication\". This requires configuring the \"Allowed to "
        "Authenticate\" permission on resources in the trusting "
        "domain afterward for users who should still be able to "
        "authenticate across the trust -- plan and test before "
        "enabling in a production environment."
    ),
    "control_id": "STIG-V-243485",
    "framework_tags": ["DISA-STIG"],
    "references": [
        {"title": "DISA Active Directory Domain STIG V3R7: V-243485",
         "url": "https://cyber.trackr.live/stig/Active_Directory_Domain/3/7#V-243485"},
        {"title": "Microsoft [MS-ADTS]: trustAttributes",
         "url": "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c"},
    ],
    "description": (
        "DISA Active Directory Domain STIG V-243485 (CAT II): Selective "
        "Authentication must be enabled on every outgoing forest "
        "trust. Without it, the less restrictive default (Forest-Wide "
        "Authentication) applies -- any authenticated user from the "
        "trusted forest can attempt to access any resource in the "
        "trusting forest, rather than only resources they've been "
        "explicitly granted the \"Allowed to Authenticate\" permission "
        "on."
    ),
    "base_severity": "medium",
    "query": """
        SELECT
            'fail' AS status,
            t.object_guid,
            'CAT_II' AS stig_severity,
            'DISA Active Directory Domain STIG V-243485' AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Outgoing forest trust to "' || t.trust_partner
                || '" does not have Selective Authentication enabled' AS summary,
            jsonb_build_object(
                'trust_partner', t.trust_partner,
                'trust_type', t.trust_type,
                'trust_direction', t.trust_direction,
                'trust_attributes', t.trust_attributes
            ) AS detail
        FROM ad_trust t
        WHERE t.client_id = %(client_id)s
          AND t.valid_to IS NULL
          AND (COALESCE(t.trust_attributes, 0) & 8) != 0
          AND t.trust_direction IN (2, 3)
          AND (COALESCE(t.trust_attributes, 0) & 16) = 0
    """,
}
