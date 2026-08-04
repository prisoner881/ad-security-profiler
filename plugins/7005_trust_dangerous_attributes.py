"""
Plugin 7005: Trust Has a Dangerous Attribute Set (TGT Delegation or PIM Trust)

Checks two specific trustAttributes bits (both confirmed against
Microsoft's own [MS-ADTS] specification, the same source already
verified for plugins 7001/7002):

- TRUST_ATTRIBUTE_CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION (0x00000800):
  forces Kerberos tickets granted under this trust to be trusted for
  delegation, when the trust's default posture would otherwise block
  it. Delegation across an organizational trust boundary widens what
  a compromise on the trusted side can reach on this side.
- TRUST_ATTRIBUTE_PIM_TRUST (0x00000400): marks a cross-forest trust
  as a Privileged Identity Management (bastion forest) trust for SID-
  filtering purposes. This is a legitimate, deliberate configuration
  in an ESAE/bastion-forest architecture, but it relaxes SID filtering
  in a specific way -- it is only meaningful, and only evaluated, in
  combination with TREAT_AS_EXTERNAL (plugin 7002), so it belongs in
  this project's set of things worth confirming were set on purpose.
"""

PLUGIN = {
    "plugin_id": 7005,
    "category": "Trusts",
    "name": "Trust Has a Dangerous Attribute Set (TGT Delegation or PIM Trust)",
    "version": "1.0",
    "revision_date": "2026-07-18",
    "remediation": (
        "For TGT delegation: confirm this trust genuinely needs "
        "Kerberos delegation to cross the organizational boundary --  "
        "most cross-organization trusts should NOT permit this. Remove "
        "the setting if it isn't a deliberate, documented requirement. "
        "For PIM trust: confirm this is a genuine, intentional bastion-"
        "forest (ESAE/PAM) configuration and not an unexpected setting "
        "-- if your organization does not run a dedicated privileged-"
        "access forest, this attribute should not be present at all."
    ),
    "control_id": "TRUST-105",
    "framework_tags": [],
    "references": [
        {"title": "Microsoft: [MS-ADTS] trustAttributes",
         "url": "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c"},
    ],
    "description": (
        "Checks two trustAttributes bits confirmed against Microsoft's "
        "own [MS-ADTS] specification: TRUST_ATTRIBUTE_CROSS_"
        "ORGANIZATION_ENABLE_TGT_DELEGATION (0x00000800), which forces "
        "Kerberos tickets to be trusted for delegation across an "
        "organizational trust boundary that would otherwise block it; "
        "and TRUST_ATTRIBUTE_PIM_TRUST (0x00000400), which marks a "
        "cross-forest trust as a Privileged Identity Management "
        "(bastion forest) trust -- a legitimate configuration in an "
        "ESAE/bastion architecture, but one worth confirming was set "
        "on purpose rather than left over from a decommissioned or "
        "misconfigured setup."
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
            'Trust with "' || COALESCE(t.trust_partner, '(unknown)') || '" has '
                || (SELECT string_agg(x, ' and ') FROM (VALUES
                        (CASE WHEN (COALESCE(t.trust_attributes, 0) & 2048) != 0 THEN 'TGT delegation enabled' END),
                        (CASE WHEN (COALESCE(t.trust_attributes, 0) & 1024) != 0 THEN 'PIM trust set' END)
                    ) AS v(x) WHERE x IS NOT NULL) AS summary,
            jsonb_build_object(
                'trust_partner', t.trust_partner,
                'trust_direction', t.trust_direction,
                'trust_type', t.trust_type,
                'trust_attributes', t.trust_attributes,
                'tgt_delegation_enabled', (COALESCE(t.trust_attributes, 0) & 2048) != 0,
                'pim_trust', (COALESCE(t.trust_attributes, 0) & 1024) != 0
            ) AS detail
        FROM ad_trust t
        WHERE t.valid_to IS NULL
          AND t.client_id = %(client_id)s
          AND (
                (COALESCE(t.trust_attributes, 0) & 2048) != 0
                OR (COALESCE(t.trust_attributes, 0) & 1024) != 0
              )
    """,
}
