"""
Plugin 9003: Organizational Unit Blocks Group Policy Inheritance

gPOptions bit 0x1 (confirmed against multiple independent sources
including a Microsoft Scripting Blog example testing this exact bit).
An OU with Block Inheritance enabled does not receive GPOs linked at
the domain or any parent OU level, UNLESS those specific links are
individually marked enforced (gpo_link_edge.link_enforced overrides
block-inheritance regardless -- confirmed against Microsoft's own
Group Policy processing documentation).

Not inherently a vulnerability -- legitimate uses exist (isolating a
lab/test OU from production policy, for instance) -- but it is a
mechanism that can silently defeat security-relevant GPOs (password
policy hardening, audit settings, security baselines) applied higher
in the hierarchy without anyone reviewing this specific OU realizing
it. Worth an explicit inventory of where this is set, the same "worth
knowing about, not automatically wrong" framing already used for
plugin 7004 (disabled trust relationships still present).
"""

PLUGIN = {
    "plugin_id": 9003,
    "category": "Organizational Units",
    "name": "Organizational Unit Blocks Group Policy Inheritance",
    "version": "1.0",
    "revision_date": "2026-07-18",
    "remediation": (
        "Confirm this was a deliberate choice and that no security-"
        "relevant GPO (password policy, audit settings, security "
        "baselines) applied at the domain or a parent OU level is being "
        "unintentionally excluded from this OU as a result. If "
        "specific higher-level GPOs genuinely need to apply here "
        "regardless of the block, mark those specific links as "
        "enforced instead of removing the block outright (Group Policy "
        "Management Console -> right-click the GPO link at its source "
        "-> Enforced) -- enforced links override block-inheritance, so "
        "this can coexist with the isolation Block Inheritance is "
        "otherwise providing for everything else."
    ),
    "control_id": "GPO-901",
    "framework_tags": [],
    "references": [
        {"title": "Microsoft: Group Policy processing for Windows",
         "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-policy/group-policy-processing"},
    ],
    "description": (
        "gPOptions bit 0x1. An OU with Block Inheritance enabled does "
        "not receive GPOs linked at the domain or any parent OU level, "
        "unless those specific links are individually marked enforced "
        "(which overrides block-inheritance regardless). Not inherently "
        "a vulnerability -- legitimate uses exist -- but it can "
        "silently defeat security-relevant GPOs applied higher in the "
        "hierarchy without anyone reviewing this specific OU realizing "
        "it. Worth an explicit inventory of where it's set, the same "
        "framing already used for plugin 7004 (disabled trusts still "
        "present)."
    ),
    "base_severity": "low",
    "query": """
        SELECT
            'warn' AS status,
            o.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'OU "' || o.ou_name || '" has Group Policy inheritance blocked' AS summary,
            jsonb_build_object(
                'ou_name', o.ou_name,
                'linked_gpos_on_this_ou', (
                    SELECT array_agg(COALESCE(g.display_name, 'unnamed') ORDER BY COALESCE(g.display_name, 'unnamed'))
                    FROM gpo_link_edge gle
                    JOIN ad_gpo g ON g.object_guid = gle.gpo_guid AND g.client_id = gle.client_id AND g.valid_to IS NULL
                    WHERE gle.container_guid = o.object_guid AND gle.client_id = %(client_id)s
                      AND gle.valid_to IS NULL AND gle.link_enabled
                )
            ) AS detail
        FROM ad_ou o
        WHERE o.valid_to IS NULL
          AND o.client_id = %(client_id)s
          AND o.block_inheritance
    """,
}
