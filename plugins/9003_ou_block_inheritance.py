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

[v1.1] The detail now also lists blocked_inherited_gpos: the enabled,
non-enforced GPO links on the domain object and on every ancestor OU
(containers whose DN is a suffix of this OU's DN), i.e. the GPOs this OU
no longer receives because of the block -- which makes the finding
actionable. Summary unchanged (ou_name COALESCEd to the DN for safety).
Site-linked GPOs are not collected and so not listed.

[v1.2] Checked against site links, which gpo_link_edge holds since
collector 0.5.16: blocked_inherited_gpos is unaffected (a site's DN is
in the Configuration partition, so it is never an ancestor of an OU).
Because Block Inheritance also stops non-enforced site-linked GPOs, they
are now listed separately in detail.blocked_site_gpos (GPO and site
name); they only ever applied to computers in that site. Summary and
severity unchanged.
"""

PLUGIN = {
    "plugin_id": 9003,
    "category": "Organizational Units",
    "name": "Organizational Unit Blocks Group Policy Inheritance",
    "version": "1.2",
    "revision_date": "2026-10-04",
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
        "it. The finding lists the inherited, non-enforced GPO links "
        "(domain and parent OUs) that the block stops from applying, and "
        "separately the non-enforced site-linked GPOs it also stops "
        "(site links collected since collector 0.5.16). "
        "Worth an explicit inventory of where it's set, the same "
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
            'OU "' || COALESCE(o.ou_name, od.dn_current, o.object_guid::text)
                || '" has Group Policy inheritance blocked' AS summary,
            jsonb_build_object(
                'ou_name', o.ou_name,
                'linked_gpos_on_this_ou', (
                    SELECT array_agg(COALESCE(g.display_name, 'unnamed') ORDER BY COALESCE(g.display_name, 'unnamed'))
                    FROM gpo_link_edge gle
                    JOIN ad_gpo g ON g.object_guid = gle.gpo_guid AND g.client_id = gle.client_id AND g.valid_to IS NULL
                    WHERE gle.container_guid = o.object_guid AND gle.client_id = %(client_id)s
                      AND gle.valid_to IS NULL AND gle.link_enabled
                ),
                -- [v1.1] enabled, non-enforced links on ancestors (domain or
                -- parent OUs) that the block stops from applying here
                'blocked_inherited_gpos', (
                    SELECT jsonb_agg(DISTINCT jsonb_build_object(
                               'gpo', COALESCE(g.display_name, 'unnamed'),
                               'linked_at', cdo.dn_current))
                    FROM gpo_link_edge gle
                    JOIN directory_object cdo
                      ON cdo.object_guid = gle.container_guid AND cdo.client_id = gle.client_id
                     AND NOT cdo.is_deleted
                    JOIN ad_gpo g ON g.object_guid = gle.gpo_guid AND g.client_id = gle.client_id AND g.valid_to IS NULL
                    WHERE gle.client_id = %(client_id)s
                      AND gle.valid_to IS NULL
                      AND gle.link_enabled
                      AND NOT gle.link_enforced
                      AND gle.container_guid <> o.object_guid
                      AND right(lower(od.dn_current), length(cdo.dn_current) + 1)
                          = ',' || lower(cdo.dn_current)
                ),
                -- [v1.2] Block Inheritance also stops non-enforced GPOs linked
                -- to AD sites (collected since 0.5.16). Site DNs live in the
                -- Configuration partition and never match the ancestor test
                -- above, so they are listed separately; they apply only to
                -- computers (and logons) in that site.
                'blocked_site_gpos', (
                    SELECT jsonb_agg(DISTINCT jsonb_build_object(
                               'gpo', COALESCE(g.display_name, 'unnamed'),
                               'site', COALESCE(st.site_name, sdo.dn_current)))
                    FROM gpo_link_edge gle
                    JOIN ad_site st
                      ON st.object_guid = gle.container_guid AND st.client_id = gle.client_id
                     AND st.valid_to IS NULL
                    JOIN directory_object sdo
                      ON sdo.object_guid = st.object_guid AND sdo.client_id = st.client_id
                    JOIN ad_gpo g ON g.object_guid = gle.gpo_guid AND g.client_id = gle.client_id AND g.valid_to IS NULL
                    WHERE gle.client_id = %(client_id)s
                      AND gle.valid_to IS NULL
                      AND gle.link_enabled
                      AND NOT gle.link_enforced
                )
            ) AS detail
        FROM ad_ou o
        LEFT JOIN directory_object od ON od.object_guid = o.object_guid AND od.client_id = o.client_id
        WHERE o.valid_to IS NULL
          AND o.client_id = %(client_id)s
          AND o.block_inheritance
    """,
}
