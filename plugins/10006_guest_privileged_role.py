"""
Plugin 10006: Guest Account Holds a Privileged Directory Role

A guest account (Graph's own userType: Guest -- an external identity,
typically from another organization's tenant via B2B collaboration,
not an account this tenant's own administrators provisioned or fully
control) holding any activated directory role is worth surfacing
regardless of which specific role. Guest accounts exist for
collaboration scenarios -- sharing a document, joining a Teams channel
-- not for tenant administration, and their credentials, MFA
enforcement, and lifecycle are governed by whatever security posture
their HOME organization maintains, not this one. This tenant has no
direct control over that.

Cross-referenced entirely from data this project already collects --
entra_directory_role_member (built for plugins 10002/10003) joined
against entra_user.user_type (added specifically to enable this
check) -- no new Graph collection needed beyond the one new field.

[v1.1] Stable identity: object_guid is now md5(member_id || role template
id)::uuid (one finding per guest per role) instead of NULL, so renaming or
disabling the guest no longer closes the finding and opens a new one.
Severity is now tiered by role: high for privileged/administrative roles
(Global, Privileged Role, Privileged Authentication, Hybrid Identity,
Application, Cloud Application, Authentication, Security, User, Exchange,
SharePoint, Intune, Conditional Access, Helpdesk, Password, Groups,
Authentication Policy, Cloud Device, Domain Name, External Identity
Provider Administrator, Directory Writers, Directory Synchronization
Accounts, Partner Tier1/Tier2 Support); low for read-only roles commonly
and deliberately given to guests (Directory Readers, Reports Reader,
Message Center Reader / Privacy Reader, Usage Summary Reports Reader,
Guest Inviter); medium for every other role; low when the guest is
disabled. External users created with userType 'Member' are now caught by
their #EXT# UPN. Not visible (collector limitation): PIM-eligible
assignments and roles held through a role-assignable group.

[v1.2] Requires entra_graph_collector.py 0.6.0 / schema v37. Also counts
roles a guest is PIM-eligible for and roles held through a role-assignable
group. Still one finding per guest per role (identity unchanged); every
path ("active", "PIM-eligible", "via group <name>", plus a non-tenant-wide
scope) is listed sorted in detail.assignment_paths and summarized. Severity
starts from the role tier and is taken from the strongest path: an
eligible-only assignment is one step lower (except Global Administrator and
Privileged Role Administrator, which stay at the tier), an
administrative-unit-only scope one step lower, floor low; disabled guests
stay low. status is 'fail' at medium/high, 'warn' at low. If eligibility or
group membership couldn't be read (e.g. no Entra ID P2),
detail.coverage_notes says so.
"""

PLUGIN = {
    "plugin_id": 10006,
    "category": "Hybrid Identity",
    "name": "Guest Account Holds a Privileged Directory Role",
    "version": "1.2",
    "revision_date": "2026-10-04",
    "remediation": (
        "Confirm this is intentional and necessary -- a genuine "
        "external-partner administration scenario is possible but "
        "uncommon. If it's not necessary, remove the role assignment: "
        "Entra admin center -> Roles and administrators -> select the "
        "role -> remove the guest account. If ongoing external "
        "collaboration access is genuinely needed, consider whether a "
        "narrower, purpose-built role would serve instead of whatever "
        "broad role is currently assigned, and confirm the guest's home "
        "organization enforces MFA on their end, since this tenant has "
        "no direct control over that account's authentication security."
    ),
    "control_id": "HYBRID-006",
    "framework_tags": [],
    "references": [
        {"title": "Microsoft: Microsoft Entra built-in roles (privileged roles)",
         "url": "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference"},
    ],
    "description": (
        "A guest account (an external identity via B2B collaboration -- "
        "userType Guest, or an #EXT# UPN -- not provisioned or fully "
        "controlled by this tenant) holds a directory role -- actively, "
        "as PIM-eligible, or through a role-assignable group (all paths "
        "listed per guest and role). "
        "High for privileged/administrative roles, low for read-only "
        "roles commonly given to guests (Directory Readers, Reports "
        "Reader, ...), medium otherwise, low when the guest is "
        "disabled; an eligible-only (except Global/Privileged Role "
        "Administrator) or administrative-unit-only assignment is one "
        "step lower. Guest accounts exist for "
        "collaboration, not tenant administration -- their credential "
        "security and lifecycle are governed by their home "
        "organization, outside this tenant's control. Worth surfacing "
        "regardless of which specific role is held. Built entirely from "
        "data already collected for plugins 10002/10003 "
        "(entra_directory_role_member) plus entra_user.user_type; gaps "
        "in eligibility/group visibility are noted in the detail."
    ),
    "base_severity": "high",
    "query": """
        WITH role_tier(role_template_id, tier) AS (
            VALUES
            -- privileged / administrative roles -> high
            ('62e90394-69f5-4237-9190-012177145e10'::uuid, 'high'),  -- Global Administrator
            ('e8611ab8-c189-46e8-94e1-60213ab1f814'::uuid, 'high'),  -- Privileged Role Administrator
            ('7be44c8a-adaf-4e2a-84d6-ab2649e08a13'::uuid, 'high'),  -- Privileged Authentication Administrator
            ('8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2'::uuid, 'high'),  -- Hybrid Identity Administrator
            ('9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'::uuid, 'high'),  -- Application Administrator
            ('158c047a-c907-4556-b7ef-446551a6b5f7'::uuid, 'high'),  -- Cloud Application Administrator
            ('c4e39bd9-1100-46d3-8c65-fb160da0071f'::uuid, 'high'),  -- Authentication Administrator
            ('0526716b-113d-4c15-b2c8-68e3c22b9f80'::uuid, 'high'),  -- Authentication Policy Administrator
            ('194ae4cb-b126-40b2-bd5b-6091b380977d'::uuid, 'high'),  -- Security Administrator
            ('fe930be7-5e62-47db-91af-98c3a49a38b1'::uuid, 'high'),  -- User Administrator
            ('29232cdf-9323-42fd-ade2-1d097af3e4de'::uuid, 'high'),  -- Exchange Administrator
            ('f28a1f50-f6e7-4571-818b-6a12f2af6b6c'::uuid, 'high'),  -- SharePoint Administrator
            ('3a2c62db-5318-420d-8d74-23affee5d9d5'::uuid, 'high'),  -- Intune Administrator
            ('b1be1c3e-b65d-4f19-8427-f6fa0d97feb9'::uuid, 'high'),  -- Conditional Access Administrator
            ('729827e3-9c14-49f7-bb1b-9608f156bbb8'::uuid, 'high'),  -- Helpdesk Administrator
            ('966707d0-3269-4727-9be2-8c3a10f19b9d'::uuid, 'high'),  -- Password Administrator
            ('fdd7a751-b60b-444a-984c-02652fe8fa1c'::uuid, 'high'),  -- Groups Administrator
            ('7698a772-787b-4ac8-901f-60d6b08affd2'::uuid, 'high'),  -- Cloud Device Administrator
            ('8329153b-31d0-4727-b945-745eb3bc5f31'::uuid, 'high'),  -- Domain Name Administrator
            ('be2f45a1-457d-42af-a067-6ec1fa63bc45'::uuid, 'high'),  -- External Identity Provider Administrator
            ('9360feb5-f418-4baa-8175-e2a00bac4301'::uuid, 'high'),  -- Directory Writers
            ('d29b2b05-8046-44ba-8758-1e26182fcf32'::uuid, 'high'),  -- Directory Synchronization Accounts
            ('4ba39ca4-527c-499a-b93d-d9b492c50246'::uuid, 'high'),  -- Partner Tier1 Support
            ('e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8'::uuid, 'high'),  -- Partner Tier2 Support
            -- read-only roles commonly given to guests -> low
            ('88d8e3e3-8f55-4a1e-953a-9b9898b8876b'::uuid, 'low'),   -- Directory Readers
            ('4a5d8f65-41da-4de4-8968-e035b65339cf'::uuid, 'low'),   -- Reports Reader
            ('790c1fb9-7f7d-4f88-86a1-ef1f95c05c1b'::uuid, 'low'),   -- Message Center Reader
            ('ac16e43d-7b2d-40e0-ac05-243ff356ab5b'::uuid, 'low'),   -- Message Center Privacy Reader
            ('75934031-6c7e-415a-99d7-48dbd49e875e'::uuid, 'low'),   -- Usage Summary Reports Reader
            ('95e79109-95c0-4d8e-aee3-d01accf2d47b'::uuid, 'low')    -- Guest Inviter
        ),
        posture AS (
            SELECT array_remove(ARRAY[
                       CASE WHEN sp.role_eligibility_status IS DISTINCT FROM 'ok' THEN
                           'PIM-eligible assignments could not be checked: '
                           || COALESCE(sp.role_eligibility_status, 'not collected (collector older than 0.6.0)') END,
                       CASE WHEN sp.group_expansion_status IS DISTINCT FROM 'ok' THEN
                           'Membership of role-holding groups could not be checked: '
                           || COALESCE(sp.group_expansion_status, 'not collected (collector older than 0.6.0)') END
                   ], NULL) AS notes
              FROM (SELECT 1) one
              LEFT JOIN entra_security_posture sp ON sp.client_id = %(client_id)s
        ),
        paths AS (
            SELECT rm.client_id, rm.member_id, rm.member_display_name, rm.member_upn,
                   rm.account_enabled, rm.role_display_name, rm.role_template_id,
                   COALESCE(rm.role_template_id, rm.role_id) AS role_key,
                   eu.user_type,
                   COALESCE(rt.tier, 'medium') AS tier,
                   -- steps below the role tier for this path
                   CASE WHEN rm.assignment_type = 'eligible'
                             AND rm.role_template_id IS DISTINCT FROM '62e90394-69f5-4237-9190-012177145e10'
                             AND rm.role_template_id IS DISTINCT FROM 'e8611ab8-c189-46e8-94e1-60213ab1f814'
                        THEN 1 ELSE 0 END
                   + CASE WHEN rm.directory_scope_id <> '/' THEN 1 ELSE 0 END AS steps_down,
                   (CASE WHEN rm.assignment_type = 'eligible' THEN 'PIM-eligible' ELSE 'active' END
                   || CASE WHEN rm.via_group_id IS NOT NULL
                           THEN ' via group ' || COALESCE(rm.via_group_display_name, rm.via_group_id::text)
                           ELSE '' END
                   || CASE WHEN rm.directory_scope_id <> '/'
                           THEN ' at scope ' || rm.directory_scope_id ELSE '' END) COLLATE "C" AS path
              FROM entra_directory_role_member rm
              LEFT JOIN entra_user eu ON eu.entra_object_id = rm.member_id AND eu.client_id = rm.client_id
              LEFT JOIN role_tier rt ON rt.role_template_id = rm.role_template_id
             WHERE rm.client_id = %(client_id)s
               AND rm.member_type = '#microsoft.graph.user'
               AND (eu.user_type = 'Guest'
                    OR COALESCE(eu.user_principal_name, rm.member_upn) ILIKE '%%#EXT#%%')
        ),
        held AS (
            SELECT p.member_id, p.role_key,
                   min(p.role_template_id::text)::uuid AS role_template_id,
                   min(p.role_display_name) AS role_display_name,
                   min(p.member_display_name) AS member_display_name,
                   min(p.member_upn) AS member_upn,
                   min(p.user_type) AS user_type,
                   min(p.tier) AS tier,
                   bool_or(p.account_enabled) AS account_enabled,
                   bool_or(p.account_enabled IS FALSE) AND NOT bool_or(p.account_enabled IS TRUE) AS disabled,
                   greatest(1, CASE min(p.tier) WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END
                               - min(p.steps_down)) AS sev_rank,
                   jsonb_agg(DISTINCT p.path ORDER BY p.path) AS assignment_paths,
                   string_agg(DISTINCT p.path, '; ' ORDER BY p.path) AS path_summary
              FROM paths p
             GROUP BY p.member_id, p.role_key
        )
        SELECT
            CASE WHEN h.disabled OR h.sev_rank = 1 THEN 'warn' ELSE 'fail' END AS status,
            md5(h.member_id::text || ':' || h.role_key::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN h.disabled THEN 'low'
                 ELSE CASE h.sev_rank WHEN 3 THEN 'high' WHEN 2 THEN 'medium' ELSE 'low' END
            END AS fd_severity,
            'Guest account ' || COALESCE(h.member_display_name, h.member_upn, h.member_id::text)
                || ' holds the "' || COALESCE(h.role_display_name, h.role_key::text)
                || '" directory role (' || h.path_summary || ')' AS summary,
            jsonb_build_object(
                'member_id', h.member_id,
                'member_display_name', h.member_display_name,
                'member_upn', h.member_upn,
                'user_type', h.user_type,
                'role_display_name', h.role_display_name,
                'role_template_id', h.role_template_id,
                'role_tier', h.tier,
                'account_enabled', h.account_enabled,
                'assignment_paths', h.assignment_paths,
                'coverage_notes', to_jsonb(po.notes)
            ) AS detail
        FROM held h
        CROSS JOIN posture po
    """,
}
