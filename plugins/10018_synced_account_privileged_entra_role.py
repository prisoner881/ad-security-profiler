"""
Plugin 10018: On-Premises-Synced Account Holds a Highly Privileged Entra Role

Reports Entra users synchronized from on-premises AD (Entra Connect /
Cloud Sync) that hold -- actively, PIM-eligible, or through a
role-assignable group -- a highly privileged Entra directory role.

Why it matters: CISA SCuBA MS.AAD.7.3 ("Privileged users SHALL be
provisioned cloud-only accounts separate from an on-premises directory or
other federated identity providers") and Microsoft's "protect Microsoft
365 from on-premises attacks" guidance. A synced account's password (via
password hash sync or pass-through authentication) and lifecycle are
controlled from on-premises AD: anyone who compromises the domain -- or
just an account that can reset this user's password, or the sync server --
inherits the cloud role, turning an on-prem breach into a tenant takeover
(the pivot seen in CISA AA26-237A).

Overlap with plugin 10003: 10003 reports accounts that hold BOTH current
on-prem Tier 0 privilege and one of four tenant-takeover roles. This plugin
applies regardless of on-prem privilege (an ordinary synced user with an
Entra admin role is exactly the case SCuBA forbids, since many on-prem
principals can reset it) and covers the whole highly privileged set:
Global, Privileged Role, Privileged Authentication, Security, Hybrid
Identity, Application, Cloud Application, Exchange, SharePoint, User,
Conditional Access, Authentication and Intune Administrator (the set shared
with plugins 10012, 10014 and 10019). Both may fire for the same account.

"Synced" means entra_user.on_premises_sync_enabled is true; when the user
has no entra_user row (or the flag is NULL), the presence of
onPremisesSecurityIdentifier / a resolved on_prem_object_guid on the role
member or user row is used instead. on_premises_sync_enabled = false
explicitly (sync stopped; the account is now cloud-managed) is not
reported even if the old SID is still present.

Severity: high; medium when every path is administrative-unit scoped; low
'warn' when the Entra account is disabled. Emergency-access accounts get no
exemption (they must be cloud-only). One finding per user (identity = the
Entra object id, member_id, as in plugin 10002), every role and path listed
sorted. If PIM eligibility or group membership couldn't be read,
detail.coverage_notes says so.
"""

PLUGIN = {
    "plugin_id": 10018,
    "category": "Hybrid Identity",
    "name": "On-Premises-Synced Account Holds a Highly Privileged Entra Role",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "HYBRID-10018",
    "framework_tags": [
        "CISA-SCUBA-MS.AAD.7.3",
        "CISA-AA26-237A",
        "NIST-800-53-AC-2(7)",
        "NIST-800-53-AC-6(5)",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "CIS-CSC-8-5.4",
        "ISO-27001-2022-A.8.2",
        "SOC2-CC6.3",
        "HIPAA-164.308(a)(4)(ii)(B)",
        "MITRE-ATTCK-T1078.004",
    ],
    "references": [
        {"title": "CISA SCuBA Microsoft Entra ID baseline (MS.AAD.7.3)",
         "url": "https://github.com/cisagov/ScubaGear/blob/main/PowerShell/ScubaGear/baselines/aad.md"},
        {"title": "Microsoft: Protecting Microsoft 365 from on-premises attacks",
         "url": "https://learn.microsoft.com/en-us/entra/architecture/protect-m365-from-on-premises-attacks"},
        {"title": "Microsoft: Privileged roles and permissions in Microsoft Entra ID",
         "url": "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/privileged-roles-permissions"},
    ],
    "description": (
        "A user synchronized from on-premises AD holds a highly "
        "privileged Entra role (Global, Privileged Role, Privileged "
        "Authentication, Security, Hybrid Identity, Application, Cloud "
        "Application, Exchange, SharePoint, User, Conditional Access, "
        "Authentication or Intune Administrator) -- active, PIM-eligible "
        "or via a role-assignable group. Its password and lifecycle are "
        "controlled on-premises, so compromising the domain, the sync "
        "server or anyone able to reset the account yields the cloud "
        "role (SCuBA MS.AAD.7.3: privileged users SHALL be cloud-only). "
        "High; medium when only administrative-unit scoped; low when the "
        "account is disabled. Applies regardless of on-prem privilege "
        "(plugin 10003 covers accounts that are also on-prem Tier 0)."
    ),
    "remediation": (
        "Create a separate cloud-only administrative account "
        "(user@<tenant>.onmicrosoft.com) for each administrator, assign "
        "the role to it (preferably PIM-eligible, with phishing-resistant "
        "MFA), and remove the role -- and any role-assignable group "
        "membership granting it -- from the synced account: "
        "Remove-MgRoleManagementDirectoryRoleAssignment / the PIM "
        "Assignments blade. Exclude on-prem admin accounts from sync "
        "scope so they can never be granted cloud roles by accident."
    ),
    "base_severity": "high",
    "query": """
        WITH hp_role(role_template_id, role_name) AS (
            VALUES ('62e90394-69f5-4237-9190-012177145e10'::uuid, 'Global Administrator'),
                   ('e8611ab8-c189-46e8-94e1-60213ab1f814'::uuid, 'Privileged Role Administrator'),
                   ('7be44c8a-adaf-4e2a-84d6-ab2649e08a13'::uuid, 'Privileged Authentication Administrator'),
                   ('194ae4cb-b126-40b2-bd5b-6091b380977d'::uuid, 'Security Administrator'),
                   ('8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2'::uuid, 'Hybrid Identity Administrator'),
                   ('9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'::uuid, 'Application Administrator'),
                   ('158c047a-c907-4556-b7ef-446551a6b5f7'::uuid, 'Cloud Application Administrator'),
                   ('29232cdf-9323-42fd-ade2-1d097af3e4de'::uuid, 'Exchange Administrator'),
                   ('f28a1f50-f6e7-4571-818b-6a12f2af6b6c'::uuid, 'SharePoint Administrator'),
                   ('fe930be7-5e62-47db-91af-98c3a49a38b1'::uuid, 'User Administrator'),
                   ('b1be1c3e-b65d-4f19-8427-f6fa0d97feb9'::uuid, 'Conditional Access Administrator'),
                   ('c4e39bd9-1100-46d3-8c65-fb160da0071f'::uuid, 'Authentication Administrator'),
                   ('3a2c62db-5318-420d-8d74-23affee5d9d5'::uuid, 'Intune Administrator')
        ),
        posture AS (
            SELECT array_remove(ARRAY[
                       CASE WHEN sp.role_eligibility_status IS DISTINCT FROM 'ok' THEN
                           'PIM-eligible assignments could not be checked: '
                           || COALESCE(sp.role_eligibility_status, 'not collected') END,
                       CASE WHEN sp.group_expansion_status IS DISTINCT FROM 'ok' THEN
                           'Membership of role-holding groups could not be checked: '
                           || COALESCE(sp.group_expansion_status, 'not collected') END
                   ], NULL) AS notes
              FROM (SELECT 1) one
              LEFT JOIN entra_security_posture sp ON sp.client_id = %(client_id)s
        ),
        paths AS (
            SELECT rm.client_id, rm.member_id, rm.member_display_name, rm.member_upn,
                   rm.account_enabled, rm.on_prem_object_guid,
                   COALESCE(rm.on_premises_security_identifier, eu.on_premises_security_identifier) AS on_prem_sid,
                   eu.on_premises_sync_enabled, rm.directory_scope_id,
                   (r.role_name || ' ('
                    || CASE WHEN rm.assignment_type = 'eligible' THEN 'PIM-eligible' ELSE 'active' END
                    || CASE WHEN rm.via_group_id IS NOT NULL
                            THEN ' via group ' || COALESCE(rm.via_group_display_name, rm.via_group_id::text)
                            ELSE '' END
                    || CASE WHEN rm.directory_scope_id <> '/'
                            THEN ' at scope ' || rm.directory_scope_id ELSE '' END
                    || ')') COLLATE "C" AS label
              FROM entra_directory_role_member rm
              JOIN hp_role r ON r.role_template_id = rm.role_template_id
              LEFT JOIN entra_user eu ON eu.entra_object_id = rm.member_id AND eu.client_id = rm.client_id
             WHERE rm.client_id = %(client_id)s
               AND rm.member_type = '#microsoft.graph.user'
               AND (eu.on_premises_sync_enabled IS TRUE
                    OR (eu.on_premises_sync_enabled IS NULL
                        AND (rm.on_prem_object_guid IS NOT NULL
                             OR rm.on_premises_security_identifier IS NOT NULL
                             OR eu.on_premises_security_identifier IS NOT NULL
                             OR eu.on_prem_object_guid IS NOT NULL)))
        ),
        held AS (
            SELECT p.member_id,
                   min(p.member_display_name) AS member_display_name,
                   min(p.member_upn) AS member_upn,
                   min(p.on_prem_object_guid::text) AS on_prem_object_guid,
                   min(p.on_prem_sid) AS on_prem_sid,
                   bool_or(p.on_premises_sync_enabled) AS sync_enabled,
                   bool_or(p.account_enabled IS FALSE) AND NOT bool_or(p.account_enabled IS TRUE) AS disabled,
                   bool_or(p.directory_scope_id = '/') AS tenant_wide,
                   string_agg(DISTINCT p.label, ', ' ORDER BY p.label) AS roles_summary,
                   jsonb_agg(DISTINCT p.label ORDER BY p.label) AS role_assignments
              FROM paths p
             GROUP BY p.member_id
        )
        SELECT
            CASE WHEN h.disabled THEN 'warn' ELSE 'fail' END AS status,
            h.member_id AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN h.disabled THEN 'low' WHEN h.tenant_wide THEN 'high' ELSE 'medium' END AS fd_severity,
            'On-premises-synced user ' || COALESCE(h.member_upn, h.member_display_name, h.member_id::text)
                || ' holds ' || h.roles_summary
                || CASE WHEN h.disabled THEN ' (account disabled)' ELSE '' END AS summary,
            jsonb_build_object(
                'member_id', h.member_id,
                'member_display_name', h.member_display_name,
                'member_upn', h.member_upn,
                'on_premises_sync_enabled', h.sync_enabled,
                'on_premises_security_identifier', h.on_prem_sid,
                'on_prem_object_guid', h.on_prem_object_guid,
                'account_disabled', h.disabled,
                'role_assignments', h.role_assignments,
                'coverage_notes', to_jsonb(po.notes)
            ) AS detail
        FROM held h
        CROSS JOIN posture po
    """,
}
