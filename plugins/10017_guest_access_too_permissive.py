"""
Plugin 10017: Guest Access or Invitation Settings Too Permissive

Reads the tenant authorization policy (entra_security_posture.
authorization_policy, schema v38) and reports guest-user directory access
and guest-invitation settings that are broader than CISA SCuBA recommends.

Why it matters: CISA SCuBA MS.AAD.8.1 ("Guest users SHOULD have limited or
restricted access to Microsoft Entra ID directory objects") and MS.AAD.8.2
("Only users with the Guest Inviter role SHOULD be able to invite guest
users"). A guest with member-level directory access can enumerate every
user, group and membership in the tenant (MITRE T1087.004), which is
reconnaissance for phishing and privilege escalation if the guest -- whose
credential security is governed by another organization -- is compromised.
If every member (or everyone, including guests) can invite guests, any
compromised account can add external identities to the tenant without an
approval process.

Checks, combined into one tenant-level finding (worst severity wins, every
issue listed in detail):
- guestUserRoleId a0b1b346-4d3e-4e8b-98f8-753987be4970 (guests have the
  same access as members) -> medium;
  10dae51f-b6af-4016-8d66-8c2a99b929b3 (limited access, the default) ->
  low; 2af84b1e-32c8-42b7-82bc-daa82404023b (restricted to their own
  objects) -> no issue.
- allowInvitesFrom 'everyone' (guests can invite too) -> medium;
  'adminsGuestInvitersAndAllMembers' (any member can invite) -> low;
  'adminsAndGuestInviters' or 'none' -> no issue.
status is 'fail' when any medium issue exists, otherwise 'warn'.

Data caveats: authorization_policy NULL (the read failed -- see
authorization_policy_status -- or collector older than 0.7.0) -> no row.
A key Graph omitted (JSON null) or an unrecognised value is skipped, not
guessed. Collaboration domain restrictions (MS.AAD.8.3) are a separate
B2B policy and not checked.

Tenant-level finding: object_guid is md5('10017:' || client_id), as in
plugin 10004.
"""

PLUGIN = {
    "plugin_id": 10017,
    "category": "Hybrid Identity",
    "name": "Guest Access or Invitation Settings Too Permissive",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "HYBRID-10017",
    "framework_tags": [
        "CISA-SCUBA-MS.AAD.8.1",
        "CISA-SCUBA-MS.AAD.8.2",
        "NIST-800-53-AC-20",
        "NIST-800-53-AC-6",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-8.2.7",
        "ISO-27001-2022-A.5.19",
        "SOC2-CC6.3",
        "MITRE-ATTCK-T1087.004",
    ],
    "references": [
        {"title": "CISA SCuBA Microsoft Entra ID baseline (MS.AAD.8.1, 8.2)",
         "url": "https://github.com/cisagov/ScubaGear/blob/main/PowerShell/ScubaGear/baselines/aad.md"},
        {"title": "Microsoft: Restrict guest access permissions in Microsoft Entra ID",
         "url": "https://learn.microsoft.com/en-us/entra/identity/users/users-restrict-guest-permissions"},
        {"title": "Microsoft: Configure external collaboration settings",
         "url": "https://learn.microsoft.com/en-us/entra/external-id/external-collaboration-settings-configure"},
        {"title": "Microsoft Graph: authorizationPolicy resource type",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/authorizationpolicy"},
    ],
    "description": (
        "Guest users have the same directory access as members "
        "(medium) or the default limited access (low) rather than "
        "restricted access, and/or guest invitations are open to "
        "everyone including guests (medium) or to all members (low) "
        "instead of only administrators and Guest Inviters (SCuBA "
        "MS.AAD.8.1/8.2). Broad guest access allows directory "
        "reconnaissance by external identities this tenant does not "
        "control; open invitations let any compromised account add "
        "external users. One tenant-level finding listing every issue; "
        "silent when the authorization policy could not be read."
    ),
    "remediation": (
        "Entra admin center -> External Identities -> External "
        "collaboration settings: Guest user access = 'Guest user access "
        "is restricted to properties and memberships of their own "
        "directory objects'; Guest invite settings = 'Only users assigned "
        "to specific admin roles can invite guest users' (assign the "
        "Guest Inviter role where needed). PowerShell: "
        "Update-MgPolicyAuthorizationPolicy -GuestUserRoleId "
        "'2af84b1e-32c8-42b7-82bc-daa82404023b' -AllowInvitesFrom "
        "'adminsAndGuestInviters'."
    ),
    "base_severity": "medium",
    "query": """
        WITH ap AS (
            SELECT sp.client_id,
                   lower(sp.authorization_policy->>'guestUserRoleId') AS guest_role,
                   sp.authorization_policy->>'allowInvitesFrom' AS invites
              FROM entra_security_posture sp
             WHERE sp.client_id = %(client_id)s
               AND jsonb_typeof(sp.authorization_policy) = 'object'
        ),
        issues AS (
            SELECT a.client_id,
                   CASE a.guest_role WHEN 'a0b1b346-4d3e-4e8b-98f8-753987be4970' THEN 2 ELSE 1 END AS rank,
                   CASE a.guest_role
                        WHEN 'a0b1b346-4d3e-4e8b-98f8-753987be4970'
                        THEN 'guests have the same directory access as members'
                        ELSE 'guests have limited (default) rather than restricted directory access' END AS issue
              FROM ap a
             WHERE a.guest_role IN ('a0b1b346-4d3e-4e8b-98f8-753987be4970',
                                    '10dae51f-b6af-4016-8d66-8c2a99b929b3')
            UNION ALL
            SELECT a.client_id,
                   CASE a.invites WHEN 'everyone' THEN 2 ELSE 1 END,
                   CASE a.invites WHEN 'everyone'
                        THEN 'anyone, including guests, can invite guest users'
                        ELSE 'all member users can invite guest users' END
              FROM ap a
             WHERE a.invites IN ('everyone', 'adminsGuestInvitersAndAllMembers')
        ),
        agg AS (
            SELECT i.client_id, max(i.rank) AS rank,
                   string_agg(i.issue COLLATE "C", '; ' ORDER BY i.rank DESC, i.issue COLLATE "C") AS summary_text,
                   jsonb_agg(i.issue ORDER BY i.rank DESC, i.issue COLLATE "C") AS issue_list
              FROM issues i
             GROUP BY i.client_id
        )
        SELECT
            CASE WHEN g.rank = 2 THEN 'fail' ELSE 'warn' END AS status,
            md5('10017:' || g.client_id::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN g.rank = 2 THEN 'medium' ELSE 'low' END AS fd_severity,
            'Guest access or invitation settings too permissive: ' || g.summary_text AS summary,
            jsonb_build_object(
                'issues', g.issue_list,
                'guest_user_role_id', a.guest_role,
                'allow_invites_from', a.invites
            ) AS detail
        FROM agg g
        JOIN ap a ON a.client_id = g.client_id
    """,
}
