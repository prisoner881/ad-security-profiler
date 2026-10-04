"""
Plugin 10003: Account Holds Both Domain Admin and Global Administrator Privileges

The third of three findings requiring both on-prem and Entra data
together, and arguably the sharpest one: an account that's both an
AdminSDHolder-protected on-prem privileged account (admin_count=1)
AND a Global Administrator in Entra simultaneously means a single
credential compromise grants full control of BOTH the on-prem domain
and the entire cloud tenant at once -- no lateral movement between
environments required, no second compromise needed. Domain Admin
alone already means full on-prem control; Global Administrator alone
already means full tenant control; the same identity holding both
collapses two supposedly separate blast radii into one.

Not automatically wrong -- a break-glass account or a very small
organization's sole administrator may legitimately need both, and
this finding doesn't assume otherwise. What it does assert is that
this specific combination deserves more scrutiny than either
privilege alone: if this account's credential (or session, or MFA
factor) is compromised once, the attacker doesn't need to pivot from
one environment to the other -- they already have both.

[v1.3] On-prem privilege is now CURRENT Tier 0 privilege
(v_privileged_principal: effective protected-group membership incl.
nested/primary group, Tier 0 ACL control, DCSync, Tier 0 ownership)
instead of the sticky adminCount=1, which stays set on former admins.
The Entra side now also covers the other tenant-takeover roles -- Privileged
Role Administrator, Privileged Authentication Administrator and Hybrid
Identity Administrator -- and rows are aggregated to one finding per
account (roles listed by fixed name, sorted). Severity drops to medium when
either side of the identity is disabled. Not visible (collector
limitation): PIM-eligible assignments and roles held through a
role-assignable group.
"""

PLUGIN = {
    "plugin_id": 10003,
    "category": "Hybrid Identity",
    "name": "Account Holds Both Domain Admin and Global Administrator Privileges",
    "version": "1.3",
    "revision_date": "2026-10-04",
    "remediation": (
        "Confirm this dual privilege is genuinely necessary rather than "
        "incidental (e.g. an account that was made Global Administrator "
        "once for a one-time setup task and never demoted). Where "
        "practical, separate on-prem and cloud administration into "
        "different identities entirely -- a compromise of one no longer "
        "automatically compromises the other. Where separation isn't "
        "practical (a small environment with limited staff), apply the "
        "strongest available protections to this specific account on "
        "both sides: phishing-resistant MFA in Entra, Protected Users "
        "group membership and smartcard-required logon on-prem (see "
        "plugins 1012/1040), and treat any anomaly on this account with "
        "elevated urgency given the combined blast radius."
    ),
    "control_id": "HYBRID-003",
    "framework_tags": ["CISA-AA26-237A", "MITRE-ATTCK-T1078.004"],
    "references": [
        "https://learn.microsoft.com/en-us/entra/architecture/protect-m365-from-on-premises-attacks",
        "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/privileged-roles-permissions",
    ],
    "description": (
        "An account holding both current on-prem Tier 0 (Domain "
        "Admin-equivalent) privilege, per v_privileged_principal, and "
        "an active Entra tenant-takeover role (Global Administrator, "
        "Privileged Role Administrator, Privileged Authentication "
        "Administrator or Hybrid Identity Administrator) "
        "simultaneously. A single credential compromise grants full "
        "control of both the on-prem domain and the entire cloud "
        "tenant at once, with no lateral movement or second compromise "
        "needed -- collapsing two otherwise-separate blast radii into "
        "one. Not automatically wrong (a small organization's sole "
        "administrator, or an intentional break-glass account, may "
        "legitimately need both), but the combination deserves more "
        "scrutiny than either privilege alone."
    ),
    "base_severity": "high",
    "query": """
        WITH roles(role_template_id, role_name) AS (
            VALUES ('62e90394-69f5-4237-9190-012177145e10'::uuid, 'Global Administrator'),
                   ('e8611ab8-c189-46e8-94e1-60213ab1f814'::uuid, 'Privileged Role Administrator'),
                   ('7be44c8a-adaf-4e2a-84d6-ab2649e08a13'::uuid, 'Privileged Authentication Administrator'),
                   ('8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2'::uuid, 'Hybrid Identity Administrator')
        )
        SELECT
            'fail' AS status,
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN u.is_enabled IS FALSE OR bool_and(rm.account_enabled IS FALSE)
                 THEN 'medium' ELSE 'high' END AS fd_severity,
            'Account ' || COALESCE(udo.sam_account_name, u.sam_account_name, u.object_guid::text)
                || ' holds both on-prem Domain Admin-equivalent privilege and Entra '
                || string_agg(DISTINCT r.role_name, ', ' ORDER BY r.role_name) AS summary,
            jsonb_build_object(
                'sam_account_name', udo.sam_account_name,
                'on_prem_enabled', u.is_enabled,
                'entra_display_name', min(rm.member_display_name),
                'entra_upn', min(rm.member_upn),
                'entra_account_enabled', bool_or(rm.account_enabled),
                'entra_roles', jsonb_agg(DISTINCT r.role_name ORDER BY r.role_name),
                'on_prem_privilege_sources', (
                    SELECT jsonb_agg(DISTINCT pp.privilege_source ORDER BY pp.privilege_source)
                      FROM v_privileged_principal pp
                     WHERE pp.client_id = u.client_id AND pp.object_guid = u.object_guid)
            ) AS detail
        FROM ad_user u
        JOIN directory_object udo ON udo.object_guid = u.object_guid AND udo.client_id = u.client_id
        JOIN entra_directory_role_member rm
            ON rm.on_prem_object_guid = u.object_guid AND rm.client_id = u.client_id
        JOIN roles r ON r.role_template_id = rm.role_template_id
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          AND EXISTS (SELECT 1 FROM v_privileged_principal pp
                       WHERE pp.client_id = u.client_id AND pp.object_guid = u.object_guid)
        GROUP BY u.client_id, u.object_guid, u.is_enabled, u.sam_account_name, udo.sam_account_name
    """,
}
