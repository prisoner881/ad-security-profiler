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
"""

PLUGIN = {
    "plugin_id": 10003,
    "category": "Hybrid Identity",
    "name": "Account Holds Both Domain Admin and Global Administrator Privileges",
    "version": "1.0",
    "revision_date": "2026-07-19",
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
        "plugins 1012/1015), and treat any anomaly on this account with "
        "elevated urgency given the combined blast radius."
    ),
    "control_id": "HYBRID-003",
    "framework_tags": [],
    "references": [],
    "description": (
        "An account holding both on-prem Domain Admin-equivalent "
        "privilege (admin_count=1) and Entra Global Administrator "
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
        SELECT
            'fail' AS status,
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'Account ' || udo.sam_account_name || ' holds both on-prem Domain Admin-equivalent '
                || 'privilege and Entra Global Administrator' AS summary,
            jsonb_build_object(
                'sam_account_name', udo.sam_account_name,
                'entra_display_name', rm.member_display_name,
                'entra_upn', rm.member_upn
            ) AS detail
        FROM ad_user u
        JOIN directory_object udo ON udo.object_guid = u.object_guid AND udo.client_id = u.client_id
        JOIN entra_directory_role_member rm
            ON rm.on_prem_object_guid = u.object_guid AND rm.client_id = u.client_id
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          AND u.admin_count = 1
          AND rm.role_template_id = '62e90394-69f5-4237-9190-012177145e10'
    """,
}
