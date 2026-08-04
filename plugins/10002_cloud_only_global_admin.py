"""
Plugin 10002: Cloud-Only Global Administrator (No On-Prem Account)

The second of three findings requiring both on-prem and Entra data
together. A Global Administrator with no corresponding on-prem AD
account bypasses every on-prem control this project's other 130+
plugins check for -- by construction, not by any specific
misconfiguration. Password policy, account lockout, AdminSDHolder
protection, Kerberos hardening, on-prem MFA/smartcard requirements --
none of it reaches an account that on-prem AD has never heard of.

Not inherently wrong: this is exactly the recommended pattern for
break-glass/emergency-access accounts (Microsoft's own guidance
explicitly recommends at least two cloud-only, excluded-from-
Conditional-Access emergency accounts per tenant), and plenty of
smaller or cloud-first organizations reasonably run some or all of
their admin accounts cloud-only rather than syncing them from an
on-prem AD they may barely still use for anything else. What matters
is knowing this exists and confirming its security posture was set
deliberately (strong, unique password; MFA; monitored sign-in
activity) rather than left at whatever Entra's own defaults happen to
be, since nothing about this project's on-prem hardening reaches it
to compensate.
"""

PLUGIN = {
    "plugin_id": 10002,
    "category": "Hybrid Identity",
    "name": "Cloud-Only Global Administrator (No On-Prem Account)",
    "version": "1.0",
    "revision_date": "2026-07-19",
    "remediation": (
        "Confirm this account's security posture was set deliberately, "
        "not left at defaults: a strong, unique password not reused "
        "anywhere else, MFA enrolled and enforced, and sign-in activity "
        "actually monitored somewhere. If this is meant to be a break-"
        "glass/emergency-access account, follow Microsoft's own "
        "documented pattern for those specifically (excluded from "
        "Conditional Access policies that could otherwise lock everyone "
        "out simultaneously, credentials stored securely offline, "
        "access to sign-in attempts alerted on). If this account is a "
        "day-to-day admin identity rather than break-glass, consider "
        "whether it should be brought into hybrid sync so this "
        "project's on-prem findings can actually cover it."
    ),
    "control_id": "HYBRID-002",
    "framework_tags": [],
    "references": [
        {"title": "Microsoft: Manage emergency access accounts in Microsoft Entra ID",
         "url": "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access"},
    ],
    "description": (
        "A Global Administrator with no corresponding on-prem AD "
        "account bypasses every on-prem control this project's other "
        "plugins check -- by construction, not misconfiguration. Not "
        "inherently wrong (this is Microsoft's own recommended pattern "
        "for break-glass/emergency-access accounts, and common for "
        "cloud-first organizations generally), but worth confirming "
        "its security posture was set deliberately rather than left at "
        "Entra's own defaults, since none of this project's on-prem "
        "hardening findings reach an account on-prem AD has never "
        "heard of."
    ),
    "base_severity": "medium",
    "query": """
        SELECT
            'warn' AS status,
            NULL::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Global Administrator ' || COALESCE(rm.member_display_name, rm.member_upn)
                || ' has no corresponding on-prem AD account' AS summary,
            jsonb_build_object(
                'member_display_name', rm.member_display_name,
                'member_upn', rm.member_upn,
                'account_enabled', rm.account_enabled
            ) AS detail
        FROM entra_directory_role_member rm
        WHERE rm.client_id = %(client_id)s
          AND rm.role_template_id = '62e90394-69f5-4237-9190-012177145e10'
          AND rm.member_type = '#microsoft.graph.user'
          AND rm.on_prem_object_guid IS NULL
    """,
}
