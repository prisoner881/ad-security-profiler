"""
Plugin 1031: User Account (Not a Computer) Configured as an RBCD Trustee

Resource-based constrained delegation (plugin 2022, on the computer
side) is conventionally a computer-to-computer or service-account
delegation mechanism -- a front-end server delegating to a back-end
service, for example. A literal human user account listed as an RBCD
trustee is unusual: it means that user, when authenticating to the
resource computer, can impersonate arbitrary domain users to it. Worth
flagging distinctly from plugin 2022's general RBCD visibility, since
"a person can impersonate anyone to this computer" is a meaningfully
different risk shape than "this service account can."
"""

PLUGIN = {
    "plugin_id": 1031,
    "category": "User Accounts",
    "name": "User Account (Not a Computer) Configured as an RBCD Trustee",
    "version": "1.2",
    "revision_date": "2026-07-17",
    "remediation": (
        "Confirm this is a deliberate, understood configuration -- RBCD "
        "trustees are conventionally computer or service accounts, not "
        "individual human users. If this user account genuinely needs "
        "this capability, document why; if it's leftover from testing "
        "or a misconfiguration, remove it: "
        "`Set-ADComputer -Identity <resource> -PrincipalsAllowedToDelegateToAccount $null` "
        "to clear entirely, or reset to a reviewed list excluding this "
        "account."
    ),
    "control_id": "DELEG-102",
    "framework_tags": ["MITRE-ATTCK-T1134"],
    "references": [
        {"title": "MITRE ATT&CK T1134: Access Token Manipulation",
         "url": "https://attack.mitre.org/techniques/T1134/"},
    ],
    "description": (
        "Complements plugin 2022 (general RBCD visibility) with a "
        "narrower, distinct observation: this specific RBCD trustee is "
        "a human user account, not a computer or service account. RBCD "
        "is conventionally a computer-to-computer delegation mechanism; "
        "a user account holding this trust means that individual, when "
        "authenticating to the resource computer, can impersonate "
        "arbitrary domain users to it -- a meaningfully different risk "
        "shape (tied to a person's own credential security, not a "
        "service account's) worth surfacing on its own."
    ),
    "base_severity": "high",
    "query": """
        SELECT
            'warn' AS status,
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'User Account ' || COALESCE(u.user_principal_name, u.sam_account_name)
                || ' is configured as an RBCD trustee on computer ' || COALESCE(resource.sam_account_name, '(unknown)') AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'resource_computer', resource.sam_account_name
            ) AS detail
        FROM delegation_edge de
        JOIN ad_user u ON u.object_guid = de.source_guid AND u.valid_to IS NULL
        JOIN ad_computer resource ON resource.object_guid = de.target_guid AND resource.valid_to IS NULL
        WHERE de.client_id = %(client_id)s
          AND de.valid_to IS NULL
          AND de.delegation_type = 'rbcd'
    """,
}
