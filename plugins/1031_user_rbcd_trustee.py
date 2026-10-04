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

[v1.4] One row per trustee user: a user trusted for RBCD by two or more
computers produced one row per computer with the same object_guid, which
violates the one-finding-per-identity rule and made the whole plugin
fail. The summary now lists every resource computer (sorted) and detail
carries resource_count and the sorted list. Joins are client-scoped. A
disabled trustee is rated 'low' (it cannot authenticate until
re-enabled). Deny ACEs in the RBCD descriptor are no longer recorded as
trustees by the collector (schema v36).
"""

PLUGIN = {
    "plugin_id": 1031,
    "category": "User Accounts",
    "name": "User Account (Not a Computer) Configured as an RBCD Trustee",
    "version": "1.4",
    "revision_date": "2026-10-04",
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
    "framework_tags": ["MITRE-ATTCK-T1134", "CISA-AA26-237A", "MITRE-ATTCK-T1098"],
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
            -- [v1.4] A disabled user cannot authenticate, so it cannot use
            -- the delegation until re-enabled.
            CASE WHEN u.is_enabled IS NOT FALSE THEN 'high' ELSE 'low' END AS fd_severity,
            'User Account ' || COALESCE(u.user_principal_name, u.sam_account_name, u.object_guid::text)
                || CASE WHEN u.is_enabled IS FALSE THEN ' (disabled)' ELSE '' END
                || ' is configured as an RBCD trustee on '
                || CASE WHEN count(DISTINCT resource.object_guid) = 1 THEN 'computer ' ELSE 'computers ' END
                || string_agg(DISTINCT COALESCE(resource.sam_account_name, resource.object_guid::text), ', '
                              ORDER BY COALESCE(resource.sam_account_name, resource.object_guid::text)) AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'is_enabled', u.is_enabled,
                'resource_count', count(DISTINCT resource.object_guid),
                'resource_computers', jsonb_agg(DISTINCT COALESCE(resource.sam_account_name, resource.object_guid::text)
                                               ORDER BY COALESCE(resource.sam_account_name, resource.object_guid::text))
            ) AS detail
        FROM delegation_edge de
        JOIN ad_user u
            ON u.object_guid = de.source_guid AND u.client_id = de.client_id AND u.valid_to IS NULL
        JOIN ad_computer resource
            ON resource.object_guid = de.target_guid AND resource.client_id = de.client_id
           AND resource.valid_to IS NULL
        WHERE de.client_id = %(client_id)s
          AND de.valid_to IS NULL
          AND de.delegation_type = 'rbcd'
        -- [v1.4] One finding per trustee user (the finding identity is the
        -- user's GUID); a user trusted by several computers used to emit
        -- one row per computer and make the plugin fail.
        GROUP BY u.object_guid, u.user_principal_name, u.sam_account_name, u.is_enabled
    """,
}
