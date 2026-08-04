"""
Plugin 8001: User Inventory

A utility plugin, not a finding plugin: reports a snapshot listing of
every user account, not a pass/fail security check. See adaudit.py's
own module docstring for the full design of this second, parallel
plugin type -- no severity, no remediation, no persistence, and no
change tracking across runs. Runs fresh every invocation.

Both sam_account_name and user_principal_name are included rather than
guessing which one "username" refers to, since both are commonly used
as the login identifier depending on the environment.

[v1.1] Email addresses now combine THREE sources into one deduplicated
list: on-prem mail (the single primary address), every on-prem
proxyAddresses entry prefixed smtp:/SMTP: (secondary/primary SMTP
aliases, prefix stripped), and -- if entra_graph_collector.py has been
run for this client -- the same two fields sourced from Microsoft
Graph instead, matched back to this on-prem account via SID. This
matters because on-prem mail/proxyAddresses is frequently empty
outright in modern environments: it's only populated when something
local (classic Exchange Hybrid, or the newer Exchange attribute
writeback feature) actively writes it, and most environments hosting
email in Exchange Online no longer have that. Non-SMTP proxyAddresses
entries (X.400, SIP), from either source, are excluded, since those
aren't email addresses. If entra_graph_collector.py has never been run
for this client, the LEFT JOIN simply contributes nothing and this
plugin behaves exactly as it did in v1.0.
"""

PLUGIN = {
    "plugin_id": 8001,
    "plugin_type": "inventory",
    "category": "Inventory",
    "name": "User Inventory",
    "version": "1.1",
    "revision_date": "2026-07-18",
    "description": (
        "Snapshot listing of every user account: username (both "
        "sAMAccountName and userPrincipalName), last logon timestamp, "
        "last password change, object creation date, and every email "
        "address associated with the account -- combining on-prem "
        "mail/proxyAddresses with Microsoft Graph data where available "
        "(see entra_graph_collector.py), since on-prem mail attributes "
        "are frequently empty in cloud-hosted-email environments."
    ),
    "query": """
        SELECT
            u.sam_account_name,
            u.user_principal_name,
            u.last_logon_timestamp,
            u.pwd_last_set,
            u.when_created,
            (
                SELECT array_agg(DISTINCT addr ORDER BY addr)
                FROM (
                    SELECT u.mail AS addr WHERE u.mail IS NOT NULL
                    UNION
                    SELECT substring(pa FROM 6) AS addr
                    FROM unnest(COALESCE(u.proxy_addresses, ARRAY[]::TEXT[])) AS pa
                    WHERE pa ILIKE 'smtp:%%'
                    UNION
                    SELECT eu.mail AS addr WHERE eu.mail IS NOT NULL
                    UNION
                    SELECT substring(pa FROM 6) AS addr
                    FROM unnest(COALESCE(eu.proxy_addresses, ARRAY[]::TEXT[])) AS pa
                    WHERE pa ILIKE 'smtp:%%'
                ) combined
            ) AS email_addresses
        FROM ad_user u
        LEFT JOIN entra_user eu ON eu.on_prem_object_guid = u.object_guid AND eu.client_id = u.client_id
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
        ORDER BY u.sam_account_name
    """,
}
