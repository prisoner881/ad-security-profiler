"""
Plugin 8005: Entra Accounts Not Linked to an AD Account

An inventory plugin (see 8001): a snapshot listing, no severity, no
persistence.

Lists every Microsoft Entra ID user that entra_graph_collector.py could
not link exactly to an AD account (entra_user.on_prem_object_guid NULL:
neither its on-premises SID nor its sync anchor matches a collected AD
object), with every e-mail address it carries and where each came from,
and the AD users it shares an address with (likely matches, from the view
v_entra_ad_address_match). These are the accounts the user inventory
(8001) cannot show: cloud-only accounts (often separate cloud
administrator accounts), guests, and accounts synced from an AD domain or
forest that was not collected (synced_from says which).

why_unlinked:
  * 'synced from a domain not collected' -- onPremisesSyncEnabled, or an
    on-premises SID / domain is present, but no collected AD object
    matches;
  * 'guest' -- userType Guest;
  * 'cloud-only' -- otherwise.

A likely match is a shared address, not proof that the two accounts
belong to the same person: an address can be reused, or typed into
otherMails by anyone who can edit the account.

Data: entra_user, v_entra_user_address, v_entra_ad_address_match,
directory_object (schema v51).
"""

PLUGIN = {
    "plugin_id": 8005,
    "plugin_type": "inventory",
    "category": "Inventory",
    "name": "Entra Accounts Not Linked to AD",
    "version": "1.0",
    "revision_date": "2026-11-24",
    "description": (
        "Snapshot listing of every Microsoft Entra ID user with no exact link to an AD "
        "account (cloud-only accounts, guests, accounts synced from a domain that was not "
        "collected): why it is unlinked, every email address it carries and where each came "
        "from (mail, proxyAddresses, otherMails, IM and sign-in addresses, UPNs), and the AD "
        "users it shares an address with (likely matches, not proof of the same person)."
    ),
    "query": """
        WITH
        unlinked AS (
            SELECT eu.*
              FROM entra_user eu
             WHERE eu.client_id = %(client_id)s AND eu.on_prem_object_guid IS NULL
        ),
        per_addr AS (
            SELECT e.entra_object_id, e.address_lc, min(e.address) AS address,
                   array_agg(DISTINCT e.source ORDER BY e.source) AS sources
              FROM v_entra_user_address e
             WHERE e.client_id = %(client_id)s
               AND e.entra_object_id IN (SELECT entra_object_id FROM unlinked)
             GROUP BY e.entra_object_id, e.address_lc
        ),
        per_user AS (
            SELECT entra_object_id,
                   array_agg(address ORDER BY address_lc) AS email_addresses,
                   array_agg(address || ' [' || array_to_string(sources, '; ') || ']'
                             ORDER BY address_lc) AS email_address_sources
              FROM per_addr
             GROUP BY entra_object_id
        ),
        likely AS (
            SELECT m.entra_object_id,
                   array_agg(DISTINCT COALESCE(o.sam_account_name, o.dn_current)
                                      || ' (shares ' || m.address || ')') AS likely_ad_accounts
              FROM v_entra_ad_address_match m
              JOIN directory_object o
                ON o.client_id = m.client_id AND o.object_guid = m.ad_object_guid
             WHERE m.client_id = %(client_id)s
             GROUP BY m.entra_object_id
        )
        SELECT
            u.user_principal_name,
            u.display_name,
            u.user_type,
            u.account_enabled,
            CASE WHEN COALESCE(u.on_premises_sync_enabled, false)
                      OR u.on_premises_security_identifier IS NOT NULL
                      OR u.on_premises_domain_name IS NOT NULL
                 THEN 'synced from a domain not collected'
                 WHEN lower(COALESCE(u.user_type, '')) = 'guest' THEN 'guest'
                 ELSE 'cloud-only' END AS why_unlinked,
            NULLIF(concat_ws('\\', u.on_premises_domain_name, u.on_premises_sam_account_name), '')
                AS synced_from,
            pu.email_addresses,
            pu.email_address_sources,
            li.likely_ad_accounts,
            u.created_at,
            u.last_sign_in_at
        FROM unlinked u
        LEFT JOIN per_user pu ON pu.entra_object_id = u.entra_object_id
        LEFT JOIN likely li ON li.entra_object_id = u.entra_object_id
        ORDER BY li.likely_ad_accounts IS NULL, u.user_principal_name
    """,
}
