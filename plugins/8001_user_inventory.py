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

[v1.2] Email addresses are deduplicated case-insensitively (an address
from mail and the same one from proxyAddresses in different casing was
listed twice); one spelling per address is kept, chosen deterministically.
Entra addresses are gathered by a correlated subquery over every Entra
user mapped to the account instead of a LEFT JOIN, so an on-prem GUID
matched by more than one Entra row can no longer list the user twice.
Adds an is_enabled column. (The Entra match is via on_prem_object_guid,
which entra_graph_collector.py resolves from the on-prem SID.)

[v1.3] Every address, with where it came from (schema v51, views
v_ad_user_address / v_entra_user_address / v_entra_ad_address_match):
  * AD: mail, SMTP proxyAddresses, otherMailbox, an SMTP targetAddress,
    userPrincipalName (adprofiler.py 1.0.11);
  * the Entra account(s) linked exactly to this user (by SID, or by the
    sync anchor -- entra_graph_collector.py 1.0.8): mail, SMTP
    proxyAddresses, otherMails, imAddresses, sign-in identities,
    userPrincipalName, onPremisesUserPrincipalName.
email_addresses is the deduplicated list (case-insensitive, one spelling
kept); email_address_sources repeats each address with its sources in
brackets. linked_entra_accounts names the exactly linked Entra account(s)
and how they were linked; likely_entra_accounts names Entra accounts with
no exact link to AD that share an address with this user -- a likely
match, not a proven one (see plugin 8005 for those accounts). The user
principal name now counts as an address (it is one in most tenants).
"""

PLUGIN = {
    "plugin_id": 8001,
    "plugin_type": "inventory",
    "category": "Inventory",
    "name": "User Inventory",
    "version": "1.3",
    "revision_date": "2026-11-24",
    "description": (
        "Snapshot listing of every user account: username (both "
        "sAMAccountName and userPrincipalName), enabled state, last logon timestamp, "
        "last password change, object creation date, every email address "
        "associated with the account with where each came from (AD mail, "
        "proxyAddresses, otherMailbox, targetAddress and UPN; the linked Entra "
        "account's mail, proxyAddresses, otherMails, IM and sign-in addresses), "
        "the Entra account(s) linked to it and how, and unlinked Entra accounts "
        "that share an address with it (likely matches)."
    ),
    "query": """
        WITH
        linked AS (
            SELECT eu.on_prem_object_guid AS object_guid, eu.entra_object_id,
                   COALESCE(eu.user_principal_name, eu.entra_object_id::text) AS entra_name,
                   CASE eu.on_prem_match_method WHEN 'immutable_id' THEN 'sync anchor' ELSE 'SID' END
                       AS how
              FROM entra_user eu
             WHERE eu.client_id = %(client_id)s AND eu.on_prem_object_guid IS NOT NULL
        ),
        all_addr AS (
            SELECT a.object_guid, a.address, a.address_lc, a.source
              FROM v_ad_user_address a
             WHERE a.client_id = %(client_id)s
            UNION ALL
            SELECT l.object_guid, e.address, e.address_lc, e.source
              FROM linked l
              JOIN v_entra_user_address e
                ON e.client_id = %(client_id)s AND e.entra_object_id = l.entra_object_id
        ),
        per_addr AS (
            SELECT object_guid, address_lc, min(address) AS address,
                   array_agg(DISTINCT source ORDER BY source) AS sources
              FROM all_addr
             GROUP BY object_guid, address_lc
        ),
        per_user AS (
            SELECT object_guid,
                   array_agg(address ORDER BY address_lc) AS email_addresses,
                   array_agg(address || ' [' || array_to_string(sources, '; ') || ']'
                             ORDER BY address_lc) AS email_address_sources
              FROM per_addr
             GROUP BY object_guid
        ),
        link AS (
            SELECT object_guid,
                   array_agg(entra_name || ' (' || how || ')' ORDER BY entra_name) AS linked_entra_accounts
              FROM linked
             GROUP BY object_guid
        ),
        likely AS (
            SELECT m.ad_object_guid AS object_guid,
                   array_agg(DISTINCT COALESCE(eu.user_principal_name, eu.entra_object_id::text)
                                      || ' (shares ' || m.address || ')') AS likely_entra_accounts
              FROM v_entra_ad_address_match m
              JOIN entra_user eu
                ON eu.client_id = m.client_id AND eu.entra_object_id = m.entra_object_id
             WHERE m.client_id = %(client_id)s
             GROUP BY m.ad_object_guid
        )
        SELECT
            u.sam_account_name,
            u.user_principal_name,
            u.last_logon_timestamp,
            u.pwd_last_set,
            u.when_created,
            pu.email_addresses,
            pu.email_address_sources,
            lk.linked_entra_accounts,
            li.likely_entra_accounts,
            u.is_enabled
        FROM ad_user u
        LEFT JOIN per_user pu ON pu.object_guid = u.object_guid
        LEFT JOIN link lk ON lk.object_guid = u.object_guid
        LEFT JOIN likely li ON li.object_guid = u.object_guid
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
        ORDER BY u.sam_account_name
    """,
}
