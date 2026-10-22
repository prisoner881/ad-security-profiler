"""
Plugin 10097: krbtgt Account Synchronized to Entra ID

Reports Entra ID users synchronized from on-premises AD that are a krbtgt
account: the domain krbtgt (RID 502), a read-only DC's krbtgt_<number>,
or the Microsoft Entra Kerberos key account krbtgt-AzureAD (CN
krbtgt-AzureAD / krbtgt_AzureAD, sAMAccountName krbtgt_<number>).

Why: these accounts hold the keys that sign Kerberos tickets. They are
disabled by design and must never exist in Entra ID: a synchronized copy
is an object whose password hash (with password hash sync) is in the
cloud, and the Entra Kerberos key account in particular is meant to exist
only as Entra ID's own key, which Microsoft keeps out of sync. Its
presence usually means the sync scope (OU / attribute filtering) was
widened to the Users container without excluding them. Maester MT.1147.

Matching: the user's on_prem_object_guid resolves (SID match) to an AD
object whose objectSid ends in -502, whose sAMAccountName starts with
'krbtgt', or whose DN starts with CN=krbtgt-AzureAD / CN=krbtgt_AzureAD;
or, when the on-premises object is not in this collection, the Entra
user's UPN or display name starts with 'krbtgt'. fail / high, one finding
per Entra user (object_guid = md5('10097:' || client_id || ':' || Entra
object id)).
"""

PLUGIN = {
    "plugin_id": 10097,
    "category": "Hybrid Identity",
    "name": "krbtgt Account Synchronized to Entra ID",
    "version": "1.0",
    "revision_date": "2026-10-22",
    "control_id": "HYBRID-10097",
    "framework_tags": [
        "NIST-800-53-AC-6",
        "NIST-800-53-IA-5",
        "NIST-CSF-2.0-PR.AA-05",
        "NIST-CSF-2.0-PR.DS-01",
        "CIS-CSC-8-5.4",
        "ISO-27001-2022-A.8.2",
        "SOC2-CC6.1",
        "MITRE-ATTCK-T1558",
    ],
    "references": [
        {"title": "Maester MT.1147: Do not sync krbtgt_AzureAD to Entra ID",
         "url": "https://maester.dev/docs/tests/MT.1147"},
        {"title": "Microsoft: Passwordless security key sign-in to on-premises resources (Microsoft Entra Kerberos server object)",
         "url": "https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-passwordless-security-key-on-premises"},
        {"title": "Microsoft: Microsoft Entra Connect Sync: Configure filtering",
         "url": "https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sync-configure-filtering"},
        {"title": "MITRE ATT&CK T1558: Steal or Forge Kerberos Tickets",
         "url": "https://attack.mitre.org/techniques/T1558/"},
    ],
    "description": (
        "A krbtgt account (the domain's, a read-only DC's, or the Microsoft Entra Kerberos "
        "krbtgt-AzureAD key account) is synchronized to Entra ID. These accounts hold the "
        "keys that sign Kerberos tickets and must stay out of the sync scope."
    ),
    "remediation": (
        "Exclude the account from synchronization: in Entra Connect Sync, remove its "
        "container from the OU filter or add an attribute-based filter (a cloudFiltered "
        "rule on sAMAccountName starting with krbtgt); in Cloud Sync, adjust the scoping "
        "filter. Run a sync cycle and confirm the cloud object is deleted. If password hash "
        "sync was on while it was in scope, rotate the key: krbtgt twice (plugin 1006), "
        "krbtgt-AzureAD with Set-AzureADKerberosServer -RotateServerKey."
    ),
    "base_severity": "high",
    "query": """
        SELECT
            'fail' AS status,
            md5('10097:' || u.client_id::text || ':' || u.entra_object_id::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'krbtgt account ' || COALESCE(o.sam_account_name, u.display_name, u.user_principal_name)
                || CASE WHEN lower(o.dn_current) LIKE 'cn=krbtgt_azuread,%%'
                        THEN ' (Microsoft Entra Kerberos key account krbtgt-AzureAD)' ELSE '' END
                || ' is synchronized to Entra ID as ' || COALESCE(u.user_principal_name, u.entra_object_id::text)
                AS summary,
            jsonb_build_object(
                'entra_object_id', u.entra_object_id,
                'user_principal_name', u.user_principal_name,
                'display_name', u.display_name,
                'account_enabled', u.account_enabled,
                'on_premises_dn', o.dn_current,
                'on_premises_sam_account_name', o.sam_account_name,
                'on_premises_sid', u.on_premises_security_identifier,
                'matched_by', CASE WHEN o.object_guid IS NOT NULL THEN 'on-premises object'
                                   ELSE 'Entra name' END
            ) AS detail
        FROM entra_user u
        LEFT JOIN directory_object o
          ON o.object_guid = u.on_prem_object_guid AND o.client_id = u.client_id
        WHERE u.client_id = %(client_id)s
          AND u.on_premises_sync_enabled IS TRUE
          AND (o.object_sid LIKE '%%-502'
               OR lower(o.sam_account_name) LIKE 'krbtgt%%'
               OR lower(o.dn_current) LIKE 'cn=krbtgt_azuread,%%'
               OR (o.object_guid IS NULL
                   AND (lower(split_part(u.user_principal_name, '@', 1)) LIKE 'krbtgt%%'
                        OR lower(u.display_name) LIKE 'krbtgt%%')))
    """,
}
