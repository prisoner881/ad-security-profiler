"""
Plugin 1047: Privileged Account Has a Mailbox or Email Address

Flags enabled Tier 0 user accounts (current v_privileged_principal members:
protected-group members, holders of control rights on or ownership of Tier
0 objects, DCSync holders, and members of groups holding those) whose
mail attribute or proxyAddresses is populated.

Why it matters: an e-mail address on an administrative account means it
receives mail -- and usually that someone reads that mail, opens
attachments and follows links while signed in with the account, or that
the same identity is used for daily work. Phishing (MITRE ATT&CK T1566)
then lands directly in a Tier 0 session. Microsoft's privileged access /
enterprise access model, the Five Eyes "Detecting and Mitigating Active
Directory Compromises" guidance (2024), ANSSI's AD hardening points and
NIST SP 800-53 AC-6(2) ("non-privileged access for non-security
functions") all require administrative accounts to be separate from
mail- and internet-using daily accounts. A mail/proxyAddresses value on an
admin account is also how Exchange hybrid sync and address-book exposure
make the account's name widely known as a target.

Caveats: mail/proxyAddresses can be set without a mailbox (e.g. for
notifications or by a sync tool); the finding still means the identity is
addressable and should be reviewed. Disabled accounts are excluded (they
cannot sign in; plugin 1042 covers disabled privileged accounts).
Severity: medium. One row per account.
"""

PLUGIN = {
    "plugin_id": 1047,
    "category": "User Accounts",
    "name": "Privileged Account Has a Mailbox or Email Address",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "PRIV-1047",
    "framework_tags": [
        "NIST-800-53-AC-6(2)", "NIST-800-53-AC-2(7)", "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.2", "CIS-CSC-8-5.4", "ISO-27001-2022-A.8.2",
        "SOC2-CC6.3", "HIPAA-164.308(a)(4)(ii)(B)", "MITRE-ATTCK-T1566",
    ],
    "references": [
        {"title": "MITRE ATT&CK T1566: Phishing",
         "url": "https://attack.mitre.org/techniques/T1566/"},
        {"title": "PingCastle health check rules (privileged account hygiene)",
         "url": "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
    ],
    "description": (
        "A Tier 0 (domain-privileged) user account has an e-mail address "
        "(mail or proxyAddresses). Administrative accounts should not "
        "receive mail or be used for daily work: a phishing message opened "
        "under this identity runs with domain-administrative rights. "
        "Microsoft's privileged access guidance, Five Eyes 2024 AD guidance, "
        "ANSSI and NIST AC-6(2) all require separate, mail-less admin accounts."
    ),
    "remediation": (
        "Give the administrator a separate, non-privileged account for mail "
        "and browsing, and remove the mailbox and addresses from the admin "
        "account: disable the mailbox (Disable-Mailbox / Disable-RemoteMailbox "
        "in Exchange), then Set-ADUser <sam> -Clear mail,proxyAddresses. If "
        "the address exists only for alert delivery, route alerts to a "
        "distribution group or the administrator's daily account instead. "
        "Enforce the separation with policy (e.g. block Outlook/browser use on "
        "PAWs and Tier 0 servers) and periodically re-run this check."
    ),
    "base_severity": "medium",
    "query": """
        WITH tier0 AS (
            SELECT object_guid,
                   array_agg(DISTINCT privilege_source ORDER BY privilege_source) AS privilege_sources
            FROM v_privileged_principal
            WHERE client_id = %(client_id)s
            GROUP BY object_guid
        )
        SELECT
            'fail' AS status,
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Tier 0 user account '
                || COALESCE(u.user_principal_name, u.sam_account_name, u.object_guid::text)
                || ' has an e-mail address ('
                || concat_ws(', ',
                       CASE WHEN NULLIF(btrim(u.mail), '') IS NOT NULL THEN 'mail' END,
                       CASE WHEN cardinality(u.proxy_addresses) > 0 THEN 'proxyAddresses' END)
                || ')' AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'user_principal_name', u.user_principal_name,
                'mail', u.mail,
                'proxy_addresses', to_jsonb(u.proxy_addresses),
                'privilege_sources', t.privilege_sources
            ) AS detail
        FROM ad_user u
        JOIN tier0 t ON t.object_guid = u.object_guid
        JOIN directory_object o
          ON o.object_guid = u.object_guid AND o.client_id = u.client_id
         AND NOT o.is_deleted
        WHERE u.client_id = %(client_id)s
          AND u.valid_to IS NULL
          AND u.is_enabled
          AND (NULLIF(btrim(u.mail), '') IS NOT NULL
               OR cardinality(u.proxy_addresses) > 0)
    """,
}
