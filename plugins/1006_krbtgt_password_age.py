"""
Plugin 1006: krbtgt Password Age Exceeds Recommended Rotation Window

The krbtgt account's password (really its NT hash) is what signs every
Kerberos ticket in the domain. An old, unrotated krbtgt password widens
the historical validity window for Golden Ticket forgery if the hash is
ever compromised (e.g. via DCSync) at any point during that span.

[v1.5] The summary now states the password-last-set time as a date (UTC,
to the day) rather than a day count computed from now(). The count
differed on every run, so an unchanged finding was recorded as 'changed'
on every audit; the date only moves when the underlying attribute does.
Severity and inclusion thresholds are unchanged. The day count is still
reported in detail (password_age_days), which is not part of the
finding's identity because object_guid is always set for this plugin.

[v1.6] The domain krbtgt account is now identified by RID 502 (objectSid
ending -502) instead of the sAMAccountName 'krbtgt' alone, and read-only
DC krbtgt accounts (krbtgt_<number>, one per RODC, signing that RODC's
tickets) are also covered. Summary for the domain krbtgt is unchanged;
RODC krbtgt accounts read "RODC krbtgt account <name> ...".

[v1.7] The Microsoft Entra Kerberos server's key account (CN=krbtgt-AzureAD,
sAMAccountName krbtgt_<number>, linked from CN=AzureADKerberos in the Domain
Controllers OU) was already covered as an "RODC krbtgt account"; it is now
named as such, found by its DN or the AzureADKerberos object's link even if
its name changes, and the detail gives the rotation command (Set-
AzureADKerberosServer -RotateServerKey). Microsoft's Entra Kerberos guidance
says to rotate it on the same schedule as krbtgt. Requires schema v46.
"""

PLUGIN = {
    "plugin_id": 1006,
    "category": "User Accounts",
    "name": "krbtgt Account Password Has Not Been Rotated Recently",
    "version": "1.7",
    "revision_date": "2026-10-22",
    "remediation": (
    'Reset the krbtgt password twice, waiting at least 10 hours between resets '
    "(confirmed directly against Microsoft's own AD Forest Recovery guidance; "
    'several independent sources recommend 24 hours for extra safety) to allow '
    'full replication before the second reset -- resetting twice in rapid '
    'succession will invalidate all outstanding Kerberos tickets immediately '
    'and likely require restarting application services domain-wide, and should '
    'only be done that way during active breach recovery, not routine '
    "maintenance. Use a well-tested reset script (Microsoft's own guidance, or "
    'the community-standard Reset-KrbtgtKeyInteractive.ps1) rather than a '
    'manual ad hoc reset, and verify replication has completed to all DCs '
    'before the second reset. For the Microsoft Entra Kerberos key account '
    '(krbtgt-AzureAD), do not reset the password in AD: run '
    'Set-AzureADKerberosServer -RotateServerKey from the '
    'AzureADHybridAuthenticationManagement module (with -SetupCloudTrust when '
    'cloud trust is set up), which updates the key in AD and in Entra ID together.'
),
    "control_id": "CRED-004",
    "framework_tags": [
        "NIST-800-53-AC-2",
        "NIST-800-53-IA-5",
        "NIST-800-53-SC-12",
        "PCI-DSS-4.0-8.6.3",
        "ISO-27001-2022-A.5.17",
        "ISO-27001-2022-A.8.24",
        "SOC2-CC6.1",
        "MITRE-ATTCK-T1558.001",
        "CISA-AA26-237A",
    ],
    "references": [
        {"title": "Microsoft: Passwordless security key sign-in to on-premises resources (rotating the Microsoft Entra Kerberos server key)",
         "url": "https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-passwordless-security-key-on-premises"},
        {"title": "MITRE ATT&CK T1558.001: Steal or Forge Kerberos Tickets -- Golden Ticket",
         "url": "https://attack.mitre.org/techniques/T1558/001/"},
    ],
    "description": (
        "The krbtgt account's password (its NT hash, specifically) signs "
        "every Kerberos ticket issued in the domain. An old, unrotated "
        "krbtgt password widens the window during which a compromised "
        "hash (e.g. via DCSync) could have been used to forge a Golden "
        "Ticket. Microsoft's own guidance recommends periodic rotation "
        "(twice, 24 hours apart, to fully invalidate old tickets) rather "
        "than leaving this password unchanged indefinitely. No specific "
        "DISA AD STIG rule with a numeric threshold was identified for "
        "this; the 180-day threshold used here is a reasonable, "
        "commonly-cited interval, not a cited standard. Note: krbtgt is "
        "always disabled by design -- unrelated to the actual risk "
        "(cryptographic exposure of the ticket-signing key), so no "
        "disabled-account severity adjustment applies here the way it "
        "does elsewhere; this account's disabled state is permanent and "
        "normal, not a mitigation being evaluated. Covers the domain "
        "krbtgt account (RID 502) and each read-only DC's krbtgt_<number> "
        "account (reset by resetting it directly or by re-creating the "
        "RODC's account), and the Microsoft Entra Kerberos server's "
        "krbtgt-AzureAD account, whose key Entra ID uses to issue partial "
        "TGTs for the domain (Windows Hello cloud trust, FIDO2 and Azure "
        "Files sign-in); Microsoft says to rotate it on the krbtgt schedule."
    ),
    "base_severity": "medium",
    "query": """
        SELECT
            'fail' AS status,
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            (CASE WHEN o.object_sid LIKE '%%-502' THEN 'krbtgt account'
                  WHEN ek.is_entra THEN 'Microsoft Entra Kerberos server key account '
                       || COALESCE(u.sam_account_name, u.object_guid::text) || ' (krbtgt-AzureAD)'
                  ELSE 'RODC krbtgt account ' || COALESCE(u.sam_account_name, u.object_guid::text)
             END)
                || ' password has not been changed since '
                || to_char(u.pwd_last_set AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'object_sid', o.object_sid,
                'is_rodc_krbtgt', o.object_sid IS DISTINCT FROM NULL AND o.object_sid NOT LIKE '%%-502'
                                  AND NOT ek.is_entra,
                'is_entra_kerberos_krbtgt', ek.is_entra,
                'rotation', CASE WHEN ek.is_entra
                                 THEN 'Set-AzureADKerberosServer -Domain <domain> -UserPrincipalName '
                                      || '<admin UPN> -RotateServerKey (add -SetupCloudTrust when cloud '
                                      || 'trust is configured), twice to retire the old key'
                            END,
                'pwd_last_set', u.pwd_last_set,
                'password_age_days', EXTRACT(DAY FROM now() - u.pwd_last_set)::int
            ) AS detail
        FROM ad_user u
        JOIN directory_object o
            ON o.object_guid = u.object_guid AND o.client_id = u.client_id
        -- [v1.7] the Microsoft Entra Kerberos server's key account: CN krbtgt-AzureAD
        -- (sAMAccountName krbtgt_<number>), linked from the AzureADKerberos object
        CROSS JOIN LATERAL (
            -- ('_' in LIKE matches the '-' and '_' spellings both)
            SELECT (lower(o.dn_current) LIKE 'cn=krbtgt_azuread,%%'
                    OR EXISTS (SELECT 1 FROM ad_computer c
                               WHERE c.client_id = u.client_id AND c.valid_to IS NULL
                                 AND lower(c.krbtgt_link) = lower(o.dn_current)
                                 AND is_entra_kerberos_server(c.sam_account_name, c.krbtgt_link))
                   ) AS is_entra
        ) ek
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          -- [v1.6] domain krbtgt by RID 502; RODC krbtgt_<number> by name
          -- (their RIDs are ordinary).
          AND (o.object_sid LIKE '%%-502'
               OR u.sam_account_name ~ '^krbtgt_[0-9]+$'
               OR ek.is_entra)
          AND u.pwd_last_set IS NOT NULL
          AND u.pwd_last_set < now() - interval '180 days'
    """,
}
