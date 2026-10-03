"""
Plugin 10008: Seamless SSO Account (AZUREADSSOACC$) Kerberos Key Not Rotated

Derived from CISA advisory AA26-237A (2026-08-25). In the Water and
Wastewater Systems assessment, the red team's route from on-premises
domain compromise into the cloud tenant ran through Microsoft Entra
Seamless Single Sign-On: with the AZUREADSSOACC$ account's Kerberos
key in hand, they forged service tickets and authenticated to Entra ID
as arbitrary synced users -- without ever needing those users'
passwords, and without touching a password reset that anyone would
notice.

AZUREADSSOACC$ is an ordinary computer object created in AD when
Seamless SSO is enabled. Its password is the Kerberos decryption key
for the AZUREADSSO service, and unlike a normal computer account it
does NOT roll automatically: Microsoft's documented guidance is to
rotate it manually at least every 30 days. In practice it is created
once during the Entra Connect deployment and then forgotten for years,
which means a single DCSync at any point in that window yields a
durable, silent forgery capability against the entire cloud tenant.

This is a Golden-Ticket-equivalent for Entra ID, and it is one of the
few Tier 0 secrets whose staleness is directly observable from ordinary
LDAP data -- pwdLastSet on a computer object -- which is why it belongs
in this project even though the consequence is entirely cloud-side.

Reports the account's absence as nothing at all: if Seamless SSO is not
deployed, the object does not exist and this plugin correctly returns
no rows.

[v1.1] The summary now states the key's last rotation time as a date
(UTC, to the day) rather than a day count computed from now(). The count
differed on every run, so an unchanged finding was recorded as 'changed'
on every audit; the date only moves when the underlying attribute does.
Severity and inclusion thresholds are unchanged. The day count is still
reported in detail (key_age_days), which is not part of the finding's
identity because object_guid is always set for this plugin.
"""

PLUGIN = {
    "plugin_id": 10008,
    "category": "Hybrid Identity",
    "name": "Seamless SSO Account (AZUREADSSOACC$) Kerberos Key Not Rotated",
    "version": "1.1",
    "revision_date": "2026-10-03",
    "remediation": (
        "Roll the AZUREADSSOACC$ Kerberos decryption key, then put the "
        "rotation on a recurring schedule of 30 days or less. On the "
        "Entra Connect server, in an elevated PowerShell session: "
        "import the Seamless SSO module (Import-Module "
        "'<Entra Connect install path>\\\\AzureADSSO.psd1'), run "
        "New-AzureADSSOAuthenticationContext and authenticate as a "
        "Hybrid Identity Administrator, then call "
        "Update-AzureADSSOForest -OnPremCredentials <Domain Admin "
        "credential> for each forest where Seamless SSO is enabled. "
        "The operation is non-disruptive to signed-in users -- it "
        "updates the key, it does not invalidate existing sessions. "
        "Because rotation requires Domain Admin credentials against "
        "the forest, schedule it as a controlled privileged task "
        "rather than delegating it broadly. If the reported age is "
        "large, assume the prior key should be treated as potentially "
        "known: rotate, then review Entra ID sign-in logs for the "
        "affected window, filtering for sign-ins that used Kerberos/"
        "Seamless SSO from unexpected source addresses. If Seamless "
        "SSO is no longer used (for example, after moving to "
        "certificate-based or cloud-native authentication), disable "
        "the feature and delete the AZUREADSSOACC$ object outright -- "
        "an unrotated key on an unused feature is pure liability."
    ),
    "control_id": "HYBRID-408",
    "framework_tags": ["CISA-AA26-237A", "MITRE-ATTCK-T1558", "MITRE-ATTCK-T1550.003",
                       "MITRE-ATTCK-T1098.001"],
    "references": [
        {"title": "CISA AA26-237A: Joint Red Team Assessment Findings",
         "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-237a"},
        {"title": "Microsoft: Entra Connect Seamless SSO -- how to roll over the Kerberos decryption key",
         "url": "https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sso-faq"},
    ],
    "description": (
        "The AZUREADSSOACC$ computer account holds the Kerberos "
        "decryption key for Microsoft Entra Seamless SSO. Anyone who "
        "obtains that key -- via DCSync, a DC compromise, or a backup "
        "of the directory -- can forge Kerberos service tickets and "
        "authenticate to Entra ID as any synced user, with no "
        "knowledge of those users' passwords and no password reset to "
        "alert on. Unlike ordinary computer accounts, this account's "
        "password does not roll on its own; Microsoft's guidance is a "
        "manual rotation at least every 30 days, and in most "
        "environments it has not been rotated since the day Entra "
        "Connect was deployed. CISA's AA26-237A red team assessment "
        "used precisely this technique to pivot from on-premises "
        "domain compromise into the cloud tenant. This finding reports "
        "the account's key age; it does not indicate the key has been "
        "stolen, only that the window in which a theft would remain "
        "useful is unbounded."
    ),
    "base_severity": "high",
    "query": """
        SELECT
            'fail' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE
                WHEN c.pwd_last_set IS NULL THEN 'high'
                WHEN c.pwd_last_set < now() - interval '180 days' THEN 'critical'
                ELSE 'high'
            END AS fd_severity,
            'Seamless SSO account AZUREADSSOACC$ Kerberos decryption key '
                || CASE
                       WHEN c.pwd_last_set IS NULL
                           THEN 'has no recorded rotation date'
                       ELSE 'has not been rotated since '
                            || to_char(c.pwd_last_set AT TIME ZONE 'UTC', 'YYYY-MM-DD')
                   END
                || ' (Microsoft guidance: at least every 30 days) -- anyone holding '
                   'this key can forge Kerberos tickets and sign in to Entra ID as '
                   'any synced user' AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'distinguished_name', do2.dn_current,
                'pwd_last_set', c.pwd_last_set,
                'key_age_days',
                    CASE WHEN c.pwd_last_set IS NULL THEN NULL
                         ELSE EXTRACT(DAY FROM now() - c.pwd_last_set)::int END,
                'recommended_max_age_days', 30,
                'is_enabled', c.is_enabled,
                'supported_encryption_types', c.supported_encryption_types,
                'when_created', c.when_created
            ) AS detail
        FROM ad_computer c
        JOIN directory_object do2
            ON do2.object_guid = c.object_guid AND do2.client_id = c.client_id
        WHERE c.valid_to IS NULL
          AND c.client_id = %(client_id)s
          AND upper(c.sam_account_name) = 'AZUREADSSOACC$'
          AND (c.pwd_last_set IS NULL OR c.pwd_last_set < now() - interval '30 days')
    """,
}
