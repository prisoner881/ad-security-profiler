"""
Plugin 1004: Built-in Administrator Account Enabled

The RID-500 built-in Administrator account is a predictable, unrenameable
(by RID) target with one property that makes it worse than an ordinary
privileged account: it is hardcoded immune to account lockout policy,
regardless of how lockoutThreshold is configured domain-wide.

[v1.4] Rationale and mappings corrected. The "hardcoded immune to lockout"
claim is outdated: whether the RID-500 account locks out depends on
pwdProperties DOMAIN_LOCKOUT_ADMINS (0x8, ad_domain.pwd_allows_admin_lockout)
and, since KB5020282 (Oct 2022), the "Allow Administrator account lockout"
policy -- detail now carries the domain flag and lockout threshold instead of
asserting immunity. The CAT II STIG mapping (WN10-SO-000005, a Windows 10
LOCAL-account rule) is dropped: no DISA STIG requires the domain RID-500
account to be disabled; Microsoft's "Appendix D: Securing Built-In
Administrator Accounts in Active Directory" recommends restricting it
(smart card, sensitive and cannot be delegated, deny network/RDP/batch/
service logon). Severity is now medium, high when the account has logged on
within the last 90 days (lastLogonTimestamp) -- PingCastle reports on use of
this account, not on its enabled state. Summary unchanged.
"""

PLUGIN = {
    "plugin_id": 1004,
    "category": "User Accounts",
    "name": "Built-in Administrator Account Is Enabled",
    "version": "1.4",
    "revision_date": "2026-10-04",
    "remediation": (
    'Stop using the account for day-to-day administration: ensure named, '
    'individually-attributable administrative accounts exist to cover whatever '
    'this account was being used for, then either disable it '
    '(`Disable-ADAccount`) or, if it must stay enabled as a break-glass '
    "account, secure it per Microsoft's Appendix D: set \"Account is "
    'sensitive and cannot be delegated" and "Smart card is required for '
    'interactive logon", deny it network, batch, service and Remote Desktop '
    'logon via GPO on all member systems, and alert on its use. Enable '
    'administrator lockout (pwdProperties DOMAIN_LOCKOUT_ADMINS / the "Allow '
    'Administrator account lockout" policy, KB5020282). Renaming the account '
    'is complementary only -- it is still RID 500 regardless of its name.'
),
    "control_id": "PRIV-101",
    "framework_tags": [
        "NIST-800-53-IA-2",
        "NIST-800-53-IA-4",
        "NIST-800-53-AC-2(9)",
        "NIST-800-53-AC-2(7)",
        "NIST-800-53-AC-6(5)",
        "NIST-800-53-AC-6(2)",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-8.2.1",
        "PCI-DSS-4.0-8.2.2",
        "PCI-DSS-4.0-2.2.2",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.2",
        "CIS-CSC-8-5.4",
        "CIS-CSC-8-4.7",
        "CIS-CSC-8-6.8",
        "ISO-27001-2022-A.8.2",
        "ISO-27001-2022-A.5.16",
        "SOC2-CC6.1",
        "SOC2-CC6.3",
        "HIPAA-164.312(a)(2)(i)",
        "HIPAA-164.308(a)(4)(ii)(B)",
        "MITRE-ATTCK-T1078.001",
    ],
    "references": [
        {"title": "Microsoft: Appendix D -- Securing Built-In Administrator Accounts in Active Directory",
         "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-d--securing-built-in-administrator-accounts-in-active-directory"},
        {"title": "Microsoft KB5020282: Account lockout available for built-in local administrators",
         "url": "https://support.microsoft.com/help/5020282"},
    ],
    "description": (
        "The built-in Administrator account (RID 500) should be disabled, "
        "or restricted as a break-glass account, in favor of named, "
        "individually-attributable administrative accounts (Microsoft "
        "'Appendix D: Securing Built-In Administrator Accounts in Active "
        "Directory'). It is a predictable, always-present Domain Admin "
        "target; historically it was exempt from account lockout, and it "
        "still is unless pwdProperties DOMAIN_LOCKOUT_ADMINS / the 'Allow "
        "Administrator account lockout' policy (KB5020282) is in effect "
        "(the domain flag is shown in detail). Severity is medium, high "
        "when the account has logged on in the last 90 days -- active use "
        "of a shared, non-attributable admin account (PingCastle "
        "P-AdminLogin). Detected by RID (the "
        "trailing -500 in the account's SID), not by name -- STIG "
        "guidance separately recommends renaming this account, and a "
        "rename does not change its RID, so a name-only check would miss "
        "a renamed-but-still-enabled instance of this exact account."
    ),
    "base_severity": "medium",
    "query": """
        SELECT
            'fail' AS status,
            u.object_guid,
            -- [v1.4] No DISA STIG requires the DOMAIN RID-500 account to be
            -- disabled (WN10-SO-000005 is a Windows 10 local-account rule).
            NULL AS stig_severity,
            NULL AS stig_reference,
            'medium' AS tool_severity,
            'PingCastle P-AdminLogin (use of the built-in Administrator); '
                'Microsoft AD security best practices, Appendix D' AS tool_reference,
            -- [v1.4] high only when the account is actually in use.
            CASE WHEN u.last_logon_timestamp > now() - interval '90 days'
                 THEN 'high' ELSE 'medium' END AS fd_severity,
            'Built-in Administrator account (RID 500, currently named "' || u.sam_account_name
                || '") is enabled' AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'object_sid', do2.object_sid,
                'pwd_last_set', u.pwd_last_set,
                'password_age_days', CASE WHEN u.pwd_last_set IS NOT NULL
                                           THEN EXTRACT(DAY FROM now() - u.pwd_last_set)::int
                                           ELSE NULL END,
                'last_logon_timestamp', u.last_logon_timestamp,
                'pwd_never_expires', u.pwd_never_expires,
                'smartcard_required', u.smartcard_required,
                'recently_used_90d', COALESCE(u.last_logon_timestamp > now() - interval '90 days', false),
                -- [v1.4] whether lockout can apply (pwdProperties 0x8);
                -- NULL when no current domain row was collected.
                'domain_pwd_allows_admin_lockout', dom.pwd_allows_admin_lockout,
                'domain_lockout_threshold', dom.lockout_threshold
            ) AS detail
        FROM ad_user u
        JOIN directory_object do2
            ON do2.object_guid = u.object_guid AND do2.client_id = u.client_id
        LEFT JOIN LATERAL (
            SELECT d.pwd_allows_admin_lockout, d.lockout_threshold
            FROM ad_domain d
            WHERE d.client_id = u.client_id AND d.valid_to IS NULL
            ORDER BY d.object_guid
            LIMIT 1
        ) dom ON true
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          AND u.is_enabled
          AND do2.object_sid LIKE '%%-500'
    """,
}
