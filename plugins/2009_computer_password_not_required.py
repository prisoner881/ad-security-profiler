"""
Plugin 2009: Computer Account Does Not Require a Password

PASSWD_NOTREQD on a computer object permits a blank password. Pre-staged
computer accounts (ADUC "New Computer", dsadd computer) are created with
userAccountControl 4128 (WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD) and
the bit usually survives the later join, so the flag alone is hygiene, not
an incident. The real exposure is an account whose password was never
changed since creation: it may be blank or name-derived (pre-Windows 2000
computer / "pre2k"), and anyone can authenticate as it.

[v1.4] The earlier premise ("no normal provisioning sets this flag",
"investigate immediately") was wrong and produced alarming false
positives on every pre-staged machine. Base severity lowered to medium;
raised one step (high, critical on a DC) when the password has never been
changed since the account was created (pwdLastSet unset, or within a
minute of whenCreated), which is marked in the summary. Description and
remediation rewritten.
"""

PLUGIN = {
    "plugin_id": 2009,
    "category": "Computer Accounts",
    "name": "Computer Account Does Not Require a Password",
    "version": "1.4",
    "revision_date": "2026-10-04",
    "remediation": (
        "Clear the flag: Set-ADAccountControl <computer>$ "
        "-PasswordNotRequired $false (or edit userAccountControl). Pre-"
        "staged computer accounts carry it by default, so on its own it is "
        "a hygiene item. If the summary says the password was never "
        "changed since creation, treat it as urgent: the account may have "
        "a blank or name-derived (pre-Windows 2000) password that anyone "
        "can use to authenticate -- reset the machine password (or join "
        "the machine, or delete the account if it was never used) and "
        "check msDS-ReplAttributeMetaData for when userAccountControl and "
        "unicodePwd last changed. Consider stopping pre-staging with the "
        "\"pre-Windows 2000 computer\" option."
    ),
    "control_id": "CRED-103",
    "framework_tags": [],
    "references": [
        {"title": "Microsoft: User Account Control flags (PASSWD_NOTREQD)",
         "url": "https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties"},
    ],
    "description": (
        "The PASSWD_NOTREQD UAC bit (0x0020) permits a blank password, "
        "bypassing password policy entirely. On computer objects it is "
        "common: accounts pre-staged in ADUC or with dsadd are created "
        "with userAccountControl 4128 (WORKSTATION_TRUST_ACCOUNT | "
        "PASSWD_NOTREQD) and the bit normally survives the join, after "
        "which the machine rotates a random password and the flag is "
        "harmless in practice. PingCastle treats it as a hygiene item. "
        "The dangerous case is an account whose password has never been "
        "changed since it was created (pwdLastSet unset or within a "
        "minute of whenCreated): its password may be blank or derived "
        "from the computer name (the \"pre-Windows 2000 computer\" / "
        "pre2k pattern), letting anyone authenticate as it. Rated medium; "
        "one step higher (high) when the password was never changed and "
        "one step higher again on a domain controller. Downgraded by two "
        "steps when disabled: exploiting a blank password requires the "
        "ability to actually authenticate, which a disabled account "
        "cannot do."
    ),
    "base_severity": "medium",
    "query": """
        WITH flagged AS (
            SELECT c.*,
                   (c.pwd_last_set IS NULL
                    OR (c.when_created IS NOT NULL
                        AND c.pwd_last_set <= c.when_created + interval '1 minute')) AS never_rotated
            FROM ad_computer c
            WHERE c.valid_to IS NULL
              AND c.client_id = %(client_id)s
              AND c.user_account_control IS NOT NULL
              AND (c.user_account_control & 32) != 0
        )
        SELECT
            'fail' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE GREATEST(0,
                1
                + (CASE WHEN c.never_rotated THEN 1 ELSE 0 END)
                + (CASE WHEN c.is_domain_controller THEN 1 ELSE 0 END)
                - (CASE WHEN c.is_enabled IS FALSE THEN 2 ELSE 0 END)
            )
                WHEN 3 THEN 'critical'
                WHEN 2 THEN 'high'
                WHEN 1 THEN 'medium'
                ELSE 'low'
            END AS fd_severity,
            (CASE WHEN c.is_domain_controller THEN 'Domain Controller ' ELSE '' END)
                || 'Computer Account ' || COALESCE(c.sam_account_name, c.object_guid::text)
                || ' does not require a password (PASSWD_NOTREQD)'
                || CASE WHEN c.never_rotated
                        THEN ' and its password was never changed since creation'
                        ELSE '' END
                || CASE WHEN c.is_enabled IS FALSE
                        THEN ' (Disabled Account)'
                        ELSE '' END AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'dns_hostname', c.dns_hostname,
                'user_account_control', c.user_account_control,
                'last_logon_timestamp', c.last_logon_timestamp,
                'pwd_last_set', c.pwd_last_set,
                'when_created', c.when_created,
                'password_never_changed', c.never_rotated,
                'is_enabled', c.is_enabled,
                'is_domain_controller', c.is_domain_controller
            ) AS detail
        FROM flagged c
    """,
}
