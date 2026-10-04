"""
Plugin 2031: Enabled Computer Account With No Password Ever Set

Automated provisioning tools (or legacy utilities such as dsadd) can
pre-create a computer account in Active Directory ahead of the actual
machine joining the domain. That pre-created object is deliberately
left with no password until the real join happens -- the join process
is what sets it. If the machine never actually joins (the project is
cancelled, the hardware is repurposed before setup finishes, or the
pre-creation was simply forgotten), the object is left permanently in
that no-password state: enabled, but with pwd_last_set never having
been set at all. Since a computer account with a known, predictable,
unset credential state is a soft target, an attacker who can identify
one of these objects has a much easier path to acting as that
computer than a normally-provisioned account would allow.

[v1.1] Severity now reflects whether a blank password is actually
permitted: with PASSWD_NOTREQD (UAC 0x20) set the account may have an
empty password, so the finding is HIGH; without it, MEDIUM as before
(summary unchanged). Also covers the more common exploitable pre-created
case this check used to miss: an account created in ADUC with "Assign
this computer account as a pre-Windows 2000 computer" gets the lowercase
computer name (without '$', truncated to 14 characters) as its password,
so pwdLastSet is non-zero; it is recognised as UAC
WORKSTATION_TRUST_ACCOUNT|PASSWD_NOTREQD (4128) with no logon ever
recorded, and reported as HIGH with its own summary. Detail adds
user_account_control, passwd_notreqd, last_logon_timestamp,
never_logged_on and the matched condition.
"""

PLUGIN = {
    "plugin_id": 2031,
    "category": "Computer Accounts",
    "name": "Enabled Computer Account With No Password Ever Set",
    "version": "1.1",
    "revision_date": "2026-10-04",
    "remediation": (
        "Confirm whether this computer account actually corresponds to "
        "a machine that is expected to join the domain soon. If the "
        "join was completed under a different computer object, or the "
        "provisioning was abandoned, disable or delete this orphaned "
        "pre-created account -- there is no reason to leave an enabled "
        "account with no password ever set sitting in the directory "
        "indefinitely. For a pre-Windows 2000 pre-created account "
        "(UAC 4128, never logged on), its password is the lowercase "
        "computer name: reset it to a random value or delete the account."
    ),
    "control_id": "HYGIENE-201",
    "framework_tags": [],
    "references": [
        {"title": "TrustedSec: Diving into Pre-Created Computer Accounts",
         "url": "https://www.trustedsec.com/blog/diving-into-pre-created-computer-accounts"},
    ],
    "description": (
        "Automated provisioning tools can pre-create a computer "
        "account ahead of the actual machine joining the domain, "
        "deliberately left with no password until the join process "
        "sets one. If the machine never actually joins, the object is "
        "left permanently enabled with pwd_last_set never having been "
        "set at all -- a soft target with a known, predictable, unset "
        "credential state. Confirmed against Purple Knight's own "
        "equivalent check. Rated high when PASSWD_NOTREQD (UAC 0x20) "
        "permits a blank password. Also reports pre-Windows 2000 "
        "pre-created computer accounts (UAC 4128 = "
        "WORKSTATION_TRUST_ACCOUNT|PASSWD_NOTREQD, never logged on), "
        "whose password is the lowercase computer name (TrustedSec "
        "'pre2k')."
    ),
    "base_severity": "medium",
    "query": """
        WITH k AS (
            SELECT c.*,
                   (COALESCE(c.user_account_control, 0) & 32) <> 0 AS passwd_notreqd,
                   CASE WHEN c.pwd_last_set IS NULL THEN 'no_password_set'
                        ELSE 'pre_windows_2000' END AS condition
            FROM ad_computer c
            WHERE c.valid_to IS NULL
              AND c.client_id = %(client_id)s
              AND c.is_enabled
              AND (c.pwd_last_set IS NULL
                   OR ((c.user_account_control & 4128) = 4128
                       AND c.last_logon_timestamp IS NULL))
        )
        SELECT
            'warn' AS status,
            k.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN k.passwd_notreqd THEN 'high' ELSE 'medium' END AS fd_severity,
            'Computer Account ' || COALESCE(k.sam_account_name, k.object_guid::text)
                || CASE WHEN k.condition = 'no_password_set'
                        THEN ' is enabled but has never had a password set'
                             || CASE WHEN k.passwd_notreqd
                                     THEN ' and PASSWD_NOTREQD permits a blank password' ELSE '' END
                        ELSE ' is an enabled pre-Windows 2000 pre-created account that has never '
                             'logged on (its password is likely the lowercase computer name)'
                   END AS summary,
            jsonb_build_object(
                'sam_account_name', k.sam_account_name,
                'condition', k.condition,
                'user_account_control', k.user_account_control,
                'passwd_notreqd', k.passwd_notreqd,
                'pwd_last_set', k.pwd_last_set,
                'last_logon_timestamp', k.last_logon_timestamp,
                'never_logged_on', k.last_logon_timestamp IS NULL
            ) AS detail
        FROM k
    """,
}
