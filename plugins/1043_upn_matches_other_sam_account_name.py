"""
Plugin 1043: User Principal Name Matches Another Account's sAMAccountName

Direct indicator for ResetNightmare (CVE-2026-27912), disclosed by Semperis in
2026 and patched by Microsoft in April 2026. The vulnerability allows an
attacker holding generic write over any single user or computer object -- or
merely the ability to create one -- to take over the domain outright.

The mechanism is a name-type confusion that survives the noPac hardening:

  1. The attacker sets a controlled account's userPrincipalName to the
     *sAMAccountName* of a privileged target, for example "DemoAdmin1". This
     is permitted and does not trip UPN uniqueness verification, because the
     target's real UPN is "DemoAdmin1@corp.example" and the two strings are
     not identical.
  2. A TGT is requested using the NT-ENTERPRISE name type, which resolves
     principals by userPrincipalName rather than sAMAccountName. The KDC
     returns a ticket bearing the target's name. The PAC still carries the
     attacker's own PAC_REQUESTOR_SID, so this ticket cannot be used for
     impersonation -- the CVE-2021-42287 patch blocks that.
  3. But the Kerberos Change Password protocol (kpasswd, port 464) goes
     straight from the TGT to an AP-REQ with no intervening TGS exchange --
     and the TGS exchange is precisely where PAC_REQUESTOR_SID is validated.
     Using that ticket to issue a password change resets the *target's*
     password.
  4. The attacker then authenticates as the target normally.

Every user can change their own password by default, so step 3 needs no
special right. The only precondition beyond write access to one UPN is that
the target's password is older than the domain minimum password age, which
defaults to one day.

Detection is exact and cheap: a userPrincipalName whose entire value equals
some other account's sAMAccountName. That configuration has no legitimate
purpose. A normal UPN is either user@domain or, at minimum, not a verbatim
copy of a different principal's logon name.

Deliberately NOT matched: the case where the local part of a UPN (before the
@) equals another account's sAMAccountName. In a healthy directory
jdoe@corp.example and sAMAccountName jdoe belong to the same person, and
across a multi-domain forest collisions between different people are routine.
Including that comparison would bury the exact match this plugin exists to
find. Only the full-string match is reported.

[v1.1] Offending accounts now include computer objects (and gMSAs/sMSAs,
which are collected as computers): schema v36 collects userPrincipalName
for them (ad_computer.user_principal_name). A computer created through
ms-DS-MachineAccountQuota by any authenticated user, with its UPN set to
a privileged account's sAMAccountName, is the zero-privilege variant of
this attack and was invisible before. The impersonated account's
adminCount and pwdLastSet are now also read for computer targets.
"""

PLUGIN = {
    "plugin_id": 1043,
    "category": "User Accounts",
    "name": "User Principal Name Matches Another Account's sAMAccountName",
    "version": "1.1",
    "revision_date": "2026-10-04",
    "remediation": (
        "Treat this as a live privilege escalation attempt until proven "
        "otherwise, particularly where the impersonated account is "
        "privileged. There is no legitimate configuration in which one "
        "account's userPrincipalName is a verbatim copy of another account's "
        "sAMAccountName. "
        "Immediate actions: clear or correct the offending "
        "userPrincipalName (Set-ADUser <account> -UserPrincipalName "
        "<account>@<domain>; for a computer or gMSA use Set-ADComputer / "
        "Set-ADServiceAccount, normally clearing the UPN entirely); reset the password of the impersonated target, "
        "because ResetNightmare works by resetting it and the attacker may "
        "already hold the new value; and review authentication activity for "
        "the target account. Security event ID 4738 (user account changed) on "
        "domain controllers identifies who set the UPN, and event 4724 "
        "records the password reset if it occurred. "
        "Then close the path. Confirm domain controllers carry the April 2026 "
        "update that patches CVE-2026-27912. Audit who holds write access to "
        "userPrincipalName on user and computer objects -- that single right "
        "is the whole precondition, and it is commonly granted to helpdesk "
        "tiers through generic write delegations that were never intended to "
        "reach Domain Admin. Raising the domain minimum password age above "
        "zero does not prevent the attack but does narrow the window, since "
        "the target's password must exceed it. Finally, enable SACL auditing "
        "on userPrincipalName so Security event 5136 records future changes."
    ),
    "control_id": "KERB-204",
    "framework_tags": ["MITRE-ATTCK-T1558", "MITRE-ATTCK-T1098",
                       "MITRE-ATTCK-T1078.002", "CVE-2026-27912"],
    "references": [
        {"title": "Semperis: KerberLoss and ResetNightmare -- Kerberos downgrade and full domain takeover",
         "url": "https://www.semperis.com/blog/identity-crisis-novel-vulnerabilities-leading-to-kerberos-downgrade-dos-and-full-domain-takeover/"},
        {"title": "MS-KILE: Kerberos name types and NT-ENTERPRISE principal resolution",
         "url": "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/b4af186e-b2ff-43f9-b18e-eedb366abf13"},
    ],
    "description": (
        "Reports a user, computer or managed service account whose userPrincipalName is a verbatim copy of "
        "a different account's sAMAccountName. This is the direct "
        "configuration signature of ResetNightmare (CVE-2026-27912): because "
        "Kerberos can resolve principals by UPN using the NT-ENTERPRISE name "
        "type, and because the Kerberos Change Password protocol skips the "
        "PAC_REQUESTOR_SID validation that blocks other name-confusion "
        "attacks, an attacker able to write one UPN can reset the "
        "impersonated account's password and take it over. UPN uniqueness "
        "verification does not prevent this, because the strings compared are "
        "a UPN and a sAMAccountName rather than two UPNs. Severity is raised "
        "to critical when the impersonated account is privileged."
    ),
    "base_severity": "critical",
    "query": """
        WITH privileged_roots AS (
            SELECT g.object_guid, g.sam_account_name
            FROM ad_group g
            JOIN directory_object gdo
                ON gdo.object_guid = g.object_guid AND gdo.client_id = g.client_id
            WHERE g.valid_to IS NULL
              AND g.client_id = %(client_id)s
              AND (gdo.object_sid LIKE '%%-512' OR gdo.object_sid LIKE '%%-516'
                   OR gdo.object_sid LIKE '%%-517' OR gdo.object_sid LIKE '%%-518'
                   OR gdo.object_sid LIKE '%%-519' OR gdo.object_sid LIKE '%%-520'
                   OR gdo.object_sid LIKE '%%-521' OR gdo.object_sid LIKE '%%-526'
                   OR gdo.object_sid LIKE '%%-527' OR gdo.object_sid LIKE '%%-544'
                   OR gdo.object_sid LIKE '%%-548' OR gdo.object_sid LIKE '%%-549'
                   OR gdo.object_sid LIKE '%%-550' OR gdo.object_sid LIKE '%%-551'
                   OR gdo.object_sid LIKE '%%-552')
        ),
        privileged_members AS (
            SELECT vem.member_guid,
                   array_agg(DISTINCT pr.sam_account_name ORDER BY pr.sam_account_name)
                       AS via_groups
            FROM v_effective_group_membership vem
            JOIN privileged_roots pr ON pr.object_guid = vem.group_guid
            WHERE vem.client_id = %(client_id)s
            GROUP BY vem.member_guid
        ),
        -- [v1.1] Offending accounts: users, and computers (incl. gMSA/sMSA)
        -- whose UPN is collected since schema v36.
        offender AS (
            SELECT u.object_guid, u.sam_account_name, u.user_principal_name,
                   u.is_enabled, u.when_created
            FROM ad_user u
            WHERE u.valid_to IS NULL
              AND u.client_id = %(client_id)s
              AND u.user_principal_name IS NOT NULL
              AND u.user_principal_name <> ''
            UNION ALL
            SELECT c.object_guid, c.sam_account_name, c.user_principal_name,
                   c.is_enabled, c.when_created
            FROM ad_computer c
            WHERE c.valid_to IS NULL
              AND c.client_id = %(client_id)s
              AND c.user_principal_name IS NOT NULL
              AND c.user_principal_name <> ''
        ),
        -- Candidate impersonation targets: any user or computer principal.
        -- Groups are excluded because Kerberos resolves security principals,
        -- not groups, so a UPN matching a group name is not exploitable.
        principal AS (
            SELECT do2.object_guid, do2.sam_account_name, do2.dn_current,
                   do2.object_class
            FROM directory_object do2
            WHERE do2.client_id = %(client_id)s
              AND do2.sam_account_name IS NOT NULL
              AND do2.sam_account_name <> ''
              AND do2.object_class IN ('user', 'computer')
              AND NOT do2.is_deleted
        )
        -- DISTINCT ON is defensive. sAMAccountName is unique per domain,
        -- so a UPN can match at most one principal and this should never
        -- collapse anything. But if collected data ever contains a
        -- duplicate sAMAccountName, two rows would share one object_guid
        -- and collide on the evidence table's identity constraint,
        -- failing the whole plugin rather than degrading gracefully.
        SELECT DISTINCT ON (u.object_guid)
            'fail' AS status,
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE
                WHEN tpm.via_groups IS NOT NULL OR tu.admin_count = 1
                    THEN 'critical'
                ELSE 'high'
            END AS fd_severity,
            'Account "' || COALESCE(u.sam_account_name, odo.dn_current)
                || '" has a userPrincipalName of "' || u.user_principal_name
                || '", which is a verbatim copy of the sAMAccountName of "'
                || p.sam_account_name || '"'
                || CASE
                       WHEN tpm.via_groups IS NOT NULL
                           THEN ' -- a PRIVILEGED account (effective member of '
                                || array_to_string(tpm.via_groups, ', ') || ')'
                       WHEN tu.admin_count = 1
                           THEN ' -- an account carrying the AdminSDHolder marker'
                       ELSE ''
                   END
                || '. This is the configuration signature of ResetNightmare '
                   '(CVE-2026-27912)' AS summary,
            jsonb_build_object(
                'offending_account', u.sam_account_name,
                'offending_object_class', odo.object_class,
                'offending_account_dn', odo.dn_current,
                'offending_account_enabled', u.is_enabled,
                'offending_user_principal_name', u.user_principal_name,
                'offending_when_created', u.when_created,
                'impersonated_account', p.sam_account_name,
                'impersonated_account_dn', p.dn_current,
                'impersonated_object_class', p.object_class,
                'impersonated_is_privileged',
                    tpm.via_groups IS NOT NULL OR tu.admin_count = 1,
                'impersonated_privileged_via_groups', tpm.via_groups,
                'impersonated_admin_count', tu.admin_count,
                'impersonated_pwd_last_set', tu.pwd_last_set,
                'corroborating_event_ids', jsonb_build_array(4738, 4724, 5136)
            ) AS detail
        FROM offender u
        JOIN directory_object odo
            ON odo.object_guid = u.object_guid AND odo.client_id = %(client_id)s
        JOIN principal p
            ON lower(p.sam_account_name) = lower(u.user_principal_name)
           AND p.object_guid <> u.object_guid
        LEFT JOIN LATERAL (
            -- [v1.1] adminCount / pwdLastSet of the target, user or computer.
            SELECT x.admin_count, x.pwd_last_set
            FROM (
                SELECT au.admin_count, au.pwd_last_set
                FROM ad_user au
                WHERE au.object_guid = p.object_guid AND au.client_id = %(client_id)s
                  AND au.valid_to IS NULL
                UNION ALL
                SELECT ac.admin_count, ac.pwd_last_set
                FROM ad_computer ac
                WHERE ac.object_guid = p.object_guid AND ac.client_id = %(client_id)s
                  AND ac.valid_to IS NULL
            ) x
            LIMIT 1
        ) tu ON TRUE
        LEFT JOIN privileged_members tpm ON tpm.member_guid = p.object_guid
        ORDER BY u.object_guid, p.sam_account_name
    """,
}
