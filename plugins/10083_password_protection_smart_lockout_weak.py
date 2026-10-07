"""
Plugin 10083: Password Protection and Smart Lockout Not Hardened

Reads the "Password Rule Settings" directory setting (entra_tenant_setting
'password_rule_settings', schema v42: the /groupSettings object stored as
{name: value}) and reports, in one tenant-level finding, the settings that
weaken Entra's defences against password spraying and guessing:
- on-premises Microsoft Entra Password Protection disabled
  (EnableBannedPasswordCheckOnPremises false) or still in audit mode
  (BannedPasswordCheckOnPremisesMode 'Audit') -> medium. In audit mode the
  DC agents only log weak passwords, so AD keeps accepting them -- and those
  passwords are synchronised to Entra by password hash sync;
- custom banned-password list disabled (EnableBannedPasswordCheck false) or
  empty (BannedPasswordList) -> low (organisation-specific terms such as
  the company, product and city names are not blocked);
- smart lockout threshold (LockoutThreshold) above 10 failed attempts ->
  medium;
- smart lockout duration (LockoutDurationInSeconds) below 60 seconds -> low.
Worst wins: any medium -> medium 'fail', only low -> low 'warn'.

Defaults: when directory_settings was read ('ok') but no Password Rule
Settings object exists, Microsoft's defaults apply: custom banned list off,
LockoutThreshold 10, LockoutDurationInSeconds 60,
EnableBannedPasswordCheckOnPremises true, BannedPasswordCheckOnPremisesMode
'Audit' -- so an untouched tenant is reported (audit mode, no custom list).
Keys absent from an existing object take the same defaults.

Hybrid only: the on-premises checks are skipped when the organization
setting (entra_tenant_setting 'organization') was read and
onPremisesSyncEnabled is not true (cloud-only tenant: no DCs to protect).
When the organization object is unavailable they are evaluated (stated in
detail).

Why it matters: NIST IA-5(1) (prohibited-password list), AC-7 (unsuccessful
logon attempts); PCI DSS 8.3.4 (lockout); MITRE T1110.003 Password
Spraying. The Entra global banned list is always on in the cloud; the
on-premises agents are what extend it to AD.

Data caveats: requires_sources ['directory_settings']. Values arrive as
strings ('True', 'Audit', '10'); booleans and modes are compared
case-insensitively and non-numeric numbers are ignored.

object_guid: md5('10083:' || client_id).
"""

PLUGIN = {
    "plugin_id": 10083,
    "category": "Hybrid Identity",
    "name": "Password Protection and Smart Lockout Not Hardened",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10083",
    "requires_sources": ["directory_settings"],
    "framework_tags": [
        "NIST-800-53-IA-5(1)",
        "NIST-800-53-AC-7",
        "NIST-800-53-IA-5",
        "NIST-CSF-2.0-PR.AA-01",
        "PCI-DSS-4.0-8.3.4",
        "PCI-DSS-4.0-8.3.6",
        "CIS-CSC-8-5.2",
        "ISO-27001-2022-A.5.17",
        "SOC2-CC6.1",
        "HIPAA-164.308(a)(5)(ii)(D)",
        "MITRE-ATTCK-T1110.003",
    ],
    "references": [
        {"title": "Microsoft: Eliminate bad passwords using Microsoft Entra Password Protection",
         "url": "https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad"},
        {"title": "Microsoft: Enable on-premises Microsoft Entra Password Protection",
         "url": "https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-ban-bad-on-premises-operations"},
        {"title": "Microsoft: Protect user accounts from attacks with Microsoft Entra smart lockout",
         "url": "https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout"},
        {"title": "MITRE ATT&CK T1110.003: Password Spraying",
         "url": "https://attack.mitre.org/techniques/T1110/003/"},
    ],
    "description": (
        "Entra password protection / smart lockout settings are weak: "
        "on-premises Password Protection disabled or in audit mode, or smart "
        "lockout threshold above 10 (medium); custom banned-password list "
        "off or empty, or lockout duration under 60 seconds (low). Defaults "
        "apply when no Password Rule Settings object exists, so an "
        "untouched hybrid tenant is reported for audit mode."
    ),
    "remediation": (
        "Entra admin center -> Protection -> Authentication methods -> "
        "Password protection: set Lockout threshold to 10 or less, Lockout "
        "duration to 60 seconds or more, 'Enforce custom list' = Yes with "
        "organisation-specific terms, 'Enable password protection on Windows "
        "Server Active Directory' = Yes and Mode = Enforced (after deploying "
        "the DC agent on every domain controller and the proxy service, and "
        "reviewing audit-mode events 10024/30008 for impact)."
    ),
    "base_severity": "medium",
    "query": """
        WITH src AS (
            SELECT EXISTS (SELECT 1 FROM entra_collection_status s
                            WHERE s.client_id = %(client_id)s AND s.source = 'directory_settings'
                              AND s.status = 'ok') AS ok
        ),
        prs AS (
            SELECT ts.content
              FROM entra_tenant_setting ts
             WHERE ts.client_id = %(client_id)s AND ts.setting_name = 'password_rule_settings'
        ),
        org AS (
            SELECT ts.content
              FROM entra_tenant_setting ts
             WHERE ts.client_id = %(client_id)s AND ts.setting_name = 'organization'
        ),
        eff AS (
            SELECT (SELECT content FROM prs) IS NOT NULL AS setting_present,
                   lower(COALESCE((SELECT content->>'EnableBannedPasswordCheckOnPremises' FROM prs), 'true')) AS onprem_enabled,
                   lower(COALESCE((SELECT content->>'BannedPasswordCheckOnPremisesMode' FROM prs), 'Audit')) AS onprem_mode,
                   lower(COALESCE((SELECT content->>'EnableBannedPasswordCheck' FROM prs), 'false')) AS custom_enabled,
                   btrim(COALESCE((SELECT content->>'BannedPasswordList' FROM prs), '')) AS custom_list,
                   COALESCE((SELECT content->>'LockoutThreshold' FROM prs), '10') AS threshold_raw,
                   COALESCE((SELECT content->>'LockoutDurationInSeconds' FROM prs), '60') AS duration_raw,
                   CASE WHEN EXISTS (SELECT 1 FROM org)
                        THEN COALESCE((SELECT content->>'onPremisesSyncEnabled' FROM org), 'false') = 'true'
                   END AS hybrid
              FROM src
             WHERE src.ok
        ),
        eff2 AS (
            SELECT e.*,
                   CASE WHEN btrim(e.threshold_raw) ~ '^[0-9]{1,9}$' THEN btrim(e.threshold_raw)::int END AS threshold,
                   CASE WHEN btrim(e.duration_raw) ~ '^[0-9]{1,9}$' THEN btrim(e.duration_raw)::int END AS duration,
                   e.hybrid IS DISTINCT FROM FALSE AS check_onprem
              FROM eff e
        ),
        issues AS (
            SELECT 2 AS rank, 'on-premises password protection is disabled' AS issue
              FROM eff2 WHERE check_onprem AND onprem_enabled = 'false'
            UNION ALL
            SELECT 2, 'on-premises password protection is in audit mode'
              FROM eff2 WHERE check_onprem AND onprem_enabled <> 'false' AND onprem_mode = 'audit'
            UNION ALL
            SELECT 2, 'smart lockout threshold ' || threshold || ' is above 10'
              FROM eff2 WHERE threshold > 10
            UNION ALL
            SELECT 1, 'custom banned-password list is disabled'
              FROM eff2 WHERE custom_enabled = 'false'
            UNION ALL
            SELECT 1, 'custom banned-password list is empty'
              FROM eff2 WHERE custom_enabled <> 'false' AND custom_list = ''
            UNION ALL
            SELECT 1, 'smart lockout duration ' || duration || ' s is below 60 s'
              FROM eff2 WHERE duration < 60
        ),
        agg AS (
            SELECT max(rank) AS rank,
                   string_agg(issue COLLATE "C", '; ' ORDER BY rank DESC, issue COLLATE "C") AS issue_text,
                   jsonb_agg(issue ORDER BY rank DESC, issue COLLATE "C") AS issue_list
              FROM issues
            HAVING count(*) > 0
        )
        SELECT
            CASE WHEN a.rank >= 2 THEN 'fail' ELSE 'warn' END AS status,
            md5('10083:' || %(client_id)s::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN a.rank >= 2 THEN 'medium' ELSE 'low' END AS fd_severity,
            'Password protection / smart lockout not hardened: ' || a.issue_text AS summary,
            jsonb_build_object(
                'issues', a.issue_list,
                'password_rule_settings_present', e.setting_present,
                'defaults_applied', NOT e.setting_present,
                'enable_banned_password_check_on_premises', e.onprem_enabled,
                'banned_password_check_on_premises_mode', e.onprem_mode,
                'enable_banned_password_check', e.custom_enabled,
                'banned_password_list_entries',
                    CASE WHEN e.custom_list = '' THEN 0
                         ELSE cardinality(regexp_split_to_array(e.custom_list, '\\s*[\\t,;]\\s*')) END,
                'lockout_threshold', e.threshold_raw,
                'lockout_duration_seconds', e.duration_raw,
                'tenant_hybrid', e.hybrid,
                'on_premises_checks', CASE WHEN e.check_onprem THEN 'evaluated' ELSE 'skipped: cloud-only tenant' END
            ) AS detail
        FROM agg a
        CROSS JOIN eff2 e
    """,
}
