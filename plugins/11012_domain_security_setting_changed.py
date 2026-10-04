"""
Plugin 11012: Security-Relevant Domain or Password Policy Setting Changed

Change Detection counterpart to the 4xxx domain-configuration plugins
(4009 MachineAccountQuota, 4030 UPN/SPN uniqueness, the password and
lockout policy checks) and the FGPP checks. Those report whether each
setting is acceptable now; this one reports that a setting was changed
since the previous successful collection run, with the old and new value.

Compared on the domain object (ad_domain):
  ms-DS-MachineAccountQuota, minPwdLength, password complexity,
  pwdHistoryLength, minPwdAge, maxPwdAge, lockoutThreshold,
  lockoutDuration, lockOutObservationWindow, reversible encryption
  (pwdProperties 0x10), DOMAIN_PASSWORD_NO_CLEAR_CHANGE (0x4),
  dSHeuristics anonymous access / UPN-SPN uniqueness / AdminSDHolder
  exclusion mask (dwAdminSDExMask), domain functional level, Recycle Bin
  enabled, and smart-card-only password hash rolling (SCRIL).
Compared on each Fine-Grained Password Policy (ad_fgpp):
  minimum length, complexity, reversible encryption, lockout threshold,
  lockout duration and lockout observation window.

Why: these settings are changed rarely and deliberately, and several are
direct attack enablers when weakened -- a MachineAccountQuota raised from
0 re-opens machine-account creation for every user (RBCD and Certifried
chains, CISA AA26-237A); dSHeuristics anonymous access exposes the
directory to unauthenticated LDAP (DISA STIG V-243503); a non-zero
dwAdminSDExMask removes operator groups from AdminSDHolder protection;
disabling UPN/SPN uniqueness re-enables CVE-2021-42282-style collisions;
reversible encryption stores recoverable passwords (MITRE ATT&CK
T1556 / T1484 policy modification).

Comparison: the current version against the version that was current at
the previous succeeded sync_run (11002's lookup), field by field. Only
the listed fields are compared, so the columns schema v38 adds to every
domain (recycle_bin_enabled, smartcard_hash_rolling_enabled, schema
version, KDS key count, silos, ...) do not count as changes; and a
NULL -> value transition on any compared field is "not previously
collected", not a change. A value -> NULL transition is reported (shown
as "(not set)") -- e.g. a cleared MachineAccountQuota falls back to the
default of 10.

Severity: medium; high when a change weakens security: MachineAccountQuota
raised from 0, minimum length lowered, complexity disabled, history
lowered, lockout disabled (threshold to 0), reversible encryption
enabled, NO_CLEAR_CHANGE cleared, anonymous access enabled, uniqueness
checks disabled, AdminSDHolder exclusion bits added, SCRIL hash rolling
disabled. One row per changed object (the domain or the FGPP).
Suppressed on a client's first collection run.
"""

PLUGIN = {
    "plugin_id": 11012,
    "category": "Change Detection",
    "name": "Security-Relevant Domain or Password Policy Setting Changed",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "CHANGE-11012",
    "framework_tags": [
        "NIST-800-53-CM-3", "NIST-800-53-SI-4", "NIST-800-53-AU-6", "NIST-800-53-CM-6",
        "NIST-800-53-IA-5(1)", "NIST-800-53-AC-7",
        "NIST-CSF-2.0-DE.CM-03", "NIST-CSF-2.0-DE.CM-09", "NIST-CSF-2.0-PR.PS-01",
        "PCI-DSS-4.0-10.2.1.2", "PCI-DSS-4.0-11.5.2", "PCI-DSS-4.0-2.2.1",
        "PCI-DSS-4.0-8.3.4", "PCI-DSS-4.0-8.3.6", "PCI-DSS-4.0-8.3.7",
        "CIS-CSC-8-8.11", "CIS-CSC-8-4.1", "CIS-CSC-8-5.2",
        "ISO-27001-2022-A.8.16", "ISO-27001-2022-A.8.32", "ISO-27001-2022-A.8.9",
        "ISO-27001-2022-A.5.17",
        "SOC2-CC7.2", "SOC2-CC8.1", "SOC2-CC7.1",
        "HIPAA-164.308(a)(1)(ii)(D)", "HIPAA-164.308(a)(5)(ii)(D)",
        "MITRE-ATTCK-T1484", "MITRE-ATTCK-T1556",
        "CISA-AA26-237A",
    ],
    "references": [
        {"title": "Microsoft: ms-DS-MachineAccountQuota attribute",
         "url": "https://learn.microsoft.com/en-us/windows/win32/adschema/a-ms-ds-machineaccountquota"},
        {"title": "Microsoft: Password Policy settings",
         "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/password-policy"},
        {"title": "Microsoft: KB5008382 -- UPN and SPN uniqueness (CVE-2021-42282)",
         "url": "https://support.microsoft.com/en-us/topic/kb5008382-verification-of-uniqueness-for-user-principal-name-service-principal-name-and-the-service-principal-name-alias-cve-2021-42282-4651b175-290c-4e59-8fcb-e4e5cd0cdb29"},
        {"title": "MITRE ATT&CK T1484: Domain or Tenant Policy Modification",
         "url": "https://attack.mitre.org/techniques/T1484/"},
        {"title": "CISA AA26-237A: Joint Red Team Assessment Findings",
         "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-237a"},
    ],
    "description": (
        "Reports security-relevant settings of the domain object and of Fine-Grained "
        "Password Policies that changed since the previous successful collection run, "
        "with old and new values: MachineAccountQuota, password length/complexity/"
        "history/age, lockout threshold/duration/window, reversible encryption, "
        "dSHeuristics anonymous access, UPN/SPN uniqueness and AdminSDHolder "
        "exclusion mask, functional level, Recycle Bin and smart-card hash rolling. "
        "Severity is medium, high when the change weakens security (for example "
        "MachineAccountQuota raised from 0, anonymous LDAP enabled, complexity "
        "disabled or reversible encryption enabled, minimum length lowered). Values "
        "collected for the first time (NULL before) are not treated as changes, so "
        "the schema v38 rescan does not produce findings. Suppressed on a client's "
        "first collection run."
    ),
    "remediation": (
        "Confirm each change against an approved change record. Security event IDs "
        "4739 (domain policy changed) and 5136 (directory object modified, on the "
        "domain object, CN=Directory Service,CN=Windows NT,CN=Services,"
        "CN=Configuration or the Password Settings Container) identify who made it. "
        "Revert unapproved changes: Set-ADDomain -Identity <domain> "
        "-Replace @{'ms-DS-MachineAccountQuota'=0}; Set-ADDefaultDomainPasswordPolicy "
        "-MinPasswordLength 14 -ComplexityEnabled $true -ReversibleEncryptionEnabled "
        "$false -LockoutThreshold <n>; Set-ADFineGrainedPasswordPolicy <name> ...; "
        "restore dSHeuristics with Set-ADObject 'CN=Directory Service,CN=Windows NT,"
        "CN=Services,CN=Configuration,<forest DN>' -Replace @{dSHeuristics='<value>'} "
        "(7th character not 2, 21st character 0, 16th character -- dwAdminSDExMask -- "
        "0). Note that the default domain password policy is normally set through the "
        "Default Domain Policy GPO, which overwrites direct changes on the next refresh."
    ),
    "base_severity": "medium",
    "query": """
        WITH prior_run AS (
            SELECT max(sr.run_id) AS prev_run_id
            FROM sync_run sr
            WHERE sr.client_id = %(client_id)s
              AND sr.run_id < %(run_id)s
              AND sr.status = 'succeeded'
        ),
        dom_cur AS (
            SELECT d.*, do2.dn_current, cv.run_id_valid_from AS change_run_id, pr.prev_run_id
            FROM ad_domain d
            CROSS JOIN prior_run pr
            JOIN directory_object do2
              ON do2.object_guid = d.object_guid AND do2.client_id = d.client_id
             AND NOT do2.is_deleted
            JOIN directory_object_version cv
              ON cv.version_id = d.version_id AND cv.object_guid = d.object_guid
             AND cv.client_id = d.client_id AND cv.valid_from = d.valid_from
            WHERE d.client_id = %(client_id)s
              AND d.valid_to IS NULL
              AND pr.prev_run_id IS NOT NULL
              AND cv.run_id_valid_from > pr.prev_run_id
              AND cv.run_id_valid_from <= %(run_id)s
        ),
        dom_fields AS (
            SELECT c.object_guid, 'Domain' AS object_kind,
                   COALESCE(c.dns_root, c.dn_current) AS object_name,
                   c.dn_current, c.valid_from, c.change_run_id, c.prev_run_id,
                   f.ord, f.field, f.old_v, f.new_v, f.weakens
            FROM dom_cur c
            JOIN LATERAL (
                SELECT p.*
                FROM ad_domain p
                JOIN directory_object_version pv
                  ON pv.version_id = p.version_id AND pv.object_guid = p.object_guid
                 AND pv.client_id = p.client_id AND pv.valid_from = p.valid_from
                WHERE p.object_guid = c.object_guid
                  AND p.client_id = %(client_id)s
                  AND p.valid_from < c.valid_from
                  AND pv.run_id_valid_from <= c.prev_run_id
                  AND (pv.run_id_valid_to IS NULL OR pv.run_id_valid_to > c.prev_run_id)
                ORDER BY p.valid_from DESC
                LIMIT 1
            ) p ON TRUE
            CROSS JOIN LATERAL (VALUES
                (1, 'MachineAccountQuota', p.machine_account_quota::text, c.machine_account_quota::text,
                 p.machine_account_quota = 0 AND COALESCE(c.machine_account_quota, 10) > 0),
                (2, 'minimum password length', p.pwd_policy_min_length::text, c.pwd_policy_min_length::text,
                 COALESCE(c.pwd_policy_min_length, 0) < p.pwd_policy_min_length),
                (3, 'password complexity', p.pwd_policy_complexity::text, c.pwd_policy_complexity::text,
                 p.pwd_policy_complexity AND c.pwd_policy_complexity IS NOT TRUE),
                (4, 'password history length', p.pwd_history_count::text, c.pwd_history_count::text,
                 COALESCE(c.pwd_history_count, 0) < p.pwd_history_count),
                (5, 'minimum password age', justify_hours(make_interval(secs => p.min_pwd_age_seconds))::text,
                 justify_hours(make_interval(secs => c.min_pwd_age_seconds))::text, false),
                (6, 'maximum password age', justify_hours(make_interval(secs => p.max_pwd_age_seconds))::text,
                 justify_hours(make_interval(secs => c.max_pwd_age_seconds))::text, false),
                (7, 'lockout threshold', p.lockout_threshold::text, c.lockout_threshold::text,
                 p.lockout_threshold > 0 AND COALESCE(c.lockout_threshold, 0) = 0),
                (8, 'lockout duration', justify_hours(make_interval(secs => p.lockout_duration_seconds))::text,
                 justify_hours(make_interval(secs => c.lockout_duration_seconds))::text, false),
                (9, 'lockout observation window',
                 justify_hours(make_interval(secs => p.lockout_observation_window_seconds))::text,
                 justify_hours(make_interval(secs => c.lockout_observation_window_seconds))::text, false),
                (10, 'reversible password encryption (domain-wide)',
                 p.pwd_reversible_encryption_domain_wide::text, c.pwd_reversible_encryption_domain_wide::text,
                 p.pwd_reversible_encryption_domain_wide IS FALSE AND c.pwd_reversible_encryption_domain_wide),
                (11, 'DOMAIN_PASSWORD_NO_CLEAR_CHANGE', p.pwd_no_clear_change::text, c.pwd_no_clear_change::text,
                 p.pwd_no_clear_change AND c.pwd_no_clear_change IS NOT TRUE),
                (12, 'dSHeuristics anonymous LDAP access', p.dsheuristics_anonymous_access::text,
                 c.dsheuristics_anonymous_access::text,
                 p.dsheuristics_anonymous_access IS FALSE AND c.dsheuristics_anonymous_access),
                (13, 'dSHeuristics UPN/SPN uniqueness-disable bits', p.dsheuristics_uniqueness::text,
                 c.dsheuristics_uniqueness::text,
                 (COALESCE(c.dsheuristics_uniqueness, 0) & ~COALESCE(p.dsheuristics_uniqueness, 0)) <> 0),
                (14, 'dSHeuristics AdminSDHolder exclusion mask (dwAdminSDExMask)',
                 p.dsheuristics_admin_sd_ex_mask::text, c.dsheuristics_admin_sd_ex_mask::text,
                 (COALESCE(c.dsheuristics_admin_sd_ex_mask, 0) & ~COALESCE(p.dsheuristics_admin_sd_ex_mask, 0)) <> 0),
                (15, 'domain functional level', p.functional_level::text, c.functional_level::text, false),
                (16, 'Recycle Bin enabled', p.recycle_bin_enabled::text, c.recycle_bin_enabled::text,
                 p.recycle_bin_enabled AND c.recycle_bin_enabled IS FALSE),
                (17, 'smart-card-only password hash rolling (SCRIL)', p.smartcard_hash_rolling_enabled::text,
                 c.smartcard_hash_rolling_enabled::text,
                 p.smartcard_hash_rolling_enabled AND c.smartcard_hash_rolling_enabled IS NOT TRUE)
            ) AS f(ord, field, old_v, new_v, weakens)
        ),
        fgpp_cur AS (
            SELECT g.*, do2.dn_current, cv.run_id_valid_from AS change_run_id, pr.prev_run_id
            FROM ad_fgpp g
            CROSS JOIN prior_run pr
            JOIN directory_object do2
              ON do2.object_guid = g.object_guid AND do2.client_id = g.client_id
             AND NOT do2.is_deleted
            JOIN directory_object_version cv
              ON cv.version_id = g.version_id AND cv.object_guid = g.object_guid
             AND cv.client_id = g.client_id AND cv.valid_from = g.valid_from
            WHERE g.client_id = %(client_id)s
              AND g.valid_to IS NULL
              AND pr.prev_run_id IS NOT NULL
              AND cv.run_id_valid_from > pr.prev_run_id
              AND cv.run_id_valid_from <= %(run_id)s
        ),
        fgpp_fields AS (
            SELECT c.object_guid, 'Fine-grained password policy' AS object_kind,
                   COALESCE(c.policy_name, c.dn_current) AS object_name,
                   c.dn_current, c.valid_from, c.change_run_id, c.prev_run_id,
                   f.ord, f.field, f.old_v, f.new_v, f.weakens
            FROM fgpp_cur c
            JOIN LATERAL (
                SELECT p.*
                FROM ad_fgpp p
                JOIN directory_object_version pv
                  ON pv.version_id = p.version_id AND pv.object_guid = p.object_guid
                 AND pv.client_id = p.client_id AND pv.valid_from = p.valid_from
                WHERE p.object_guid = c.object_guid
                  AND p.client_id = %(client_id)s
                  AND p.valid_from < c.valid_from
                  AND pv.run_id_valid_from <= c.prev_run_id
                  AND (pv.run_id_valid_to IS NULL OR pv.run_id_valid_to > c.prev_run_id)
                ORDER BY p.valid_from DESC
                LIMIT 1
            ) p ON TRUE
            CROSS JOIN LATERAL (VALUES
                (2, 'minimum password length', p.min_pwd_length::text, c.min_pwd_length::text,
                 COALESCE(c.min_pwd_length, 0) < p.min_pwd_length),
                (3, 'password complexity', p.pwd_complexity_enabled::text, c.pwd_complexity_enabled::text,
                 p.pwd_complexity_enabled AND c.pwd_complexity_enabled IS NOT TRUE),
                (7, 'lockout threshold', p.lockout_threshold::text, c.lockout_threshold::text,
                 p.lockout_threshold > 0 AND COALESCE(c.lockout_threshold, 0) = 0),
                (8, 'lockout duration', justify_hours(make_interval(secs => p.lockout_duration_seconds))::text,
                 justify_hours(make_interval(secs => c.lockout_duration_seconds))::text, false),
                (9, 'lockout observation window',
                 justify_hours(make_interval(secs => p.lockout_observation_window_seconds))::text,
                 justify_hours(make_interval(secs => c.lockout_observation_window_seconds))::text, false),
                (10, 'reversible password encryption', p.reversible_encryption_enabled::text,
                 c.reversible_encryption_enabled::text,
                 p.reversible_encryption_enabled IS FALSE AND c.reversible_encryption_enabled)
            ) AS f(ord, field, old_v, new_v, weakens)
        ),
        -- NULL before = not previously collected, not a change.
        changes AS (
            SELECT x.*, COALESCE(x.weakens, false) AS weakened
            FROM (SELECT * FROM dom_fields UNION ALL SELECT * FROM fgpp_fields) x
            WHERE x.old_v IS NOT NULL
              AND x.old_v IS DISTINCT FROM x.new_v
        )
        SELECT
            'warn' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN bool_or(c.weakened) THEN 'high' ELSE 'medium' END AS fd_severity,
            c.object_kind || ' "' || c.object_name
                || '" security settings changed since the previous collection run: '
                || string_agg(c.field || ' ' || c.old_v || ' -> ' || COALESCE(c.new_v, '(not set)'),
                              '; ' ORDER BY c.ord)
                || CASE WHEN bool_or(c.weakened)
                        THEN ' -- weakened: '
                             || string_agg(c.field, ', ' ORDER BY c.ord) FILTER (WHERE c.weakened)
                        ELSE '' END AS summary,
            jsonb_build_object(
                'object_kind', c.object_kind,
                'object_name', c.object_name,
                'distinguished_name', c.dn_current,
                'changes', jsonb_agg(jsonb_build_object(
                    'setting', c.field,
                    'previous_value', c.old_v,
                    'current_value', c.new_v,
                    'weakens_security', c.weakened
                ) ORDER BY c.ord),
                'weakened', bool_or(c.weakened),
                'change_observed_run_id', min(c.change_run_id),
                'baseline_run_id', min(c.prev_run_id),
                'change_observed_at', min(c.valid_from),
                'corroborating_event_ids', jsonb_build_array(4739, 5136)
            ) AS detail
        FROM changes c
        GROUP BY c.object_guid, c.object_kind, c.object_name, c.dn_current
    """,
}
