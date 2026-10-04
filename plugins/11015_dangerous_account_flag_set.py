"""
Plugin 11015: Dangerous userAccountControl Flag Newly Set on an Account

Change Detection companion to the 1xxx/2xxx account plugins that report
these flags as standing state (AS-REP roastable accounts, unconstrained
and protocol-transition delegation, password-not-required, reversible
encryption, DES-only, password never expires). This one reports the
event: an existing user or computer account whose userAccountControl
gained one of the flags since the previous successful collection run.

Flags (and why setting one is an attack step):
- DONT_REQ_PREAUTH 0x400000 -- makes the account AS-REP roastable
  (MITRE ATT&CK T1558.004); "targeted AS-REP roasting" sets it on an
  account the attacker can write, cracks the hash, and clears it.
- TRUSTED_FOR_DELEGATION 0x80000 -- unconstrained delegation: any TGT
  presented to the host is cached and reusable (printer-bug / coercion to
  domain compromise). Ignored on domain controllers, which carry it by
  default.
- TRUSTED_TO_AUTH_FOR_DELEGATION 0x1000000 -- protocol transition (S4U2Self
  to any user for the constrained targets). Ignored on read-only DCs,
  which carry it by default.
- PASSWD_NOTREQD 0x20 -- the account may have an empty password.
- ENCRYPTED_TEXT_PWD_ALLOWED 0x80 -- password stored reversibly at the
  next change.
- USE_DES_KEY_ONLY 0x200000 -- forces DES Kerberos keys (crackable).
- DONT_EXPIRE_PASSWORD 0x10000 -- password never expires.
These map to MITRE ATT&CK T1098 (Account Manipulation) and T1556
(Modify Authentication Process).

Comparison: the stored userAccountControl of the current ad_user /
ad_computer version against the version current at the previous
succeeded sync_run (11002's lookup). Only that integer is compared, so
the schema v38 rescan (every user gains account_expires etc.) cannot
produce findings. Accounts that did not exist at the previous run are
out of scope (new-account plugins cover them).

Severity: high. Critical (fail) when the account is Tier 0
(v_privileged_principal or v_tier0_object) and the gained flag is
DONT_REQ_PREAUTH or TRUSTED_FOR_DELEGATION. Disabled accounts are
reported one level lower (critical -> high, high -> medium): the flag
becomes usable the moment the account is re-enabled (plugin 11002).
One row per account listing every gained flag. Suppressed on a client's
first collection run.
"""

PLUGIN = {
    "plugin_id": 11015,
    "category": "Change Detection",
    "name": "Dangerous userAccountControl Flag Newly Set on an Account",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "CHANGE-11015",
    "framework_tags": [
        "NIST-800-53-CM-3", "NIST-800-53-SI-4", "NIST-800-53-AU-6", "NIST-800-53-AC-2(4)",
        "NIST-800-53-IA-5", "NIST-800-53-IA-2(8)",
        "NIST-CSF-2.0-DE.CM-03", "NIST-CSF-2.0-DE.CM-09",
        "PCI-DSS-4.0-10.2.1.2", "PCI-DSS-4.0-10.2.1.5",
        "CIS-CSC-8-8.11",
        "ISO-27001-2022-A.8.16", "ISO-27001-2022-A.5.17",
        "SOC2-CC7.2",
        "HIPAA-164.308(a)(1)(ii)(D)",
        "MITRE-ATTCK-T1098", "MITRE-ATTCK-T1558.004", "MITRE-ATTCK-T1556",
        "CISA-AA26-237A",
    ],
    "references": [
        {"title": "Microsoft: userAccountControl flags",
         "url": "https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties"},
        {"title": "MITRE ATT&CK T1558.004: AS-REP Roasting",
         "url": "https://attack.mitre.org/techniques/T1558/004/"},
        {"title": "MITRE ATT&CK T1098: Account Manipulation",
         "url": "https://attack.mitre.org/techniques/T1098/"},
        {"title": "CISA AA26-237A: Joint Red Team Assessment Findings",
         "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-237a"},
    ],
    "description": (
        "Reports existing user and computer accounts whose userAccountControl gained, "
        "since the previous successful collection run, a flag that weakens "
        "authentication or enables delegation abuse: DONT_REQ_PREAUTH (AS-REP "
        "roasting), TRUSTED_FOR_DELEGATION (unconstrained delegation, not on DCs), "
        "TRUSTED_TO_AUTH_FOR_DELEGATION (protocol transition, not on RODCs), "
        "PASSWD_NOTREQD, ENCRYPTED_TEXT_PWD_ALLOWED, USE_DES_KEY_ONLY or "
        "DONT_EXPIRE_PASSWORD. Severity is high; critical when the account is Tier 0 "
        "and the flag is DONT_REQ_PREAUTH or TRUSTED_FOR_DELEGATION; one level lower "
        "for disabled accounts. Only the userAccountControl value is compared, so "
        "re-collection by a newer collector does not produce findings. Suppressed on "
        "a client's first collection run."
    ),
    "remediation": (
        "Confirm each change against a change record; Security event ID 4738 (user "
        "account changed) / 4742 (computer account changed) shows the old and new "
        "userAccountControl and who changed it. Clear unapproved flags: "
        "Set-ADAccountControl <account> -DoesNotRequirePreAuth $false "
        "-TrustedForDelegation $false -TrustedToAuthForDelegation $false "
        "-PasswordNotRequired $false -AllowReversiblePasswordEncryption $false "
        "-UseDESKeyOnly $false -PasswordNeverExpires $false. If DONT_REQ_PREAUTH or "
        "ENCRYPTED_TEXT_PWD_ALLOWED was set, reset the account's password (the hash may "
        "already have been captured, or the password stored reversibly). If "
        "TRUSTED_FOR_DELEGATION was set on a host, treat TGTs of accounts that "
        "authenticated to it as exposed. Restrict who can write userAccountControl and "
        "who holds SeEnableDelegationPrivilege on domain controllers."
    ),
    "base_severity": "high",
    "query": """
        WITH prior_run AS (
            SELECT max(sr.run_id) AS prev_run_id
            FROM sync_run sr
            WHERE sr.client_id = %(client_id)s
              AND sr.run_id < %(run_id)s
              AND sr.status = 'succeeded'
        ),
        uac_flag (bit, name, tier0_critical) AS (
            VALUES (4194304, 'DONT_REQ_PREAUTH', true),
                   (524288, 'TRUSTED_FOR_DELEGATION', true),
                   (16777216, 'TRUSTED_TO_AUTH_FOR_DELEGATION', false),
                   (32, 'PASSWD_NOTREQD', false),
                   (128, 'ENCRYPTED_TEXT_PWD_ALLOWED', false),
                   (2097152, 'USE_DES_KEY_ONLY', false),
                   (65536, 'DONT_EXPIRE_PASSWORD', false)
        ),
        acct AS (
            SELECT 'user' AS kind, u.object_guid, u.sam_account_name, u.user_account_control,
                   u.is_enabled, false AS is_dc, false AS is_rodc, u.version_id, u.valid_from
            FROM ad_user u
            WHERE u.client_id = %(client_id)s AND u.valid_to IS NULL
            UNION ALL
            SELECT 'computer', c.object_guid, c.sam_account_name, c.user_account_control,
                   c.is_enabled, c.is_domain_controller, c.is_read_only_dc, c.version_id, c.valid_from
            FROM ad_computer c
            WHERE c.client_id = %(client_id)s AND c.valid_to IS NULL
        ),
        cur AS (
            SELECT a.*, cv.run_id_valid_from AS change_run_id, pr.prev_run_id
            FROM acct a
            CROSS JOIN prior_run pr
            JOIN directory_object_version cv
              ON cv.version_id = a.version_id AND cv.object_guid = a.object_guid
             AND cv.client_id = %(client_id)s AND cv.valid_from = a.valid_from
            WHERE pr.prev_run_id IS NOT NULL
              AND cv.run_id_valid_from > pr.prev_run_id
              AND cv.run_id_valid_from <= %(run_id)s
        ),
        cmp AS (
            SELECT c.*, prev.prev_uac
            FROM cur c
            JOIN LATERAL (
                SELECT p.user_account_control AS prev_uac
                FROM (SELECT u.object_guid, u.version_id, u.valid_from, u.user_account_control
                        FROM ad_user u
                       WHERE c.kind = 'user' AND u.object_guid = c.object_guid
                         AND u.client_id = %(client_id)s
                      UNION ALL
                      SELECT k.object_guid, k.version_id, k.valid_from, k.user_account_control
                        FROM ad_computer k
                       WHERE c.kind = 'computer' AND k.object_guid = c.object_guid
                         AND k.client_id = %(client_id)s) p
                JOIN directory_object_version pv
                  ON pv.version_id = p.version_id AND pv.object_guid = p.object_guid
                 AND pv.client_id = %(client_id)s AND pv.valid_from = p.valid_from
                WHERE p.valid_from < c.valid_from
                  AND pv.run_id_valid_from <= c.prev_run_id
                  AND (pv.run_id_valid_to IS NULL OR pv.run_id_valid_to > c.prev_run_id)
                ORDER BY p.valid_from DESC
                LIMIT 1
            ) prev ON TRUE
            WHERE prev.prev_uac IS NOT NULL
              AND c.user_account_control IS NOT NULL
        ),
        gained AS (
            SELECT m.*, f.bit, f.name, f.tier0_critical
            FROM cmp m
            JOIN uac_flag f
              ON (m.user_account_control & f.bit) <> 0
             AND (m.prev_uac & f.bit) = 0
            WHERE NOT (f.bit = 524288 AND m.is_dc)
              AND NOT (f.bit = 16777216 AND m.is_rodc)
        ),
        tier0 AS (
            SELECT pp.object_guid FROM v_privileged_principal pp WHERE pp.client_id = %(client_id)s
            UNION
            SELECT t.object_guid FROM v_tier0_object t WHERE t.client_id = %(client_id)s
        ),
        per_acct AS (
            SELECT g.object_guid, g.kind, g.sam_account_name, g.is_enabled, g.is_dc,
                   g.user_account_control, g.prev_uac, g.valid_from, g.change_run_id, g.prev_run_id,
                   t0.object_guid IS NOT NULL AS is_tier0,
                   bool_or(g.tier0_critical) AS has_critical_flag,
                   string_agg(g.name, ', ' ORDER BY g.bit DESC) AS flags,
                   jsonb_agg(g.name ORDER BY g.bit DESC) AS flag_list
            FROM gained g
            LEFT JOIN tier0 t0 ON t0.object_guid = g.object_guid
            GROUP BY g.object_guid, g.kind, g.sam_account_name, g.is_enabled, g.is_dc,
                     g.user_account_control, g.prev_uac, g.valid_from, g.change_run_id,
                     g.prev_run_id, t0.object_guid
        ),
        rated AS (
            SELECT p.*,
                   (p.is_tier0 AND p.has_critical_flag) AS critical_case,
                   CASE WHEN p.is_tier0 AND p.has_critical_flag
                        THEN CASE WHEN p.is_enabled IS FALSE THEN 'high' ELSE 'critical' END
                        ELSE CASE WHEN p.is_enabled IS FALSE THEN 'medium' ELSE 'high' END
                   END AS sev
            FROM per_acct p
        )
        SELECT
            CASE WHEN r.critical_case AND r.is_enabled IS NOT FALSE THEN 'fail' ELSE 'warn' END AS status,
            r.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            r.sev AS fd_severity,
            CASE WHEN r.is_tier0 THEN 'Tier 0 ' || CASE r.kind WHEN 'computer' THEN 'computer account "'
                                                       ELSE 'account "' END
                 ELSE CASE r.kind WHEN 'computer' THEN 'Computer account "' ELSE 'Account "' END END
                || COALESCE(r.sam_account_name, do2.dn_current)
                || '" had ' || r.flags
                || ' newly set in userAccountControl since the previous collection run'
                || CASE WHEN r.is_enabled IS FALSE THEN ' (account is disabled)' ELSE '' END AS summary,
            jsonb_build_object(
                'sam_account_name', r.sam_account_name,
                'distinguished_name', do2.dn_current,
                'account_kind', r.kind,
                'flags_gained', r.flag_list,
                'user_account_control', r.user_account_control,
                'previous_user_account_control', r.prev_uac,
                'is_tier0', r.is_tier0,
                'is_enabled', r.is_enabled,
                'is_domain_controller', r.is_dc,
                'change_observed_run_id', r.change_run_id,
                'baseline_run_id', r.prev_run_id,
                'change_observed_at', r.valid_from,
                'corroborating_event_ids', jsonb_build_array(4738, 4742)
            ) AS detail
        FROM rated r
        JOIN directory_object do2
          ON do2.object_guid = r.object_guid AND do2.client_id = %(client_id)s
         AND NOT do2.is_deleted
    """,
}
