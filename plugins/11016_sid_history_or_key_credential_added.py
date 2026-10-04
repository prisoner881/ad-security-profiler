"""
Plugin 11016: SID History or Key Credential Added to an Existing Account

Change Detection companion to the standing-state plugins for sIDHistory
(privileged SID history) and msDS-KeyCredentialLink (1022 users, 2013
computers -- Shadow Credentials). This one reports the event: an account
that existed at the previous successful collection run and has since
gained
- a sIDHistory value (MITRE ATT&CK T1134.005, SID-History Injection: a
  privileged SID in sIDHistory is honoured in the account's token, and
  it is a well-known persistence technique -- mimikatz sid::add,
  DCShadow); or
- a key credential (msDS-KeyCredentialLink entry) whose key ID was not
  there before (Shadow Credentials, MITRE ATT&CK T1556 / T1098: anyone who
  can write the attribute can then authenticate as the account with
  PKINIT, and the account's NT hash can be recovered via U2U).

Device self-registration is not reported for computers, mirroring plugin
2013: a computer may write its own key only while it has none, so a new
key is ignored when its device ID equals the computer's objectGUID, or
when the computer had no key at the previous run and now has exactly one
NGC key with source AD and a valid creation time (the hybrid-join /
Windows Hello device key). For users, mirroring plugin 1022, a new key
whose usage is NGC or FIDO and whose source is AzureAD (Windows Hello
for Business / FIDO2 written back by Entra Connect) is rated medium on a
non-Tier-0 account instead of high.

Comparison: the current ad_user / ad_computer version against the version
current at the previous succeeded sync_run (11002's lookup), on sid_history
and key_credentials only (so the schema v38 rescan cannot produce
findings). Key credentials are compared by key ID (an entry without one,
e.g. unparseable, by its whole parsed content). When the previous version
predates parsed key credentials (collector < 0.5.16: a count but no
parsed list), a new key is inferred only if the count went up.

Severity: SID history: critical if a gained SID has a privileged RID (500,
502, 512, 516, 518, 519, 520, 521, 498, 526, 527 or BUILTIN 544, 548-551)
or belongs to a current Tier 0 principal, else high. Key credential: high,
critical if the account is Tier 0 (v_privileged_principal or
v_tier0_object). Disabled accounts one level lower. One row per account.
Suppressed on a client's first collection run.
"""

PLUGIN = {
    "plugin_id": 11016,
    "category": "Change Detection",
    "name": "SID History or Key Credential Added to an Existing Account",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "CHANGE-11016",
    "framework_tags": [
        "NIST-800-53-CM-3", "NIST-800-53-SI-4", "NIST-800-53-AU-6", "NIST-800-53-AC-2(4)",
        "NIST-800-53-AC-6",
        "NIST-CSF-2.0-DE.CM-03", "NIST-CSF-2.0-DE.CM-09", "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-10.2.1.2", "PCI-DSS-4.0-10.2.1.5",
        "CIS-CSC-8-8.11",
        "ISO-27001-2022-A.8.16",
        "SOC2-CC7.2",
        "HIPAA-164.308(a)(1)(ii)(D)",
        "MITRE-ATTCK-T1134.005", "MITRE-ATTCK-T1556", "MITRE-ATTCK-T1098",
        "CISA-AA26-237A",
    ],
    "references": [
        {"title": "MITRE ATT&CK T1134.005: SID-History Injection",
         "url": "https://attack.mitre.org/techniques/T1134/005/"},
        {"title": "MITRE ATT&CK T1556: Modify Authentication Process",
         "url": "https://attack.mitre.org/techniques/T1556/"},
        {"title": "SpecterOps: Shadow Credentials: Abusing Key Trust Account Mapping for Account Takeover",
         "url": "https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab"},
        {"title": "BloodHound: AddKeyCredentialLink",
         "url": "https://bloodhound.specterops.io/resources/edges/add-key-credential-link"},
        {"title": "CISA AA26-237A: Joint Red Team Assessment Findings",
         "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-237a"},
    ],
    "description": (
        "Reports accounts that existed at the previous successful collection run and "
        "have since gained a sIDHistory value (SID-history injection) or a new "
        "msDS-KeyCredentialLink key (Shadow Credentials). A gained privileged SID "
        "(Domain/Enterprise/Schema Admins, Administrator, Administrators, Operators, "
        "or any current Tier 0 principal) is critical, other SID history high; a new "
        "key is high, critical on a Tier 0 account, medium for an Entra-written "
        "Windows Hello / FIDO2 key on an ordinary user. A computer's own device key "
        "(device ID = the computer's GUID, or the single NGC/AD key a computer may "
        "self-register when it has none) is not reported. Disabled accounts are "
        "rated one level lower. Suppressed on a client's first collection run."
    ),
    "remediation": (
        "SID history: legitimate only during a documented domain migration. Identify "
        "who wrote it (event 4765/4766 'SID History was added', 4738/4742, 5136) and "
        "remove it: Set-ADUser <account> -Remove @{sIDHistory='<SID>'} (or "
        "Get-ADUser <account> -Properties sIDHistory). Then investigate how the writer "
        "obtained the rights (adding SID history needs Domain Admin-level access or "
        "DCShadow) and enable SID filtering on trusts. Key credentials: confirm the key "
        "against a known Windows Hello for Business / device enrollment (compare the "
        "device ID and creation time in this finding's detail with Entra/Intune device "
        "records). Remove unexplained keys (Whisker/pyWhisker 'remove' or "
        "Set-ADObject <dn> -Remove @{'msDS-KeyCredentialLink'=<value>}), reset the "
        "account's password, and find who held write access to msDS-KeyCredentialLink "
        "(event 5136 on the attribute)."
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
        acct AS (
            SELECT 'user' AS kind, u.object_guid, u.sam_account_name, u.is_enabled,
                   u.sid_history, u.key_credentials, u.key_credential_count,
                   u.version_id, u.valid_from
            FROM ad_user u
            WHERE u.client_id = %(client_id)s AND u.valid_to IS NULL
            UNION ALL
            SELECT 'computer', c.object_guid, c.sam_account_name, c.is_enabled,
                   c.sid_history, c.key_credentials, c.key_credential_count,
                   c.version_id, c.valid_from
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
              AND (cardinality(a.sid_history) > 0 OR COALESCE(a.key_credential_count, 0) > 0
                   OR jsonb_typeof(a.key_credentials) = 'array')
        ),
        cmp AS (
            SELECT c.*, prev.prev_sid_history, prev.prev_keys, prev.prev_key_count
            FROM cur c
            JOIN LATERAL (
                SELECT p.sid_history AS prev_sid_history, p.key_credentials AS prev_keys,
                       p.key_credential_count AS prev_key_count
                FROM (SELECT u.version_id, u.object_guid, u.valid_from, u.sid_history,
                             u.key_credentials, u.key_credential_count
                        FROM ad_user u
                       WHERE c.kind = 'user' AND u.object_guid = c.object_guid
                         AND u.client_id = %(client_id)s
                      UNION ALL
                      SELECT k.version_id, k.object_guid, k.valid_from, k.sid_history,
                             k.key_credentials, k.key_credential_count
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
        ),
        tier0 AS (
            SELECT pp.object_guid FROM v_privileged_principal pp WHERE pp.client_id = %(client_id)s
            UNION
            SELECT t.object_guid FROM v_tier0_object t WHERE t.client_id = %(client_id)s
        ),
        new_sids AS (
            SELECT m.object_guid,
                   array_agg(s.sid ORDER BY s.sid) AS gained_sids,
                   bool_or(s.sid ~ '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-(500|502|512|516|518|519|520|521|498|526|527)$'
                           OR s.sid IN ('S-1-5-32-544', 'S-1-5-32-548', 'S-1-5-32-549',
                                        'S-1-5-32-550', 'S-1-5-32-551')
                           OR EXISTS (SELECT 1 FROM directory_object sd
                                      JOIN tier0 t ON t.object_guid = sd.object_guid
                                      WHERE sd.client_id = %(client_id)s
                                        AND sd.object_sid = s.sid AND NOT sd.is_deleted))
                       AS privileged_sid
            FROM cmp m
            CROSS JOIN LATERAL unnest(m.sid_history) AS s(sid)
            WHERE NOT (s.sid = ANY (COALESCE(m.prev_sid_history, ARRAY[]::text[])))
            GROUP BY m.object_guid
        ),
        cur_keys AS (
            SELECT m.object_guid, m.kind, e.key,
                   COALESCE(e.key ->> 'key_id', md5(e.key::text)) AS kid,
                   m.prev_keys, m.prev_key_count, m.key_credential_count,
                   jsonb_array_length(m.key_credentials) AS n_now
            FROM cmp m
            CROSS JOIN LATERAL jsonb_array_elements(
                CASE WHEN jsonb_typeof(m.key_credentials) = 'array'
                     THEN m.key_credentials ELSE '[]'::jsonb END) AS e(key)
        ),
        new_keys_raw AS (
            SELECT k.*,
                   (jsonb_typeof(k.prev_keys) = 'array') AS prev_parsed,
                   COALESCE(CASE WHEN jsonb_typeof(k.prev_keys) = 'array'
                                 THEN jsonb_array_length(k.prev_keys) END,
                            k.prev_key_count, 0) AS n_prev
            FROM cur_keys k
        ),
        new_keys AS (
            SELECT r.*
            FROM new_keys_raw r
            WHERE CASE
                      WHEN r.prev_parsed
                          THEN NOT EXISTS (
                                   SELECT 1 FROM jsonb_array_elements(r.prev_keys) pk(key)
                                   WHERE COALESCE(pk.key ->> 'key_id', md5(pk.key::text)) = r.kid)
                      -- previous version had keys but no parsed list: infer by count
                      WHEN r.n_prev > 0 THEN r.n_now > r.n_prev
                      ELSE true
                  END
              -- a computer's own device key (plugin 2013's heuristic)
              AND NOT (r.kind = 'computer'
                       AND (COALESCE(lower(r.key ->> 'device_id') = lower(r.object_guid::text), false)
                            OR (r.n_prev = 0 AND r.n_now = 1
                                AND r.key ->> 'parse_error' IS DISTINCT FROM 'true'
                                AND r.key ->> 'usage' = 'NGC'
                                AND r.key ->> 'source' = 'AD'
                                AND COALESCE(r.key ->> 'creation_time', '')
                                    ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}')))
        ),
        key_summary AS (
            SELECT n.object_guid,
                   count(*) AS new_key_count,
                   bool_and(n.kind = 'user'
                            AND n.key ->> 'parse_error' IS DISTINCT FROM 'true'
                            AND n.key ->> 'usage' IN ('NGC', 'FIDO')
                            AND n.key ->> 'source' = 'AzureAD') AS all_entra_whfb,
                   jsonb_agg(n.key ORDER BY n.kid) AS new_keys
            FROM new_keys n
            GROUP BY n.object_guid
        ),
        rated AS (
            SELECT m.object_guid, m.kind, m.sam_account_name, m.is_enabled, m.valid_from,
                   m.change_run_id, m.prev_run_id,
                   ns.gained_sids, ns.privileged_sid, ks.new_key_count, ks.new_keys,
                   ks.all_entra_whfb,
                   t0.object_guid IS NOT NULL AS is_tier0,
                   GREATEST(
                       CASE WHEN ns.gained_sids IS NULL THEN 0
                            WHEN ns.privileged_sid THEN 4 ELSE 3 END,
                       CASE WHEN ks.new_key_count IS NULL THEN 0
                            WHEN t0.object_guid IS NOT NULL THEN 4
                            WHEN ks.all_entra_whfb THEN 2 ELSE 3 END
                   ) - CASE WHEN m.is_enabled IS FALSE THEN 1 ELSE 0 END AS score
            FROM cmp m
            LEFT JOIN new_sids ns ON ns.object_guid = m.object_guid
            LEFT JOIN key_summary ks ON ks.object_guid = m.object_guid
            LEFT JOIN tier0 t0 ON t0.object_guid = m.object_guid
            WHERE ns.object_guid IS NOT NULL OR ks.object_guid IS NOT NULL
        )
        SELECT
            CASE WHEN r.score >= 4 THEN 'fail' ELSE 'warn' END AS status,
            r.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN r.score >= 4 THEN 'critical' WHEN r.score = 3 THEN 'high'
                 WHEN r.score = 2 THEN 'medium' ELSE 'low' END AS fd_severity,
            CASE WHEN r.is_tier0 THEN 'Tier 0 ' || CASE WHEN r.kind = 'computer' THEN 'computer account "'
                                                       ELSE 'account "' END
                 ELSE CASE WHEN r.kind = 'computer' THEN 'Computer account "' ELSE 'Account "' END END
                || COALESCE(r.sam_account_name, do2.dn_current) || '" gained '
                || array_to_string(array_remove(ARRAY[
                       CASE WHEN r.gained_sids IS NOT NULL
                            THEN 'SID history ' || array_to_string(r.gained_sids, ', ')
                                 || CASE WHEN r.privileged_sid THEN ' (privileged SID)' ELSE '' END END,
                       CASE WHEN r.new_key_count IS NOT NULL
                            THEN r.new_key_count || ' new key credential(s) (msDS-KeyCredentialLink)'
                                 || CASE WHEN r.all_entra_whfb
                                         THEN ' consistent with Windows Hello for Business / FIDO2 '
                                              'written back from Entra ID'
                                         ELSE ' -- possible Shadow Credentials' END END
                   ], NULL), ' and ')
                || ' since the previous collection run'
                || CASE WHEN r.is_enabled IS FALSE THEN ' (account is disabled)' ELSE '' END AS summary,
            jsonb_build_object(
                'sam_account_name', r.sam_account_name,
                'distinguished_name', do2.dn_current,
                'account_kind', r.kind,
                'gained_sid_history', to_jsonb(r.gained_sids),
                'gained_privileged_sid', r.privileged_sid,
                'new_key_credentials', r.new_keys,
                'new_keys_look_like_entra_whfb', r.all_entra_whfb,
                'is_tier0', r.is_tier0,
                'is_enabled', r.is_enabled,
                'change_observed_run_id', r.change_run_id,
                'baseline_run_id', r.prev_run_id,
                'change_observed_at', r.valid_from,
                'corroborating_event_ids', jsonb_build_array(4765, 4766, 5136)
            ) AS detail
        FROM rated r
        JOIN directory_object do2
          ON do2.object_guid = r.object_guid AND do2.client_id = %(client_id)s
         AND NOT do2.is_deleted
    """,
}
