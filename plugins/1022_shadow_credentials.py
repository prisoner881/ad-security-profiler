"""
Plugin 1022: Account Has Shadow Credentials (msDS-KeyCredentialLink) Registered

Presence is not itself evidence of compromise -- legitimate on any
Windows Hello for Business or hybrid-Entra-join-enrolled account. Flagged
as a data point worth reviewing, not a confirmed finding: full validation
(is this key legitimate, does the DeviceID match a real enrolled device)
needs cross-referencing with Entra/Intune device records, which this
read-only on-prem collector has no visibility into.

[v1.5] "Privileged" now comes from the shared Tier 0 view
v_privileged_principal (schema v34) instead of an inline subquery that
counted GenericAll/GenericWrite/WriteDACL/WriteOwner on, or ownership of,
ANY object with a collected ACL -- every OU, every certificate template --
so OU delegates and whoever created an OU were treated as privileged.
Protected-group membership, control of or ownership of a Tier 0 object
(domain root, AdminSDHolder, DCs, CAs, ...), DCSync, and membership in a
group holding any of those still count. detail gains privilege_sources
(the view's reasons, sorted); summary wording is unchanged.

[v1.6] Uses the parsed KeyCredentials (ad_user.key_credentials, collector
0.5.16 / schema v37) to separate expected keys from suspicious ones.
Heuristics, not proof:
- Windows Hello for Business and FIDO2 keys are normal on users: usage
  NGC or FIDO, and source AzureAD when written back from Entra ID (cloud /
  hybrid WHfB, Entra Connect). If every key looks like that, an ordinary
  user is reported as info.
- A key whose source is AD is either on-premises WHfB key trust or a key
  written directly over LDAP, as Shadow Credentials tools (Whisker,
  pyWhisker, Certipy) do: low on an ordinary user.
- Anomalies raise severity by one level and make the finding 'fail': an
  entry that could not be parsed, a missing/invalid creation time, a
  usage other than NGC/FIDO, and an AD-sourced key on a privileged
  account (Tier 0/1 classification, adminCount=1 or v_privileged_principal).
- Privileged accounts keep their higher base (medium, high for Tier 0);
  an anomalous key on a Tier 0 account is critical.
- Rows collected before 0.5.16 (count but no parsed keys) keep the old
  rating with a "re-collect" note. Disabled accounts are still reduced by
  two levels.
detail adds key_assessment, anomalies, newest_key_created and
key_credentials (per-key id, device id, usage, source, times, flags and
anomalies; never key material). Summary wording changed.
"""

PLUGIN = {
    "plugin_id": 1022,
    "category": "User Accounts",
    "name": "Account Has Shadow Credentials (msDS-KeyCredentialLink) Registered",
    "version": "1.6",
    "revision_date": "2026-10-04",
    "remediation": (
    "Review each entry's legitimacy by cross-referencing against known Windows "
    'Hello for Business or hybrid-Entra-join device enrollment records for that '
    "user. Remove any key credential entries that can't be confirmed as "
    "legitimate device enrollments. If an entry can't be attributed to a known, "
    'expected enrollment, investigate who or what held the delegated rights '
    'needed to write msDS-KeyCredentialLink on this account -- writing this '
    'attribute requires specific elevated rights, so an illegitimate entry '
    'implies a separate privilege issue worth finding, not just a key to '
    'delete. Start with keys listed with anomalies, and with AD-sourced keys '
    'on privileged accounts: compare each key\'s device_id and creation_time '
    'with the user\'s registered devices in Entra ID / Intune.'
),
    "control_id": "CRED-010",
    "framework_tags": ["MITRE-ATTCK-T1556"],
    "references": [
        {"title": "MITRE ATT&CK T1556: Modify Authentication Process",
         "url": "https://attack.mitre.org/techniques/T1556/"},
    ],
    "description": (
        "msDS-KeyCredentialLink stores Key Credential material used for "
        "passwordless authentication (Windows Hello for Business) via "
        "PKINIT. Anyone with write access to this attribute on an "
        "account (GenericWrite, GenericAll, or explicit attribute-level "
        "write) can add a rogue key and authenticate as that account via "
        "PKINIT without ever touching its password -- the 'Shadow "
        "Credentials' technique (MITRE ATT&CK T1556). Presence alone is "
        "NOT evidence of compromise; it is entirely legitimate on any "
        "WHfB-enrolled or hybrid-Entra-joined account, and this finding "
        "will fire broadly in any environment using either. Full "
        "validation of whether a given entry is legitimate requires "
        "cross-referencing its DeviceID against real Entra/Intune device "
        "records -- out of scope for this read-only on-prem AD "
        "collector. Flagged as a data point worth review, particularly "
        "on accounts that would not normally be expected to use WHfB "
        "(most service accounts), not as a confirmed finding. Since "
        "collector 0.5.16 each key is parsed and assessed with "
        "heuristics: NGC/FIDO keys written back from Entra ID (source "
        "AzureAD) are treated as expected WHfB/FIDO2 registrations (info on "
        "ordinary users); AD-sourced keys (on-premises key trust, or written "
        "directly as Shadow Credentials tools do) are low; unparseable "
        "entries, missing creation times, unusual usages and AD-sourced keys "
        "on privileged accounts raise the severity by one level (critical on "
        "Tier 0)."
    ),
    "base_severity": "low",
    # Shadow Credentials authenticate via PKINIT, which -- like normal
    # password auth -- goes through the AS-REQ exchange, so the same
    # protocol-level reasoning as plugin 1013 should extend here: a
    # disabled account's AS-REQ should be rejected regardless of whether
    # PKINIT or a password is being used. Downgraded, not excluded, for
    # the same audit-completeness/re-enablement reasoning as elsewhere.
    "query": """
        WITH privileged_check AS (
            -- [v1.5] "Privileged" is the shared Tier 0 definition in
            -- v_privileged_principal (schema v34): membership, direct or
            -- nested, in an AdminSDHolder-protected group; a control right
            -- (GenericAll/GenericWrite/WriteDACL/WriteOwner) on, or
            -- ownership of, a Tier 0 object; DCSync on the domain root; or
            -- membership in a group that holds any of those. The inline
            -- subquery this replaces counted such a right on, or ownership
            -- of, ANY object with a collected ACL, so every OU delegate and
            -- OU creator was treated as privileged.
            SELECT object_guid,
                   array_agg(DISTINCT privilege_source ORDER BY privilege_source) AS privilege_sources
            FROM v_privileged_principal
            WHERE client_id = %(client_id)s
            GROUP BY object_guid
        ),
        acct AS (
            SELECT u.*,
                   oc.tier,
                   pc.object_guid IS NOT NULL AS in_privileged_view,
                   pc.privilege_sources,
                   COALESCE(jsonb_typeof(u.key_credentials) = 'array', false) AS keys_parsed,
                   CASE WHEN oc.tier = 0 THEN 3
                        WHEN oc.tier = 1 OR u.admin_count = 1 OR pc.object_guid IS NOT NULL THEN 2
                        ELSE 1 END AS tier_score
            FROM ad_user u
            LEFT JOIN object_classification oc
                ON oc.object_guid = u.object_guid AND oc.client_id = u.client_id
            LEFT JOIN privileged_check pc
                ON pc.object_guid = u.object_guid
            WHERE u.valid_to IS NULL
              AND u.client_id = %(client_id)s
              AND (COALESCE(u.key_credential_count, 0) > 0
                   OR COALESCE(jsonb_array_length(CASE WHEN jsonb_typeof(u.key_credentials) = 'array'
                                                       THEN u.key_credentials END), 0) > 0)
        ),
        -- [v1.6] Per-key heuristics (see the docstring); no key material is
        -- stored by the collector, only the parsed metadata.
        key_rows AS (
            SELECT a.object_guid, e.key,
                   array_remove(ARRAY[
                       CASE WHEN e.key ->> 'parse_error' = 'true'
                            THEN 'unparseable_key_credential' END,
                       CASE WHEN e.key ->> 'parse_error' IS DISTINCT FROM 'true'
                                 AND COALESCE(e.key ->> 'usage', '') NOT IN ('NGC', 'FIDO')
                            THEN 'usage_not_whfb_or_fido' END,
                       CASE WHEN e.key ->> 'parse_error' IS DISTINCT FROM 'true'
                                 AND COALESCE(e.key ->> 'creation_time', '')
                                     !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}'
                            THEN 'creation_time_missing_or_invalid' END,
                       CASE WHEN a.tier_score >= 2
                                 AND e.key ->> 'parse_error' IS DISTINCT FROM 'true'
                                 AND e.key ->> 'source' = 'AD'
                            THEN 'ad_sourced_key_on_privileged_account' END
                   ]::text[], NULL) AS reasons
            FROM acct a
            CROSS JOIN LATERAL jsonb_array_elements(
                CASE WHEN a.keys_parsed THEN a.key_credentials ELSE '[]'::jsonb END) AS e(key)
        ),
        key_eval AS (
            SELECT a.object_guid,
                   count(kr.key) AS parsed_key_count,
                   count(kr.key) FILTER (WHERE cardinality(kr.reasons) > 0) AS anomalous_key_count,
                   COALESCE(bool_and(kr.key ->> 'source' = 'AzureAD'), false) AS all_cloud_sourced,
                   max(kr.key ->> 'creation_time') AS newest_key_created,
                   jsonb_agg(kr.key || jsonb_build_object('anomalies', to_jsonb(kr.reasons))
                             ORDER BY kr.key ->> 'creation_time', kr.key ->> 'key_id', kr.key::text)
                       FILTER (WHERE kr.key IS NOT NULL) AS keys,
                   (SELECT array_agg(DISTINCT r.reason ORDER BY r.reason)
                    FROM key_rows kr2 CROSS JOIN LATERAL unnest(kr2.reasons) AS r(reason)
                    WHERE kr2.object_guid = a.object_guid) AS anomaly_kinds
            FROM acct a
            LEFT JOIN key_rows kr ON kr.object_guid = a.object_guid
            GROUP BY a.object_guid
        ),
        rated AS (
            SELECT a.*, ke.parsed_key_count, ke.anomalous_key_count, ke.anomaly_kinds,
                   ke.keys, ke.newest_key_created,
                   CASE
                       WHEN NOT a.keys_parsed THEN 'not_parsed'
                       WHEN ke.anomalous_key_count > 0 THEN 'anomalous'
                       WHEN ke.all_cloud_sourced THEN 'likely_whfb_or_fido'
                       ELSE 'ad_sourced'
                   END AS assessment,
                   CASE WHEN a.keys_parsed THEN ke.parsed_key_count
                        ELSE COALESCE(a.key_credential_count, 0) END AS n_keys
            FROM acct a
            JOIN key_eval ke ON ke.object_guid = a.object_guid
        ),
        scored AS (
            SELECT r.*,
                   GREATEST(0, LEAST(4,
                       r.tier_score
                       + CASE WHEN r.assessment = 'anomalous' THEN 1 ELSE 0 END
                       - CASE WHEN r.assessment = 'likely_whfb_or_fido' AND r.tier_score = 1
                              THEN 1 ELSE 0 END
                       - CASE WHEN r.is_enabled IS FALSE THEN 2 ELSE 0 END
                   )) AS score
            FROM rated r
        )
        SELECT
            CASE WHEN s.assessment = 'anomalous' THEN 'fail' ELSE 'warn' END AS status,
            s.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE s.score WHEN 4 THEN 'critical' WHEN 3 THEN 'high' WHEN 2 THEN 'medium'
                         WHEN 1 THEN 'low' ELSE 'info' END AS fd_severity,
            (CASE
                WHEN s.tier = 0 THEN 'Tier-0 '
                WHEN s.tier = 1 THEN 'Tier-1 '
                WHEN s.tier_score >= 2 THEN 'Privileged '
                ELSE ''
             END)
                || 'User Account ' || COALESCE(s.user_principal_name, s.sam_account_name, s.object_guid::text)
                || ' has ' || s.n_keys
                || CASE WHEN s.n_keys = 1 THEN ' key credential' ELSE ' key credentials' END
                || ' (msDS-KeyCredentialLink) registered -- '
                || CASE s.assessment
                       WHEN 'anomalous' THEN 'possible Shadow Credentials ('
                           || array_to_string(s.anomaly_kinds, ', ') || ')'
                       WHEN 'likely_whfb_or_fido' THEN 'consistent with Windows Hello for Business / '
                           'FIDO2 keys synced from Entra ID; review only if unexpected'
                       WHEN 'ad_sourced' THEN 'on-premises-sourced key (on-premises WHfB key trust, '
                           'or added with a Shadow Credentials tool); review'
                       ELSE 'key details not collected (collector before 0.5.16); '
                            'review for legitimacy'
                   END
                || CASE WHEN s.is_enabled IS FALSE
                        THEN ' (severity reduced: account is disabled)'
                        ELSE '' END AS summary,
            jsonb_build_object(
                'sam_account_name', s.sam_account_name,
                'user_principal_name', s.user_principal_name,
                'is_enabled', s.is_enabled,
                'key_credential_count', s.key_credential_count,
                'key_assessment', s.assessment,
                'anomalies', s.anomaly_kinds,
                'newest_key_created', s.newest_key_created,
                'key_credentials', s.keys,
                'admin_count', s.admin_count,
                'tier', s.tier,
                'privileged_group_member', s.in_privileged_view,
                'privilege_sources', s.privilege_sources
            ) AS detail
        FROM scored s
    """,
}
