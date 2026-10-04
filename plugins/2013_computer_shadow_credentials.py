"""
Plugin 2013: Computer Account Has Shadow Credentials Registered

Same technique as user-account plugin 1022, applied to computer objects.
Presence is not itself evidence of compromise, but computer objects have
less legitimate reason to carry Windows Hello for Business key material
than user accounts do, making an unexplained entry here somewhat more
noteworthy than the equivalent user-account finding.

[v1.3] Uses the parsed KeyCredentials (ad_computer.key_credentials,
collector 0.5.16 / schema v37) to tell a device's own key from an added
one. These are heuristics, not proof:
- A computer may write msDS-KeyCredentialLink on itself only through the
  validated write, which succeeds only while the attribute is empty. So a
  computer with MORE THAN ONE key, or a key whose usage is not NGC, whose
  source is not AD (e.g. AzureAD), whose creation time is missing or
  invalid, or that could not be parsed, was most likely written by
  another principal -- the Shadow Credentials pattern. Rated high
  ('fail'), critical when the computer is a domain controller or Tier 0
  (v_tier0_object or object_classification tier 0).
- A single NGC key with source AD and a creation time is what hybrid
  Entra join / Windows Hello device registration writes: info ('verify'),
  low on a DC / Tier 0 computer.
- Rows collected before 0.5.16 (count but no parsed keys) keep the old
  rating (medium, high on DC/Tier 0) with a "re-collect" note.
Disabled accounts are still reduced by two levels. detail.key_credentials
lists each key (key id, device id, usage, source, creation/last-logon
time, flags; never key material) with its anomalies, and
detail.key_credential_link_repl_metadata carries the attribute's
replication metadata version when the DC reports one (it usually does
not for this linked attribute). Summary wording changed.
"""

PLUGIN = {
    "plugin_id": 2013,
    "category": "Computer Accounts",
    "name": "Computer Account Has Shadow Credentials Registered",
    "version": "1.3",
    "revision_date": "2026-10-04",
    "remediation": (
        "Review each entry's legitimacy. Computer objects have "
        "considerably less legitimate reason to carry Windows Hello for "
        "Business key material than user accounts do, so treat an "
        "unexplained entry here with somewhat more suspicion than the "
        "equivalent user-account finding. If an entry can't be attributed "
        "to a known, expected cause, investigate who or what held the "
        "delegated rights needed to write msDS-KeyCredentialLink on this "
        "computer object -- writing this attribute requires specific "
        "elevated rights. A single NGC key with source AD is normally the "
        "device's own key: compare its device_id and creation time with the "
        "device's Entra ID registration before acting. Remove keys flagged "
        "as anomalous that cannot be attributed (e.g. "
        "`Get-ADComputer <name> -Properties msDS-KeyCredentialLink`, "
        "Whisker/pyWhisker list/remove), then find who could write the "
        "attribute."
    ),
    "control_id": "CRED-107",
    "framework_tags": ["MITRE-ATTCK-T1556"],
    "references": [
        {"title": "MITRE ATT&CK T1556: Modify Authentication Process",
         "url": "https://attack.mitre.org/techniques/T1556/"},
    ],
    "description": (
        "msDS-KeyCredentialLink stores Key Credential material used for "
        "passwordless authentication via PKINIT -- the same 'Shadow "
        "Credentials' technique (MITRE ATT&CK T1556) covered for user "
        "accounts by plugin 1022. Anyone with write access to this "
        "attribute can add a rogue key and authenticate as the account "
        "without ever touching its password. Computer objects have "
        "considerably less legitimate reason to carry this kind of key "
        "material than user accounts (which commonly do via WHfB device "
        "enrollment), so an entry here -- while still not automatic proof "
        "of compromise -- is somewhat more noteworthy than the equivalent "
        "user-account finding and worth a closer look. Downgraded when "
        "disabled: PKINIT authentication goes through the same AS-REQ "
        "path as ordinary password authentication, so a disabled "
        "account's AS-REQ should be rejected regardless of which "
        "credential type is presented. "
        "Since collector 0.5.16 each key is parsed and assessed with "
        "heuristics: a computer can register its own key only while it has "
        "none, so more than one key, a non-NGC usage, a non-AD (e.g. "
        "AzureAD) source, a missing creation time or an unparseable entry "
        "indicates a key added by someone else -- high, critical on a "
        "domain controller or Tier 0 computer. A single NGC/AD key is "
        "consistent with the device's own hybrid-join / Windows Hello key "
        "and is reported as info (low on DC/Tier 0) for verification."
    ),
    "base_severity": "medium",
    "query": """
        WITH comp AS (
            SELECT c.*,
                   COALESCE(jsonb_typeof(c.key_credentials) = 'array', false) AS keys_parsed,
                   (c.is_domain_controller
                    OR EXISTS (SELECT 1 FROM v_tier0_object t
                               WHERE t.object_guid = c.object_guid AND t.client_id = c.client_id)
                    OR EXISTS (SELECT 1 FROM object_classification oc
                               WHERE oc.object_guid = c.object_guid AND oc.client_id = c.client_id
                                 AND oc.tier = 0)) AS is_tier0
            FROM ad_computer c
            WHERE c.valid_to IS NULL
              AND c.client_id = %(client_id)s
              AND (COALESCE(c.key_credential_count, 0) > 0
                   OR COALESCE(jsonb_array_length(CASE WHEN jsonb_typeof(c.key_credentials) = 'array'
                                                       THEN c.key_credentials END), 0) > 0)
        ),
        -- [v1.3] Per-key heuristics (see the docstring). Key material is
        -- never stored by the collector; only the parsed metadata is.
        key_eval AS (
            SELECT c.object_guid,
                   count(k.key) AS parsed_key_count,
                   count(*) FILTER (WHERE cardinality(k.reasons) > 0) AS anomalous_key_count,
                   jsonb_agg(k.key || jsonb_build_object('anomalies', to_jsonb(k.reasons))
                             ORDER BY k.key ->> 'creation_time', k.key ->> 'key_id', k.key::text)
                       FILTER (WHERE k.key IS NOT NULL) AS keys
            FROM comp c
            CROSS JOIN LATERAL (
                SELECT e.key,
                       array_remove(ARRAY[
                           CASE WHEN e.key ->> 'parse_error' = 'true'
                                THEN 'unparseable_key_credential' END,
                           CASE WHEN e.key ->> 'parse_error' IS DISTINCT FROM 'true'
                                     AND e.key ->> 'usage' IS DISTINCT FROM 'NGC'
                                THEN 'usage_not_ngc' END,
                           CASE WHEN e.key ->> 'parse_error' IS DISTINCT FROM 'true'
                                     AND e.key ->> 'source' IS DISTINCT FROM 'AD'
                                THEN 'source_not_ad' END,
                           CASE WHEN e.key ->> 'parse_error' IS DISTINCT FROM 'true'
                                     AND COALESCE(e.key ->> 'creation_time', '')
                                         !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}'
                                THEN 'creation_time_missing_or_invalid' END
                       ]::text[], NULL) AS reasons
                FROM jsonb_array_elements(CASE WHEN c.keys_parsed THEN c.key_credentials
                                               ELSE '[]'::jsonb END) AS e(key)
                UNION ALL
                -- keep computers without parsed keys in the aggregate
                SELECT NULL::jsonb, ARRAY[]::text[]
            ) k
            GROUP BY c.object_guid
        ),
        -- [v1.3] msDS-KeyCredentialLink replication metadata, when the DC
        -- reported it (linked-value replication usually keeps it in
        -- msDS-ReplValueMetaData instead, so this is often absent).
        repl_meta AS (
            SELECT c.object_guid,
                   (SELECT jsonb_build_object(
                               'version', m ->> 'version',
                               'last_originating_change', m ->> 'lastOriginatingChangeTime')
                    FROM jsonb_array_elements(
                             CASE WHEN jsonb_typeof(v.attributes_full -> 'msDS-ReplAttributeMetaData') = 'array'
                                  THEN v.attributes_full -> 'msDS-ReplAttributeMetaData'
                                  ELSE '[]'::jsonb END) AS m
                    WHERE lower(m ->> 'attributeName') = 'msds-keycredentiallink'
                    ORDER BY m::text
                    LIMIT 1) AS meta
            FROM comp c
            JOIN directory_object_current cur
                ON cur.object_guid = c.object_guid AND cur.client_id = c.client_id
            JOIN directory_object_version v
                ON v.version_id = cur.version_id AND v.object_guid = cur.object_guid
        ),
        scored AS (
            SELECT c.*,
                   ke.parsed_key_count, ke.anomalous_key_count, ke.keys,
                   rm.meta AS repl_meta,
                   CASE
                       WHEN NOT c.keys_parsed THEN 'not_parsed'
                       WHEN ke.parsed_key_count > 1 OR ke.anomalous_key_count > 0 THEN 'suspicious'
                       ELSE 'likely_device_key'
                   END AS assessment
            FROM comp c
            JOIN key_eval ke ON ke.object_guid = c.object_guid
            LEFT JOIN repl_meta rm ON rm.object_guid = c.object_guid
        ),
        rated AS (
            SELECT s.*,
                   GREATEST(0,
                       CASE s.assessment
                           WHEN 'suspicious' THEN CASE WHEN s.is_tier0 THEN 4 ELSE 3 END
                           WHEN 'not_parsed' THEN CASE WHEN s.is_tier0 THEN 3 ELSE 2 END
                           ELSE CASE WHEN s.is_tier0 THEN 1 ELSE 0 END
                       END
                       - (CASE WHEN s.is_enabled IS FALSE THEN 2 ELSE 0 END)
                   ) AS score,
                   CASE WHEN s.keys_parsed THEN s.parsed_key_count
                        ELSE COALESCE(s.key_credential_count, 0) END AS n_keys
            FROM scored s
        )
        SELECT
            CASE WHEN r.assessment = 'suspicious' THEN 'fail' ELSE 'warn' END AS status,
            r.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE r.score WHEN 4 THEN 'critical' WHEN 3 THEN 'high' WHEN 2 THEN 'medium'
                         WHEN 1 THEN 'low' ELSE 'info' END AS fd_severity,
            (CASE WHEN r.is_domain_controller THEN 'Domain Controller '
                  WHEN r.is_tier0 THEN 'Tier-0 ' ELSE '' END)
                || 'Computer Account ' || COALESCE(r.sam_account_name, r.object_guid::text)
                || ' has ' || r.n_keys
                || CASE WHEN r.n_keys = 1 THEN ' key credential' ELSE ' key credentials' END
                || ' (msDS-KeyCredentialLink) registered -- '
                || CASE r.assessment
                       WHEN 'suspicious' THEN
                           'likely added (Shadow Credentials): '
                           || CASE WHEN r.parsed_key_count > 1
                                   THEN 'a computer can only self-register a key when it has none'
                                   ELSE 'the key does not look like a device self-registration' END
                       WHEN 'not_parsed' THEN
                           'key details not collected (collector before 0.5.16); review for legitimacy'
                       ELSE 'single NGC key from AD, consistent with the device''s own '
                            '(hybrid join / Windows Hello) key; verify'
                   END
                || CASE WHEN r.is_enabled IS FALSE
                        THEN ' (severity reduced: account is disabled)'
                        ELSE '' END AS summary,
            jsonb_build_object(
                'sam_account_name', r.sam_account_name,
                'dns_hostname', r.dns_hostname,
                'key_credential_count', r.key_credential_count,
                'assessment', r.assessment,
                'anomalous_key_count', r.anomalous_key_count,
                'key_credentials', r.keys,
                'key_credential_link_repl_metadata', r.repl_meta,
                'is_enabled', r.is_enabled,
                'is_domain_controller', r.is_domain_controller,
                'is_tier0', r.is_tier0,
                'heuristic',
                    'A computer may write its own key only while it has none (validated '
                    'write), so more than one key, a non-NGC usage, a non-AD source, a '
                    'missing creation time or an unparseable entry suggests an added key.'
            ) AS detail
        FROM rated r
    """,
}
