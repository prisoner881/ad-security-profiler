"""
Plugin 2029: Computer Directly Holding DCSync or Dangerous ACL Rights Has Shadow Credentials Registered

Distinct in kind from the other chains in this batch: those combine ACL
power with a structural weakness (old OS, dormancy). This one combines
ACL power with a possible ACTIVE COMPROMISE indicator. Shadow
credentials (msDS-KeyCredentialLink) are a known persistence mechanism
-- an attacker who briefly gains write access to an already-powerful
account can register their own authentication key, retaining access to
that account's power even if the password is later rotated. Finding
this specifically on an account that already holds DCSync or dangerous
ACL rights is one of the more concerning combinations this project can
surface, and warrants investigation as a potential incident, not simply
a configuration cleanup item.

[v1.3] GenericAll/GenericWrite are now recognised in the form AD stores
them. ACE masks are stored already mapped: GenericAll as 0xF01FF and
GenericWrite as 0x20028 (WRITE_PROP with no object type, i.e. write
every property), so the raw GENERIC_ALL (0x10000000) / GENERIC_WRITE
(0x40000000) bits tested before essentially never matched --
GenericWrite-only grants were missed and GenericAll was labelled as
WriteDacl/WriteOwner (raw bits are still matched too). Inherit-only ACEs
(acl_edge.inherit_only, schema v34) are skipped: they grant nothing on
the object they are stored on, only on its descendants.

[v1.4] DCSync now follows v_privileged_principal exactly: on the domain root only,
both DS-Replication-Get-Changes and Get-Changes-All (or All Extended
Rights, which GenericAll includes), each with CONTROL_ACCESS (0x100) set.
Get-Changes alone, a replication GUID without CONTROL_ACCESS, or a
replication right on AdminSDHolder no longer qualify on their own. "All
Extended Rights" (CONTROL_ACCESS with no object type) on either object is
now matched (on the root it is DCSync; on AdminSDHolder it propagates
e.g. User-Force-Change-Password to every protected account). Deleted
trustee objects are excluded. Detail adds has_all_extended_rights and
has_dcsync. The key-credential side is now described as what it is:
domain-joined Windows 10+/Server 2016+ computers (Windows Hello for
Business key trust, hybrid join, device PKINIT) commonly register their
own key in msDS-KeyCredentialLink, so a non-zero count on a computer is
weak evidence on its own. The summary now reads "N msDS-KeyCredentialLink
value(s) registered (possible Shadow Credentials; may be the device's own
key)". The KeyCredential blobs (DeviceId, creation time, source) are not
parsed by the collector, so self-registered device keys cannot yet be
told apart from added ones; severity stays critical because the ACL-power
side alone warrants it.

[v1.5] The KeyCredentials are now parsed (ad_computer.key_credentials,
collector 0.5.16 / schema v37) and assessed with the same heuristics as
plugin 2013 -- heuristics, not proof. A computer may write its own
msDS-KeyCredentialLink only through the validated write, which succeeds
only while the attribute is empty; so more than one key, or a key whose
usage is not NGC, whose source is not AD, whose creation time is missing
or invalid, or that could not be parsed, is most likely an added key:
critical ('fail'), as before. A single NGC/AD key with a creation time is
consistent with the device's own hybrid-join / Windows Hello key: the
finding drops to high ('warn') -- the ACL power is still reported by
plugins 5001-5003. Rows collected before 0.5.16 (no parsed keys) stay
critical. detail adds key_assessment, anomalous_key_count and
key_credentials (per-key id, device id, usage, source, times, flags and
anomalies; no key material). Summary wording changed.
"""

PLUGIN = {
    "plugin_id": 2029,
    "category": "Computer Accounts",
    "name": "Computer Directly Holding DCSync or Dangerous ACL Rights Has Shadow Credentials Registered",
    "version": "1.5",
    "revision_date": "2026-10-04",
    "remediation": (
        "Treat as a potential active compromise, not a routine finding: "
        "review the registered key credential(s) for legitimacy "
        "(`Get-ADComputer -Filter * -Properties msDS-KeyCredentialLink`, "
        "or Whisker/similar tooling to enumerate and inspect), and if "
        "not explainable, assume this account's power has already been "
        "used maliciously -- investigate accordingly rather than simply "
        "removing the shadow credential and moving on. Rotating the "
        "account's password alone will NOT remove this persistence "
        "mechanism."
    ),
    "control_id": "CHAIN-207",
    "framework_tags": ["MITRE-ATTCK-T1556"],
    "references": [
        {"title": "MITRE ATT&CK T1556: Modify Authentication Process",
         "url": "https://attack.mitre.org/techniques/T1556/"},
    ],
    "description": (
        "Distinct in kind from this batch's other chains: those combine "
        "ACL power (plugins 5001/5002/5003) with a structural weakness; "
        "this combines it with a possible active-compromise indicator "
        "(plugin 2013 -- msDS-KeyCredentialLink populated). Shadow "
        "credentials are a known persistence mechanism: an attacker who "
        "briefly gains write access to an already-powerful account can "
        "register their own authentication key, retaining that "
        "account's power even after a password rotation. Finding this "
        "on an account that already holds DCSync or dangerous ACL "
        "rights is one of the more concerning combinations this project "
        "can surface. Caveat: Windows 10+/Server 2016+ computers commonly "
        "register their own device key in msDS-KeyCredentialLink, so on a "
        "computer the value may be legitimate. Since collector 0.5.16 the "
        "keys are parsed: a computer can only self-register a key while it "
        "has none, so more than one key, a non-NGC usage, a non-AD source, "
        "a missing creation time or an unparseable entry is treated as an "
        "added key (critical); a single NGC/AD key is consistent with the "
        "device's own key and is rated high (heuristic; verify DeviceId and "
        "creation time)."
    ),
    "base_severity": "critical",
    "query": """
        WITH acl_power_raw AS (
            SELECT do2.object_guid,
                   bool_or((a.access_mask & 983551) = 983551 OR (a.access_mask & 268435456) <> 0) AS is_generic_all,
                   bool_or(((a.access_mask & 32) <> 0 AND a.object_type_guid IS NULL)
                              OR (a.access_mask & 1073741824) <> 0) AS is_generic_write,
                   bool_or((a.access_mask & 262144) != 0) AS is_write_dacl,
                   bool_or((a.access_mask & 524288) != 0) AS is_write_owner,
                   bool_or((a.access_mask & 256) <> 0 AND a.object_type_guid IS NULL) AS has_all_extended_rights,
                   -- replication rights only matter on the domain root and need CONTROL_ACCESS
                   bool_or(d.object_guid IS NOT NULL AND (a.access_mask & 256) <> 0
                           AND a.object_type_guid = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2') AS has_get_changes,
                   bool_or(d.object_guid IS NOT NULL AND (a.access_mask & 256) <> 0
                           AND a.object_type_guid = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2') AS has_get_changes_all,
                   bool_or(d.object_guid IS NOT NULL AND (a.access_mask & 256) <> 0
                           AND a.object_type_guid IS NULL) AS root_all_extended_rights
            FROM acl_edge a
            JOIN directory_object secured
                ON secured.object_guid = a.object_guid AND secured.client_id = a.client_id
            LEFT JOIN ad_domain d
                ON d.object_guid = a.object_guid AND d.client_id = a.client_id AND d.valid_to IS NULL
            JOIN directory_object do2
                ON do2.object_sid = a.trustee_sid AND do2.client_id = a.client_id AND NOT do2.is_deleted
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND a.inherit_only IS NOT TRUE   -- inherit-only: grants nothing on this object
              AND (
                    (a.access_mask & (268435456 | 1073741824 | 262144 | 524288)) != 0
                    OR (a.access_mask & 983551) = 983551                    -- GenericAll, as stored
                    OR ((a.access_mask & 32) <> 0 AND a.object_type_guid IS NULL)  -- GenericWrite, as stored
                    OR ((a.access_mask & 256) <> 0                          -- CONTROL_ACCESS: all extended
                        AND (a.object_type_guid IS NULL                     -- rights, or a replication right
                             OR a.object_type_guid IN ('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
                                                       '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')))
                  )
              AND (
                    secured.dn_current ILIKE 'CN=AdminSDHolder,%%'
                    OR d.object_guid IS NOT NULL
                  )
            GROUP BY do2.object_guid
        ), acl_power AS (
            -- DCSync exactly as v_privileged_principal defines it: on the domain root, both
            -- Get-Changes and Get-Changes-All, or All Extended Rights (GenericAll includes it).
            SELECT r.*,
                   (r.root_all_extended_rights OR (r.has_get_changes AND r.has_get_changes_all)) AS has_dcsync
            FROM acl_power_raw r
            WHERE r.root_all_extended_rights
               OR (r.has_get_changes AND r.has_get_changes_all)
               OR r.is_generic_all OR r.is_generic_write OR r.is_write_dacl OR r.is_write_owner
               OR r.has_all_extended_rights
        )
        , comp AS (
            SELECT c.*,
                   COALESCE(jsonb_typeof(c.key_credentials) = 'array', false) AS keys_parsed
            FROM ad_computer c
            JOIN acl_power ap ON ap.object_guid = c.object_guid
            WHERE c.valid_to IS NULL
              AND c.client_id = %(client_id)s
              AND (COALESCE(c.key_credential_count, 0) > 0
                   OR COALESCE(jsonb_array_length(CASE WHEN jsonb_typeof(c.key_credentials) = 'array'
                                                       THEN c.key_credentials END), 0) > 0)
        ),
        -- [v1.5] Per-key heuristics, as plugin 2013: a computer may write its
        -- own key only while it has none, so more than one key, a non-NGC
        -- usage, a non-AD source, a missing creation time or an unparseable
        -- entry points at a key added by someone else.
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
                SELECT NULL::jsonb, ARRAY[]::text[]
            ) k
            GROUP BY c.object_guid
        ),
        assessed AS (
            SELECT c.*, ke.parsed_key_count, ke.anomalous_key_count, ke.keys,
                   CASE
                       WHEN NOT c.keys_parsed THEN 'not_parsed'
                       WHEN ke.parsed_key_count > 1 OR ke.anomalous_key_count > 0 THEN 'suspicious'
                       ELSE 'likely_device_key'
                   END AS assessment,
                   CASE WHEN c.keys_parsed THEN ke.parsed_key_count
                        ELSE COALESCE(c.key_credential_count, 0) END AS n_keys
            FROM comp c
            JOIN key_eval ke ON ke.object_guid = c.object_guid
        )
        SELECT
            CASE WHEN c.assessment = 'likely_device_key' THEN 'warn' ELSE 'fail' END AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN c.assessment = 'likely_device_key' THEN 'high' ELSE 'critical' END AS fd_severity,
            'Computer Account ' || COALESCE(c.sam_account_name, c.object_guid::text)
                || ' directly holds DCSync or dangerous ACL rights on the domain root or '
                   'AdminSDHolder AND has ' || c.n_keys
                || CASE WHEN c.n_keys = 1 THEN ' msDS-KeyCredentialLink value'
                        ELSE ' msDS-KeyCredentialLink values' END
                || ' registered ('
                || CASE c.assessment
                       WHEN 'suspicious' THEN 'likely Shadow Credentials: '
                           || CASE WHEN c.parsed_key_count > 1
                                   THEN 'more than one key, a computer can only self-register one'
                                   ELSE 'the key does not look like a device self-registration' END
                       WHEN 'not_parsed' THEN 'possible Shadow Credentials; key details not collected '
                                              'by collectors before 0.5.16'
                       ELSE 'single NGC key from AD, consistent with the device''s own key; verify'
                   END
                || ')' AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'key_credential_count', c.key_credential_count,
                'key_assessment', c.assessment,
                'anomalous_key_count', c.anomalous_key_count,
                'key_credentials', c.keys,
                'is_generic_all', ap.is_generic_all,
                'is_generic_write', ap.is_generic_write,
                'is_write_dacl', ap.is_write_dacl,
                'is_write_owner', ap.is_write_owner,
                'has_all_extended_rights', ap.has_all_extended_rights,
                'has_get_changes', ap.has_get_changes,
                'has_get_changes_all', ap.has_get_changes_all,
                'has_dcsync', ap.has_dcsync
            ) AS detail
        FROM assessed c
        JOIN acl_power ap ON ap.object_guid = c.object_guid
    """,
}
