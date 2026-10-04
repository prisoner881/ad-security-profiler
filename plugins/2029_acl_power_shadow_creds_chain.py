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
"""

PLUGIN = {
    "plugin_id": 2029,
    "category": "Computer Accounts",
    "name": "Computer Directly Holding DCSync or Dangerous ACL Rights Has Shadow Credentials Registered",
    "version": "1.4",
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
        "computer the value may be legitimate -- inspect the entries "
        "(DeviceId, creation time) before treating it as an incident."
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
        SELECT
            'fail' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'critical' AS fd_severity,
            'Computer Account ' || COALESCE(c.sam_account_name, c.object_guid::text)
                || ' directly holds DCSync or dangerous ACL rights on the domain root or '
                'AdminSDHolder AND has ' || c.key_credential_count || ' msDS-KeyCredentialLink '
                'value(s) registered (possible Shadow Credentials; may be the device''s own key)' AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'key_credential_count', c.key_credential_count,
                'is_generic_all', ap.is_generic_all,
                'is_generic_write', ap.is_generic_write,
                'is_write_dacl', ap.is_write_dacl,
                'is_write_owner', ap.is_write_owner,
                'has_all_extended_rights', ap.has_all_extended_rights,
                'has_get_changes', ap.has_get_changes,
                'has_get_changes_all', ap.has_get_changes_all,
                'has_dcsync', ap.has_dcsync
            ) AS detail
        FROM ad_computer c
        JOIN acl_power ap ON ap.object_guid = c.object_guid
        WHERE c.valid_to IS NULL
          AND c.client_id = %(client_id)s
          AND c.key_credential_count IS NOT NULL
          AND c.key_credential_count > 0
    """,
}
