"""
Plugin 2025: Computer Directly Holding DCSync or Dangerous ACL Rights Runs an Unsupported Operating System

A powerful-but-vulnerable asset: this computer directly holds DCSync or
dangerous ACL rights on the domain root/AdminSDHolder (already flagged
generically by plugins 5001/5002/5003), and is ALSO running an
unsupported, no-longer-patched operating system -- meaning it's not
just unexpectedly powerful, it's an easier-than-average target for
whoever wants that power. Old, unpatched, and privileged is a
particularly unfavorable combination.

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
has_dcsync. The unsupported-OS list no longer matches Windows 10
Enterprise LTSC (2019/2021 and IoT LTSC are still in support) and now
includes Windows 2000 and Windows NT. Detail adds is_enabled (disabled
accounts stay in scope: the standing ACL rights return the moment the
account is re-enabled).
"""

PLUGIN = {
    "plugin_id": 2025,
    "category": "Computer Accounts",
    "name": "Computer Directly Holding DCSync or Dangerous ACL Rights Runs an Unsupported Operating System",
    "version": "1.4",
    "revision_date": "2026-10-04",
    "remediation": (
        "Prioritize over an ordinary unsupported-OS finding -- this "
        "machine's exposure to known, unpatched vulnerabilities is "
        "compounded by the domain-level power it already holds. Replace "
        "or upgrade the OS, and separately review why this computer "
        "holds this level of ACL access at all (see plugins "
        "5001/5002/5003's remediation)."
    ),
    "control_id": "CHAIN-203",
    "framework_tags": [
        "NIST-800-53-AC-3",
        "NIST-800-53-AC-6",
        "NIST-800-53-AC-6(1)",
        "NIST-800-53-SI-2",
        "NIST-800-53-RA-5",
        "NIST-800-53-SA-22",
        "NIST-CSF-2.0-PR.AA-05",
        "NIST-CSF-2.0-ID.RA-01",
        "NIST-CSF-2.0-PR.PS-02",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.2",
        "PCI-DSS-4.0-6.3.3",
        "PCI-DSS-4.0-12.3.4",
        "CIS-CSC-8-3.3",
        "CIS-CSC-8-6.8",
        "CIS-CSC-8-2.2",
        "CIS-CSC-8-7.3",
        "ISO-27001-2022-A.5.15",
        "ISO-27001-2022-A.8.3",
        "ISO-27001-2022-A.8.8",
        "SOC2-CC6.3",
        "SOC2-CC7.1",
        "HIPAA-164.312(a)(1)",
        "MITRE-ATTCK-T1003.006",
    ],
    "references": [
        {"title": "MITRE ATT&CK T1003.006: OS Credential Dumping -- DCSync",
         "url": "https://attack.mitre.org/techniques/T1003/006/"},
        {"title": "BloodHound (SpecterOps): GenericAll edge",
         "url": "https://bloodhound.specterops.io/resources/edges/generic-all"},
    ],
    "description": (
        "Chains ACL data (plugins 5001/5002/5003 -- direct DCSync or "
        "dangerous rights on the domain root/AdminSDHolder) with an "
        "unsupported, end-of-support operating system (plugin 2003). "
        "Old and unpatched is already a real exposure; combined with "
        "domain-level power, it means the easier-than-average path to "
        "compromising this machine leads directly to a complete path to "
        "domain compromise, not just a foothold."
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
                'AdminSDHolder AND is running an unsupported operating system ('
                || c.operating_system || ')' AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'operating_system', c.operating_system,
                'is_enabled', c.is_enabled,
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
          AND (
                (c.operating_system ILIKE '%%windows 10%%' AND c.operating_system NOT ILIKE '%%LTSC%%') OR c.operating_system ILIKE '%%server 2012%%'
                OR c.operating_system ILIKE '%%server 2008%%' OR c.operating_system ILIKE '%%server 2003%%'
                OR c.operating_system ILIKE '%%windows 7%%' OR c.operating_system ILIKE '%%windows 8%%'
                OR c.operating_system ILIKE '%%windows xp%%' OR c.operating_system ILIKE '%%windows vista%%'
                OR c.operating_system ILIKE '%%windows 2000%%' OR c.operating_system ILIKE '%%windows nt%%'
              )
    """,
}
