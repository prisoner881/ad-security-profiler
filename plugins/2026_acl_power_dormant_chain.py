"""
Plugin 2026: Computer Directly Holding DCSync or Dangerous ACL Rights Is Dormant

An abandoned-but-powerful asset: this computer directly holds DCSync or
dangerous ACL rights on the domain root/AdminSDHolder, and has not
logged on in 90+ days (or has never logged on). Nobody appears to be
actively watching this machine, yet it retains standing, high-value
domain access -- exactly the kind of forgotten asset that gets
overlooked in routine monitoring while remaining fully exploitable.

[v1.3] The summary now states the last logon time as a date (UTC, to the
day) rather than a day count computed from now(). The count differed on
every run, so an unchanged finding was recorded as 'changed' on every
audit; the date only moves when the underlying attribute does. Severity
and inclusion thresholds are unchanged.

[v1.4] GenericAll/GenericWrite are now recognised in the form AD stores
them. ACE masks are stored already mapped: GenericAll as 0xF01FF and
GenericWrite as 0x20028 (WRITE_PROP with no object type, i.e. write
every property), so the raw GENERIC_ALL (0x10000000) / GENERIC_WRITE
(0x40000000) bits tested before essentially never matched --
GenericWrite-only grants were missed and GenericAll was labelled as
WriteDacl/WriteOwner (raw bits are still matched too). Inherit-only ACEs
(acl_edge.inherit_only, schema v34) are skipped: they grant nothing on
the object they are stored on, only on its descendants.
"""

PLUGIN = {
    "plugin_id": 2026,
    "category": "Computer Accounts",
    "name": "Computer Directly Holding DCSync or Dangerous ACL Rights Is Dormant",
    "version": "1.4",
    "revision_date": "2026-10-03",
    "remediation": (
        "Investigate immediately: either this machine is still in "
        "legitimate service but something is preventing normal logon "
        "activity (worth understanding on its own merits), or it's "
        "genuinely abandoned and still holds domain-level power nobody "
        "is accounting for. If abandoned, remove the ACL grant and "
        "decommission the account; if still needed, confirm the grant "
        "is still appropriate and document why it exists."
    ),
    "control_id": "CHAIN-204",
    "framework_tags": [],
    "references": [
        {"title": "MITRE ATT&CK T1003.006: OS Credential Dumping -- DCSync",
         "url": "https://attack.mitre.org/techniques/T1003/006/"},
        {"title": "BloodHound (SpecterOps): GenericAll edge",
         "url": "https://bloodhound.specterops.io/resources/edges/generic-all"},
    ],
    "description": (
        "Chains ACL data (plugins 5001/5002/5003) with dormancy (plugin "
        "2006 -- 90+ days since last logon, or never logged on). An "
        "asset nobody appears to be actively monitoring, yet which "
        "retains standing, high-value access to the domain root or "
        "AdminSDHolder -- exactly the kind of forgotten configuration "
        "that survives routine reviews while remaining fully "
        "exploitable to anyone who finds it."
    ),
    "base_severity": "critical",
    "query": """
        WITH acl_power AS (
            SELECT do2.object_guid,
                   bool_or((a.access_mask & 983551) = 983551 OR (a.access_mask & 268435456) <> 0) AS is_generic_all,
                   bool_or(((a.access_mask & 32) <> 0 AND a.object_type_guid IS NULL)
                              OR (a.access_mask & 1073741824) <> 0) AS is_generic_write,
                   bool_or((a.access_mask & 262144) != 0) AS is_write_dacl,
                   bool_or((a.access_mask & 524288) != 0) AS is_write_owner,
                   bool_or(a.object_type_guid = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2') AS has_get_changes,
                   bool_or(a.object_type_guid = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2') AS has_get_changes_all
            FROM acl_edge a
            JOIN directory_object secured
                ON secured.object_guid = a.object_guid AND secured.client_id = a.client_id
            JOIN directory_object do2 ON do2.object_sid = a.trustee_sid AND do2.client_id = a.client_id
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND a.inherit_only IS NOT TRUE   -- [v1.4] inherit-only: grants nothing on this object
              AND (
                    (a.access_mask & (268435456 | 1073741824 | 262144 | 524288)) != 0
                    OR (a.access_mask & 983551) = 983551                    -- GenericAll, as stored
                    OR ((a.access_mask & 32) <> 0 AND a.object_type_guid IS NULL)  -- GenericWrite, as stored
                    OR a.object_type_guid IN ('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
                                               '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')
                  )
              AND (
                    secured.dn_current ILIKE 'CN=AdminSDHolder,%%'
                    OR EXISTS (SELECT 1 FROM ad_domain d WHERE d.object_guid = secured.object_guid AND d.valid_to IS NULL)
                  )
            GROUP BY do2.object_guid
        )
        SELECT
            'fail' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'critical' AS fd_severity,
            'Computer Account ' || c.sam_account_name
                || ' directly holds DCSync or dangerous ACL rights on the domain root or '
                'AdminSDHolder AND '
                || (CASE WHEN c.last_logon_timestamp IS NULL THEN 'has never logged on'
                         ELSE 'has not logged on since ' || to_char(c.last_logon_timestamp AT TIME ZONE 'UTC', 'YYYY-MM-DD') END)
                AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'last_logon_timestamp', c.last_logon_timestamp,
                'is_generic_all', ap.is_generic_all,
                'is_generic_write', ap.is_generic_write,
                'is_write_dacl', ap.is_write_dacl,
                'is_write_owner', ap.is_write_owner,
                'has_get_changes', ap.has_get_changes,
                'has_get_changes_all', ap.has_get_changes_all
            ) AS detail
        FROM ad_computer c
        JOIN acl_power ap ON ap.object_guid = c.object_guid
        WHERE c.valid_to IS NULL
          AND c.client_id = %(client_id)s
          AND (c.last_logon_timestamp IS NULL OR c.last_logon_timestamp < now() - interval '90 days')
    """,
}
