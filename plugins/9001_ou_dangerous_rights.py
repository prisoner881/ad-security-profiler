"""
Plugin 9001: Dangerous Rights on an Organizational Unit Held by an Unexpected Principal

Same pattern as plugins 5002 (AdminSDHolder) and 5003 (domain root),
applied per-OU: GenericAll, GenericWrite, WriteDacl, or WriteOwner on
an OU is functionally equivalent to full control over every object
within it -- new accounts created there, existing ones modified,
computer objects reconfigured for delegation, anything. OU delegation
is one of the more common real-world privilege-escalation paths this
project had no visibility into before Organizational Unit collection
existed: a broad grant made once for a legitimate reason (a help desk
team needing to manage one department's computers, say) that's never
revisited, or was scoped more broadly than intended from the start.

Unlike domain root/AdminSDHolder, there's no fixed, universal "this OU
should only ever be touched by these specific principals" answer --
every organization's OU structure and delegation model is different.
This finding flags anything beyond the same baseline well-known
holders excluded elsewhere in this project (Domain Admins, Enterprise
Admins, Administrators, SYSTEM); a security team reviewing results
will need to apply their own knowledge of what delegation is
legitimate for their specific OU structure.

[v1.2] GenericAll/GenericWrite are now recognised in the form AD stores
them. ACE masks are stored already mapped: GenericAll as 0xF01FF and
GenericWrite as 0x20028 (WRITE_PROP with no object type, i.e. write
every property), so the raw GENERIC_ALL (0x10000000) / GENERIC_WRITE
(0x40000000) bits tested before essentially never matched --
GenericWrite-only grants were missed and GenericAll was labelled as
WriteDacl/WriteOwner (raw bits are still matched too). The rights label
names only GenericAll when it is held, since it subsumes the rest.
Inherit-only ACEs are deliberately still counted: OU delegation to
descendant objects is what this plugin reports.

[v1.3] Trustees no longer have to exist in directory_object. The inner
join silently dropped every SID without a collected object -- Everyone
(S-1-1-0), Anonymous Logon (S-1-5-7), Authenticated Users, Creator
Owner, principals of trusted domains without an FSP, orphaned SIDs of
deleted principals -- so the worst grants (Everyone/Anonymous with
GenericAll or WriteDacl) were never reported. Unresolved SIDs are now
labelled from a well-known-SID map, else shown as the raw SID. Expected
holders are excluded by SID (SYSTEM S-1-5-18, Administrators
S-1-5-32-544, this domain's Domain Admins -512, Enterprise Admins -519)
instead of through directory_object (SYSTEM was only excluded by accident
of the inner join). Only explicit ACEs are evaluated (acl_edge.inherited
= FALSE): an ACE inherited from a parent OU is reported once, on the OU
where it is set, not again on every descendant OU; grants inherited from
the domain root are plugins 5003/5010's. Rights are aggregated per
trustee per OU first (one entry per trustee, sorted by label then SID),
so the summary is deterministic and a trustee is never listed twice. OU
joins are client-scoped.
"""

PLUGIN = {
    "plugin_id": 9001,
    "category": "Organizational Units",
    "name": "Dangerous Rights on an Organizational Unit Held by an Unexpected Principal",
    "version": "1.3",
    "revision_date": "2026-10-04",
    "remediation": (
        "Confirm whether this grant is a deliberate, understood "
        "delegation (e.g. a help desk team scoped to manage computers "
        "within this specific OU) or leftover/overly broad. Review via "
        "the OU's own Security tab in Active Directory Users and "
        "Computers (enable Advanced Features to see it), or "
        "`dsacls \"<OU DN>\" /R <trustee>` to remove a specific grant. "
        "GenericAll/WriteDacl on an OU is equivalent to full control "
        "over everything within it -- if the underlying need is "
        "narrower (e.g. only resetting passwords, or only managing "
        "computer objects specifically), delegate that specific, "
        "narrower right instead via the Delegation of Control Wizard."
    ),
    "control_id": "ACL-901",
    "framework_tags": [
        "NIST-800-53-AC-3",
        "NIST-800-53-AC-6",
        "NIST-800-53-AC-6(1)",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.2",
        "CIS-CSC-8-3.3",
        "CIS-CSC-8-6.8",
        "ISO-27001-2022-A.5.15",
        "ISO-27001-2022-A.8.3",
        "SOC2-CC6.3",
        "HIPAA-164.312(a)(1)",
        "DISA-STIG",
        "MITRE-ATTCK-T1098",
    ],
    "references": [
        {"title": "BloodHound (SpecterOps): GenericAll edge",
         "url": "https://bloodhound.specterops.io/resources/edges/generic-all"},
        {"title": "BloodHound (SpecterOps): WriteDacl edge",
         "url": "https://bloodhound.specterops.io/resources/edges/write-dacl"},
    ],
    "description": (
        "Same pattern as plugins 5002/5003 (AdminSDHolder/domain root), "
        "applied per-OU: GenericAll, GenericWrite, WriteDacl, or "
        "WriteOwner on an OU is functionally equivalent to full control "
        "over every object within it. OU delegation is one of the more "
        "common real-world privilege-escalation paths -- a broad grant "
        "made once for a legitimate, narrower reason, never revisited. "
        "Excludes the same baseline well-known holders (Domain Admins, "
        "Enterprise Admins, Administrators, SYSTEM) used elsewhere in "
        "this project; unlike domain root/AdminSDHolder there's no "
        "universal answer for what else is expected, since every "
        "organization's OU delegation model differs. Well-known SIDs "
        "with no directory object (Everyone, Anonymous Logon, "
        "Authenticated Users, ...) and orphaned SIDs are reported too. "
        "Only ACEs set explicitly on the OU are evaluated, so a "
        "delegation inherited from a parent OU is reported once, on the "
        "OU where it is set."
    ),
    "base_severity": "high",
    "query": """
        WITH dom AS (
            SELECT cl.domain_sid
            FROM client cl
            WHERE cl.client_id = %(client_id)s
        ),
        dangerous_aces AS (
            SELECT a.object_guid AS ou_guid, a.trustee_sid, a.access_mask,
                   ((a.access_mask & 983551) = 983551 OR (a.access_mask & 268435456) <> 0) AS is_generic_all,
                   (((a.access_mask & 32) <> 0 AND a.object_type_guid IS NULL)
                       OR (a.access_mask & 1073741824) <> 0) AS is_generic_write,
                   (a.access_mask & 262144) != 0 AS is_write_dacl,
                   (a.access_mask & 524288) != 0 AS is_write_owner
            FROM acl_edge a
            JOIN ad_ou o ON o.object_guid = a.object_guid AND o.client_id = a.client_id
                        AND o.valid_to IS NULL
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              -- [v1.3] explicit ACEs only: inherited copies are reported on
              -- the OU where they are set (or by 5003/5010 for the root)
              AND a.inherited = FALSE
              AND (
                    (a.access_mask & (268435456 | 1073741824 | 262144 | 524288)) != 0
                    OR (a.access_mask & 983551) = 983551                    -- GenericAll, as stored
                    OR ((a.access_mask & 32) <> 0 AND a.object_type_guid IS NULL)  -- GenericWrite, as stored
                  )
              -- [v1.3] expected holders excluded by SID, not via directory_object
              AND a.trustee_sid NOT IN ('S-1-5-18', 'S-1-5-32-544')
              AND a.trustee_sid !~ '^S-1-5-21-[0-9-]+-519$'
              AND NOT EXISTS (
                    SELECT 1 FROM dom
                    WHERE (dom.domain_sid IS NOT NULL AND a.trustee_sid = dom.domain_sid || '-512')
                       OR (dom.domain_sid IS NULL AND a.trustee_sid ~ '^S-1-5-21-[0-9-]+-512$')
                  )
        ),
        -- [v1.3] one entry per (OU, trustee): several ACEs of the same
        -- trustee used to list it twice and order the summary ambiguously
        per_trustee AS (
            SELECT da.ou_guid, da.trustee_sid,
                   bit_or(da.access_mask) AS access_mask,
                   array_agg(DISTINCT da.access_mask ORDER BY da.access_mask) AS access_masks,
                   bool_or(da.is_generic_all) AS is_generic_all,
                   bool_or(da.is_generic_write) AS is_generic_write,
                   bool_or(da.is_write_dacl) AS is_write_dacl,
                   bool_or(da.is_write_owner) AS is_write_owner
            FROM dangerous_aces da
            GROUP BY da.ou_guid, da.trustee_sid
        ),
        unexpected_holders AS (
            SELECT pt.ou_guid, pt.trustee_sid,
                   -- [v1.3] trustees without a directory object are kept
                   COALESCE(tdo.sam_account_name, fsp.well_known_name, wk.name, pt.trustee_sid)
                       AS trustee_label,
                   tdo.object_class AS trustee_object_class,
                   pt.access_mask, pt.access_masks,
                   (SELECT string_agg(x, ', ' ORDER BY n) FROM (VALUES
                        (1, CASE WHEN pt.is_generic_all THEN 'GenericAll' END),
                        (2, CASE WHEN pt.is_generic_write AND NOT pt.is_generic_all THEN 'GenericWrite' END),
                        (3, CASE WHEN pt.is_write_dacl AND NOT pt.is_generic_all THEN 'WriteDacl' END),
                        (4, CASE WHEN pt.is_write_owner AND NOT pt.is_generic_all THEN 'WriteOwner' END)
                    ) AS v(n, x) WHERE x IS NOT NULL) AS rights_label
            FROM per_trustee pt
            LEFT JOIN LATERAL (
                SELECT d.object_guid, d.sam_account_name, d.object_class
                FROM directory_object d
                WHERE d.client_id = %(client_id)s
                  AND d.object_sid = pt.trustee_sid
                ORDER BY d.is_deleted, d.object_guid
                LIMIT 1
            ) tdo ON TRUE
            LEFT JOIN ad_foreign_security_principal fsp
                ON fsp.object_guid = tdo.object_guid AND fsp.client_id = %(client_id)s
               AND fsp.valid_to IS NULL
            LEFT JOIN (VALUES
                ('S-1-1-0', 'Everyone'),
                ('S-1-5-7', 'Anonymous Logon'),
                ('S-1-5-11', 'Authenticated Users'),
                ('S-1-3-0', 'Creator Owner'),
                ('S-1-3-1', 'Creator Group'),
                ('S-1-5-10', 'Self'),
                ('S-1-5-2', 'Network'),
                ('S-1-5-4', 'Interactive'),
                ('S-1-5-9', 'Enterprise Domain Controllers'),
                ('S-1-5-32-545', 'Users'),
                ('S-1-5-32-546', 'Guests'),
                ('S-1-5-32-548', 'Account Operators'),
                ('S-1-5-32-549', 'Server Operators'),
                ('S-1-5-32-550', 'Print Operators'),
                ('S-1-5-32-551', 'Backup Operators'),
                ('S-1-5-32-554', 'Pre-Windows 2000 Compatible Access')
            ) AS wk(sid, name) ON wk.sid = pt.trustee_sid
        ),
        -- [fix, caught via a real production crash at large scale (525
        -- OUs) that this project's own small test lab never exposed]
        -- identity_guid is the OU's object_guid, not the trustee's --
        -- the original version produced one row per unexpected
        -- trustee, and any OU with more than one over-delegated
        -- principal (routine at real-world scale, even if never
        -- exercised by a 1-OU test lab) collided on identity_guid.
        -- Aggregated here instead: one finding per OU, listing every
        -- unexpected trustee and what they hold.
        aggregated AS (
            SELECT ou_guid,
                   array_agg(trustee_label || ' (' || rights_label || ')'
                             ORDER BY trustee_label, trustee_sid) AS holder_summaries,
                   jsonb_agg(jsonb_build_object(
                       'trustee_sid', trustee_sid,
                       'trustee_sam_account_name', trustee_label,
                       'trustee_object_class', trustee_object_class,
                       'access_mask', access_mask,
                       'access_masks', to_jsonb(access_masks),
                       'rights', rights_label
                   ) ORDER BY trustee_label, trustee_sid) AS holder_details,
                   count(*) AS holder_count
            FROM unexpected_holders
            GROUP BY ou_guid
        )
        SELECT
            'fail' AS status,
            a.ou_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            a.holder_count || ' unexpected principal(s) hold dangerous rights on OU "'
                || COALESCE(o.ou_name, a.ou_guid::text) || '": '
                || array_to_string(a.holder_summaries, '; ') AS summary,
            jsonb_build_object(
                'ou_name', o.ou_name,
                'holders', a.holder_details
            ) AS detail
        FROM aggregated a
        JOIN ad_ou o ON o.object_guid = a.ou_guid AND o.client_id = %(client_id)s
                    AND o.valid_to IS NULL
    """,
}
