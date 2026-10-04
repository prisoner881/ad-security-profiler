"""
Plugin 5010: Broad Rights Over Descendant Objects Delegated at the Domain Root

Companion to plugin 5003. 5003 reports dangerous rights over the domain
root object itself; this reports the same rights granted at the domain
root but marked inherit-only (INHERIT_ONLY_ACE) -- i.e. delegated over
every descendant object, or every descendant object of one class
(all users, all computers, all groups), domain-wide. A typical example
is "Full Control over descendant Computer objects" granted at the root
to a deployment or imaging account.

Before schema v34 these ACEs were indistinguishable from rights over the
domain root itself, so 5003 reported them as domain-root control (and
the shared definition of "privileged" counted their holders as domain
admins). They aren't that: SDProp disables inheritance on
AdminSDHolder-protected objects (Domain Admins, domain controllers,
...), so these rights don't reach Tier 0. But they do give control of
every other account or computer of that class in the domain -- a
password reset, shadow credentials or RBCD away from any server or
user that isn't protected -- which is still a finding worth reviewing,
at high rather than critical severity.

Only ACEs whose inherit_only flag is known (TRUE) are reported here.
Rows collected before schema v34 have inherit_only NULL and are still
reported by 5003 until adprofiler.py's next run backfills the flag.

One row per trustee: a trustee holding several such ACEs (different
rights, or different object classes) gets one finding listing all of
them, so the finding identity (the trustee's object_guid) is unique.

[v1.1] Corrected the severity rationale above. SDProp protects only
objects with adminCount = 1, and DC computer objects normally don't
carry it -- their DACL inherits from the domain root through
OU=Domain Controllers. A grant that reaches computer objects (all
descendant classes, or the computer class) therefore reaches the DCs,
and GenericAll/GenericWrite/WriteDacl/WriteOwner on a DC computer object
(RBCD, shadow credentials) is domain compromise. Such a finding is now
critical whenever some DC in the collection has adminCount other than 1
(the same test v_privileged_principal applies since schema v36); it
stays high otherwise, and for grants scoped to other classes.
Collector caveat: adprofiler.py merges ACEs that differ only in
inherited_object_type_guid into one edge with that column NULL, so two
class-scoped delegations with the same mask can be reported as "all
descendant objects" (and rated as reaching computers).
"""

PLUGIN = {
    "plugin_id": 5010,
    "category": "ACLs",
    "name": "Broad Rights Over Descendant Objects Delegated at the Domain Root",
    "version": "1.1",
    "revision_date": "2026-10-04",
    "remediation": (
        "Confirm the delegation is intended and scoped as narrowly as it "
        "can be. Prefer delegating on the specific OU(s) holding the "
        "objects the principal actually manages, with only the specific "
        "rights needed (e.g. reset password, write specific attributes), "
        "instead of GenericAll/GenericWrite/WriteDacl/WriteOwner over a "
        "whole object class domain-wide. Remove with `dsacls \"DC=...\" "
        "/R <trustee>` (removes all of the trustee's ACEs on the root, so "
        "re-grant anything legitimate) or via ADSI Edit's Advanced "
        "Security settings on the domain root."
    ),
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
        "MITRE-ATTCK-T1098",
    ],
    "references": [
        {"title": "Microsoft: ACE inheritance rules",
         "url": "https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-inheritance-rules"},
        {"title": "Microsoft: Protected Accounts and Groups in Active Directory (SDProp)",
         "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory"},
    ],
    "description": (
        "Flags GenericAll, GenericWrite, WriteDacl and WriteOwner granted "
        "at the domain root as inherit-only, i.e. over all descendant "
        "objects (or all descendants of one class) domain-wide. Critical "
        "when the grant reaches computer objects and some domain "
        "controller's computer object is not AdminSDHolder-protected "
        "(adminCount <> 1), so it inherits the grant; high otherwise. "
        "Excludes the well-known expected holders (Domain Admins, "
        "Enterprise Admins, Administrators, SYSTEM)."
    ),
    "base_severity": "critical",
    "query": """
        WITH expected_holders AS (
            SELECT do2.object_guid
            FROM directory_object do2
            WHERE do2.client_id = %(client_id)s
              AND (do2.object_sid LIKE '%%-512' OR do2.object_sid LIKE '%%-519'
                   OR do2.object_sid LIKE '%%-544')
            UNION
            SELECT fsp.object_guid
            FROM ad_foreign_security_principal fsp
            WHERE fsp.client_id = %(client_id)s AND fsp.valid_to IS NULL
              AND fsp.well_known_name = 'Local System'
        ),
        descendant_aces AS (
            SELECT a.trustee_sid, a.access_mask, a.inherited_object_type_guid,
                   ((a.access_mask & 983551) = 983551 OR (a.access_mask & 268435456) <> 0) AS is_generic_all,
                   (((a.access_mask & 32) <> 0 AND a.object_type_guid IS NULL)
                       OR (a.access_mask & 1073741824) <> 0) AS is_generic_write,
                   (a.access_mask & 262144) <> 0 AS is_write_dacl,
                   (a.access_mask & 524288) <> 0 AS is_write_owner,
                   CASE a.inherited_object_type_guid
                       WHEN 'bf967aba-0de6-11d0-a285-00aa003049e2' THEN 'User'
                       WHEN 'bf967a86-0de6-11d0-a285-00aa003049e2' THEN 'Computer'
                       WHEN 'bf967a9c-0de6-11d0-a285-00aa003049e2' THEN 'Group'
                       WHEN 'bf967aa5-0de6-11d0-a285-00aa003049e2' THEN 'Organizational Unit'
                       WHEN '7b8b558a-93a5-4af7-adca-c017e67f1057' THEN 'Group Managed Service Account'
                       ELSE NULL
                   END AS class_name,
                   -- [v1.1] reaches computer objects (and so DC computer objects)
                   (a.inherited_object_type_guid IS NULL
                    OR a.inherited_object_type_guid = 'bf967a86-0de6-11d0-a285-00aa003049e2') AS reaches_computers
            FROM acl_edge a
            JOIN ad_domain d
                ON d.object_guid = a.object_guid AND d.client_id = a.client_id
               AND d.valid_to IS NULL
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND a.inherit_only IS TRUE
              AND (
                    (a.access_mask & (268435456 | 1073741824 | 262144 | 524288)) <> 0
                    OR (a.access_mask & 983551) = 983551
                    OR ((a.access_mask & 32) <> 0 AND a.object_type_guid IS NULL)
                  )
        ),
        labelled AS (
            SELECT da.*,
                   (SELECT string_agg(x, ', ') FROM (VALUES
                        (CASE WHEN da.is_generic_all THEN 'GenericAll' END),
                        (CASE WHEN da.is_generic_write AND NOT da.is_generic_all THEN 'GenericWrite' END),
                        (CASE WHEN da.is_write_dacl AND NOT da.is_generic_all THEN 'WriteDacl' END),
                        (CASE WHEN da.is_write_owner AND NOT da.is_generic_all THEN 'WriteOwner' END)
                    ) AS v(x) WHERE x IS NOT NULL) AS rights_label,
                   CASE
                       WHEN da.inherited_object_type_guid IS NULL THEN 'all descendant objects'
                       WHEN da.class_name IS NOT NULL THEN 'all descendant ' || da.class_name || ' objects'
                       ELSE 'all descendant objects of class ' || da.inherited_object_type_guid
                   END AS scope_label
            FROM descendant_aces da
        ),
        -- [v1.1] SDProp only shields DC computer objects that are
        -- AdminSDHolder-protected (adminCount = 1). If any DC isn't, its
        -- computer object inherits these ACEs: RBCD / shadow credentials
        -- on a DC is domain compromise. Same test v_privileged_principal
        -- uses for inherit-only root ACEs (schema v36).
        unprotected_dc AS (
            SELECT EXISTS (
                SELECT 1 FROM ad_computer dc
                WHERE dc.client_id = %(client_id)s AND dc.valid_to IS NULL
                  AND dc.is_domain_controller
                  AND dc.admin_count IS DISTINCT FROM 1
            ) AS present
        )
        SELECT
            'fail' AS status,
            do2.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN bool_or(l.reaches_computers) AND bool_or(ud.present)
                 THEN 'critical' ELSE 'high' END AS fd_severity,
            'Principal ' || COALESCE(do2.sam_account_name, l.trustee_sid)
                || ' holds, via the domain root, '
                || string_agg(DISTINCT l.rights_label || ' over ' || l.scope_label, '; '
                              ORDER BY l.rights_label || ' over ' || l.scope_label)
                || ' domain-wide' AS summary,
            jsonb_build_object(
                'trustee_sid', l.trustee_sid,
                'sam_account_name', do2.sam_account_name,
                'object_class', do2.object_class,
                'grants', jsonb_agg(DISTINCT jsonb_build_object(
                    'rights', l.rights_label,
                    'applies_to', l.scope_label,
                    'inherited_object_type_guid', l.inherited_object_type_guid,
                    'access_mask', l.access_mask
                )),
                'reaches_computer_objects', bool_or(l.reaches_computers),
                'unprotected_domain_controller_present', bool_or(ud.present)
            ) AS detail
        FROM labelled l
        CROSS JOIN unprotected_dc ud
        JOIN directory_object do2
            ON do2.object_sid = l.trustee_sid AND do2.client_id = %(client_id)s
           AND NOT do2.is_deleted
        WHERE NOT EXISTS (
            SELECT 1 FROM expected_holders eh WHERE eh.object_guid = do2.object_guid
        )
        GROUP BY do2.object_guid, do2.sam_account_name, do2.object_class, l.trustee_sid
    """,
}
