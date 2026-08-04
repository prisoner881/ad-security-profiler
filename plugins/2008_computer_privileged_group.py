"""
Plugin 2008: Computer Account Holds Unexpected Privileged Access

A workstation or member server's machine account is not normally
expected to hold privileged access at all -- whether via membership in
an AdminSDHolder-protected group (the original, sole check this plugin
performed), or, as of this version, directly holding dangerous rights
or DCSync rights on the domain root/AdminSDHolder, or owning either
object outright. Any of the three means anyone who achieves SYSTEM-level
access on that machine (a much lower bar than compromising a human's
credentials directly -- SYSTEM access is the routine outcome of
countless common exploitation and misconfiguration paths) inherits that
privileged access along with it.

[v1.2] Broadened from group-membership-only to also recognize
ACL-derived privilege, mirroring the identical enhancement applied to
the equivalent user-account privileged_check CTE. The summary text now
correctly names whichever mechanism(s) actually apply, rather than
always claiming group membership -- a real, if narrow, accuracy risk
found while making this change: a naive broadening of the trigger
condition without also updating the summary construction would have
produced a factually wrong "is a member of a privileged group" claim
for a computer that was actually privileged via a direct ACE or
ownership instead.
"""

PLUGIN = {
    "plugin_id": 2008,
    "category": "Computer Accounts",
    "name": "Computer Account Holds Unexpected Privileged Access",
    "version": "1.3",
    "revision_date": "2026-07-17",
    "remediation": (
        "Determine why this computer account holds this access -- it is "
        "almost never an intentional, necessary configuration for an "
        "ordinary workstation or member server. If it was added for a "
        "specific automation/service purpose, replace it with a properly "
        "scoped service account or gMSA instead of granting the privilege "
        "to the machine account itself, then remove the access. If it "
        "cannot be explained, treat it as a potential compromise "
        "indicator and investigate before simply removing it, since "
        "removal alone won't explain how it got there."
    ),
    "control_id": "PRIV-201",
    "framework_tags": [],
    "references": [],
    "description": (
        "A workstation or member server's machine account is not "
        "normally expected to hold privileged access at all -- domain "
        "controllers are the one legitimate, expected exception and are "
        "excluded from this check. Checks three independent mechanisms: "
        "membership (direct or nested, via the same view used for the "
        "equivalent user-account check) in an AdminSDHolder-protected "
        "group; directly holding GenericAll/GenericWrite/WriteDacl/"
        "WriteOwner or DCSync rights on the domain root or AdminSDHolder "
        "via an explicit ACE; or owning either object outright. Any of "
        "the three means anyone who achieves SYSTEM-level access on this "
        "machine -- a routine outcome of a very wide range of common "
        "exploitation paths, a much lower bar than compromising a "
        "specific human's credentials -- inherits that privileged access "
        "along with it. "
        "NOT downgraded when disabled: this kind of privilege is persistent configuration unaffected by the account's enabled state."
    ),
    "base_severity": "high",
    "query": """
        WITH privileged_membership AS (
            SELECT DISTINCT vem.member_guid AS object_guid,
                   TRUE AS via_group, FALSE AS via_acl, FALSE AS via_owner
            FROM v_effective_group_membership vem
            JOIN directory_object pgo
                ON pgo.object_guid = vem.group_guid AND pgo.client_id = vem.client_id
            JOIN ad_group pg
                ON pg.object_guid = pgo.object_guid AND pg.valid_to IS NULL
            WHERE vem.client_id = %(client_id)s
              AND pg.is_protected_group
            UNION ALL
            SELECT do_acl.object_guid, FALSE, TRUE, FALSE
            FROM acl_edge a
            JOIN directory_object do_acl ON do_acl.object_sid = a.trustee_sid AND do_acl.client_id = a.client_id
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND (
                    (a.access_mask & (268435456 | 1073741824 | 262144 | 524288)) != 0
                    OR a.object_type_guid IN ('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
                                               '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')
                  )
            UNION ALL
            SELECT do_owner.object_guid, FALSE, FALSE, TRUE
            FROM directory_object owned_target
            JOIN directory_object do_owner
                ON do_owner.object_sid = owned_target.owner_sid AND do_owner.client_id = owned_target.client_id
            WHERE owned_target.client_id = %(client_id)s
              AND owned_target.owner_sid IS NOT NULL
        ),
        privileged_agg AS (
            SELECT object_guid, bool_or(via_group) AS via_group,
                   bool_or(via_acl) AS via_acl, bool_or(via_owner) AS via_owner
            FROM privileged_membership
            GROUP BY object_guid
        )
        SELECT
            'fail' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'Computer Account ' || c.sam_account_name || ' holds privileged access: ' || (
                SELECT string_agg(x, '; ') FROM (VALUES
                    (CASE WHEN pa.via_group THEN 'member of a privileged (AdminSDHolder-protected) group' END),
                    (CASE WHEN pa.via_acl THEN 'directly holds dangerous or DCSync rights on the domain root/AdminSDHolder' END),
                    (CASE WHEN pa.via_owner THEN 'owns the domain root or AdminSDHolder' END)
                ) AS v(x) WHERE x IS NOT NULL
            ) AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'dns_hostname', c.dns_hostname,
                'operating_system', c.operating_system,
                'is_enabled', c.is_enabled,
                'via_group', pa.via_group,
                'via_acl', pa.via_acl,
                'via_owner', pa.via_owner
            ) AS detail
        FROM ad_computer c
        JOIN privileged_agg pa ON pa.object_guid = c.object_guid
        WHERE c.valid_to IS NULL
          AND c.client_id = %(client_id)s
          AND NOT c.is_domain_controller
    """,
}

