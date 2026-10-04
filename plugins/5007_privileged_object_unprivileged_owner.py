"""
Plugin 5007: Privileged Object Owned by an Unprivileged Account

Broader than plugin 5006 (which checks ownership of the domain root
and AdminSDHolder specifically): this checks the owner of every
AdminSDHolder-protected object (admin_count=1 user, group, or
computer) across the domain. An owner can always rewrite an object's
ACL outright, regardless of what the object's current explicit
permissions say -- so any compromise of an unprivileged account that
happens to own a privileged object is a direct path to rewriting that
privileged object's own delegation, independent of whatever rights the
unprivileged account holds today.

"Unprivileged" here means: not one of the well-known Tier-0 RIDs
(Domain Admins, Enterprise Admins, Schema Admins, the built-in
Administrator, BUILTIN\\Administrators), and not itself carrying the
admin_count=1 marker.

[v1.1] Now covers computers as well as users and groups -- previously
excluded because this project didn't collect admin_count for computer
objects at all; that gap is closed as of adprofiler.py v0.5.2.

[v1.3] directory_object.owner_sid is now collected for every adminCount=1
user, group and computer (adprofiler 0.5.15 / schema v36); before that
only DC computer objects had an owner, so the user and group branches
could never match. An owner also counts as privileged when it is an
effective member of a protected group (v_privileged_principal source
protected_group_member -- not its ACL-control or ownership sources,
which would excuse the very owner reported here), or is the Domain Controllers group (516) or
Enterprise Domain Controllers. Disabled users/computers are reported at
warn / medium instead of fail / high. The summary now says "group" when
the owner is a group, "principal" when it doesn't resolve, and never
goes NULL for an object without a sAMAccountName. Deleted objects are
ignored.
"""

PLUGIN = {
    "plugin_id": 5007,
    "category": "ACLs",
    "name": "Privileged Object Owned by an Unprivileged Account",
    "version": "1.3",
    "revision_date": "2026-10-04",
    "remediation": (
        "Reassign ownership of the affected object to Domain Admins "
        "(via the Advanced Security Settings dialog in Active "
        "Directory Users and Computers -> Owner tab, or an equivalent "
        "tool). Investigate why the current owner -- an account or "
        "group without Tier-0 status -- was ever set as the owner of a "
        "privileged object, since this is not a default outcome under "
        "normal AD provisioning and often indicates either migration "
        "residue or a genuine, exploitable misconfiguration."
    ),
    "control_id": "ACL-007",
    "framework_tags": [
        "NIST-800-53-AC-3",
        "NIST-800-53-AC-6",
        "NIST-800-53-AC-6(1)",
        "NIST-800-53-AC-2(7)",
        "NIST-800-53-AC-6(5)",
        "NIST-800-53-AC-6(2)",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.2",
        "CIS-CSC-8-3.3",
        "CIS-CSC-8-6.8",
        "CIS-CSC-8-5.4",
        "ISO-27001-2022-A.5.15",
        "ISO-27001-2022-A.8.3",
        "ISO-27001-2022-A.8.2",
        "SOC2-CC6.3",
        "HIPAA-164.312(a)(1)",
        "HIPAA-164.308(a)(4)(ii)(B)",
        "MITRE-ATTCK-T1098",
        "CISA-AA26-237A",
    ],
    "references": [],
    "description": (
        "Broader than plugin 5006 (domain root/AdminSDHolder ownership "
        "specifically): checks the owner of every AdminSDHolder-"
        "protected object (admin_count=1 user, group, or computer) "
        "domain-wide. An owner can always rewrite an object's ACL "
        "regardless of its current explicit permissions, so any "
        "compromise of an unprivileged account that happens to own a "
        "privileged object is a direct path to rewriting that object's "
        "own delegation. 'Unprivileged' means not a well-known Tier-0 "
        "SID, not itself admin_count=1 and not an effective member of a "
        "protected group. Covers users, "
        "groups, and computers; disabled accounts are reported at a "
        "lower severity."
    ),
    "base_severity": "high",
    "query": """
        WITH privileged_objects AS (
            SELECT u.object_guid, udo.owner_sid, udo.sam_account_name, udo.object_class,
                   u.is_enabled
            FROM ad_user u
            JOIN directory_object udo ON udo.object_guid = u.object_guid AND udo.client_id = u.client_id
             AND NOT udo.is_deleted
            WHERE u.valid_to IS NULL AND u.client_id = %(client_id)s AND u.admin_count = 1
            UNION ALL
            SELECT g.object_guid, gdo.owner_sid, gdo.sam_account_name, gdo.object_class,
                   true
            FROM ad_group g
            JOIN directory_object gdo ON gdo.object_guid = g.object_guid AND gdo.client_id = g.client_id
             AND NOT gdo.is_deleted
            WHERE g.valid_to IS NULL AND g.client_id = %(client_id)s AND g.admin_count = 1
            UNION ALL
            SELECT c.object_guid, cdo.owner_sid, cdo.sam_account_name, cdo.object_class,
                   c.is_enabled
            FROM ad_computer c
            JOIN directory_object cdo ON cdo.object_guid = c.object_guid AND cdo.client_id = c.client_id
             AND NOT cdo.is_deleted
            WHERE c.valid_to IS NULL AND c.client_id = %(client_id)s AND c.admin_count = 1
        ),
        owner_is_privileged AS (
            -- Well-known Tier 0 owners, matched by SID so they count even
            -- when not collected: Domain Admins (512), Schema Admins (518),
            -- Enterprise Admins (519), built-in Administrator (500),
            -- Domain Controllers (516), SYSTEM, BUILTIN\\Administrators,
            -- Enterprise Domain Controllers.
            SELECT s.sid AS object_sid
            FROM (SELECT DISTINCT po.owner_sid AS sid FROM privileged_objects po) s
            WHERE s.sid LIKE '%%-512' OR s.sid LIKE '%%-518'
               OR s.sid LIKE '%%-519' OR s.sid LIKE '%%-500'
               OR s.sid LIKE '%%-516'
               OR s.sid IN ('S-1-5-18', 'S-1-5-32-544', 'S-1-5-9')
            UNION
            SELECT owner.object_sid
            FROM directory_object owner
            WHERE owner.client_id = %(client_id)s
              AND NOT owner.is_deleted
              AND (
                    EXISTS (SELECT 1 FROM ad_user ou WHERE ou.object_guid = owner.object_guid
                               AND ou.client_id = owner.client_id AND ou.valid_to IS NULL AND ou.admin_count = 1)
                    OR EXISTS (SELECT 1 FROM ad_group og WHERE og.object_guid = owner.object_guid
                               AND og.client_id = owner.client_id AND og.valid_to IS NULL AND og.admin_count = 1)
                    OR EXISTS (SELECT 1 FROM ad_computer oc WHERE oc.object_guid = owner.object_guid
                               AND oc.client_id = owner.client_id AND oc.valid_to IS NULL AND oc.admin_count = 1)
                    -- [v1.3] Effective (nested / primary-group) member of a
                    -- protected group. Only this v_privileged_principal source
                    -- is used: the ACL-control / ownership sources would make
                    -- the very owner this plugin reports count as privileged
                    -- (owning a protected group is itself Tier 0 ownership).
                    OR EXISTS (SELECT 1 FROM v_privileged_principal vp
                               WHERE vp.client_id = owner.client_id
                                 AND vp.object_guid = owner.object_guid
                                 AND vp.privilege_source = 'protected_group_member')
                  )
        )
        SELECT
            CASE WHEN po.is_enabled IS FALSE THEN 'warn' ELSE 'fail' END AS status,
            po.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN po.is_enabled IS FALSE THEN 'medium' ELSE 'high' END AS fd_severity,
            (CASE WHEN po.object_class = 'user' THEN 'User '
                  WHEN po.object_class = 'computer' THEN 'Computer '
                  ELSE 'Group ' END)
                || COALESCE(po.sam_account_name, po.object_guid::text)
                || (CASE WHEN po.is_enabled IS FALSE THEN ' (privileged, admin_count=1, disabled)'
                         ELSE ' (privileged, admin_count=1)' END)
                || ' is owned by unprivileged '
                || (CASE WHEN owner.object_class = 'group' THEN 'group '
                         WHEN owner.object_class IS NULL THEN 'principal '
                         ELSE 'account ' END)
                || COALESCE(owner.sam_account_name, po.owner_sid) AS summary,
            jsonb_build_object(
                'sam_account_name', po.sam_account_name,
                'object_class', po.object_class,
                'is_enabled', po.is_enabled,
                'owner_sid', po.owner_sid,
                'owner_sam_account_name', owner.sam_account_name,
                'owner_object_class', owner.object_class
            ) AS detail
        FROM privileged_objects po
        LEFT JOIN directory_object owner ON owner.object_sid = po.owner_sid AND owner.client_id = %(client_id)s
         AND NOT owner.is_deleted
        WHERE po.owner_sid IS NOT NULL
          AND NOT EXISTS (SELECT 1 FROM owner_is_privileged oip WHERE oip.object_sid = po.owner_sid)
    """,
}
