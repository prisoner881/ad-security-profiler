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
"""

PLUGIN = {
    "plugin_id": 5007,
    "category": "ACLs",
    "name": "Privileged Object Owned by an Unprivileged Account",
    "version": "1.1",
    "revision_date": "2026-07-19",
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
    "framework_tags": [],
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
        "RID and not itself admin_count=1. Covers users, groups, and "
        "computers."
    ),
    "base_severity": "high",
    "query": """
        WITH privileged_objects AS (
            SELECT u.object_guid, udo.owner_sid, udo.sam_account_name, udo.object_class
            FROM ad_user u
            JOIN directory_object udo ON udo.object_guid = u.object_guid AND udo.client_id = u.client_id
            WHERE u.valid_to IS NULL AND u.client_id = %(client_id)s AND u.admin_count = 1
            UNION ALL
            SELECT g.object_guid, gdo.owner_sid, gdo.sam_account_name, gdo.object_class
            FROM ad_group g
            JOIN directory_object gdo ON gdo.object_guid = g.object_guid AND gdo.client_id = g.client_id
            WHERE g.valid_to IS NULL AND g.client_id = %(client_id)s AND g.admin_count = 1
            UNION ALL
            SELECT c.object_guid, cdo.owner_sid, cdo.sam_account_name, cdo.object_class
            FROM ad_computer c
            JOIN directory_object cdo ON cdo.object_guid = c.object_guid AND cdo.client_id = c.client_id
            WHERE c.valid_to IS NULL AND c.client_id = %(client_id)s AND c.admin_count = 1
        ),
        owner_is_privileged AS (
            SELECT owner.object_sid
            FROM directory_object owner
            WHERE owner.client_id = %(client_id)s
              AND (
                    owner.object_sid LIKE '%%-512' OR owner.object_sid LIKE '%%-518'
                    OR owner.object_sid LIKE '%%-519' OR owner.object_sid LIKE '%%-500'
                    OR owner.object_sid = 'S-1-5-18' OR owner.object_sid = 'S-1-5-32-544'
                    OR EXISTS (SELECT 1 FROM ad_user ou WHERE ou.object_guid = owner.object_guid
                               AND ou.client_id = owner.client_id AND ou.valid_to IS NULL AND ou.admin_count = 1)
                    OR EXISTS (SELECT 1 FROM ad_group og WHERE og.object_guid = owner.object_guid
                               AND og.client_id = owner.client_id AND og.valid_to IS NULL AND og.admin_count = 1)
                    OR EXISTS (SELECT 1 FROM ad_computer oc WHERE oc.object_guid = owner.object_guid
                               AND oc.client_id = owner.client_id AND oc.valid_to IS NULL AND oc.admin_count = 1)
                  )
        )
        SELECT
            'fail' AS status,
            po.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            (CASE WHEN po.object_class = 'user' THEN 'User '
                  WHEN po.object_class = 'computer' THEN 'Computer '
                  ELSE 'Group ' END)
                || po.sam_account_name || ' (privileged, admin_count=1) is owned by unprivileged account '
                || COALESCE(owner.sam_account_name, po.owner_sid) AS summary,
            jsonb_build_object(
                'sam_account_name', po.sam_account_name,
                'object_class', po.object_class,
                'owner_sid', po.owner_sid,
                'owner_sam_account_name', owner.sam_account_name,
                'owner_object_class', owner.object_class
            ) AS detail
        FROM privileged_objects po
        LEFT JOIN directory_object owner ON owner.object_sid = po.owner_sid AND owner.client_id = %(client_id)s
        LEFT JOIN owner_is_privileged oip ON oip.object_sid = po.owner_sid
        WHERE po.owner_sid IS NOT NULL
          AND oip.object_sid IS NULL
    """,
}
