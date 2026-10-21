r"""
Plugin 5021: Control Path From Broad or Low-Privileged Principals to Tier 0

Builds one directed graph of "can take control of" relationships from data
the collector already stores, and searches it (up to 6 hops) for paths that
end at a Tier 0 object or principal (v_tier0_object, v_privileged_principal).
Edges:

  member of        group membership (direct and primary group)
  ACL rights       allow ACEs giving control -- GenericAll, GenericWrite,
                   WriteDacl, WriteOwner, WriteProperty (all properties or
                   the member attribute), All Extended Rights, Reset
                   Password, the DCSync rights -- on every object whose ACL
                   is collected (domain root, AdminSDHolder, OUs, GPOs,
                   AD CS objects, DNS zones, KDS keys)
  owns             ownership (owner SID) of an object
  contains         an OU or the domain over the groups, computers and
                   sub-OUs below it (objects protected by AdminSDHolder are
                   left out -- inherited ACEs do not reach them -- except
                   domain controllers); users only when they are Tier 0;
                   computers only when they lead somewhere
  linked to        a GPO over the OUs / domain it is linked to (enabled links)
  RBCD to          resource-based constrained delegation trustee -> computer
  delegates to     constrained delegation source -> target
  reads gMSA pwd   gMSA password reader -> the gMSA

Two kinds of finding:

  1. One row per broad principal -- Everyone, Authenticated Users,
     Anonymous Logon, Users, Domain Users, Domain Computers, Domain Guests --
     that reaches Tier 0: every account in the domain can follow the path,
     so this is a domain compromise waiting to happen ('fail', critical;
     PingCastle P-ControlPathIndirectEveryone). object_guid = the principal
     (its foreign security principal for well-known SIDs, when collected).
     The detail shows the shortest path to each Tier 0 target reached (up
     to 10), hop by hop.

  2. One row for the domain when 20 or more OTHER principals -- not Tier 0
     themselves, and not merely members of a broad group -- hold a multi-hop
     path to Tier 0 ('warn'; low at 20+, medium at 100+, high at 200+;
     PingCastle P-ControlPathIndirectMany). The detail lists up to 50 of
     them with their distance.

Single-hop control is what plugins 5001-5013, 9001 and the v_privileged_
principal definition already report; this plugin adds the chains through
GPOs, OUs, groups, delegation and gMSA readers. Not modelled: ACLs of
ordinary users, groups and computers (not collected), LAPS readers, logon
sessions, local group membership.
"""

PLUGIN = {
    "plugin_id": 5021,
    "category": "ACLs",
    "name": "Control Path From Broad or Low-Privileged Principals to Tier 0",
    "version": "1.0",
    "revision_date": "2026-10-20",
    "control_id": "ACL-5021",
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
        "MITRE-ATTCK-T1484",
        "MITRE-ATTCK-T1222.001",
        "MITRE-ATTCK-T1098",
    ],
    "references": [
        {"title": "PingCastle health check rules (P-ControlPathIndirectEveryone, P-ControlPathIndirectMany)",
         "url": "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
        {"title": "Microsoft: Securing privileged access -- enterprise access model (Tier 0 control plane)",
         "url": "https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model"},
        {"title": "MITRE ATT&CK T1484: Domain or Tenant Policy Modification",
         "url": "https://attack.mitre.org/techniques/T1484/"},
    ],
    "description": (
        "A chain of control relationships (group membership, ACL rights, "
        "ownership, GPO links, OU containment, delegation, gMSA password "
        "readers) leads from a broad group such as Domain Users to a Tier 0 "
        "object (critical), or 20 or more non-Tier 0 principals hold such a "
        "multi-hop path (low to high by count). The detail shows each path "
        "hop by hop."
    ),
    "remediation": (
        "Break the weakest link of each path shown in the detail: remove the "
        "ACE (dsacls / Advanced Security), unlink or re-permission the GPO, "
        "remove the delegation or the gMSA reader, or take the group out of "
        "the chain. Prefer fixing the hop closest to the broad group. Then "
        "re-run the collection and the analysis to confirm no path remains."
    ),
    "base_severity": "critical",
    "query": r"""
        WITH RECURSIVE
        dom AS (
            SELECT d.object_guid, d.object_sid::text AS dsid
            FROM ad_domain m
            JOIN directory_object d
              ON d.object_guid = m.object_guid AND d.client_id = m.client_id AND NOT d.is_deleted
            WHERE m.client_id = %(client_id)s AND m.valid_to IS NULL
            ORDER BY d.object_guid LIMIT 1
        ),
        obj AS (
            SELECT o.object_guid, o.object_guid::text AS node, o.object_sid::text AS sid, o.object_class::text AS cls,
                   o.dn_current, lower(o.dn_current) AS dn, o.sam_account_name, o.owner_sid::text AS owner_sid
            FROM directory_object o
            WHERE o.client_id = %(client_id)s AND NOT o.is_deleted
        ),
        sidmap AS (
            SELECT DISTINCT ON (sid) sid, node FROM obj WHERE sid IS NOT NULL ORDER BY sid, node
        ),
        target AS (
            SELECT t.object_guid::text AS node FROM v_tier0_object t WHERE t.client_id = %(client_id)s
            UNION
            SELECT p.object_guid::text FROM v_privileged_principal p WHERE p.client_id = %(client_id)s
        ),
        protected AS (
            SELECT u.object_guid FROM ad_user u
             WHERE u.client_id = %(client_id)s AND u.valid_to IS NULL AND u.admin_count = 1
            UNION
            SELECT g.object_guid FROM ad_group g
             WHERE g.client_id = %(client_id)s AND g.valid_to IS NULL AND g.admin_count = 1
        ),
        broad (sid, label) AS (
            SELECT v.sid, v.label FROM (VALUES ('S-1-1-0', 'Everyone'), ('S-1-5-11', 'Authenticated Users'),
                                              ('S-1-5-7', 'Anonymous Logon'), ('S-1-5-32-545', 'Users')) AS v(sid, label)
            UNION ALL
            SELECT dom.dsid || r.rid, r.label FROM dom
            CROSS JOIN (VALUES ('-513', 'Domain Users'), ('-515', 'Domain Computers'), ('-514', 'Domain Guests'))
                       AS r(rid, label)
        ),
        start AS (
            SELECT b.sid, b.label, COALESCE(m.node, 'sid:' || b.sid) AS node
            FROM broad b LEFT JOIN sidmap m ON m.sid = b.sid
        ),
        base_edge AS (
            -- membership: member -> group
            SELECT e.member_guid::text AS src, e.group_guid::text AS dst, 'member of' AS kind
            FROM group_member_edge e
            WHERE e.client_id = %(client_id)s AND e.valid_to IS NULL
            UNION
            -- ACL control: trustee -> object
            SELECT COALESCE(m.node, 'sid:' || a.trustee_sid), a.object_guid::text,
                   CASE WHEN (a.access_mask & 268435456) <> 0 OR (a.access_mask & 983551) = 983551 THEN 'GenericAll'
                        WHEN (a.access_mask & 262144) <> 0 THEN 'WriteDacl'
                        WHEN (a.access_mask & 524288) <> 0 THEN 'WriteOwner'
                        WHEN (a.access_mask & 1073741824) <> 0 THEN 'GenericWrite'
                        WHEN (a.access_mask & 32) <> 0 AND a.object_type_guid IS NULL THEN 'WriteProperty (all)'
                        WHEN (a.access_mask & 32) <> 0 THEN 'AddMember'
                        WHEN a.object_type_guid IS NULL THEN 'AllExtendedRights'
                        WHEN lower(a.object_type_guid::text) = '00299570-246d-11d0-a768-00aa006e0529' THEN 'ResetPassword'
                        ELSE 'DCSync' END
            FROM acl_edge a
            LEFT JOIN sidmap m ON m.sid = a.trustee_sid::text
            WHERE a.client_id = %(client_id)s AND a.valid_to IS NULL AND a.ace_type = 'allow'
              AND a.trustee_sid::text NOT IN ('S-1-5-18', 'S-1-3-0', 'S-1-5-10')
              AND ( (a.access_mask & (268435456 | 1073741824 | 262144 | 524288)) <> 0
                    OR (a.access_mask & 983551) = 983551
                    OR ((a.access_mask & 32) <> 0
                        AND (a.object_type_guid IS NULL
                             OR lower(a.object_type_guid::text) = 'bf9679c0-0de6-11d0-a285-00aa003049e2'))
                    OR ((a.access_mask & 256) <> 0
                        AND (a.object_type_guid IS NULL
                             OR lower(a.object_type_guid::text) IN ('00299570-246d-11d0-a768-00aa006e0529',
                                                                    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
                                                                    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'))) )
            UNION
            -- ownership: owner -> object
            SELECT m.node, o.node, 'owns'
            FROM obj o JOIN sidmap m ON m.sid = o.owner_sid
            WHERE o.owner_sid IS NOT NULL AND m.node <> o.node
            UNION
            -- GPO -> the containers it is linked to
            SELECT l.gpo_guid::text, l.container_guid::text, 'linked to'
            FROM gpo_link_edge l
            WHERE l.client_id = %(client_id)s AND l.valid_to IS NULL AND l.link_enabled
            UNION
            -- delegation: RBCD trustee -> resource, constrained source -> target
            SELECT d.source_guid::text, d.target_guid::text,
                   CASE d.delegation_type WHEN 'rbcd' THEN 'RBCD to' ELSE 'delegates to' END
            FROM delegation_edge d
            WHERE d.client_id = %(client_id)s AND d.valid_to IS NULL
              AND d.delegation_type IN ('rbcd', 'constrained') AND d.target_guid IS NOT NULL
            UNION
            -- gMSA password readers
            SELECT COALESCE(m.node, 'sid:' || r.trustee_sid), r.gmsa_guid::text, 'reads gMSA password of'
            FROM gmsa_password_reader_edge r
            LEFT JOIN sidmap m ON m.sid = r.trustee_sid::text
            WHERE r.client_id = %(client_id)s AND r.valid_to IS NULL AND r.ace_type = 'allow'
        ),
        interesting AS (
            -- computers worth entering: they lead somewhere other than the
            -- broad default groups, or they are Tier 0
            SELECT DISTINCT e.src AS node
            FROM base_edge e
            WHERE e.kind <> 'member of'
               OR e.dst NOT IN (SELECT node FROM start)
            UNION
            SELECT node FROM target
        ),
        edge AS (
            SELECT * FROM base_edge
            UNION
            -- containment: OU / domain -> groups, sub-OUs, interesting computers, Tier 0 users
            SELECT c.node, x.node, 'contains'
            FROM obj c
            JOIN obj x ON right(x.dn, length(c.dn) + 1) = ',' || c.dn
            WHERE c.cls IN ('ou', 'domain')
              AND x.cls IN ('group', 'computer', 'ou', 'user')
              AND (x.cls IN ('group', 'ou')
                   OR (x.cls = 'computer' AND x.node IN (SELECT node FROM interesting))
                   OR x.node IN (SELECT node FROM target))
              AND (x.object_guid NOT IN (SELECT object_guid FROM protected)
                   OR EXISTS (SELECT 1 FROM ad_computer dc
                              WHERE dc.client_id = %(client_id)s AND dc.valid_to IS NULL
                                AND dc.object_guid = x.object_guid AND dc.is_domain_controller))
        ),
        reach (start_node, node, depth, prev, kind) AS (
            SELECT s.node, s.node, 0, NULL::text, NULL::text FROM start s
            UNION
            SELECT r.start_node, e.dst, r.depth + 1, r.node, e.kind
            FROM reach r
            JOIN edge e ON e.src = r.node
            WHERE r.depth < 6
              AND NOT EXISTS (SELECT 1 FROM target t WHERE t.node = r.node)
        ),
        first_hit AS (
            SELECT DISTINCT ON (r.start_node, r.node) r.start_node, r.node, r.depth
            FROM reach r JOIN target t ON t.node = r.node
            ORDER BY r.start_node, r.node, r.depth
        ),
        chosen AS (
            SELECT h.*, row_number() OVER (PARTITION BY h.start_node ORDER BY h.depth, h.node) AS rn
            FROM first_hit h
        ),
        best_prev AS (
            SELECT DISTINCT ON (r.start_node, r.node, r.depth) r.start_node, r.node, r.depth, r.prev, r.kind
            FROM reach r
            WHERE r.depth > 0
            ORDER BY r.start_node, r.node, r.depth, r.prev, r.kind
        ),
        lbl AS (
            SELECT o.node,
                   COALESCE(CASE WHEN g.display_name IS NOT NULL THEN 'GPO ' || g.display_name END,
                            o.sam_account_name, o.dn_current, o.node) AS label
            FROM obj o
            LEFT JOIN ad_gpo g
              ON g.object_guid = o.object_guid AND g.client_id = %(client_id)s AND g.valid_to IS NULL
            UNION ALL
            SELECT 'sid:' || b.sid, b.label FROM broad b
        ),
        bt (start_node, target_node, node, depth, path) AS (
            SELECT c.start_node, c.node, c.node, c.depth,
                   COALESCE((SELECT l.label FROM lbl l WHERE l.node = c.node LIMIT 1), c.node) || ' [Tier 0]'
            FROM chosen c WHERE c.rn <= 10
            UNION ALL
            SELECT b.start_node, b.target_node, bp.prev, b.depth - 1,
                   COALESCE((SELECT l.label FROM lbl l WHERE l.node = bp.prev LIMIT 1), bp.prev)
                       || ' -[' || bp.kind || ']-> ' || b.path
            FROM bt b
            JOIN best_prev bp ON bp.start_node = b.start_node AND bp.node = b.node AND bp.depth = b.depth
            WHERE b.depth > 0
        ),
        paths AS (
            SELECT b.start_node, b.target_node, b.path,
                   (SELECT c.depth FROM chosen c WHERE c.start_node = b.start_node AND c.node = b.target_node) AS hops
            FROM bt b WHERE b.depth = 0
        ),
        everyone_rows AS (
            SELECT s.label, s.sid, s.node,
                   min(p.hops) AS shortest,
                   (SELECT count(*) FROM first_hit f WHERE f.start_node = s.node) AS targets_reached,
                   jsonb_agg(jsonb_build_object('hops', p.hops, 'path', p.path) ORDER BY p.hops, p.path) AS paths,
                   (array_agg(p.path ORDER BY p.hops, p.path))[1] AS first_path
            FROM start s
            JOIN paths p ON p.start_node = s.node
            GROUP BY s.label, s.sid, s.node
        ),
        -- part 2: other principals with a multi-hop path (reverse search,
        -- not walking back through the broad groups)
        back (node, depth) AS (
            SELECT t.node, 0 FROM target t
            UNION
            SELECT e.src, b.depth + 1
            FROM back b JOIN edge e ON e.dst = b.node
            WHERE b.depth < 6
              AND b.node NOT IN (SELECT node FROM start)
        ),
        many AS (
            SELECT b.node, min(b.depth) AS depth
            FROM back b
            WHERE b.depth >= 2
              AND b.node NOT IN (SELECT node FROM target)
              AND b.node NOT IN (SELECT node FROM start)
              AND (b.node LIKE 'sid:%%'
                   OR EXISTS (SELECT 1 FROM obj o WHERE o.node = b.node
                                AND o.cls IN ('user', 'group', 'computer', 'foreign_security_principal')))
            GROUP BY b.node
        )
        SELECT
            'fail' AS status,
            CASE WHEN e.node LIKE 'sid:%%' THEN NULL ELSE e.node::uuid END AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'critical' AS fd_severity,
            e.label || ' has a control path to Tier 0: ' || e.first_path AS summary,
            jsonb_build_object(
                'start_principal', e.label,
                'start_sid', e.sid,
                'shortest_path_hops', e.shortest,
                'tier0_targets_reached', e.targets_reached,
                'paths', e.paths
            ) AS detail
        FROM everyone_rows e
        UNION ALL
        SELECT
            'warn',
            (SELECT object_guid FROM dom),
            NULL, NULL, NULL, NULL,
            CASE WHEN count(*) >= 200 THEN 'high' WHEN count(*) >= 100 THEN 'medium' ELSE 'low' END,
            CASE WHEN count(*) >= 200 THEN '200 or more' WHEN count(*) >= 100 THEN '100 or more'
                 ELSE '20 or more' END
                || ' principals that are not Tier 0 hold a multi-hop control path to Tier 0 '
                || '(through groups, OUs, GPOs, delegation or gMSA readers)',
            jsonb_build_object(
                'principal_count', count(*),
                'principals', (SELECT jsonb_agg(jsonb_build_object('principal', x.label, 'hops_to_tier0', x.depth)
                                                ORDER BY x.depth, x.label)
                               FROM (SELECT COALESCE((SELECT l.label FROM lbl l WHERE l.node = m2.node LIMIT 1),
                                                     m2.node) AS label, m2.depth
                                     FROM many m2 ORDER BY m2.depth, 1 LIMIT 50) x)
            )
        FROM many m
        HAVING count(*) >= 20
    """,
}
