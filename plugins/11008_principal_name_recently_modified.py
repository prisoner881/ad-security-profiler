"""
Plugin 11008: Principal Name Attribute Modified Recently (Replication Metadata)

Reports accounts whose sAMAccountName, userPrincipalName or
servicePrincipalName was modified recently, using the directory's own
replication metadata rather than a comparison between collection runs.

Why this is different from the rest of the 11xxx category
---------------------------------------------------------
Every other Change Detection plugin compares this run against the previous
one, and is therefore silent on a client's first collection. This one reads
msDS-ReplAttributeMetaData, which Active Directory maintains per attribute on
every object: the version counter, the originating domain controller, and the
timestamp of the last originating change. That information is already in the
directory before we ever connect.

The practical consequence is that **this plugin works on a first run**. On an
initial engagement, where there is no baseline and no event log retention to
speak of, it can still answer "was this account's UPN set last week or five
years ago" -- which is precisely the question that separates a long-standing
misconfiguration from an active intrusion.

It pairs directly with the three name-confusion plugins:

  * 1043 reports a UPN copied from another account's sAMAccountName
    (ResetNightmare, CVE-2026-27912)
  * 4028 reports a duplicate SPN, and 4029 an SPN shadowing a HOST alias
    (KerberLoss, CVE-2026-25177)

Those report the dangerous state. This reports that the state is new. A
conflicting SPN that has existed since 2019 is migration debris; the same SPN
created yesterday is an incident.

The attribute set is deliberately narrow. sAMAccountName, userPrincipalName
and servicePrincipalName are the three names Kerberos resolves principals by,
and they are the three that the 2026 vulnerabilities manipulate. Watching
every attribute would produce noise; watching these three produces a short,
reviewable list.

Timestamp format caveat
-----------------------
adprofiler.py parses msDS-ReplAttributeMetaData into structured JSON, but
ftimeLastOriginatingChange is stored as the string the domain controller
emitted, and that rendering has not been verified across DC versions. This
plugin accepts both an ISO-style timestamp and an LDAP generalized-time value,
and treats anything it cannot parse as unknown -- yielding no finding rather
than an error. A malformed timestamp therefore produces a false negative, not
a failed run. If this plugin reports nothing in an environment where names are
known to have changed recently, check the raw value before assuming the
directory is quiet:

    SELECT jsonb_pretty(attributes_full -> 'msDS-ReplAttributeMetaData')
    FROM directory_object_version
    WHERE valid_to IS NULL LIMIT 1;
"""

PLUGIN = {
    "plugin_id": 11008,
    "category": "Change Detection",
    "name": "Principal Name Attribute Modified Recently (Replication Metadata)",
    "version": "1.0",
    "revision_date": "2026-09-29",
    "remediation": (
        "Reconcile each change against a known administrative action. The "
        "evidence names the attribute, the originating domain controller and "
        "the directory's own timestamp for the change, which is enough to "
        "locate the corresponding Security event 5136 on that specific DC "
        "rather than searching all of them. "
        "Prioritise by attribute. A userPrincipalName change is the one to "
        "look at first: cross-reference plugin 1043, because a UPN newly set "
        "to another account's sAMAccountName is an active ResetNightmare "
        "attempt rather than a historical artefact. A servicePrincipalName "
        "change should be checked against plugins 4028 and 4029 for "
        "duplicate or shadowing registrations, and against plugin 1009, "
        "since adding an SPN to a user account makes it Kerberoastable -- an "
        "attacker may add an SPN, request and crack a service ticket, then "
        "remove the SPN, in which case the replication version counter will "
        "have advanced even though the current value looks unremarkable. A "
        "sAMAccountName change on an existing account is uncommon outside "
        "of a rename process and worth confirming against a ticket. "
        "Where a change cannot be accounted for, treat the account as "
        "suspect: review what it can access, reset its credential, and "
        "examine who holds write access to that attribute. Note that the "
        "version counter in the evidence is cumulative -- a high version on "
        "a rarely-changed attribute indicates repeated modification, which "
        "is itself worth a question even when the current value is benign."
    ),
    "control_id": "CHANGE-508",
    "framework_tags": ["MITRE-ATTCK-T1098", "MITRE-ATTCK-T1558.003",
                       "MITRE-ATTCK-T1036", "CVE-2026-25177", "CVE-2026-27912"],
    "references": [
        {"title": "MS-DRSR: DS_REPL_ATTR_META_DATA",
         "url": "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/9d5b9f9b-e5f3-4d1a-b0a1-1a0f2b5a45f4"},
        {"title": "Semperis: KerberLoss and ResetNightmare",
         "url": "https://www.semperis.com/blog/identity-crisis-novel-vulnerabilities-leading-to-kerberos-downgrade-dos-and-full-domain-takeover/"},
    ],
    "description": (
        "Reports accounts whose sAMAccountName, userPrincipalName or "
        "servicePrincipalName was modified within the last 14 days according "
        "to the directory's own replication metadata "
        "(msDS-ReplAttributeMetaData). Unlike the other Change Detection "
        "plugins this does not compare collection runs, so it produces "
        "results on a first collection and does not require a baseline. "
        "These three attributes are the names Kerberos resolves principals "
        "by, and are the ones manipulated by the 2026 name-confusion "
        "vulnerabilities; the plugin exists to distinguish a long-standing "
        "misconfiguration from a change made this week. Evidence includes "
        "the originating domain controller and the attribute version "
        "counter. Timestamps that cannot be parsed are treated as unknown "
        "and produce no finding."
    ),
    "base_severity": "medium",
    "query": """
        WITH reference AS (
            -- Measure the window from the collection, not from analysis time,
            -- so re-analysing an older snapshot still gives a sane answer.
            SELECT COALESCE(
                       (SELECT sr.completed_at FROM sync_run sr
                         WHERE sr.run_id = %(run_id)s
                           AND sr.client_id = %(client_id)s),
                       now()) AS ref_time
        ),
        privileged_roots AS (
            SELECT g.object_guid, g.sam_account_name
            FROM ad_group g
            JOIN directory_object gdo
                ON gdo.object_guid = g.object_guid AND gdo.client_id = g.client_id
            WHERE g.valid_to IS NULL
              AND g.client_id = %(client_id)s
              AND (gdo.object_sid LIKE '%%-512' OR gdo.object_sid LIKE '%%-516'
                   OR gdo.object_sid LIKE '%%-518' OR gdo.object_sid LIKE '%%-519'
                   OR gdo.object_sid LIKE '%%-520' OR gdo.object_sid LIKE '%%-544'
                   OR gdo.object_sid LIKE '%%-548' OR gdo.object_sid LIKE '%%-549'
                   OR gdo.object_sid LIKE '%%-550' OR gdo.object_sid LIKE '%%-551')
        ),
        privileged_members AS (
            SELECT vem.member_guid,
                   array_agg(DISTINCT pr.sam_account_name ORDER BY pr.sam_account_name)
                       AS via_groups
            FROM v_effective_group_membership vem
            JOIN privileged_roots pr ON pr.object_guid = vem.group_guid
            WHERE vem.client_id = %(client_id)s
            GROUP BY vem.member_guid
        ),
        meta AS (
            SELECT v.object_guid,
                   e.value ->> 'attributeName'                 AS attr_name,
                   e.value ->> 'version'                       AS attr_version,
                   e.value ->> 'lastOriginatingDcInvocationId' AS origin_dc,
                   e.value ->> 'lastOriginatingChangeTime'     AS change_time_raw
            FROM directory_object_version v
            CROSS JOIN LATERAL jsonb_array_elements(
                     v.attributes_full -> 'msDS-ReplAttributeMetaData') AS e
            WHERE v.client_id = %(client_id)s
              AND v.valid_to IS NULL
              AND jsonb_typeof(v.attributes_full -> 'msDS-ReplAttributeMetaData')
                  = 'array'
              AND e.value ->> 'attributeName' IN
                  ('sAMAccountName', 'userPrincipalName', 'servicePrincipalName')
        ),
        parsed AS (
            SELECT m.*,
                   CASE
                       -- ISO-like: 2026-09-14T15:00:00Z / 2026-09-14 15:00:00+00
                       WHEN m.change_time_raw ~
                            '^[0-9]{4}-[0-9]{2}-[0-9]{2}[ T][0-9]{2}:[0-9]{2}:[0-9]{2}'
                           THEN m.change_time_raw::timestamptz
                       -- LDAP generalized time: 20260914150000.0Z
                       WHEN m.change_time_raw ~ '^[0-9]{14}'
                           THEN to_timestamp(substr(m.change_time_raw, 1, 14),
                                             'YYYYMMDDHH24MISS')
                       ELSE NULL
                   END AS change_time
            FROM meta m
        ),
        recent AS (
            SELECT p.object_guid,
                   bool_or(p.attr_name = 'userPrincipalName')    AS upn_changed,
                   bool_or(p.attr_name = 'servicePrincipalName') AS spn_changed,
                   bool_or(p.attr_name = 'sAMAccountName')       AS sam_changed,
                   max(p.change_time) AS most_recent_change,
                   jsonb_agg(jsonb_build_object(
                       'attribute', p.attr_name,
                       'changed_at', p.change_time,
                       'version', p.attr_version,
                       'originating_dc_invocation_id', p.origin_dc
                   ) ORDER BY p.change_time DESC) AS changes
            FROM parsed p
            CROSS JOIN reference r
            WHERE p.change_time IS NOT NULL
              AND p.change_time >  r.ref_time - interval '14 days'
              AND p.change_time <= r.ref_time + interval '1 day'
            GROUP BY p.object_guid
        )
        SELECT
            'warn' AS status,
            rc.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE
                WHEN pm.via_groups IS NOT NULL THEN 'high'
                WHEN rc.upn_changed OR rc.sam_changed THEN 'high'
                ELSE 'medium'
            END AS fd_severity,
            'Account "' || COALESCE(do2.sam_account_name, do2.dn_current)
                || '" had '
                || array_to_string(ARRAY_REMOVE(ARRAY[
                       CASE WHEN rc.sam_changed THEN 'sAMAccountName' END,
                       CASE WHEN rc.upn_changed THEN 'userPrincipalName' END,
                       CASE WHEN rc.spn_changed THEN 'servicePrincipalName' END
                   ], NULL), ', ')
                || ' modified on ' || to_char(rc.most_recent_change,
                                              'YYYY-MM-DD HH24:MI')
                || ' according to directory replication metadata'
                || CASE WHEN pm.via_groups IS NOT NULL
                        THEN ' -- the account is an effective member of '
                             || array_to_string(pm.via_groups, ', ')
                        ELSE '' END AS summary,
            jsonb_build_object(
                'sam_account_name', do2.sam_account_name,
                'distinguished_name', do2.dn_current,
                'object_class', do2.object_class,
                'most_recent_change', rc.most_recent_change,
                'user_principal_name_changed', rc.upn_changed,
                'service_principal_name_changed', rc.spn_changed,
                'sam_account_name_changed', rc.sam_changed,
                'privileged_via_groups', pm.via_groups,
                'changes', rc.changes,
                'source',
                    'msDS-ReplAttributeMetaData (directory-reported, does not '
                    'depend on a previous collection run)',
                'related_plugins', jsonb_build_array(1009, 1043, 4027, 4028, 4029),
                'corroborating_event_id', 5136
            ) AS detail
        FROM recent rc
        JOIN directory_object do2
            ON do2.object_guid = rc.object_guid AND do2.client_id = %(client_id)s
        LEFT JOIN privileged_members pm ON pm.member_guid = rc.object_guid
    """,
}
