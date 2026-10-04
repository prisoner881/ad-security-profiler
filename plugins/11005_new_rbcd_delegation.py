"""
Plugin 11005: Resource-Based Constrained Delegation Newly Configured

Change Detection companion to plugins 1031, 2022, 2027 and 1034, which
report standing RBCD configuration. This one reports the moment it
appears.

Derived from CISA advisory AA26-237A (2026-08-25). In the Water and
Wastewater Systems assessment, the red team held AllExtendedRights over
a domain controller through an over-permissioned service account, used
it to configure resource-based constrained delegation against that DC,
and from there performed DCSync and obtained the krbtgt hash.

RBCD deserves change detection more than most delegation
misconfigurations because of how it is written. Unlike classic
constrained delegation, which requires SeEnableDelegationPrivilege and
is therefore a domain-admin operation, RBCD is configured by writing
msDS-AllowedToActOnBehalfOfOtherIdentity on the *target* object -- so
whoever can write that one attribute on a host can grant themselves
the ability to impersonate any user to it. That right is bundled into
GenericAll, GenericWrite and WriteDacl, all of which are handed out far
more freely than delegation rights ever were. It is also fast to set
and fast to remove, which makes it a poor fit for point-in-time
auditing and a good fit for this category.

Any new RBCD edge is reported. Severity is critical where the target is
a domain controller, since that configuration is a direct path to
domain compromise and has no legitimate use in ordinary operations.

[v1.2] Review found no defect. Since collector schema v36,
msDS-AllowedToActOnBehalfOfOtherIdentity is also collected on user
objects, so RBCD can now target krbtgt (RID 502) -- a known persistence
technique: a principal allowed to delegate to krbtgt can obtain a TGT for
any user via S4U2Self/S4U2Proxy. Such a target is now critical, like a
domain controller. Note the snapshot limit: RBCD set and cleared again
between two collection runs is not observed here. Trustee SIDs that do not
resolve to a collected object (foreign or deleted principals) are dropped
by the collector and therefore not reported.

[v1.3] Unresolved trustees are reported too: since collector 0.5.16
(schema v37) RBCD trustees that are not collected objects -- well-known
SIDs such as Everyone or Authenticated Users, foreign or orphaned SIDs --
are kept in rbcd_unresolved_trustee_edge, and an edge opened in this run
(run_id_valid_from, as for delegation_edge) is new. Because older
collectors never recorded them, unresolved edges are only counted when
the previous successful run was collected by 0.5.16 or later; otherwise
every pre-existing one would read as new on the first upgraded run.
Well-known SIDs are labelled by name; a broad trustee (Everyone,
Authenticated Users, Anonymous Logon, BUILTIN Users, Domain Users,
Domain Computers, ...) makes the finding critical regardless of target.
Each detail.delegations entry gains delegated_to_sid, trustee_kind and
is_broad_principal; detail gains broad_principal_trustee. Deleted trustee
objects are no longer listed. Still one row per target.
"""

PLUGIN = {
    "plugin_id": 11005,
    "category": "Change Detection",
    "name": "Resource-Based Constrained Delegation Newly Configured",
    "version": "1.3",
    "revision_date": "2026-10-04",
    "remediation": (
        "Establish whether the delegation was configured deliberately. "
        "RBCD has legitimate uses, but they are specific and "
        "documented -- typically a front-end service that must "
        "impersonate users to a back-end resource -- and the "
        "configuring team will be able to name both ends. Where the "
        "target is a domain controller, treat the finding as an "
        "incident rather than a misconfiguration: there is no "
        "legitimate reason to permit any principal to impersonate "
        "arbitrary users to a DC, and this is a documented path to "
        "DCSync and full domain compromise, used against a domain "
        "controller in CISA's AA26-237A red team assessment. Clear "
        "the attribute (Set-ADComputer <target> -Clear "
        "msDS-AllowedToActOnBehalfOfOtherIdentity), then determine "
        "how the write was possible: enumerate who holds GenericAll, "
        "GenericWrite or WriteDacl on the target object, since all "
        "three confer the ability to set this attribute, and review "
        "whether the principal named in this finding should hold any "
        "of them. Rotate credentials for both the delegating "
        "principal and any account that could have been impersonated "
        "through the delegation window. Longer term, add domain "
        "controller computer objects to a monitored set and alert on "
        "any write to msDS-AllowedToActOnBehalfOfOtherIdentity "
        "against them (Security event ID 5136, directory service "
        "object modified)."
    ),
    "control_id": "CHANGE-505",
    "framework_tags": ["CISA-AA26-237A", "MITRE-ATTCK-T1098", "MITRE-ATTCK-T1550.003",
                       "MITRE-ATTCK-T1484"],
    "references": [
        {"title": "CISA AA26-237A: Joint Red Team Assessment Findings",
         "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-237a"},
    ],
    "description": (
        "Reports resource-based constrained delegation relationships "
        "that were configured between the previous collection run and "
        "this one. RBCD is set by writing a single attribute on the "
        "target object rather than by exercising a delegation "
        "privilege, so any principal holding GenericAll, GenericWrite "
        "or WriteDacl over a host can grant itself the ability to "
        "impersonate arbitrary users to that host -- including a "
        "domain controller. CISA's AA26-237A red team assessment used "
        "this exact sequence against a DC to reach DCSync and the "
        "krbtgt hash. Change detection surfaces a configuration in "
        "the first run that observes it (one set and cleared again "
        "between two runs is not seen). Severity is critical where "
        "the delegation target is a domain controller or the krbtgt "
        "account, or when a trustee is a broad principal (Everyone, "
        "Authenticated Users, Domain Users/Computers, ...). Trustees that "
        "are not collected objects (well-known, foreign or orphaned SIDs) "
        "are included from collector 0.5.16 on. "
        "Suppressed on a client's first collection run."
    ),
    "base_severity": "high",
    "query": """
        WITH prior_run AS (
            SELECT EXISTS (
                SELECT 1 FROM sync_run sr
                WHERE sr.client_id = %(client_id)s
                  AND sr.run_id < %(run_id)s
                  AND sr.status = 'succeeded'
            ) AS have_prior,
            -- [v1.3] Unresolved trustees are only recorded from collector
            -- 0.5.16 on. If the previous successful run was older, every
            -- existing well-known/foreign/orphaned trustee appears in this
            -- run for the first time without having changed -- not "new".
            COALESCE((
                SELECT (regexp_match(sr.collector_version, '^([0-9]+)[.]([0-9]+)[.]([0-9]+)'))::int[]
                       >= ARRAY[0, 5, 16]
                FROM sync_run sr
                WHERE sr.client_id = %(client_id)s
                  AND sr.run_id < %(run_id)s
                  AND sr.status = 'succeeded'
                ORDER BY sr.run_id DESC
                LIMIT 1
            ), false) AS prior_kept_unresolved
        ),
        dom AS (
            SELECT DISTINCT o.object_sid AS domain_sid
            FROM ad_domain d
            JOIN directory_object o
                ON o.object_guid = d.object_guid AND o.client_id = d.client_id
            WHERE d.client_id = %(client_id)s
              AND d.valid_to IS NULL
              AND o.object_sid IS NOT NULL
            UNION
            SELECT cl.domain_sid FROM client cl
            WHERE cl.client_id = %(client_id)s AND cl.domain_sid IS NOT NULL
        ),
        -- Well-known SIDs by name; is_broad = (nearly) every user or computer.
        wk_sid (sid, label, is_broad) AS (
            VALUES ('S-1-1-0', 'Everyone', true),
                   ('S-1-5-7', 'Anonymous Logon', true),
                   ('S-1-5-11', 'Authenticated Users', true),
                   ('S-1-5-2', 'Network', true),
                   ('S-1-5-4', 'Interactive', true),
                   ('S-1-5-15', 'This Organization', true),
                   ('S-1-5-32-545', 'BUILTIN Users', true),
                   ('S-1-5-32-546', 'BUILTIN Guests', true),
                   ('S-1-5-32-554', 'Pre-Windows 2000 Compatible Access', true),
                   ('S-1-5-32-544', 'BUILTIN Administrators', false),
                   ('S-1-5-9', 'Enterprise Domain Controllers', false),
                   ('S-1-5-18', 'Local System', false),
                   ('S-1-5-10', 'Principal Self', false),
                   ('S-1-3-0', 'Creator Owner', false)
        ),
        wk_rid (rid, label, is_broad) AS (
            VALUES ('513', 'Domain Users', true),
                   ('515', 'Domain Computers', true),
                   ('514', 'Domain Guests', true),
                   ('500', 'Administrator', false),
                   ('501', 'Guest', false),
                   ('502', 'krbtgt', false),
                   ('512', 'Domain Admins', false),
                   ('516', 'Domain Controllers', false),
                   ('517', 'Cert Publishers', false),
                   ('518', 'Schema Admins', false),
                   ('519', 'Enterprise Admins', false),
                   ('521', 'Read-only Domain Controllers', false),
                   ('498', 'Enterprise Read-only Domain Controllers', false)
        ),
        trustee_raw AS (
            -- trustees resolved to a collected object (delegation_edge) ...
            SELECT de.target_guid, tdo.object_guid AS trustee_guid,
                   tdo.object_sid::text AS trustee_sid, tdo.sam_account_name AS trustee_name,
                   tdo.object_class::text AS trustee_object_class, tdo.dn_current AS trustee_dn,
                   true AS resolved,
                   de.run_id_valid_from, de.valid_from
            FROM delegation_edge de
            JOIN directory_object tdo
                ON tdo.object_guid = de.source_guid AND tdo.client_id = de.client_id
               AND NOT tdo.is_deleted
            WHERE de.client_id = %(client_id)s
              AND de.valid_to IS NULL
              AND de.delegation_type = 'rbcd'
            UNION ALL
            -- ... and, since collector 0.5.16 / schema v37, trustees kept by
            -- SID because they are not a collected object
            SELECT ru.target_guid, NULL::uuid, ru.trustee_sid, NULL::text,
                   NULL::text, NULL::text, false, ru.run_id_valid_from, ru.valid_from
            FROM rbcd_unresolved_trustee_edge ru
            WHERE ru.client_id = %(client_id)s
              AND ru.valid_to IS NULL
        ),
        trustee AS (
            SELECT tr.*,
                   COALESCE(ws.is_broad, wr.is_broad, false) AS is_broad,
                   CASE
                       WHEN tr.resolved THEN 'collected_object'
                       WHEN ws.sid IS NOT NULL OR wr.rid IS NOT NULL THEN 'well_known'
                       WHEN sp.same_domain THEN 'orphaned_sid'
                       ELSE 'foreign_or_unknown_sid'
                   END AS trustee_kind,
                   CASE
                       WHEN tr.resolved
                           THEN COALESCE(tr.trustee_name, ws.label, tr.trustee_sid, tr.trustee_guid::text)
                       WHEN ws.sid IS NOT NULL
                           THEN ws.label || ' (' || tr.trustee_sid || ')'
                       WHEN wr.rid IS NOT NULL
                           THEN wr.label
                                || CASE WHEN sp.same_domain THEN '' ELSE ' of another domain' END
                                || ' (' || tr.trustee_sid || ')'
                       WHEN sp.same_domain
                           THEN 'orphaned SID ' || tr.trustee_sid
                       ELSE 'unresolved SID ' || tr.trustee_sid
                   END AS trustee_label
            FROM trustee_raw tr
            LEFT JOIN wk_sid ws ON ws.sid = tr.trustee_sid
            CROSS JOIN LATERAL (
                SELECT substring(tr.trustee_sid FROM '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-([0-9]+)$') AS rid,
                       EXISTS (SELECT 1 FROM dom
                               WHERE tr.trustee_sid LIKE dom.domain_sid || '-%%') AS same_domain
            ) sp
            LEFT JOIN wk_rid wr ON wr.rid = sp.rid
        ),
        -- [v1.1] One row per delegation target. The finding is keyed on the
        -- target's GUID, so two principals newly granted RBCD on the same
        -- host in one run used to emit two rows with the same object_guid
        -- and collide on idx_cef_one_open_version. The individual
        -- delegations now live in detail.delegations, sorted by source name
        -- so the summary and detail are stable from run to run.
        new_rbcd AS (
            SELECT t.*
            FROM trustee t
            CROSS JOIN prior_run pr
            WHERE t.run_id_valid_from = %(run_id)s
              AND (t.resolved OR pr.prior_kept_unresolved)
        )
        SELECT
            'fail' AS status,
            nr.target_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN tc.is_domain_controller OR tdo.object_sid LIKE '%%-502' OR bool_or(nr.is_broad)
                 THEN 'critical' ELSE 'high' END
                AS fd_severity,
            'Resource-based constrained delegation was newly configured allowing '
                || CASE WHEN count(*) > 1
                        THEN count(*) || ' principals ('
                             || string_agg(nr.trustee_label, ', '
                                           ORDER BY nr.trustee_label, nr.trustee_sid)
                             || ')'
                        ELSE min(nr.trustee_label) END
                || ' to impersonate users to '
                || COALESCE(tdo.sam_account_name, tdo.dn_current, nr.target_guid::text)
                || CASE WHEN tc.is_domain_controller
                        THEN ' -- the target is a DOMAIN CONTROLLER, which is a direct '
                             'path to DCSync and full domain compromise'
                        WHEN tdo.object_sid LIKE '%%-502'
                        THEN ' -- the target is the KRBTGT account, which lets the '
                             'trustee obtain a ticket-granting ticket for any user'
                        ELSE '' END
                || CASE WHEN bool_or(nr.is_broad)
                        THEN ' -- a broad principal (e.g. Everyone, Authenticated Users, '
                             'Domain Users/Computers) is among the trustees'
                        ELSE '' END AS summary,
            jsonb_build_object(
                'delegation_count', count(*),
                'delegations', jsonb_agg(jsonb_build_object(
                    'delegated_to_principal', CASE WHEN nr.resolved THEN nr.trustee_name
                                                   ELSE nr.trustee_label END,
                    'delegated_to_sid', nr.trustee_sid,
                    'delegated_to_dn', nr.trustee_dn,
                    'delegated_to_object_class', nr.trustee_object_class,
                    'trustee_kind', nr.trustee_kind,
                    'is_broad_principal', nr.is_broad,
                    'delegation_type', 'rbcd',
                    'change_observed_at', nr.valid_from
                ) ORDER BY nr.trustee_label, nr.trustee_sid),
                'broad_principal_trustee', bool_or(nr.is_broad),
                'target', tdo.sam_account_name,
                'target_dn', tdo.dn_current,
                'target_is_domain_controller', COALESCE(tc.is_domain_controller, false),
                'target_operating_system', tc.operating_system,
                'change_observed_at', min(nr.valid_from),
                'corroborating_event_id', 5136
            ) AS detail
        FROM new_rbcd nr
        JOIN directory_object tdo
            ON tdo.object_guid = nr.target_guid AND tdo.client_id = %(client_id)s
        LEFT JOIN ad_computer tc
            ON tc.object_guid = nr.target_guid
           AND tc.client_id = %(client_id)s
           AND tc.valid_to IS NULL
        CROSS JOIN prior_run pr
        WHERE pr.have_prior
        GROUP BY nr.target_guid, tdo.sam_account_name, tdo.dn_current, tdo.object_sid,
                 tc.is_domain_controller, tc.operating_system
    """,
}
