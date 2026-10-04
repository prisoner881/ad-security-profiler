"""
Plugin 2022: Computer Account Has Resource-Based Constrained Delegation Configured

Closes a gap this project has explicitly disclosed since early in its
development -- every prior run log through v0.2.6 included the literal
note "RBCD not collected." Any principal listed as a trustee in a
computer's msDS-AllowedToActOnBehalfOfOtherIdentity can impersonate
arbitrary domain users (including Domain Admins, absent specific
protections like Protected Users group membership) when authenticating
to that computer -- a well-documented, actively-used privilege
escalation and lateral movement primitive.

Not inherently a misconfiguration -- RBCD has legitimate uses (certain
constrained-delegation-replacement scenarios since Server 2012 R2) -- but
every grant is a standing trust relationship worth being deliberately
aware of, not discovered by accident.

[v1.5] One row per resource computer. The query used to emit one row
per trustee while using the resource computer's GUID as the finding
identity, so any computer with two or more RBCD trustees produced
duplicate identities and the whole plugin errored (recording nothing in
exactly the environments with the most RBCD). Trustees are now
aggregated: the summary lists them sorted ("trustee: X" for one,
"trustees: X, Y" for several) and detail carries the sorted list. The
ad_computer join is now client-scoped and deleted trustee objects are
excluded. RODCs are escalated like other DCs (schema v36). Note: the
collector records only trustee SIDs it can resolve to a collected
object, so a grant to a well-known or foreign SID is not visible here.

[v1.6] Trustees that are not collected objects are now included: since
collector 0.5.16 (schema v37) they are kept by SID in
rbcd_unresolved_trustee_edge instead of being dropped. Well-known SIDs
are labelled by name (Everyone S-1-1-0, Authenticated Users S-1-5-11,
Anonymous Logon S-1-5-7, BUILTIN Users S-1-5-32-545, Domain Users -513,
Domain Computers -515, ...), other SIDs as "orphaned SID" (this domain,
no object -- typically a deleted principal) or "unresolved SID" (another
domain or unknown). A trustee that is a broad principal -- Everyone,
Authenticated Users, Anonymous Logon, Network, Interactive, This
Organization, BUILTIN Users/Guests, Pre-Windows 2000 Compatible Access,
Domain Users, Domain Computers or Domain Guests (of any domain), whether
collected or not -- lets practically anyone impersonate any user to the
computer: 'fail'/critical, with a summary suffix. detail gains
trustee_details (label, SID, kind, object class, broad flag) and
broad_principal_trustee. Still one row per resource computer.
"""

PLUGIN = {
    "plugin_id": 2022,
    "category": "Computer Accounts",
    "name": "Computer Account Has Resource-Based Constrained Delegation Configured",
    "version": "1.6",
    "revision_date": "2026-10-04",
    "remediation": (
        "Confirm each trustee is a deliberate, understood delegation "
        "relationship, not leftover from a decommissioned service or an "
        "unintended grant (RBCD can be configured by anyone holding "
        "WriteProperty/GenericWrite on the resource computer object, "
        "not only administrators -- itself worth cross-checking against "
        "the ACL findings in this same category). Remove trustees that "
        "are no longer needed: "
        "`Set-ADComputer -Identity <resource> -PrincipalsAllowedToDelegateToAccount $null` "
        "to clear entirely, or reset it to a specific, reviewed list. "
        "Remove a broad trustee (Everyone, Authenticated Users, Domain "
        "Users/Computers, ...) immediately and investigate how it was "
        "set; remove orphaned SIDs (deleted principals) as well."
    ),
    "control_id": "DELEG-101",
    "framework_tags": ["MITRE-ATTCK-T1134", "CISA-AA26-237A", "MITRE-ATTCK-T1098"],
    "references": [
        {"title": "MITRE ATT&CK T1134: Access Token Manipulation",
         "url": "https://attack.mitre.org/techniques/T1134/"},
    ],
    "description": (
        "msDS-AllowedToActOnBehalfOfOtherIdentity lists every principal "
        "permitted to impersonate arbitrary domain users (including "
        "Domain Admins, absent specific protections like Protected "
        "Users group membership) when authenticating to this computer -- "
        "a well-documented privilege escalation and lateral movement "
        "primitive. This project explicitly disclosed \"RBCD not "
        "collected\" in every run log through v0.2.6; this plugin exists "
        "specifically to close that gap now that the underlying ACL/SD "
        "parsing capability has been built. Not inherently a "
        "misconfiguration -- RBCD has legitimate uses -- but every grant "
        "is a standing trust relationship worth being deliberately aware "
        "of. Trustees that are not collected objects (well-known, foreign "
        "or orphaned SIDs; collector 0.5.16+) are included and named. A "
        "broad trustee (Everyone, Authenticated Users, Anonymous Logon, "
        "Domain Users, Domain Computers and similar) lets practically anyone "
        "impersonate any user to the computer and is rated critical."
    ),
    "base_severity": "medium",
    "query": """
        WITH
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
                   tdo.object_class::text AS trustee_object_class, true AS resolved,
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
                   NULL::text, false, ru.run_id_valid_from, ru.valid_from
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
        t AS (
            SELECT DISTINCT
                   c.object_guid,
                   c.sam_account_name,
                   c.is_domain_controller,
                   tr.trustee_label,
                   tr.trustee_sid,
                   tr.trustee_kind,
                   tr.trustee_object_class,
                   tr.is_broad
            FROM trustee tr
            JOIN ad_computer c ON c.object_guid = tr.target_guid
                              AND c.client_id = %(client_id)s
                              AND c.valid_to IS NULL
        )
        SELECT
            CASE WHEN bool_or(t.is_broad) THEN 'fail' ELSE 'warn' END AS status,
            t.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN bool_or(t.is_broad) THEN 'critical'
                 WHEN t.is_domain_controller THEN 'high'
                 ELSE 'medium' END AS fd_severity,
            (CASE WHEN t.is_domain_controller THEN 'Domain Controller ' ELSE 'Computer Account ' END)
                || COALESCE(t.sam_account_name, t.object_guid::text)
                || ' has resource-based constrained delegation configured -- '
                || CASE WHEN count(*) = 1 THEN 'trustee: ' ELSE 'trustees: ' END
                || string_agg(t.trustee_label, ', ' ORDER BY t.trustee_label, t.trustee_sid)
                || CASE WHEN bool_or(t.is_broad)
                        THEN ' -- a broad principal can impersonate any user to this computer'
                        ELSE '' END AS summary,
            jsonb_build_object(
                'resource_computer', t.sam_account_name,
                'trustees', jsonb_agg(t.trustee_label ORDER BY t.trustee_label, t.trustee_sid),
                'trustee_details', jsonb_agg(jsonb_build_object(
                    'trustee', t.trustee_label,
                    'sid', t.trustee_sid,
                    'kind', t.trustee_kind,
                    'object_class', t.trustee_object_class,
                    'is_broad_principal', t.is_broad
                ) ORDER BY t.trustee_label, t.trustee_sid),
                'trustee_count', count(*),
                'broad_principal_trustee', bool_or(t.is_broad),
                'is_domain_controller', t.is_domain_controller
            ) AS detail
        FROM t
        GROUP BY t.object_guid, t.sam_account_name, t.is_domain_controller
        ORDER BY t.object_guid
    """,
}
