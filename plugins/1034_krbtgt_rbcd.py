"""
Plugin 1034: krbtgt Account Has Resource-Based Constrained Delegation Configured

Resource-based constrained delegation (RBCD) is a mechanism for
computer/service objects to explicitly designate which principals may
impersonate users when authenticating to them (via
msDS-AllowedToActOnBehalfOfOtherIdentity). It has no legitimate
operational purpose on krbtgt: krbtgt is the special account backing
the Key Distribution Center itself, not a delegatable service. Any
RBCD configuration found on it is a strong anomaly -- either a
misconfiguration with no plausible benign explanation, or a deliberate
backdoor letting whoever is listed as the trustee impersonate
arbitrary users against the KDC's own account. Confirmed against
Purple Knight's own equivalent check.

[v1.2] Can now fire: since schema v36 the collector reads
msDS-AllowedToActOnBehalfOfOtherIdentity on user objects too (before, it
was read for computers only, so an RBCD edge targeting krbtgt could
never exist). One row per krbtgt account with every trustee aggregated
(sorted) -- several trustees used to emit rows with the same
object_guid. krbtgt is matched by RID 502 instead of by name, and the
RODC krbtgt_<n> accounts are covered too.

[v1.3] Trustees that are not collected objects are included: since
collector 0.5.16 (schema v37) they are kept by SID in
rbcd_unresolved_trustee_edge instead of being dropped, so RBCD on krbtgt
granted to e.g. Everyone or Authenticated Users -- the worst case -- is
no longer invisible. Well-known SIDs are named (Everyone S-1-1-0,
Authenticated Users S-1-5-11, Anonymous Logon S-1-5-7, BUILTIN Users
S-1-5-32-545, Domain Users -513, Domain Computers -515, ...), other SIDs
labelled "orphaned SID" (this domain, no object) or "unresolved SID".
Broad principals add a summary suffix and detail.broad_principal_trustee
(severity is already critical). Each detail.trustees entry gains
trustee_sid, trustee_kind and is_broad_principal; deleted trustee objects
are excluded. Still one row per krbtgt account.
"""

PLUGIN = {
    "plugin_id": 1034,
    "category": "User Accounts",
    "name": "krbtgt Account Has Resource-Based Constrained Delegation Configured",
    "version": "1.3",
    "revision_date": "2026-10-04",
    "remediation": (
        "Treat this as a likely active-compromise indicator, not a "
        "routine misconfiguration -- there is no legitimate reason for "
        "krbtgt to have RBCD configured. Immediately investigate the "
        "principal(s) listed in this finding's evidence as the "
        "delegation trustee: confirm who or what controls that "
        "account/computer object, and treat it as potentially "
        "compromised until proven otherwise. Remove the "
        "msDS-AllowedToActOnBehalfOfOtherIdentity attribute from "
        "krbtgt (`Set-ADUser krbtgt -Clear "
        "msDS-AllowedToActOnBehalfOfOtherIdentity`), then reset the "
        "krbtgt password twice per Microsoft's documented procedure, "
        "and review authentication logs for signs the delegation was "
        "already exploited."
    ),
    "control_id": "ANOM-101",
    "framework_tags": ["CISA-AA26-237A", "MITRE-ATTCK-T1098", "MITRE-ATTCK-T1003.006"],
    "references": [],
    "description": (
        "Resource-based constrained delegation lets a computer/service "
        "object explicitly designate which principals may impersonate "
        "users when authenticating to it. It has no legitimate "
        "operational purpose on krbtgt, the special account backing "
        "the Key Distribution Center. Any RBCD configuration found "
        "here is a strong anomaly -- either a misconfiguration with no "
        "plausible benign explanation, or a deliberate backdoor "
        "letting the listed trustee impersonate arbitrary users "
        "against the KDC's own account. Confirmed against Purple "
        "Knight's own equivalent check. Trustees that are not collected "
        "objects (well-known, foreign or orphaned SIDs; collector 0.5.16+) "
        "are included and named, and broad principals such as Everyone or "
        "Authenticated Users are called out."
    ),
    "base_severity": "critical",
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
            SELECT DISTINCT u.object_guid, u.sam_account_name, udo.object_sid,
                   tr.trustee_label, tr.trustee_sid, tr.trustee_kind,
                   tr.trustee_object_class, tr.is_broad
            FROM ad_user u
            JOIN directory_object udo ON udo.object_guid = u.object_guid AND udo.client_id = u.client_id
            JOIN trustee tr ON tr.target_guid = u.object_guid
            WHERE u.valid_to IS NULL
              AND u.client_id = %(client_id)s
              -- [v1.2] krbtgt by RID 502 (rename-proof), plus the per-RODC
              -- krbtgt_<n> accounts, which have no well-known RID.
              AND (udo.object_sid LIKE '%%-502' OR u.sam_account_name ILIKE 'krbtgt\\_%%')
        )
        SELECT
            'fail' AS status,
            t.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'critical' AS fd_severity,
            CASE WHEN t.object_sid LIKE '%%-502' THEN 'krbtgt account'
                 ELSE COALESCE(t.sam_account_name, t.object_sid, t.object_guid::text) || ' (RODC krbtgt) account' END
                || ' has Resource-Based Constrained Delegation configured -- '
                || CASE WHEN count(*) = 1 THEN 'trustee: ' ELSE 'trustees: ' END
                || string_agg(t.trustee_label, ', ' ORDER BY t.trustee_label, t.trustee_sid)
                || CASE WHEN bool_or(t.is_broad)
                        THEN ' -- including a broad principal: practically anyone can obtain a '
                             'ticket for any user'
                        ELSE '' END
                AS summary,
            jsonb_build_object(
                'krbtgt_account', t.sam_account_name,
                'trustees', jsonb_agg(jsonb_build_object(
                    'trustee', t.trustee_label,
                    'trustee_object_class', t.trustee_object_class,
                    'trustee_sid', t.trustee_sid,
                    'trustee_kind', t.trustee_kind,
                    'is_broad_principal', t.is_broad)
                    ORDER BY t.trustee_label, t.trustee_sid),
                'broad_principal_trustee', bool_or(t.is_broad)
            ) AS detail
        FROM t
        GROUP BY t.object_guid, t.sam_account_name, t.object_sid
    """,
}
