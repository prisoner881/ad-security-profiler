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
"""

PLUGIN = {
    "plugin_id": 1034,
    "category": "User Accounts",
    "name": "krbtgt Account Has Resource-Based Constrained Delegation Configured",
    "version": "1.2",
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
        "Knight's own equivalent check."
    ),
    "base_severity": "critical",
    "query": """
        SELECT
            'fail' AS status,
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'critical' AS fd_severity,
            CASE WHEN udo.object_sid LIKE '%%-502' THEN 'krbtgt account'
                 ELSE COALESCE(u.sam_account_name, udo.object_sid) || ' (RODC krbtgt) account' END
                || ' has Resource-Based Constrained Delegation configured -- '
                || CASE WHEN count(DISTINCT trustee.object_guid) = 1 THEN 'trustee: ' ELSE 'trustees: ' END
                || string_agg(DISTINCT COALESCE(trustee.sam_account_name, trustee.object_sid, trustee.object_guid::text),
                              ', ' ORDER BY COALESCE(trustee.sam_account_name, trustee.object_sid, trustee.object_guid::text))
                AS summary,
            jsonb_build_object(
                'krbtgt_account', u.sam_account_name,
                'trustees', jsonb_agg(DISTINCT jsonb_build_object(
                    'trustee', COALESCE(trustee.sam_account_name, trustee.object_sid, trustee.object_guid::text),
                    'trustee_object_class', trustee.object_class)
                    ORDER BY jsonb_build_object(
                    'trustee', COALESCE(trustee.sam_account_name, trustee.object_sid, trustee.object_guid::text),
                    'trustee_object_class', trustee.object_class))
            ) AS detail
        FROM ad_user u
        JOIN directory_object udo ON udo.object_guid = u.object_guid AND udo.client_id = u.client_id
        JOIN delegation_edge de ON de.target_guid = u.object_guid AND de.client_id = u.client_id AND de.valid_to IS NULL
        JOIN directory_object trustee ON trustee.object_guid = de.source_guid AND trustee.client_id = de.client_id
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          -- [v1.2] krbtgt by RID 502 (rename-proof), plus the per-RODC
          -- krbtgt_<n> accounts, which have no well-known RID.
          AND (udo.object_sid LIKE '%%-502' OR u.sam_account_name ILIKE 'krbtgt\\_%%')
          AND de.delegation_type = 'rbcd'
        GROUP BY u.object_guid, u.sam_account_name, udo.object_sid
    """,
}
