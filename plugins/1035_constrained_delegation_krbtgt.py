"""
Plugin 1035: Constrained Delegation Configured to krbtgt

msDS-AllowedToDelegateTo (constrained delegation) lets an account
authenticate to specific services on behalf of another user. Like
plugin 1034's check for RBCD on krbtgt, there is no legitimate
operational reason for any account's constrained delegation target
list to resolve to the krbtgt account -- krbtgt does not register a
service principal name for any normal purpose, and any object it
resolves to via constrained delegation configuration should be
treated as strong evidence of tampering rather than a benign,
overlooked setting.

[v1.2] Now detects the canonical form, msDS-AllowedToDelegateTo:
krbtgt/<DOMAIN>. krbtgt/* is never a registered SPN, so the collector
records it in unresolved_delegation_target_edge, which v1.1 did not
read -- only the obscure kadmin/changepw entry (the one SPN krbtgt
registers) could match. Resolved targets are matched by RID 502 (plus
RODC krbtgt_<n> accounts) instead of the name 'krbtgt'. One row per
delegating account; detail.krbtgt_targets lists the matching entries.
"""

PLUGIN = {
    "plugin_id": 1035,
    "category": "User Accounts",
    "name": "Constrained Delegation Configured to krbtgt",
    "version": "1.2",
    "revision_date": "2026-10-04",
    "remediation": (
        "Treat this as a likely active-compromise indicator, not a "
        "routine misconfiguration -- there is no legitimate reason for "
        "any account's constrained delegation to resolve to krbtgt. "
        "Immediately investigate the account listed in this finding's "
        "evidence as the source of the delegation, and treat it as "
        "potentially compromised until proven otherwise. Remove the "
        "krbtgt-related entry from that account's "
        "msDS-AllowedToDelegateTo attribute, then reset the krbtgt "
        "password twice per Microsoft's documented procedure, and "
        "review authentication logs for signs the delegation was "
        "already exploited."
    ),
    "control_id": "ANOM-102",
    "framework_tags": ["CISA-AA26-237A", "MITRE-ATTCK-T1098"],
    "references": [],
    "description": (
        "msDS-AllowedToDelegateTo (constrained delegation) lets an "
        "account authenticate to specific services on behalf of "
        "another user. Like plugin 1034's RBCD-on-krbtgt check, there "
        "is no legitimate reason for any account's constrained "
        "delegation target list to name krbtgt -- either the "
        "krbtgt/<DOMAIN> service (which is never a registered SPN, so "
        "it is read from the unresolved-target data) or an SPN that "
        "resolves to the krbtgt account. Delegating to krbtgt lets the "
        "account obtain a TGT for any user via S4U2Proxy, so any such "
        "entry should be treated as strong evidence of tampering."
    ),
    "base_severity": "critical",
    "query": """
        WITH krbtgt_target AS (
            -- msDS-AllowedToDelegateTo entries that resolved to a krbtgt
            -- account (RID 502, or an RODC krbtgt_<n>) -- in practice only
            -- the kadmin/changepw SPN, the one SPN krbtgt registers.
            SELECT de.source_guid,
                   COALESCE(target.sam_account_name, target.object_sid) || ' (resolved account)' AS target_desc
            FROM delegation_edge de
            JOIN directory_object target
                ON target.object_guid = de.target_guid AND target.client_id = de.client_id
            WHERE de.client_id = %(client_id)s
              AND de.valid_to IS NULL
              AND de.delegation_type = 'constrained'
              AND (target.object_sid LIKE '%%-502' OR target.sam_account_name ILIKE 'krbtgt\\_%%')
            UNION
            -- [v1.2] krbtgt/<DOMAIN> -- the canonical persistence entry
            -- (S4U2Proxy to the TGS returns a TGT for any user). krbtgt/*
            -- is never a registered SPN, so the collector cannot resolve it
            -- and stores it in unresolved_delegation_target_edge.
            SELECT ude.source_guid, ude.target_spn
            FROM unresolved_delegation_target_edge ude
            WHERE ude.client_id = %(client_id)s
              AND ude.valid_to IS NULL
              AND ude.target_spn ILIKE 'krbtgt/%%'
        )
        SELECT
            'fail' AS status,
            source.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'critical' AS fd_severity,
            'Account ' || COALESCE(source.sam_account_name, source.object_sid, source.object_guid::text)
                || ' has constrained delegation configured to krbtgt' AS summary,
            jsonb_build_object(
                'sam_account_name', source.sam_account_name,
                'object_class', source.object_class,
                'krbtgt_targets', jsonb_agg(DISTINCT kt.target_desc ORDER BY kt.target_desc)
            ) AS detail
        FROM krbtgt_target kt
        JOIN directory_object source
            ON source.object_guid = kt.source_guid AND source.client_id = %(client_id)s
           AND NOT source.is_deleted
        -- One finding per delegating account, however many krbtgt entries.
        GROUP BY source.object_guid, source.sam_account_name, source.object_sid, source.object_class
    """,
}
