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
"""

PLUGIN = {
    "plugin_id": 1035,
    "category": "User Accounts",
    "name": "Constrained Delegation Configured to krbtgt",
    "version": "1.0",
    "revision_date": "2026-07-18",
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
    "framework_tags": [],
    "references": [],
    "description": (
        "msDS-AllowedToDelegateTo (constrained delegation) lets an "
        "account authenticate to specific services on behalf of "
        "another user. Like plugin 1034's RBCD-on-krbtgt check, there "
        "is no legitimate reason for any account's constrained "
        "delegation target list to resolve to krbtgt -- it does not "
        "register a service principal name for any normal purpose, "
        "and any resolution to it should be treated as strong evidence "
        "of tampering."
    ),
    "base_severity": "critical",
    "query": """
        SELECT
            'fail' AS status,
            source.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'critical' AS fd_severity,
            'Account ' || COALESCE(source.sam_account_name, source.object_sid)
                || ' has constrained delegation configured to krbtgt' AS summary,
            jsonb_build_object(
                'sam_account_name', source.sam_account_name,
                'object_class', source.object_class
            ) AS detail
        FROM delegation_edge de
        JOIN directory_object source ON source.object_guid = de.source_guid AND source.client_id = de.client_id
        JOIN directory_object target ON target.object_guid = de.target_guid AND target.client_id = de.client_id
        WHERE de.client_id = %(client_id)s
          AND de.valid_to IS NULL
          AND de.delegation_type = 'constrained'
          AND target.sam_account_name = 'krbtgt'
    """,
}
