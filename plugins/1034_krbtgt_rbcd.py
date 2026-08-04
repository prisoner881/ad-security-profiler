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
"""

PLUGIN = {
    "plugin_id": 1034,
    "category": "User Accounts",
    "name": "krbtgt Account Has Resource-Based Constrained Delegation Configured",
    "version": "1.0",
    "revision_date": "2026-07-18",
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
    "framework_tags": [],
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
            'krbtgt account has Resource-Based Constrained Delegation configured -- trustee: '
                || COALESCE(trustee.sam_account_name, trustee.object_sid) AS summary,
            jsonb_build_object(
                'trustee', COALESCE(trustee.sam_account_name, trustee.object_sid),
                'trustee_object_class', trustee.object_class
            ) AS detail
        FROM ad_user u
        JOIN directory_object udo ON udo.object_guid = u.object_guid AND udo.client_id = u.client_id
        JOIN delegation_edge de ON de.target_guid = u.object_guid AND de.client_id = u.client_id AND de.valid_to IS NULL
        JOIN directory_object trustee ON trustee.object_guid = de.source_guid AND trustee.client_id = de.client_id
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          AND u.sam_account_name = 'krbtgt'
          AND de.delegation_type = 'rbcd'
    """,
}
