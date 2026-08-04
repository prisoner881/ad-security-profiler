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
"""

PLUGIN = {
    "plugin_id": 2022,
    "category": "Computer Accounts",
    "name": "Computer Account Has Resource-Based Constrained Delegation Configured",
    "version": "1.3",
    "revision_date": "2026-07-15",
    "remediation": (
        "Confirm each trustee is a deliberate, understood delegation "
        "relationship, not leftover from a decommissioned service or an "
        "unintended grant (RBCD can be configured by anyone holding "
        "WriteProperty/GenericWrite on the resource computer object, "
        "not only administrators -- itself worth cross-checking against "
        "the ACL findings in this same category). Remove trustees that "
        "are no longer needed: "
        "`Set-ADComputer -Identity <resource> -PrincipalsAllowedToDelegateToAccount $null` "
        "to clear entirely, or reset it to a specific, reviewed list."
    ),
    "control_id": "DELEG-101",
    "framework_tags": ["MITRE-ATTCK-T1134"],
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
        "of."
    ),
    "base_severity": "medium",
    "query": """
        SELECT
            'warn' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN c.is_domain_controller THEN 'high' ELSE 'medium' END AS fd_severity,
            (CASE WHEN c.is_domain_controller THEN 'Domain Controller ' ELSE 'Computer Account ' END)
                || c.sam_account_name || ' has resource-based constrained delegation configured -- trustee: '
                || COALESCE(trustee.sam_account_name, trustee.object_sid) AS summary,
            jsonb_build_object(
                'resource_computer', c.sam_account_name,
                'trustee', COALESCE(trustee.sam_account_name, trustee.object_sid),
                'is_domain_controller', c.is_domain_controller
            ) AS detail
        FROM delegation_edge de
        JOIN ad_computer c ON c.object_guid = de.target_guid AND c.valid_to IS NULL
        JOIN directory_object trustee ON trustee.object_guid = de.source_guid AND trustee.client_id = de.client_id
        WHERE de.client_id = %(client_id)s
          AND de.valid_to IS NULL
          AND de.delegation_type = 'rbcd'
    """,
}
