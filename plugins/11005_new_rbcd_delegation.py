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
"""

PLUGIN = {
    "plugin_id": 11005,
    "category": "Change Detection",
    "name": "Resource-Based Constrained Delegation Newly Configured",
    "version": "1.0",
    "revision_date": "2026-09-02",
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
        "krbtgt hash. Because the attribute can be written and "
        "cleared quickly, change detection catches configurations "
        "that a point-in-time audit would miss. Severity is critical "
        "where the delegation target is a domain controller. "
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
            ) AS have_prior
        )
        SELECT
            'fail' AS status,
            de.target_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN tc.is_domain_controller THEN 'critical' ELSE 'high' END
                AS fd_severity,
            'Resource-based constrained delegation was newly configured allowing '
                || COALESCE(sdo.sam_account_name, sdo.dn_current, de.source_guid::text)
                || ' to impersonate users to '
                || COALESCE(tdo.sam_account_name, tdo.dn_current, de.target_guid::text)
                || CASE WHEN tc.is_domain_controller
                        THEN ' -- the target is a DOMAIN CONTROLLER, which is a direct '
                             'path to DCSync and full domain compromise'
                        ELSE '' END AS summary,
            jsonb_build_object(
                'delegated_to_principal', sdo.sam_account_name,
                'delegated_to_dn', sdo.dn_current,
                'delegated_to_object_class', sdo.object_class,
                'target', tdo.sam_account_name,
                'target_dn', tdo.dn_current,
                'target_is_domain_controller', COALESCE(tc.is_domain_controller, false),
                'target_operating_system', tc.operating_system,
                'delegation_type', de.delegation_type,
                'change_observed_at', de.valid_from,
                'corroborating_event_id', 5136
            ) AS detail
        FROM delegation_edge de
        JOIN directory_object tdo
            ON tdo.object_guid = de.target_guid AND tdo.client_id = de.client_id
        LEFT JOIN directory_object sdo
            ON sdo.object_guid = de.source_guid AND sdo.client_id = de.client_id
        LEFT JOIN ad_computer tc
            ON tc.object_guid = de.target_guid
           AND tc.client_id = de.client_id
           AND tc.valid_to IS NULL
        CROSS JOIN prior_run pr
        WHERE de.client_id = %(client_id)s
          AND de.valid_to IS NULL
          AND de.delegation_type = 'rbcd'
          AND de.run_id_valid_from = %(run_id)s
          AND pr.have_prior
    """,
}
