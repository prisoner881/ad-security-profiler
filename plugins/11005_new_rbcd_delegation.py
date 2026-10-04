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
"""

PLUGIN = {
    "plugin_id": 11005,
    "category": "Change Detection",
    "name": "Resource-Based Constrained Delegation Newly Configured",
    "version": "1.2",
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
        "account. "
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
        ),
        -- [v1.1] One row per delegation target. The finding is keyed on the
        -- target's GUID, so two principals newly granted RBCD on the same
        -- host in one run used to emit two rows with the same object_guid
        -- and collide on idx_cef_one_open_version. The individual
        -- delegations now live in detail.delegations, sorted by source name
        -- so the summary and detail are stable from run to run.
        new_rbcd AS (
            SELECT de.target_guid, de.source_guid, de.delegation_type, de.valid_from,
                   sdo.sam_account_name AS source_sam, sdo.dn_current AS source_dn,
                   sdo.object_class AS source_class,
                   COALESCE(sdo.sam_account_name, sdo.dn_current, de.source_guid::text)
                       AS source_label
            FROM delegation_edge de
            LEFT JOIN directory_object sdo
                ON sdo.object_guid = de.source_guid AND sdo.client_id = de.client_id
            WHERE de.client_id = %(client_id)s
              AND de.valid_to IS NULL
              AND de.delegation_type = 'rbcd'
              AND de.run_id_valid_from = %(run_id)s
        )
        SELECT
            'fail' AS status,
            nr.target_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN tc.is_domain_controller OR tdo.object_sid LIKE '%%-502'
                 THEN 'critical' ELSE 'high' END
                AS fd_severity,
            'Resource-based constrained delegation was newly configured allowing '
                || CASE WHEN count(*) > 1
                        THEN count(*) || ' principals ('
                             || string_agg(nr.source_label, ', '
                                           ORDER BY nr.source_label, nr.source_guid)
                             || ')'
                        ELSE min(nr.source_label) END
                || ' to impersonate users to '
                || COALESCE(tdo.sam_account_name, tdo.dn_current, nr.target_guid::text)
                || CASE WHEN tc.is_domain_controller
                        THEN ' -- the target is a DOMAIN CONTROLLER, which is a direct '
                             'path to DCSync and full domain compromise'
                        WHEN tdo.object_sid LIKE '%%-502'
                        THEN ' -- the target is the KRBTGT account, which lets the '
                             'trustee obtain a ticket-granting ticket for any user'
                        ELSE '' END AS summary,
            jsonb_build_object(
                'delegation_count', count(*),
                'delegations', jsonb_agg(jsonb_build_object(
                    'delegated_to_principal', nr.source_sam,
                    'delegated_to_dn', nr.source_dn,
                    'delegated_to_object_class', nr.source_class,
                    'delegation_type', nr.delegation_type,
                    'change_observed_at', nr.valid_from
                ) ORDER BY nr.source_label, nr.source_guid),
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
