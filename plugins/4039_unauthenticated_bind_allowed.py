"""
Plugin 4039: Unauthenticated LDAP Binds Not Denied (DenyUnauthenticatedBind)

Reports a forest whose msDS-Other-Settings (CN=Directory Service,CN=Windows
NT,CN=Services in the configuration partition, ad_domain.ds_other_settings)
does not contain DenyUnauthenticatedBind=1.

Why it matters: without it, a domain controller accepts an LDAP simple bind
that names an account but gives an empty password, treating it as an
anonymous bind -- an application that takes "the bind succeeded" as proof
of the password then logs anyone in -- and the RootDSE (domain names, DC
OS level, supported features) is readable without authenticating
(PingCastle A-RootDseAnonBinding, informative). Windows Server 2019 and
later domain controllers honour the setting; older ones ignore it, and are
listed in detail even when it is set.

One row per domain (object_guid = the domain): info ('warn') when the
setting is not 1, or when it is but domain controllers older than Windows
Server 2019 (build 17763) still accept such binds. Nothing is reported while
ad_domain.ds_other_settings is NULL (collected before adprofiler 0.8.0, or
the object was unreadable).
"""

PLUGIN = {
    "plugin_id": 4039,
    "category": "Domain",
    "name": "Unauthenticated LDAP Binds Not Denied (DenyUnauthenticatedBind)",
    "version": "1.0",
    "revision_date": "2026-10-21",
    "control_id": "DOMAIN-4039",
    "framework_tags": [
        "NIST-800-53-CM-6",
        "NIST-800-53-CM-7",
        "NIST-800-53-AC-3",
        "NIST-CSF-2.0-PR.PS-01",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-2.2.1",
        "CIS-CSC-8-4.1",
        "ISO-27001-2022-A.8.9",
        "SOC2-CC7.1",
        "HIPAA-164.312(c)(1)",
        "MITRE-ATTCK-T1087.002",
    ],
    "references": [
        {"title": "Microsoft [MS-ADTS]: LDAP configurable settings (msDS-Other-Settings, "
                  "DenyUnauthenticatedBind)",
         "url": "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/41cbdb2c-eab1-45b0-8236-ae777b1c5406"},
        {"title": "PingCastle health check rules (A-RootDseAnonBinding)",
         "url": "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
    ],
    "description": (
        "The forest's msDS-Other-Settings does not set DenyUnauthenticatedBind=1, "
        "so domain controllers accept simple binds with an empty password as "
        "anonymous and expose the RootDSE without authentication (info). DCs "
        "older than Windows Server 2019 ignore the setting."
    ),
    "remediation": (
        "With ADSI Edit (Configuration partition), open CN=Directory Service,"
        "CN=Windows NT,CN=Services,CN=Configuration,<forest root>, edit "
        "msDS-Other-Settings and add the value DenyUnauthenticatedBind=1. Test "
        "applications that bind with an empty password first. Upgrade domain "
        "controllers older than Windows Server 2019, which ignore it."
    ),
    "base_severity": "info",
    "query": """
        WITH dom AS (
            SELECT m.object_guid, m.dns_root,
                   (SELECT e.value FROM jsonb_each_text(m.ds_other_settings) e
                    WHERE lower(e.key) = 'denyunauthenticatedbind'
                    ORDER BY e.key LIMIT 1) AS deny_value
            FROM ad_domain m
            JOIN directory_object d
              ON d.object_guid = m.object_guid AND d.client_id = m.client_id AND NOT d.is_deleted
            WHERE m.client_id = %(client_id)s AND m.valid_to IS NULL
              AND m.ds_other_settings IS NOT NULL
        ),
        old_dc AS (
            SELECT COALESCE(c.dns_hostname, c.sam_account_name) AS dc_name,
                   c.operating_system, c.operating_system_version
            FROM ad_computer c
            JOIN directory_object o
              ON o.object_guid = c.object_guid AND o.client_id = c.client_id AND NOT o.is_deleted
            WHERE c.client_id = %(client_id)s AND c.valid_to IS NULL
              AND c.is_domain_controller AND c.is_enabled IS NOT FALSE
              AND (substring(c.operating_system_version FROM '\\(([0-9]+)\\)'))::int < 17763
        )
        SELECT
            'warn' AS status,
            d.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'info' AS fd_severity,
            CASE WHEN d.deny_value IS DISTINCT FROM '1'
                 THEN 'Forest of domain ' || COALESCE(d.dns_root, d.object_guid::text)
                      || ' does not deny unauthenticated LDAP binds (msDS-Other-Settings '
                      || 'DenyUnauthenticatedBind ' || COALESCE('= ' || d.deny_value, 'not set') || ')'
                 ELSE 'Forest of domain ' || COALESCE(d.dns_root, d.object_guid::text)
                      || ' sets DenyUnauthenticatedBind=1, but '
                      || (SELECT count(*) FROM old_dc) || ' domain controller(s) older than Windows '
                      || 'Server 2019 ignore it'
            END AS summary,
            jsonb_build_object(
                'dns_root', d.dns_root,
                'deny_unauthenticated_bind', d.deny_value,
                'domain_controllers_ignoring_setting',
                    COALESCE((SELECT jsonb_agg(jsonb_build_object('dc', o.dc_name,
                                                                  'operating_system', o.operating_system,
                                                                  'operating_system_version',
                                                                  o.operating_system_version)
                                               ORDER BY o.dc_name)
                              FROM old_dc o), '[]'::jsonb)
            ) AS detail
        FROM dom d
        WHERE d.deny_value IS DISTINCT FROM '1'
           OR EXISTS (SELECT 1 FROM old_dc)
    """,
}
