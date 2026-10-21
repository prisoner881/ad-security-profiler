"""
Plugin 4038: dSHeuristics Enables List Object Mode, Anonymous NSPI or Weakens LDAP Hardening

Reads the forest-wide dSHeuristics string (CN=Directory Service,CN=Windows
NT,CN=Services in the configuration partition, ad_domain.dsheuristics) and
reports the characters PingCastle checks that no other plugin covers:

  3   fDoListObject = 1         List Object mode: object visibility then
                                follows the List Object right, so objects
                                can be hidden from administrators and tools
                                (PingCastle P-DsHeuristicsDoListObject) -- info
  8   fAllowAnonNSPI <> 0       anonymous access to the NSPI (address book)
                                interface Exchange uses, which lets anyone
                                list every user in the forest without an
                                account (A-DsHeuristicsAllowAnonNSPI) -- medium
  28  LDAPAddAuthZVerifications CVE-2021-42291 hardening (KB5008383): 1
  29  LDAPOwnerModify           enforces it, 2 disables it, 0 or unset keeps
                                the Windows default (A-DsHeuristicsLDAPSecurity)
                                -- low when either is 2, info when either is
                                not 1

Characters 7, 16 and 21 are plugins 4015, 3029 and 4030. One row per domain
(object_guid = the domain) listing every issue; dSHeuristics is forest-wide,
so each domain of a forest reports the same. Status 'fail' at medium,
'warn' otherwise. Nothing is reported while ad_domain.dsheuristics is NULL
(collected before adprofiler 0.8.0, or the object was unreadable).
"""

PLUGIN = {
    "plugin_id": 4038,
    "category": "Domain",
    "name": "dSHeuristics Enables List Object Mode, Anonymous NSPI or Weakens LDAP Hardening",
    "version": "1.0",
    "revision_date": "2026-10-21",
    "control_id": "DOMAIN-4038",
    "framework_tags": [
        "NIST-800-53-CM-6",
        "NIST-800-53-CM-7",
        "NIST-800-53-AC-3",
        "NIST-CSF-2.0-PR.PS-01",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-2.2.1",
        "CIS-CSC-8-4.1",
        "CIS-CSC-8-3.3",
        "ISO-27001-2022-A.8.9",
        "ISO-27001-2022-A.5.15",
        "SOC2-CC7.1",
        "SOC2-CC6.3",
        "HIPAA-164.312(c)(1)",
        "CVE-2021-42291",
        "MITRE-ATTCK-T1087.002",
    ],
    "references": [
        {"title": "Microsoft [MS-ADTS] 6.1.1.2.4.1.2: dSHeuristics",
         "url": "https://msdn.microsoft.com/en-us/library/cc223560.aspx"},
        {"title": "Microsoft KB5008383: Active Directory permissions updates (CVE-2021-42291)",
         "url": "https://support.microsoft.com/help/5008383"},
        {"title": "PingCastle health check rules (P-DsHeuristicsDoListObject, A-DsHeuristicsAllowAnonNSPI, "
                  "A-DsHeuristicsLDAPSecurity)",
         "url": "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
    ],
    "description": (
        "The forest's dSHeuristics turns on List Object mode (info), allows "
        "anonymous NSPI address-book access (medium), or does not enforce "
        "the CVE-2021-42291 LDAP add / owner-modify hardening (characters "
        "28 and 29: low when disabled with 2, info when not set to 1)."
    ),
    "remediation": (
        "Edit dSHeuristics on CN=Directory Service,CN=Windows NT,CN=Services,"
        "CN=Configuration,<forest root> with ADSI Edit: set character 3 and "
        "character 8 to 0, and characters 28 and 29 to 1. Keep the control "
        "characters (character 10 must be 1, character 20 must be 2). Starting "
        "from an empty value, 00000000010000000002000000011 sets only the "
        "LDAP hardening."
    ),
    "base_severity": "medium",
    "query": """
        WITH dom AS (
            SELECT m.object_guid, m.dns_root, m.dsheuristics AS dsh
            FROM ad_domain m
            JOIN directory_object d
              ON d.object_guid = m.object_guid AND d.client_id = m.client_id AND NOT d.is_deleted
            WHERE m.client_id = %(client_id)s AND m.valid_to IS NULL
              AND m.dsheuristics IS NOT NULL
        ),
        chars AS (
            SELECT d.*,
                   NULLIF(substr(d.dsh, 3, 1), '') AS c3,
                   NULLIF(substr(d.dsh, 8, 1), '') AS c8,
                   NULLIF(substr(d.dsh, 28, 1), '') AS c28,
                   NULLIF(substr(d.dsh, 29, 1), '') AS c29
            FROM dom d
        ),
        issue AS (
            SELECT c.object_guid, x.ord, x.sev, x.issue
            FROM chars c
            CROSS JOIN LATERAL (VALUES
                (1, 3, CASE WHEN c.c8 IS NOT NULL AND c.c8 <> '0'
                            THEN 'anonymous NSPI access is allowed (character 8 fAllowAnonNSPI = '
                                 || c.c8 || ')' END),
                (2, 2, CASE WHEN c.c28 = '2' OR c.c29 = '2'
                            THEN 'the CVE-2021-42291 LDAP hardening is disabled (character 28 '
                                 || 'LDAPAddAuthZVerifications = ' || COALESCE(c.c28, 'unset')
                                 || ', character 29 LDAPOwnerModify = ' || COALESCE(c.c29, 'unset') || ')' END),
                (3, 1, CASE WHEN NOT (COALESCE(c.c28, '') = '2' OR COALESCE(c.c29, '') = '2')
                             AND (c.c28 IS DISTINCT FROM '1' OR c.c29 IS DISTINCT FROM '1')
                            THEN 'the CVE-2021-42291 LDAP hardening is not set to enforce (character 28 '
                                 || 'LDAPAddAuthZVerifications = ' || COALESCE(c.c28, 'unset')
                                 || ', character 29 LDAPOwnerModify = ' || COALESCE(c.c29, 'unset')
                                 || '; 1 enforces)' END),
                (4, 1, CASE WHEN c.c3 = '1'
                            THEN 'List Object mode is on (character 3 fDoListObject = 1)' END)
            ) AS x(ord, sev, issue)
            WHERE x.issue IS NOT NULL
        )
        SELECT
            CASE WHEN max(i.sev) >= 3 THEN 'fail' ELSE 'warn' END AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE max(i.sev) WHEN 3 THEN 'medium' WHEN 2 THEN 'low' ELSE 'info' END AS fd_severity,
            'Forest dSHeuristics (domain ' || COALESCE(c.dns_root, c.object_guid::text) || '): '
                || string_agg(i.issue, '; ' ORDER BY i.ord) AS summary,
            jsonb_build_object(
                'dns_root', c.dns_root,
                'dsheuristics', c.dsh,
                'fdolistobject_char3', c.c3,
                'fallowanonnspi_char8', c.c8,
                'ldap_add_authz_verifications_char28', c.c28,
                'ldap_owner_modify_char29', c.c29,
                'issues', jsonb_agg(i.issue ORDER BY i.ord)
            ) AS detail
        FROM chars c
        JOIN issue i ON i.object_guid = c.object_guid
        GROUP BY c.object_guid, c.dns_root, c.dsh, c.c3, c.c8, c.c28, c.c29
    """,
}
