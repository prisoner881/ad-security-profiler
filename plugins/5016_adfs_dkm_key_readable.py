"""
Plugin 5016: AD FS DKM Master Key Readable by Unexpected Principals (Golden SAML)

AD FS encrypts its token-signing and token-decryption certificates with a
Distributed Key Manager (DKM) master key stored in Active Directory, in
the thumbnailPhoto attribute of a contact object under
CN=<guid>,CN=ADFS,CN=Microsoft,CN=Program Data,<domain>. Anyone who can
read that attribute (plus the AD FS configuration database) can decrypt
the token-signing key and forge SAML tokens for every relying party --
including Microsoft 365 / Entra ID when the domain is federated
("Golden SAML", used in the SolarWinds / Solorigate intrusions). CISA
AA21-008A, MITRE ATT&CK T1606.002 and T1552.004.

Data: ad_adfs_dkm_object (schema v38) lists the objects under the AD FS
container; is_key_object marks the contacts holding a key. The collector
never reads the key; key_readable_by_collector records whether its own,
normally low-privileged, account matched a presence filter on
thumbnailPhoto -- i.e. could read it. ACLs of these objects are in
acl_edge.

Findings:
  (a) key_readable_by_collector TRUE on a key object -> critical, one row
      per DKM key object: the collection account itself could read the
      AD FS key material.
  (b) allow ACEs, per trustee, that let a principal read the key:
      GenericAll, GenericRead (0x80000000, or READ_PROP 0x10 with no
      object type, as AD stores it), READ_PROP on thumbnailPhoto
      (8d3bca50-1d7e-11d0-a081-00aa006c33ed), or WriteDacl / WriteOwner
      (which let the holder grant itself read). Evaluated on the key
      objects (ACEs that apply to them, explicit or inherited) and on
      the DKM containers' inherit-only ACEs that flow to contacts
      (inherited object type empty or contact), which also cover keys
      the collector could not see.
        - broad principals (Everyone, Authenticated Users, Domain Users,
          Domain Computers, Domain Guests, Anonymous Logon, Builtin Users,
          Pre-Windows 2000 Compatible Access) -> fail / critical;
        - any other principal outside Tier 0 -> warn / medium: normally
          this is the AD FS service account (or gMSA), which must be able
          to read the key -- verify that it is, and that nobody else is.
      One row per trustee.
Excluded trustees: SYSTEM, Administrators, Domain Admins, Enterprise
Admins, Domain Controllers, Enterprise Domain Controllers, Creator Owner
(an inherit-only placeholder for the creating account, normally the
AD FS service account), AdminSDHolder-protected groups and Tier 0
principals (v_privileged_principal) -- they already control the domain.

No AD FS container (most domains) -> no rows. A broad principal nested in
a group that is granted read is not expanded.
"""

PLUGIN = {
    "plugin_id": 5016,
    "category": "ACLs",
    "name": "AD FS DKM Master Key Readable by Unexpected Principals (Golden SAML)",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "CRED-5016",
    "framework_tags": [
        "NIST-800-53-AC-3",
        "NIST-800-53-AC-6",
        "NIST-800-53-IA-5(1)",
        "NIST-800-53-SC-28",
        "NIST-CSF-2.0-PR.AA-05",
        "NIST-CSF-2.0-PR.DS-01",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-8.3.2",
        "CIS-CSC-8-3.3",
        "CIS-CSC-8-3.11",
        "ISO-27001-2022-A.5.15",
        "ISO-27001-2022-A.5.17",
        "SOC2-CC6.1",
        "SOC2-CC6.3",
        "HIPAA-164.312(a)(1)",
        "HIPAA-164.312(a)(2)(iv)",
        "MITRE-ATTCK-T1606.002",
        "MITRE-ATTCK-T1552.004",
        "CISA-AA21-008A",
    ],
    "references": [
        {"title": "CISA AA21-008A: Detecting Post-Compromise Threat Activity in Microsoft Cloud Environments",
         "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-008a"},
        {"title": "MITRE ATT&CK T1606.002: Forge Web Credentials - SAML Tokens",
         "url": "https://attack.mitre.org/techniques/T1606/002/"},
        {"title": "Microsoft: AD FS best practices for securing AD FS and Web Application Proxy",
         "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/deployment/best-practices-securing-ad-fs"},
    ],
    "description": (
        "Flags read access to the AD FS DKM master key (thumbnailPhoto of the "
        "contact objects under CN=ADFS,CN=Microsoft,CN=Program Data). Critical "
        "when the low-privileged collection account itself could read the key, "
        "or when a broad principal (Everyone, Authenticated Users, Domain "
        "Users/Computers, ...) holds GenericAll/GenericRead/read thumbnailPhoto/"
        "WriteDacl/WriteOwner on it; any other non-Tier-0 reader is reported "
        "as a warning to confirm it is the AD FS service account. Reading the "
        "key enables Golden SAML token forgery."
    ),
    "remediation": (
        "Restrict the DKM container and its contact objects to the AD FS "
        "service account (or gMSA), SYSTEM and Domain/Enterprise Admins: in "
        "ADSI Edit open CN=ADFS,CN=Microsoft,CN=Program Data,<domain>, Security > "
        "Advanced, remove the broad/unexpected entries (on the container and "
        "on each contact), and check inheritance from CN=Program Data. If the "
        "key may have been read, treat it as compromised: rotate the AD FS "
        "token-signing and token-decryption certificates twice "
        "(Update-AdfsCertificate -Urgent), create a new DKM key, and review "
        "federated sign-ins for forged tokens (CISA AA21-008A)."
    ),
    "base_severity": "critical",
    "query": """
        WITH dkm AS (
            SELECT k.object_guid, k.is_key_object, k.key_readable_by_collector,
                   k.object_class_name, o.dn_current
            FROM ad_adfs_dkm_object k
            JOIN directory_object o
              ON o.object_guid = k.object_guid AND o.client_id = k.client_id AND NOT o.is_deleted
            WHERE k.client_id = %(client_id)s AND k.valid_to IS NULL
        ),
        tier0_sid AS (
            SELECT d.object_sid AS sid
            FROM v_privileged_principal p
            JOIN directory_object d
              ON d.object_guid = p.object_guid AND d.client_id = p.client_id
            WHERE p.client_id = %(client_id)s AND d.object_sid IS NOT NULL
            UNION
            SELECT d.object_sid
            FROM ad_group g
            JOIN directory_object d ON d.object_guid = g.object_guid AND d.client_id = g.client_id
            WHERE g.client_id = %(client_id)s AND g.valid_to IS NULL
              AND g.is_protected_group AND d.object_sid IS NOT NULL
        ),
        read_aces AS (
            SELECT a.trustee_sid, k.dn_current, k.is_key_object,
                   ((a.access_mask & 983551) = 983551 OR (a.access_mask & 268435456) <> 0) AS ga,
                   ((a.access_mask & 2147483648) <> 0
                    OR ((a.access_mask & 16) <> 0 AND a.object_type_guid IS NULL)) AS gr,
                   ((a.access_mask & 16) <> 0
                    AND a.object_type_guid = '8d3bca50-1d7e-11d0-a081-00aa006c33ed') AS rp_photo,
                   (a.access_mask & 262144) <> 0 AS wd,
                   (a.access_mask & 524288) <> 0 AS wo
            FROM acl_edge a
            JOIN dkm k ON k.object_guid = a.object_guid
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND (
                    -- applies to the key object itself
                    (k.is_key_object AND a.inherit_only IS NOT TRUE)
                    -- container ACE flowing down to contact objects
                    OR (NOT k.is_key_object AND a.inherit_only IS TRUE
                        AND (a.inherited_object_type_guid IS NULL
                             OR a.inherited_object_type_guid = '5cb41ed0-0e4c-11d0-a286-00aa003049e2'))
                  )
              AND (
                    (a.access_mask & 983551) = 983551
                    OR (a.access_mask & (268435456 | 2147483648 | 262144 | 524288)) <> 0
                    OR ((a.access_mask & 16) <> 0
                        AND (a.object_type_guid IS NULL
                             OR a.object_type_guid = '8d3bca50-1d7e-11d0-a081-00aa006c33ed'))
                  )
              AND a.trustee_sid NOT IN ('S-1-5-18', 'S-1-5-32-544', 'S-1-5-9', 'S-1-3-0')
              AND a.trustee_sid !~ '^S-1-5-21-[0-9-]+-(512|516|519)$'
              AND NOT EXISTS (SELECT 1 FROM tier0_sid t WHERE t.sid = a.trustee_sid)
        ),
        per_trustee AS (
            SELECT r.trustee_sid,
                   bool_or(r.ga) AS ga, bool_or(r.gr) AS gr, bool_or(r.rp_photo) AS rp_photo,
                   bool_or(r.wd) AS wd, bool_or(r.wo) AS wo,
                   jsonb_agg(DISTINCT jsonb_build_object('dn', r.dn_current,
                                                         'is_key_object', r.is_key_object)) AS objects,
                   (r.trustee_sid IN ('S-1-1-0', 'S-1-5-11', 'S-1-5-7', 'S-1-5-32-545', 'S-1-5-32-554')
                    OR r.trustee_sid ~ '^S-1-5-21-[0-9-]+-(513|514|515)$') AS is_broad
            FROM read_aces r
            GROUP BY r.trustee_sid
        )
        -- (a) the collection account could read the key
        SELECT
            'fail' AS status,
            k.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'critical' AS fd_severity,
            'AD FS DKM key object ' || k.dn_current || ' is readable by the low-privileged '
                || 'collection account itself: it could read the AD FS token-signing key '
                || 'material (Golden SAML)' AS summary,
            jsonb_build_object(
                'dn', k.dn_current,
                'object_class', k.object_class_name,
                'key_readable_by_collector', true
            ) AS detail
        FROM dkm k
        WHERE k.key_readable_by_collector IS TRUE

        UNION ALL

        -- (b) principals with read access, per trustee
        SELECT
            CASE WHEN pt.is_broad THEN 'fail' ELSE 'warn' END,
            tdo.object_guid,
            NULL, NULL, NULL, NULL,
            CASE WHEN pt.is_broad THEN 'critical' ELSE 'medium' END,
            'Principal ' || COALESCE(tdo.sam_account_name,
                                     CASE pt.trustee_sid
                                         WHEN 'S-1-1-0' THEN 'Everyone'
                                         WHEN 'S-1-5-11' THEN 'Authenticated Users'
                                         WHEN 'S-1-5-7' THEN 'Anonymous Logon'
                                         WHEN 'S-1-5-32-545' THEN 'Users'
                                         WHEN 'S-1-5-32-554' THEN 'Pre-Windows 2000 Compatible Access'
                                     END,
                                     pt.trustee_sid)
                || ' can read the AD FS DKM master key ('
                || (SELECT string_agg(x, ', ' ORDER BY n) FROM (VALUES
                        (1, CASE WHEN pt.ga THEN 'GenericAll' END),
                        (2, CASE WHEN pt.gr AND NOT pt.ga THEN 'GenericRead' END),
                        (3, CASE WHEN pt.rp_photo AND NOT pt.ga AND NOT pt.gr THEN 'Read thumbnailPhoto' END),
                        (4, CASE WHEN pt.wd AND NOT pt.ga THEN 'WriteDacl' END),
                        (5, CASE WHEN pt.wo AND NOT pt.ga THEN 'WriteOwner' END)
                    ) AS v(n, x) WHERE x IS NOT NULL)
                || ')'
                || CASE WHEN pt.is_broad THEN ': Golden SAML exposure to a broad principal'
                        ELSE ': verify this is the AD FS service account' END,
            jsonb_build_object(
                'trustee_sid', pt.trustee_sid,
                'sam_account_name', tdo.sam_account_name,
                'object_class', tdo.object_class,
                'broad_principal', pt.is_broad,
                'dkm_objects', pt.objects
            )
        FROM per_trustee pt
        LEFT JOIN LATERAL (
            SELECT d.object_guid, d.sam_account_name, d.object_class
            FROM directory_object d
            WHERE d.client_id = %(client_id)s AND d.object_sid = pt.trustee_sid
              AND NOT d.is_deleted
            ORDER BY d.object_guid
            LIMIT 1
        ) tdo ON TRUE
    """,
}
