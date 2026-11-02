"""
Plugin 5022: AD FS Is Deployed -- Confirm the July and October 2026 AD FS Updates

AD FS received a run of security fixes in 2026:
  * July 2026: CVE-2026-56155, elevation of privilege to administrator on
    the AD FS server, marked "Exploitation Detected" and reported by
    Microsoft's incident response team (DART); also CVE-2026-58529
    (information disclosure), CVE-2026-50684 (spoofing) and seven denial-of-
    service fixes.
  * October 2026: two Critical spoofing fixes (CVE-2026-108131,
    CVE-2026-96222), four more spoofing fixes (CVE-2026-103576,
    CVE-2026-83511, CVE-2026-83646, CVE-2026-83674, CVE-2026-96252), two
    security feature bypasses (CVE-2026-69982, CVE-2026-70005), an
    information disclosure (CVE-2026-97788) and denial-of-service fixes.
An administrator on an AD FS server holds the token-signing key, so can mint
SAML tokens for every federated user and relying party, Microsoft 365 /
Entra ID included ("Golden SAML", MITRE ATT&CK T1606.002); a spoofing flaw in
token issuance has the same reach. Patch level is not visible in the
directory: the finding stands while AD FS is deployed, as a prompt to confirm
the updates, like plugin 6014 for NDES. Plugins 5016 (DKM key readable),
10090 / 10091 (federation settings), 11022 (federation changes) and 10113
(AD FS host not Tier 0) cover the configuration.

Evidence:
  * an AD FS farm: a container directly under CN=ADFS,CN=Microsoft,
    CN=Program Data,<domain> (the Distributed Key Manager container AD FS
    setup creates per farm), with its DKM key objects (contacts) below it
    (ad_adfs_dkm_object);
  * the farm's service account: gMSAs (or other accounts outside Tier 0)
    holding allow ACEs on the farm's DKM objects, and the computers allowed
    to retrieve those gMSAs' passwords -- the AD FS servers (the same
    derivation as plugin 10113);
  * Entra ID federation: federated domains whose issuer, passive sign-in or
    metadata exchange URI is an AD FS endpoint (".../adfs/...")
    (entra_domain_federation, source 'federation').

One finding per farm, status 'warn':
  * high: the farm has DKM key objects and Entra ID federates at least one
    domain to an AD FS endpoint;
  * medium: the farm has key objects and Entra federation was not read
    (no Entra collection, or source 'federation' not 'ok'), or Entra
    federates domains only to non-AD FS identity providers;
  * low: the farm has key objects and Entra ID federates no domain (AD FS
    serves only other relying parties, or the farm is decommissioned), or
    the farm container holds no key object (leftover of a removed farm).
Plus one row (identity md5('5022:' || client_id || ':federation')) when
Entra ID federates domains to an AD FS endpoint and no farm is found in this
domain -- the farm lives in another domain or forest: medium.

Data: ad_adfs_dkm_object, directory_object, acl_edge, ad_computer,
gmsa_password_reader_edge, v_effective_group_membership,
entra_domain_federation, entra_collection_status. Identity = the farm
container object.
"""

PLUGIN = {
    "plugin_id": 5022,
    "category": "Hybrid Identity",
    "name": "AD FS Is Deployed -- Confirm the July and October 2026 AD FS Updates",
    "version": "1.0",
    "revision_date": "2026-11-01",
    "control_id": "ADFS-5022",
    "framework_tags": [
        "NIST-800-53-SI-2",
        "NIST-800-53-RA-5",
        "NIST-800-53-IA-5(2)",
        "NIST-CSF-2.0-ID.RA-01",
        "NIST-CSF-2.0-PR.PS-02",
        "PCI-DSS-4.0-6.3.3",
        "CIS-CSC-8-7.3",
        "ISO-27001-2022-A.8.8",
        "SOC2-CC7.1",
        "MITRE-ATTCK-T1606.002",
        "MITRE-ATTCK-T1068",
        "CVE-2026-56155",
        "CVE-2026-108131",
        "CVE-2026-96222",
        "CVE-2026-103576",
        "CVE-2026-83511",
        "CVE-2026-83646",
        "CVE-2026-83674",
        "CVE-2026-96252",
        "CVE-2026-69982",
        "CVE-2026-70005",
        "CVE-2026-97788",
        "CVE-2026-58529",
        "CVE-2026-50684",
    ],
    "references": [
        {"title": "Microsoft Security Update Guide: CVE-2026-56155 (AD FS Elevation of Privilege, exploited)",
         "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-56155"},
        {"title": "Microsoft Security Update Guide: CVE-2026-108131 (AD FS Spoofing, Critical)",
         "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-108131"},
        {"title": "Microsoft Security Update Guide: CVE-2026-96222 (AD FS Spoofing, Critical)",
         "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-96222"},
        {"title": "Microsoft: Migrate from federation to cloud authentication",
         "url": "https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/migrate-from-federation-to-cloud-authentication"},
        {"title": "MITRE ATT&CK T1606.002: Forge Web Credentials: SAML Tokens",
         "url": "https://attack.mitre.org/techniques/T1606/002/"},
    ],
    "description": (
        "An AD FS farm is present (its Distributed Key Manager container and keys are in this "
        "domain). AD FS received an elevation-of-privilege fix in July 2026 that was exploited in "
        "the wild (CVE-2026-56155) and two Critical spoofing fixes in October 2026 "
        "(CVE-2026-108131, CVE-2026-96222), among others. An attacker in control of an AD FS "
        "server can forge tokens for every federated user. High when Entra ID federates a domain "
        "to AD FS; medium when that could not be checked or only other identity providers are "
        "federated; low when no domain is federated or the farm holds no key. Patch level is not "
        "visible to this check."
    ),
    "remediation": (
        "Confirm the July 2026 and October 2026 security updates (or later) are installed on "
        "every AD FS server and Web Application Proxy listed in the detail. Because "
        "CVE-2026-56155 was exploited before the fix, review the AD FS servers for compromise: "
        "changes to their local Administrators group, new or exported token-signing / token-"
        "decryption certificates, AD FS configuration changes, and unusual reads of the DKM "
        "container. Treat the AD FS servers and their service account as Tier 0 (plugin 10113). "
        "Where AD FS only serves Microsoft 365 / Entra ID, Microsoft recommends moving the "
        "federated domains to cloud authentication (password hash synchronization or pass-"
        "through authentication) and decommissioning the farm; a farm container with no key "
        "object is usually left over from a removed farm and can be deleted once confirmed."
    ),
    "base_severity": "high",
    "query": r"""
        WITH
        dkm AS (
            SELECT k.object_guid, k.is_key_object, lower(o.dn_current) AS dn_lc, o.dn_current
              FROM ad_adfs_dkm_object k
              JOIN directory_object o
                ON o.object_guid = k.object_guid AND o.client_id = k.client_id AND NOT o.is_deleted
             WHERE k.client_id = %(client_id)s AND k.valid_to IS NULL
        ),
        farm AS (
            SELECT d.object_guid AS farm_guid, d.dn_current AS farm_dn, d.dn_lc,
                   (SELECT count(*) FROM dkm x
                     WHERE x.is_key_object AND right(x.dn_lc, length(d.dn_lc) + 1) = ',' || d.dn_lc) AS key_count
              FROM dkm d
             WHERE NOT d.is_key_object
               AND d.dn_lc ~ '^cn=[^,]+,cn=adfs,cn=microsoft,cn=program data,'
        ),
        farm_object AS (
            SELECT f.farm_guid, x.object_guid
              FROM farm f
              JOIN dkm x ON x.dn_lc = f.dn_lc OR right(x.dn_lc, length(f.dn_lc) + 1) = ',' || f.dn_lc
        ),
        -- accounts outside Tier 0 holding allow ACEs on the farm's objects: the
        -- AD FS service account (normally a gMSA)
        svc AS (
            SELECT DISTINCT fo.farm_guid, t.object_guid AS svc_guid, t.sam_account_name,
                   COALESCE(g.is_gmsa, false) AS is_gmsa
              FROM farm_object fo
              JOIN acl_edge a
                ON a.client_id = %(client_id)s AND a.object_guid = fo.object_guid
               AND a.valid_to IS NULL AND a.ace_type = 'allow'
              JOIN directory_object t
                ON t.client_id = a.client_id AND t.object_sid = a.trustee_sid AND NOT t.is_deleted
              LEFT JOIN ad_computer g
                ON g.client_id = t.client_id AND g.object_guid = t.object_guid AND g.valid_to IS NULL
             WHERE t.object_class IN ('user', 'computer')
               AND NOT COALESCE(g.is_domain_controller, false)
               AND NOT EXISTS (SELECT 1 FROM v_privileged_principal vp
                                WHERE vp.client_id = t.client_id AND vp.object_guid = t.object_guid)
        ),
        host AS (
            SELECT DISTINCT s.farm_guid, COALESCE(hc.dns_hostname, hc.sam_account_name) AS host_name
              FROM svc s
              JOIN gmsa_password_reader_edge e
                ON e.client_id = %(client_id)s AND e.gmsa_guid = s.svc_guid
               AND e.valid_to IS NULL AND e.ace_type = 'allow'
              JOIN directory_object t
                ON t.client_id = e.client_id AND t.object_sid = e.trustee_sid AND NOT t.is_deleted
              LEFT JOIN v_effective_group_membership vem
                ON vem.client_id = t.client_id AND vem.group_guid = t.object_guid
              JOIN ad_computer hc
                ON hc.client_id = t.client_id AND hc.valid_to IS NULL
               AND hc.object_guid = COALESCE(vem.member_guid, t.object_guid)
             WHERE s.is_gmsa AND NOT hc.is_gmsa
        ),
        fed_src AS (
            SELECT EXISTS (SELECT 1 FROM entra_collection_status s
                            WHERE s.client_id = %(client_id)s
                              AND s.source = 'federation' AND s.status = 'ok') AS ok
        ),
        fed AS (
            SELECT f.domain_name,
                   (COALESCE(f.issuer_uri, '') ~* '/adfs/'
                    OR COALESCE(f.passive_sign_in_uri, '') ~* '/adfs/'
                    OR COALESCE(f.metadata_exchange_uri, '') ~* '/adfs/') AS is_adfs,
                   COALESCE(substring(f.passive_sign_in_uri from '^[a-zA-Z]+://([^/:]+)'),
                            substring(f.issuer_uri from '^[a-zA-Z]+://([^/:]+)')) AS sts_host
              FROM entra_domain_federation f
              CROSS JOIN fed_src s
             WHERE f.client_id = %(client_id)s AND s.ok
        ),
        fed_sum AS (
            SELECT (SELECT ok FROM fed_src) AS federation_read,
                   count(*) FILTER (WHERE is_adfs) AS adfs_domains,
                   count(*) FILTER (WHERE NOT is_adfs) AS other_domains,
                   to_jsonb(COALESCE(array_agg(domain_name ORDER BY domain_name) FILTER (WHERE is_adfs),
                                     '{}'::text[])) AS adfs_domain_list,
                   to_jsonb(COALESCE(array_agg(DISTINCT sts_host) FILTER (WHERE is_adfs AND sts_host IS NOT NULL),
                                     '{}'::text[])) AS adfs_sts_hosts,
                   to_jsonb(COALESCE(array_agg(domain_name ORDER BY domain_name) FILTER (WHERE NOT is_adfs),
                                     '{}'::text[])) AS other_domain_list
              FROM fed
        ),
        farm_row AS (
            SELECT f.farm_guid, f.farm_dn, f.key_count,
                   (SELECT jsonb_agg(DISTINCT s.sam_account_name) FROM svc s WHERE s.farm_guid = f.farm_guid)
                       AS service_accounts,
                   (SELECT jsonb_agg(DISTINCT h.host_name) FROM host h WHERE h.farm_guid = f.farm_guid)
                       AS adfs_servers,
                   (SELECT string_agg(DISTINCT h.host_name, ', ') FROM host h WHERE h.farm_guid = f.farm_guid)
                       AS server_text,
                   fs.*,
                   CASE WHEN f.key_count = 0 THEN 'low'
                        WHEN fs.federation_read AND fs.adfs_domains > 0 THEN 'high'
                        WHEN NOT fs.federation_read OR fs.other_domains > 0 THEN 'medium'
                        ELSE 'low' END AS sev
              FROM farm f
              CROSS JOIN fed_sum fs
        )
        SELECT
            'warn' AS status,
            r.farm_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            r.sev AS fd_severity,
            CASE WHEN r.key_count = 0
                 THEN 'AD FS farm container ' || r.farm_dn || ' holds no DKM key object: probably left over '
                      || 'from a removed farm; confirm and delete it, or confirm the farm''s servers have the '
                      || 'July and October 2026 AD FS updates'
                 ELSE 'AD FS is deployed (farm ' || r.farm_dn
                      || CASE WHEN r.server_text IS NOT NULL THEN ', servers ' || r.server_text ELSE '' END
                      || ')'
                      || CASE WHEN r.federation_read AND r.adfs_domains > 0
                              THEN ' and Entra ID federates ' || r.adfs_domains || ' domain(s) to AD FS'
                              WHEN NOT r.federation_read
                              THEN '; Entra ID federation was not read'
                              WHEN r.other_domains > 0
                              THEN '; Entra ID federates domains only to other identity providers'
                              ELSE '; Entra ID federates no domain' END
                      || '. Confirm the July 2026 (CVE-2026-56155, exploited in the wild) and October 2026 '
                      || '(CVE-2026-108131, CVE-2026-96222, Critical) AD FS updates are installed' END AS summary,
            jsonb_build_object(
                'farm_container', r.farm_dn,
                'dkm_key_objects', r.key_count,
                'service_accounts', COALESCE(r.service_accounts, '[]'::jsonb),
                'adfs_servers', COALESCE(r.adfs_servers, '[]'::jsonb),
                'entra_federation_read', r.federation_read,
                'entra_domains_federated_to_adfs', r.adfs_domain_list,
                'adfs_sts_hosts', r.adfs_sts_hosts,
                'entra_domains_federated_elsewhere', r.other_domain_list,
                'cves_exploited', jsonb_build_array('CVE-2026-56155'),
                'cves_critical', jsonb_build_array('CVE-2026-108131', 'CVE-2026-96222'),
                'note', 'Patch level is not visible in the directory. AD FS servers are found through '
                        'the gMSA holding rights on the farm''s DKM objects; a farm run under a user '
                        'service account lists the account but not the servers.'
            ) AS detail
        FROM farm_row r
        UNION ALL
        SELECT
            'warn',
            md5('5022:' || %(client_id)s::text || ':federation')::uuid,
            NULL, NULL, NULL, NULL,
            'medium',
            'Entra ID federates ' || fs.adfs_domains || ' domain(s) to AD FS ('
                || array_to_string(ARRAY(SELECT jsonb_array_elements_text(fs.adfs_sts_hosts)), ', ')
                || ') but no AD FS farm is in this domain (another domain or forest hosts it). Confirm the '
                || 'July 2026 (CVE-2026-56155, exploited in the wild) and October 2026 (CVE-2026-108131, '
                || 'CVE-2026-96222, Critical) AD FS updates are installed on that farm',
            jsonb_build_object(
                'entra_domains_federated_to_adfs', fs.adfs_domain_list,
                'adfs_sts_hosts', fs.adfs_sts_hosts,
                'cves_exploited', jsonb_build_array('CVE-2026-56155'),
                'cves_critical', jsonb_build_array('CVE-2026-108131', 'CVE-2026-96222'))
        FROM fed_sum fs
        WHERE fs.federation_read AND fs.adfs_domains > 0
          AND NOT EXISTS (SELECT 1 FROM farm)
    """,
}
