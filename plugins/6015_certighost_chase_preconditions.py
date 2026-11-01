"""
Plugin 6015: Enterprise CA Exposed to CertiGhost (CVE-2026-54121) Preconditions

CVE-2026-54121 ("CertiGhost", July 2026, Critical, public proof of concept
since 24 July 2026) lets any authenticated user obtain a certificate that
authenticates as a domain controller. An Enterprise CA, when a request
carries the cdc (client DC) and rmd (remote domain) attributes, performs a
second directory lookup -- the "chase" -- against the host the requester
names, over SMB and LDAP, without checking that it is a domain controller,
and builds the certificate from what that host returns. The attacker
creates a computer account (MachineAccountQuota), enrolls with it in a
template whose subject is built from the requester's DNS name (the default
Machine template), points the chase at a host it controls, returns the
DC's objectSid and dNSHostName, and receives a certificate for the DC:
PKINIT as the DC, then DCSync, then krbtgt. Strong certificate mapping does
not help -- the certificate carries the DC's own SID.

Preconditions reported here, all visible in the directory:
  * an Enterprise CA (ad_enrollment_service) publishes a template
    (cert_template_enabled_edge) that
      - is client-authentication capable,
      - builds its subject from the requester's DNS name
        (msPKI-Certificate-Name-Flag CT_FLAG_SUBJECT_ALT_REQUIRE_DNS
        0x08000000 or CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN 0x10000000) and
        does not take the subject from the request (6001 covers that),
      - issues without manager approval (msPKI-Enrollment-Flag
        CT_FLAG_PEND_ALL_REQUESTS 0x2) or authorized signatures, and
      - grants Enroll / AutoEnroll (or All Extended Rights, or GenericAll)
        to Domain Computers, Domain Users, Authenticated Users, Everyone or
        Users, through an allow ACE that applies to the template;
  * and an ordinary user can come by a computer account: the effective
    ms-DS-MachineAccountQuota is above 0 and "Add workstations to domain"
    is held by a broad group (Authenticated Users, Everyone, Users, Domain
    Users) or not set by the domain controllers' Group Policy, or SYSVOL was
    not read (as plugin 4009 reads it), or enabled non-Tier-0 computers are
    owned by principals outside Tier 0 (as plugin 2044 reads it).

What is not visible: whether the CA has the July 2026 update, whether the
fix's feature gate is active (the researchers report the old path stays
open when it is not), and the CA's EditFlags (EDITF_ENABLECHASECLIENTDC,
set by default) -- all in the CA's registry. The finding therefore stands
as long as the preconditions do, as a prompt to confirm the CA is patched,
like plugin 6014 for NDES.

One finding per Enterprise CA, status 'warn':
  * high: a qualifying template is published and an ordinary user can come
    by a computer account (quota usable, or computers owned outside Tier 0);
  * medium: a qualifying template is published, the quota is 0 (or only
    named principals, or nobody, may use it) and no computer is owned
    outside Tier 0 -- only an attacker who already controls a computer
    account, or one of those principals, can use the path.

Data: ad_enrollment_service, cert_template_enabled_edge, ad_cert_template,
acl_edge, ad_domain.machine_account_quota, ad_computer, directory_object,
v_dc_effective_gpo_setting and sysvol_collection_status (only when the
evaluated run read SYSVOL; this plugin assesses without it).
Identity = the CA's enrollment service object.
"""

PLUGIN = {
    "plugin_id": 6015,
    "category": "Certificate Services",
    "name": "Enterprise CA Exposed to CertiGhost (CVE-2026-54121) Preconditions",
    "version": "1.0",
    "revision_date": "2026-11-01",
    "control_id": "ADCS-6015",
    "framework_tags": [
        "NIST-800-53-SI-2",
        "NIST-800-53-RA-5",
        "NIST-800-53-IA-5(2)",
        "NIST-800-53-AC-6",
        "NIST-CSF-2.0-ID.RA-01",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-6.3.3",
        "CIS-CSC-8-7.3",
        "ISO-27001-2022-A.8.8",
        "SOC2-CC7.1",
        "MITRE-ATTCK-T1649",
        "MITRE-ATTCK-T1136.002",
        "MITRE-ATTCK-T1003.006",
        "CVE-2026-54121",
    ],
    "references": [
        {"title": "Microsoft Security Update Guide: CVE-2026-54121 (AD CS Elevation of Privilege)",
         "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-54121"},
        {"title": "CertiGhost (CVE-2026-54121): How a Low-Privileged AD User Impersonated a Domain Controller via AD CS",
         "url": "https://asbawy.github.io/logs/certighost-cve-2026-54121"},
        {"title": "IT-Connect: Certighost CVE-2026-54121 -- a standard AD account is enough to impersonate a DC",
         "url": "https://www.it-connect.tech/certighost-cve-2026-54121-a-standard-ad-account-is-enough-to-impersonate-a-domain-controller/"},
        {"title": "DIESEC: Certighost CVE-2026-54121 Active Directory domain takeover",
         "url": "https://diesec.com/2026/07/certighost-cve-2026-54121-active-directory/"},
        {"title": "MITRE ATT&CK T1649: Steal or Forge Authentication Certificates",
         "url": "https://attack.mitre.org/techniques/T1649/"},
    ],
    "description": (
        "An Enterprise CA publishes a client-authentication template whose subject is built "
        "from the requester's DNS name (such as the default Machine template) and that Domain "
        "Computers or another broad group can enroll in. These are the preconditions of "
        "CertiGhost (CVE-2026-54121, July 2026, public proof of concept): a CA without the fix "
        "follows a requester-chosen 'chase' host and issues a certificate for a domain "
        "controller, leading to DCSync. High when an ordinary user can also come by a computer "
        "account (MachineAccountQuota above 0, or computers owned outside Tier 0); medium "
        "otherwise. The CA's patch level, the fix's feature gate and its EditFlags are not "
        "visible to this check."
    ),
    "remediation": (
        "Install the July 2026 security update (or later) on every Enterprise CA and confirm "
        "the fix is active there -- the researchers report that the old code path remains "
        "when its feature gate is off. Where cross-domain or cross-forest enrollment is not "
        "used, also clear the chase flag on each CA: certutil -setreg policy\\EditFlags "
        "-EDITF_ENABLECHASECLIENTDC, then restart CertSvc (net stop certsvc && net start "
        "certsvc); test enrollment afterwards. Set ms-DS-MachineAccountQuota to 0 (plugin "
        "4009) and give computer objects owned by ordinary users to Domain Admins (plugin "
        "2044). Remove Enroll / AutoEnroll for Domain Computers (or broader groups) from "
        "DNS-subject templates that are not used for autoenrollment, or unpublish them. "
        "Watch the CA for requests whose cdc attribute names a host that is not a domain "
        "controller, and for outbound SMB/LDAP from the CA to unexpected hosts. The August "
        "2026 AD CS remote code execution fix (CVE-2026-62818, Critical) is another reason "
        "the CA must be current."
    ),
    "base_severity": "high",
    "sysvol_optional": True,
    "query": """
        WITH
        broad_enroller AS (
            -- allow ACEs applying to a published template that grant enrollment
            -- to a group any computer account (or any user) belongs to
            SELECT a.object_guid AS template_guid,
                   CASE WHEN a.trustee_sid = 'S-1-1-0' THEN 'Everyone'
                        WHEN a.trustee_sid = 'S-1-5-11' THEN 'Authenticated Users'
                        WHEN a.trustee_sid = 'S-1-5-32-545' THEN 'Users'
                        WHEN a.trustee_sid LIKE 'S-1-5-21-%%-513' THEN 'Domain Users'
                        ELSE 'Domain Computers' END AS trustee_name
              FROM acl_edge a
             WHERE a.client_id = %(client_id)s
               AND a.valid_to IS NULL
               AND a.ace_type = 'allow'
               AND a.inherit_only IS NOT TRUE
               AND (a.trustee_sid IN ('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545')
                    OR a.trustee_sid LIKE 'S-1-5-21-%%-513'
                    OR a.trustee_sid LIKE 'S-1-5-21-%%-515')
               AND (((a.access_mask & 256) <> 0
                     AND (a.object_type_guid IS NULL
                          OR a.object_type_guid IN ('0e10c968-78fb-11d2-90d4-00c04f79dc55',
                                                    'a05b8cc2-17bc-4802-a710-e7c15ab866a2')))
                    OR (a.access_mask & 268435456) <> 0)
        ),
        qualifying AS (
            SELECT es.object_guid AS ca_guid, es.ca_name, es.dns_hostname,
                   ct.object_guid AS template_guid,
                   COALESCE(ct.template_name, ct.display_name, ct.object_guid::text) AS template_name,
                   ct.certificate_name_flags,
                   array_agg(DISTINCT be.trustee_name ORDER BY be.trustee_name) AS enrollers
              FROM ad_enrollment_service es
              JOIN cert_template_enabled_edge e
                ON e.ca_guid = es.object_guid AND e.client_id = es.client_id AND e.valid_to IS NULL
              JOIN ad_cert_template ct
                ON ct.object_guid = e.template_guid AND ct.client_id = e.client_id AND ct.valid_to IS NULL
              JOIN broad_enroller be ON be.template_guid = ct.object_guid
             WHERE es.client_id = %(client_id)s
               AND es.valid_to IS NULL
               AND ct.client_authentication_capable
               AND (COALESCE(ct.certificate_name_flags, 0) & 402653184) <> 0   -- 0x08000000 | 0x10000000
               AND NOT ct.enrollee_supplies_subject
               AND (COALESCE(ct.enrollment_flags, 0) & 2) = 0                   -- no manager approval
               AND COALESCE(ct.ra_signature_count, 0) = 0                       -- no authorized signatures
             GROUP BY es.object_guid, es.ca_name, es.dns_hostname, ct.object_guid, ct.template_name,
                      ct.display_name, ct.certificate_name_flags
        ),
        -- Can an ordinary user come by a computer account?  (a) the quota, as
        -- plugin 4009 reads it: usable unless the evaluated run read SYSVOL
        -- and every domain controller's Group Policy grants "Add workstations
        -- to domain" to nobody.
        sysvol AS (
            SELECT EXISTS (SELECT 1 FROM sysvol_collection_status s
                           WHERE s.client_id = %(client_id)s AND s.run_id = %(run_id)s
                             AND (s.status = 'ok' OR (s.status = 'partial' AND s.gpos_read > 0)))
                   AS collected
        ),
        dc AS (
            SELECT c.object_guid
              FROM ad_computer c
             WHERE c.client_id = %(client_id)s AND c.valid_to IS NULL AND c.is_domain_controller IS TRUE
               AND NOT is_entra_kerberos_server(c.sam_account_name, c.krbtgt_link)
        ),
        add_ws AS (
            SELECT e.dc_guid, btrim(COALESCE(e.setting_value, '')) AS v
              FROM v_dc_effective_gpo_setting e
              CROSS JOIN sysvol sv
             WHERE sv.collected
               AND e.client_id = %(client_id)s
               AND e.source = 'security_template'
               AND lower(e.section) = 'privilege rights'
               AND lower(e.setting_key) = 'semachineaccountprivilege'
        ),
        quota AS (
            SELECT COALESCE(d.machine_account_quota, 10) AS quota,
                   CASE WHEN NOT sv.collected THEN 'not_collected'
                        WHEN EXISTS (SELECT 1 FROM dc WHERE NOT EXISTS
                                         (SELECT 1 FROM add_ws w WHERE w.dc_guid = dc.object_guid))
                             THEN 'not_configured'
                        WHEN EXISTS (
                            SELECT 1
                              FROM add_ws w
                              CROSS JOIN LATERAL unnest(string_to_array(w.v, ',')) AS x(entry)
                             WHERE upper(btrim(x.entry)) IN ('*S-1-5-11', '*S-1-1-0', '*S-1-5-32-545')
                                OR upper(btrim(x.entry)) ~ '^\\*S-1-5-21-[0-9-]+-513$'
                                OR lower(reverse(split_part(reverse(btrim(x.entry)), chr(92), 1)))
                                   IN ('authenticated users', 'everyone', 'users', 'domain users'))
                             THEN 'broad'
                        WHEN EXISTS (SELECT 1 FROM add_ws w WHERE w.v <> '') THEN 'restricted'
                        ELSE 'nobody' END AS add_workstations
              FROM ad_domain d
              CROSS JOIN sysvol sv
             WHERE d.client_id = %(client_id)s AND d.valid_to IS NULL
             ORDER BY d.object_guid
             LIMIT 1
        ),
        -- (b) computers owned outside Tier 0, as plugin 2044 reads it
        admin_sid AS (
            SELECT p.object_sid::text AS sid
              FROM directory_object p
              JOIN (SELECT u.object_guid FROM ad_user u
                     WHERE u.client_id = %(client_id)s AND u.valid_to IS NULL AND u.admin_count = 1
                    UNION
                    SELECT g.object_guid FROM ad_group g
                     WHERE g.client_id = %(client_id)s AND g.valid_to IS NULL AND g.admin_count = 1
                    UNION
                    SELECT vp.object_guid FROM v_privileged_principal vp
                     WHERE vp.client_id = %(client_id)s) a
                ON a.object_guid = p.object_guid
             WHERE p.client_id = %(client_id)s AND NOT p.is_deleted AND p.object_sid IS NOT NULL
        ),
        user_owned AS (
            SELECT count(*) AS n
              FROM ad_computer c
              JOIN directory_object o
                ON o.object_guid = c.object_guid AND o.client_id = c.client_id AND NOT o.is_deleted
              JOIN directory_object ow
                ON ow.object_sid = o.owner_sid AND ow.client_id = o.client_id AND NOT ow.is_deleted
             WHERE c.client_id = %(client_id)s AND c.valid_to IS NULL AND c.is_enabled
               AND NOT COALESCE(c.is_domain_controller, false)
               AND NOT COALESCE(c.is_gmsa, false) AND NOT COALESCE(c.is_dmsa, false)
               AND o.owner_sid IS DISTINCT FROM o.object_sid
               AND NOT (o.owner_sid LIKE '%%-512' OR o.owner_sid LIKE '%%-518' OR o.owner_sid LIKE '%%-519'
                        OR o.owner_sid LIKE '%%-500' OR o.owner_sid LIKE '%%-516'
                        OR o.owner_sid IN ('S-1-5-18', 'S-1-5-32-544', 'S-1-5-9'))
               AND NOT EXISTS (SELECT 1 FROM admin_sid s WHERE s.sid = o.owner_sid)
        ),
        per_ca AS (
            SELECT q.ca_guid, q.ca_name, q.dns_hostname,
                   jsonb_agg(jsonb_build_object(
                       'template', q.template_name,
                       'certificate_name_flags', q.certificate_name_flags,
                       'broad_enrollers', to_jsonb(q.enrollers)) ORDER BY q.template_name) AS templates,
                   string_agg(q.template_name, ', ' ORDER BY q.template_name) AS template_list
              FROM qualifying q
             GROUP BY q.ca_guid, q.ca_name, q.dns_hostname
        ),
        graded AS (
            SELECT p.*, h.sam_account_name AS host_account,
                   COALESCE(h.is_domain_controller, false) AS host_is_dc,
                   COALESCE(qt.quota, 10) AS quota,
                   COALESCE(qt.add_workstations, 'not_collected') AS add_workstations,
                   (COALESCE(qt.quota, 10) > 0
                    AND COALESCE(qt.add_workstations, 'not_collected')
                        IN ('not_collected', 'not_configured', 'broad')) AS quota_usable,
                   uo.n AS user_owned_computers
              FROM per_ca p
              LEFT JOIN quota qt ON true
              CROSS JOIN user_owned uo
              LEFT JOIN LATERAL (
                  SELECT c.sam_account_name, c.is_domain_controller
                    FROM ad_computer c
                   WHERE c.client_id = %(client_id)s AND c.valid_to IS NULL
                     AND lower(c.dns_hostname) = lower(p.dns_hostname)
                   ORDER BY c.is_domain_controller DESC, c.sam_account_name
                   LIMIT 1) h ON true
        )
        SELECT
            'warn' AS status,
            g.ca_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN g.quota_usable OR g.user_owned_computers > 0 THEN 'high' ELSE 'medium' END AS fd_severity,
            'CA "' || COALESCE(g.ca_name, g.dns_hostname, g.ca_guid::text) || '"'
                || CASE WHEN g.host_account IS NOT NULL THEN ' (on ' || g.host_account || ')' ELSE '' END
                || ' publishes DNS-subject client-authentication template(s) that broad groups can enroll in ('
                || g.template_list || ')'
                || CASE WHEN g.quota_usable
                        THEN ' and any domain user can create a computer account (ms-DS-MachineAccountQuota '
                             || g.quota || ')'
                        WHEN g.user_owned_computers > 0
                        THEN ' and ' || g.user_owned_computers
                             || ' computer account(s) are owned by principals outside Tier 0'
                        ELSE '' END
                || ': the preconditions of CertiGhost (CVE-2026-54121, domain controller impersonation). '
                || 'Confirm the CA has the July 2026 update with the fix active' AS summary,
            jsonb_build_object(
                'ca_guid', g.ca_guid,
                'ca_name', g.ca_name,
                'ca_dns_hostname', g.dns_hostname,
                'ca_host_account', g.host_account,
                'ca_host_is_domain_controller', g.host_is_dc,
                'qualifying_templates', g.templates,
                'machine_account_quota', g.quota,
                'add_workstations_assignment', g.add_workstations,
                'machine_account_quota_usable', g.quota_usable,
                'computers_owned_outside_tier0', g.user_owned_computers,
                'cves', jsonb_build_array('CVE-2026-54121'),
                'not_visible', 'CA patch level, the fix''s feature gate, and the CA''s EditFlags '
                               '(EDITF_ENABLECHASECLIENTDC) are in the CA''s registry and are not collected.'
            ) AS detail
        FROM graded g
    """,
}
