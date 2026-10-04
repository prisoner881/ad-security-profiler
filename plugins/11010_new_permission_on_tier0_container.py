"""
Plugin 11010: New Permission on the Domain Root, AdminSDHolder or a PKI / Key Object

Change Detection companion to the 5xxx ACL plugins and to 11007 (new
DCSync grant). Those report who holds dangerous rights now; this one
reports allow ACEs that appeared since the previous successful
collection run on the handful of objects whose ACL is control of the
domain or of its key material:
- the domain root (DCSync, GenericAll, WriteDacl -> full domain);
- CN=AdminSDHolder (its ACL is stamped onto every protected account
  hourly by SDProp -- the classic AdminSDHolder persistence technique,
  MITRE ATT&CK T1098 / T1484);
- the PKI containers under CN=Public Key Services, the NTAuth store and
  the Enterprise CA (pKIEnrollmentService) objects, and the CA
  certificate objects under CN=Certification Authorities / CN=AIA
  (ESC5 / ESC7-style control of the PKI, SpecterOps "Certified Pre-Owned");
- KDS root keys and their container (read access = Golden gMSA: every
  gMSA password in the forest can be computed offline);
- AD FS DKM container objects (read access = the AD FS token-signing key
  decryption key: Golden SAML, MITRE ATT&CK T1606.002).
Certificate templates are out of scope here (plugin 11014).

How "new" is decided (mirrors 11007): an acl_edge row that is open now
and was opened after the previous succeeded sync_run is new only for the
access-mask bits that the same trustee did not already hold at the
previous run through an allow ACE with the same object type on the same
object. acl_edge is keyed on (object, trustee, type, mask, object type);
when only an ACE's inheritance flags change, the collector
(reconcile_acl_edge_inheritance) closes and reopens the row with the
same key -- that is therefore never reported, and neither is a mask that
was narrowed.

v38 churn: collector 0.6.0 / schema v38 collects ACLs of GPOs, DNS zones,
KDS root keys and AD FS DKM objects for the first time, so every ACE on
those objects opens in its first v38 run. Objects that had no ACL edge
open at the previous run are therefore skipped entirely -- the first
collection of an ACL is a baseline, not a change.

Only rights that matter are considered: GenericAll, GenericWrite,
WriteDacl, WriteOwner, WriteProperty, extended rights (CONTROL_ACCESS),
validated writes, CreateChild, DeleteChild, Delete and DeleteTree; plus
read rights (ReadProperty, GenericRead) on the KDS and DKM objects, where
reading is the attack, and attribute-specific ReadProperty elsewhere
(e.g. a confidential attribute such as a LAPS password inherited from the
domain root). Deny ACEs are not reported.

Severity: high. Critical (fail) when a new ACE held by a principal other
than the default administrative SIDs confers DCSync on the domain root
(DS-Replication-Get-Changes-All, All Extended Rights or GenericAll) or
GenericAll / WriteDacl / WriteOwner on the domain root or AdminSDHolder
(ACEs that apply to the object itself, not inherit-only). Medium when
every new ACE on the object is held by a default administrative SID
(Domain/Enterprise/Schema/Key Admins, Administrators, SYSTEM, Domain
Controllers, Enterprise DCs, Enterprise Read-only DCs). Trustee SIDs that
do not resolve to a collected object are reported by SID.

One row per object; the individual grants are in detail.new_aces.
Suppressed on a client's first collection run.
"""

PLUGIN = {
    "plugin_id": 11010,
    "category": "Change Detection",
    "name": "New Permission on the Domain Root, AdminSDHolder or a PKI / Key Object",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "CHANGE-11010",
    "framework_tags": [
        "NIST-800-53-CM-3", "NIST-800-53-SI-4", "NIST-800-53-AU-6",
        "NIST-800-53-AC-3", "NIST-800-53-AC-6", "NIST-800-53-AC-6(1)",
        "NIST-CSF-2.0-DE.CM-03", "NIST-CSF-2.0-DE.CM-09", "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1", "PCI-DSS-4.0-7.2.2", "PCI-DSS-4.0-10.2.1.2", "PCI-DSS-4.0-11.5.2",
        "CIS-CSC-8-3.3", "CIS-CSC-8-6.8", "CIS-CSC-8-8.11",
        "ISO-27001-2022-A.5.15", "ISO-27001-2022-A.8.3", "ISO-27001-2022-A.8.16",
        "ISO-27001-2022-A.8.32",
        "SOC2-CC6.3", "SOC2-CC7.2", "SOC2-CC8.1",
        "HIPAA-164.308(a)(1)(ii)(D)", "HIPAA-164.312(a)(1)",
        "MITRE-ATTCK-T1098", "MITRE-ATTCK-T1484", "MITRE-ATTCK-T1222.001",
        "MITRE-ATTCK-T1003.006", "MITRE-ATTCK-T1649", "MITRE-ATTCK-T1606.002",
        "CISA-AA26-237A",
    ],
    "references": [
        {"title": "Microsoft: AdminSDHolder, Protected Accounts and Groups (Appendix C)",
         "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory"},
        {"title": "MITRE ATT&CK T1222.001: File and Directory Permissions Modification",
         "url": "https://attack.mitre.org/techniques/T1222/001/"},
        {"title": "MITRE ATT&CK T1003.006: OS Credential Dumping: DCSync",
         "url": "https://attack.mitre.org/techniques/T1003/006/"},
        {"title": "MITRE ATT&CK T1606.002: Forge Web Credentials: SAML Tokens",
         "url": "https://attack.mitre.org/techniques/T1606/002/"},
        {"title": "SpecterOps: Certified Pre-Owned (AD CS abuse, ESC5/ESC7)",
         "url": "https://posts.specterops.io/certified-pre-owned-d95910965cd2"},
        {"title": "CISA AA26-237A: Joint Red Team Assessment Findings",
         "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-237a"},
    ],
    "description": (
        "Reports allow ACEs that appeared since the previous successful collection "
        "run on the domain root, AdminSDHolder, the PKI containers, the NTAuth store, "
        "Enterprise CA objects, CA certificate objects, KDS root keys and their "
        "container, and AD FS DKM objects -- the objects whose ACL is control of the "
        "domain, of every protected account, of the PKI, of every gMSA password or of "
        "AD FS token signing. A right counts as new only if the trustee did not "
        "already hold it on that object at the previous run, so inheritance-flag "
        "changes and narrowed masks are not reported, and objects whose ACL was being "
        "collected for the first time (GPOs, KDS and DKM objects in the first schema "
        "v38 run) are skipped. Severity is high; critical when a non-default "
        "principal gains DCSync on the domain root or GenericAll/WriteDacl/WriteOwner "
        "on the domain root or AdminSDHolder; medium when only default administrative "
        "SIDs gained rights. Certificate templates are covered by plugin 11014. "
        "Suppressed on a client's first collection run."
    ),
    "remediation": (
        "Match every new ACE to an approved change. Security event ID 5136 (directory "
        "service object modified, attribute nTSecurityDescriptor) on domain controllers "
        "identifies who changed the ACL; enable 'Audit Directory Service Changes' and "
        "SACLs on these objects if it is not recorded. Remove unexplained ACEs with "
        "Active Directory Users and Computers (Advanced Features > Security) or "
        "PowerShell: $acl = Get-Acl 'AD:<DN>'; $acl.RemoveAccessRule($rule); "
        "Set-Acl 'AD:<DN>' $acl. For AdminSDHolder, remember SDProp re-stamps its ACL "
        "on every protected account within an hour: after removing the ACE there, "
        "check the protected accounts too (or run SDProp: RunProtectAdminGroupsTask). "
        "Treat an unexplained DCSync or GenericAll grant on the domain root as a "
        "compromise: rotate krbtgt twice and privileged credentials. An unexplained "
        "read grant on a KDS root key means every gMSA password must be considered "
        "exposed (create a new KDS root key and re-key the gMSAs); on the AD FS DKM "
        "container, rotate the AD FS token-signing and decryption certificates."
    ),
    "base_severity": "high",
    "query": """
        WITH prior_run AS (
            SELECT max(sr.run_id) AS prev_run_id
            FROM sync_run sr
            WHERE sr.client_id = %(client_id)s
              AND sr.run_id < %(run_id)s
              AND sr.status = 'succeeded'
        ),
        target_raw AS (
            SELECT d.object_guid, 1 AS prio, 'Domain root' AS kind, false AS read_sensitive
            FROM ad_domain d
            WHERE d.client_id = %(client_id)s AND d.valid_to IS NULL
            UNION ALL
            SELECT t.object_guid,
                   CASE t.tier0_reason WHEN 'adminsdholder' THEN 2 WHEN 'enterprise_ca' THEN 3
                                       WHEN 'ntauth_store' THEN 4 ELSE 5 END,
                   CASE t.tier0_reason WHEN 'adminsdholder' THEN 'AdminSDHolder'
                                       WHEN 'enterprise_ca' THEN 'Enterprise CA object'
                                       WHEN 'ntauth_store' THEN 'NTAuth store'
                                       ELSE 'PKI container' END,
                   false
            FROM v_tier0_object t
            WHERE t.client_id = %(client_id)s
              AND t.tier0_reason IN ('adminsdholder', 'enterprise_ca', 'ntauth_store', 'pki_container')
            UNION ALL
            SELECT s.object_guid, 6, 'CA certificate object ('
                   || CASE s.store WHEN 'root' THEN 'Certification Authorities' WHEN 'aia' THEN 'AIA'
                                   ELSE s.store END || ')', false
            FROM ad_pki_certificate_store s
            WHERE s.client_id = %(client_id)s AND s.valid_to IS NULL
            UNION ALL
            SELECT k.object_guid, 7, 'KDS root key', true
            FROM ad_kds_root_key k
            WHERE k.client_id = %(client_id)s AND k.valid_to IS NULL
            UNION ALL
            SELECT o.object_guid, 8, 'KDS root key container', true
            FROM directory_object o
            WHERE o.client_id = %(client_id)s
              AND lower(o.dn_current) LIKE 'cn=master root keys,cn=group key distribution service,cn=services,cn=configuration,%%'
            UNION ALL
            SELECT a.object_guid, 9, 'AD FS DKM object', true
            FROM ad_adfs_dkm_object a
            WHERE a.client_id = %(client_id)s AND a.valid_to IS NULL
        ),
        target AS (
            SELECT DISTINCT ON (tr.object_guid)
                   tr.object_guid, tr.kind, tr.read_sensitive, o.dn_current
            FROM target_raw tr
            JOIN directory_object o
              ON o.object_guid = tr.object_guid AND o.client_id = %(client_id)s
             AND NOT o.is_deleted
            -- certificate templates belong to plugin 11014
            WHERE NOT EXISTS (SELECT 1 FROM ad_cert_template ct
                               WHERE ct.object_guid = tr.object_guid
                                 AND ct.client_id = %(client_id)s)
            ORDER BY tr.object_guid, tr.prio
        ),
        -- Objects whose ACL was already collected at the previous run; an
        -- ACL collected for the first time is a baseline, not a change.
        baselined AS (
            SELECT t.*, pr.prev_run_id
            FROM target t
            CROSS JOIN prior_run pr
            WHERE pr.prev_run_id IS NOT NULL
              AND EXISTS (SELECT 1 FROM acl_edge b
                          WHERE b.client_id = %(client_id)s
                            AND b.object_guid = t.object_guid
                            AND b.run_id_valid_from <= pr.prev_run_id
                            AND (b.run_id_valid_to IS NULL OR b.run_id_valid_to > pr.prev_run_id))
        ),
        opened AS (
            SELECT b.object_guid, b.kind, b.read_sensitive, b.dn_current, b.prev_run_id,
                   a.trustee_sid, a.access_mask, a.object_type_guid, a.inherited,
                   a.inherit_only, a.valid_from, a.run_id_valid_from,
                   -- rights the trustee already held through an equivalent ACE
                   COALESCE((SELECT bit_or(p.access_mask) FROM acl_edge p
                             WHERE p.client_id = %(client_id)s
                               AND p.object_guid = a.object_guid
                               AND p.trustee_sid = a.trustee_sid
                               AND p.ace_type = 'allow'
                               AND p.object_type_guid IS NOT DISTINCT FROM a.object_type_guid
                               AND p.run_id_valid_from <= b.prev_run_id
                               AND (p.run_id_valid_to IS NULL OR p.run_id_valid_to > b.prev_run_id)),
                            0) AS prev_mask
            FROM baselined b
            JOIN acl_edge a
              ON a.client_id = %(client_id)s
             AND a.object_guid = b.object_guid
             AND a.valid_to IS NULL
             AND a.ace_type = 'allow'
             AND a.run_id_valid_from > b.prev_run_id
             AND a.run_id_valid_from <= %(run_id)s
        ),
        new_bits AS (
            SELECT op.*, (op.access_mask & ~op.prev_mask) AS nb
            FROM opened op
        ),
        relevant AS (
            SELECT n.*
            FROM new_bits n
            WHERE (n.nb & 1343029611) <> 0          -- write / control / create / delete rights
               OR ((n.nb & (16 | 2147483648)) <> 0  -- ReadProperty / GENERIC_READ
                   AND (n.read_sensitive OR n.object_type_guid IS NOT NULL))
        ),
        named AS (
            SELECT r.*,
                   tdo.sam_account_name AS trustee_name, tdo.dn_current AS trustee_dn,
                   tdo.object_class::text AS trustee_class,
                   (r.trustee_sid IN ('S-1-5-32-544', 'S-1-5-18', 'S-1-5-9')
                    OR r.trustee_sid ~ '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-(498|512|516|518|519|526|527)$')
                       AS is_default_admin,
                   COALESCE(tdo.sam_account_name,
                            CASE r.trustee_sid
                                WHEN 'S-1-1-0' THEN 'Everyone'
                                WHEN 'S-1-5-11' THEN 'Authenticated Users'
                                WHEN 'S-1-5-7' THEN 'Anonymous Logon'
                                WHEN 'S-1-5-18' THEN 'Local System'
                                WHEN 'S-1-5-9' THEN 'Enterprise Domain Controllers'
                                WHEN 'S-1-5-10' THEN 'Principal Self'
                                WHEN 'S-1-3-0' THEN 'Creator Owner'
                                WHEN 'S-1-5-32-544' THEN 'BUILTIN Administrators'
                                WHEN 'S-1-5-32-545' THEN 'BUILTIN Users'
                                WHEN 'S-1-5-32-554' THEN 'Pre-Windows 2000 Compatible Access'
                            END,
                            r.trustee_sid) AS trustee_label,
                   array_to_string(array_remove(ARRAY[
                       CASE WHEN (r.nb & 983551) = 983551 OR (r.nb & 268435456) <> 0 THEN 'GenericAll' END,
                       CASE WHEN (r.nb & 1073741824) <> 0 THEN 'GenericWrite' END,
                       CASE WHEN (r.nb & 983551) <> 983551 AND (r.nb & 262144) <> 0 THEN 'WriteDacl' END,
                       CASE WHEN (r.nb & 983551) <> 983551 AND (r.nb & 524288) <> 0 THEN 'WriteOwner' END,
                       CASE WHEN (r.nb & 983551) <> 983551 AND (r.nb & 32) <> 0 THEN 'WriteProperty' END,
                       CASE WHEN (r.nb & 983551) <> 983551 AND (r.nb & 256) <> 0
                            THEN CASE WHEN r.object_type_guid IS NULL THEN 'AllExtendedRights'
                                      ELSE 'ExtendedRight' END END,
                       CASE WHEN (r.nb & 983551) <> 983551 AND (r.nb & 8) <> 0 THEN 'ValidatedWrite' END,
                       CASE WHEN (r.nb & 983551) <> 983551 AND (r.nb & 1) <> 0 THEN 'CreateChild' END,
                       CASE WHEN (r.nb & 983551) <> 983551 AND (r.nb & 2) <> 0 THEN 'DeleteChild' END,
                       CASE WHEN (r.nb & 983551) <> 983551 AND (r.nb & 65536) <> 0 THEN 'Delete' END,
                       CASE WHEN (r.nb & 983551) <> 983551 AND (r.nb & 64) <> 0 THEN 'DeleteTree' END,
                       CASE WHEN (r.nb & 983551) <> 983551 AND (r.nb & 2147483648) <> 0 THEN 'GenericRead' END,
                       CASE WHEN (r.nb & 983551) <> 983551 AND (r.nb & 16) <> 0 THEN 'ReadProperty' END
                   ], NULL), '+')
                   || CASE WHEN r.object_type_guid IS NULL THEN ''
                           ELSE ' on ' || CASE r.object_type_guid::text
                               WHEN '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' THEN 'DS-Replication-Get-Changes'
                               WHEN '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' THEN 'DS-Replication-Get-Changes-All'
                               WHEN '89e95b76-444d-4c62-991a-0facbeda640c' THEN 'DS-Replication-Get-Changes-In-Filtered-Set'
                               WHEN '00299570-246d-11d0-a768-00aa006e0529' THEN 'User-Force-Change-Password'
                               WHEN 'bf9679c0-0de6-11d0-a285-00aa003049e2' THEN 'member'
                               WHEN 'f30e3bbe-9ff0-11d1-b603-0000f80367c1' THEN 'gPLink'
                               WHEN '5b47d60f-6090-40b2-9f37-2a4de88f3063' THEN 'msDS-KeyCredentialLink'
                               WHEN '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79' THEN 'msDS-AllowedToActOnBehalfOfOtherIdentity'
                               WHEN '0e10c968-78fb-11d2-90d4-00c04f79dc55' THEN 'Certificate-Enrollment'
                               WHEN 'a05b8cc2-17bc-4802-a710-e7c15ab866a2' THEN 'Certificate-AutoEnrollment'
                               WHEN 'bf967a86-0de6-11d0-a285-00aa003049e2' THEN 'computer objects'
                               WHEN 'bf967aba-0de6-11d0-a285-00aa003049e2' THEN 'user objects'
                               WHEN 'bf967a9c-0de6-11d0-a285-00aa003049e2' THEN 'group objects'
                               ELSE r.object_type_guid::text END END
                   || CASE WHEN r.inherit_only THEN ', inherit-only' ELSE '' END AS rights_label,
                   -- DCSync on the domain root, or full control of root/AdminSDHolder
                   (r.inherit_only IS NOT TRUE
                    AND ((r.kind = 'Domain root'
                          AND ((r.nb & 983551) = 983551 OR (r.nb & 268435456) <> 0
                               OR ((r.nb & 256) <> 0
                                   AND (r.object_type_guid IS NULL
                                        OR r.object_type_guid = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'))))
                         OR (r.kind IN ('Domain root', 'AdminSDHolder')
                             AND ((r.nb & 983551) = 983551 OR (r.nb & 268435456) <> 0
                                  OR (r.nb & 262144) <> 0 OR (r.nb & 524288) <> 0))))
                       AS takeover_right
            FROM relevant r
            LEFT JOIN LATERAL (
                SELECT x.sam_account_name, x.dn_current, x.object_class
                FROM directory_object x
                WHERE x.object_sid = r.trustee_sid AND x.client_id = %(client_id)s
                ORDER BY x.is_deleted, x.object_guid
                LIMIT 1
            ) tdo ON TRUE
        ),
        per_object AS (
            SELECT n.object_guid, n.kind, n.dn_current, n.prev_run_id,
                   bool_or(n.takeover_right AND NOT n.is_default_admin) AS critical_grant,
                   bool_and(n.is_default_admin) AS only_default_admins,
                   count(*) AS ace_count,
                   string_agg(n.trustee_label || ' (' || n.rights_label || ')', ', '
                              ORDER BY n.trustee_label, n.trustee_sid, n.rights_label) AS grant_list,
                   jsonb_agg(jsonb_build_object(
                       'trustee_sid', n.trustee_sid,
                       'trustee', n.trustee_label,
                       'trustee_distinguished_name', n.trustee_dn,
                       'trustee_object_class', n.trustee_class,
                       'trustee_resolved', n.trustee_name IS NOT NULL,
                       'is_default_admin_sid', n.is_default_admin,
                       'rights', n.rights_label,
                       'access_mask', n.access_mask,
                       'newly_granted_mask', n.nb,
                       'object_type_guid', n.object_type_guid,
                       'inherited', n.inherited,
                       'inherit_only', n.inherit_only,
                       'confers_domain_takeover', n.takeover_right,
                       'change_observed_at', n.valid_from
                   ) ORDER BY n.trustee_label, n.trustee_sid, n.rights_label) AS new_aces,
                   min(n.valid_from) AS change_observed_at
            FROM named n
            GROUP BY n.object_guid, n.kind, n.dn_current, n.prev_run_id
        )
        SELECT
            CASE WHEN p.critical_grant THEN 'fail' ELSE 'warn' END AS status,
            p.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN p.critical_grant THEN 'critical'
                 WHEN p.only_default_admins THEN 'medium'
                 ELSE 'high' END AS fd_severity,
            p.kind || ' "' || p.dn_current || '" gained '
                || CASE WHEN p.ace_count = 1 THEN 'a new permission'
                        ELSE p.ace_count || ' new permissions' END
                || ' since the previous collection run: ' || p.grant_list
                || CASE WHEN p.critical_grant
                        THEN ' -- this confers control of the domain (DCSync or full control '
                             'of the domain root / AdminSDHolder)'
                        WHEN p.only_default_admins
                        THEN ' (default administrative principals only)'
                        ELSE '' END AS summary,
            jsonb_build_object(
                'object_kind', p.kind,
                'distinguished_name', p.dn_current,
                'new_ace_count', p.ace_count,
                'new_aces', p.new_aces,
                'confers_domain_takeover', p.critical_grant,
                'only_default_admin_trustees', p.only_default_admins,
                'baseline_run_id', p.prev_run_id,
                'change_observed_at', p.change_observed_at,
                'corroborating_event_id', 5136
            ) AS detail
        FROM per_object p
    """,
}
