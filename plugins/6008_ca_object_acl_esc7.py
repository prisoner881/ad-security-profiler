"""
Plugin 6008: Certificate Authority AD Object ACL Misconfiguration (ESC5)

(Named "... Matches ESC7" before v1.4 -- see the [v1.4] note below.)

ESC7 is most precisely defined as a non-admin holding the ManageCA or
ManageCertificates control-access rights on a CA's own AD object
(pKIEnrollmentService) -- ManageCA lets a holder reconfigure the CA
(including flipping the EDITF_ATTRIBUTESUBJECTALTNAME2 flag to chain
into ESC6, or enabling/publishing an ESC1-shaped template like the
built-in SubCA), and ManageCertificates lets a holder approve a
pending certificate request, bypassing manager-approval protections.

This plugin deliberately covers a NARROWER, but confidently-verified,
slice of that: GenericAll/GenericWrite/WriteDacl/WriteOwner on the CA
object, which always implies ManageCA/ManageCertificates along with
everything else (the same reasoning plugins 6006/6007 already use for
ESC4/ESC5). The full ESC7 definition also includes a principal holding
JUST the specific ManageCA/ManageCertificates control-access right
(not full control) -- multiple independent sources confirm these are
represented as object-type ACEs with the ADS_RIGHT_DS_CONTROL_ACCESS
flag plus a specific ObjectType GUID, the same general mechanism as a
certificate template's own Enroll/AutoEnroll extended rights, but the
exact GUID values for ManageCA/ManageCertificates specifically could
not be confirmed precisely enough from available public sources to
build a rule around safely. Documented as a known, narrower gap rather
than guessed at -- a principal with ONLY the narrow extended right
(not full control) will not be caught by this plugin.

[v1.3] GenericAll/GenericWrite are now recognised in the form AD stores
them. ACE masks are stored already mapped: GenericAll as 0xF01FF and
GenericWrite as 0x20028 (WRITE_PROP with no object type, i.e. write
every property), so the raw GENERIC_ALL (0x10000000) / GENERIC_WRITE
(0x40000000) bits tested before essentially never matched --
GenericWrite-only grants were missed and GenericAll was labelled as
WriteDacl/WriteOwner (raw bits are still matched too). The rights label
names only GenericAll when it is held, since it subsumes the rest.
Inherit-only ACEs (acl_edge.inherit_only, schema v34) are skipped: they
grant nothing on the object they are stored on, only on its descendants.

[v1.4] Re-scoped from ESC7 to ESC5. The premise above was wrong: ESC7's
ManageCA / ManageCertificates ("Manage CA" / "Issue and Manage
Certificates") are CA-server permissions held in the CA's own security
descriptor in the registry (HKLM\\SYSTEM\\CurrentControlSet\\Services\\
CertSvc\\Configuration\\<CA>\\Security, read over RPC/certutil), not
ACEs on the AD pKIEnrollmentService object -- there is no such AD
control-access right GUID, and GenericAll on the AD object does not
confer them. ESC7 is therefore not detectable from LDAP and is not
claimed any more. What this plugin really detects -- control of the CA's
AD object -- is an ESC5 risk in its own right: the holder can rewrite
certificateTemplates (publish SubCA or any ESC1/ESC2-shaped template on
that CA), dNSHostName or cACertificate. Name, description, remediation
(ADSI Edit / dsacls on CN=<CA>,CN=Enrollment Services, not the
certsrv.msc Security tab) and summary wording ("(ESC5)") changed
accordingly. Also: Tier 0 trustees (RID 500, 516, 518, S-1-5-9,
AdminSDHolder-protected groups, v_privileged_principal for a reason other
than control of a PKI object) and the CA host's
own computer account (which holds full control on its enrollment
service object by default) are excluded; the object's owner (implicit
WriteDacl) is reported; rows are aggregated per (CA, trustee); joins are
client-scoped; the summary COALESCEs the CA name.
"""

PLUGIN = {
    "plugin_id": 6008,
    "category": "Certificate Services",
    "name": "Certificate Authority AD Object ACL Misconfiguration (ESC5)",
    "version": "1.4",
    "revision_date": "2026-10-04",
    "remediation": (
        "Confirm whether this grant is a deliberate PKI administration "
        "delegation or leftover/overly broad. The object is the CA's AD "
        "registration, CN=<CA>,CN=Enrollment Services,CN=Public Key "
        "Services,CN=Services,CN=Configuration,<forest root> -- review "
        "its Security tab in ADSI Edit (Configuration partition) or "
        "remove the grant with `dsacls \"<object DN>\" /R <trustee>`. "
        "Control of this object lets the holder publish any template "
        "on the CA (certificateTemplates), e.g. SubCA or an ESC1-shaped "
        "one. Note: this is NOT the CA's own permission set (Manage CA / "
        "Issue and Manage Certificates, ESC7), which lives in the CA "
        "registry and is reviewed in certsrv.msc -> CA Properties -> "
        "Security or `certutil -config \"<CA>\" -getreg CA\\Security`; "
        "review that separately, as it cannot be read over LDAP."
    ),
    "control_id": "PKI-701",
    "framework_tags": [
        "NIST-800-53-AC-3",
        "NIST-800-53-AC-6",
        "NIST-800-53-AC-6(1)",
        "NIST-800-53-SC-17",
        "NIST-800-53-IA-5(2)",
        "NIST-CSF-2.0-PR.AA-05",
        "NIST-CSF-2.0-PR.DS-02",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.2",
        "PCI-DSS-4.0-4.2.1.1",
        "CIS-CSC-8-3.3",
        "CIS-CSC-8-6.8",
        "ISO-27001-2022-A.5.15",
        "ISO-27001-2022-A.8.3",
        "ISO-27001-2022-A.8.24",
        "SOC2-CC6.3",
        "SOC2-CC6.1",
        "HIPAA-164.312(a)(1)",
        "MITRE-ATTCK-T1649",
        "CISA-AA26-237A",
    ],
    "references": [
        {"title": "SpecterOps: Certified Pre-Owned -- Abusing Active Directory Certificate Services",
         "url": "https://posts.specterops.io/certified-pre-owned-d95910965cd2"},
        {"title": "BloodHound (SpecterOps): WriteDacl edge",
         "url": "https://bloodhound.specterops.io/resources/edges/write-dacl"},
    ],
    "description": (
        "A non-admin principal owns, or holds GenericAll, GenericWrite, "
        "WriteDacl or WriteOwner on, a CA's AD object "
        "(pKIEnrollmentService) -- an ESC5 path: the holder can change "
        "which templates the CA publishes (e.g. SubCA or an ESC1-shaped "
        "template). ESC7 (Manage CA / Issue and Manage Certificates) is "
        "held in the CA's registry security descriptor and is not "
        "visible over LDAP, so it is not covered. Excludes Domain "
        "Admins, Enterprise Admins, Administrators, SYSTEM, the CA host's "
        "own computer account, the built-in Administrator, "
        "AdminSDHolder-protected groups and any principal already "
        "privileged per v_privileged_principal for a reason other than "
        "control of a PKI object."
    ),
    "base_severity": "critical",
    "query": """
        WITH expected_holders AS (
            SELECT do2.object_guid
            FROM directory_object do2
            WHERE do2.client_id = %(client_id)s
              AND (do2.object_sid LIKE '%%-512' OR do2.object_sid LIKE '%%-519'
                   OR do2.object_sid LIKE '%%-544')
            UNION
            SELECT fsp.object_guid
            FROM ad_foreign_security_principal fsp
            WHERE fsp.client_id = %(client_id)s AND fsp.valid_to IS NULL
              AND fsp.well_known_name = 'Local System'
        ),
        dangerous_aces AS (
            SELECT a.object_guid AS ca_guid, a.trustee_sid, a.access_mask,
                   ((a.access_mask & 983551) = 983551 OR (a.access_mask & 268435456) <> 0) AS is_generic_all,
                   (((a.access_mask & 32) <> 0 AND a.object_type_guid IS NULL)
                       OR (a.access_mask & 1073741824) <> 0) AS is_generic_write,
                   (a.access_mask & 262144) != 0 AS is_write_dacl,
                   (a.access_mask & 524288) != 0 AS is_write_owner,
                   false AS is_owner
            FROM acl_edge a
            JOIN ad_enrollment_service es ON es.object_guid = a.object_guid AND es.client_id = a.client_id
             AND es.valid_to IS NULL
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND a.inherit_only IS NOT TRUE   -- [v1.3] inherit-only: grants nothing on this object
              AND (
                    (a.access_mask & (268435456 | 1073741824 | 262144 | 524288)) != 0
                    OR (a.access_mask & 983551) = 983551                    -- GenericAll, as stored
                    OR ((a.access_mask & 32) <> 0 AND a.object_type_guid IS NULL)  -- GenericWrite, as stored
                  )
            UNION ALL
            -- [v1.4] The owner can always rewrite the DACL (implicit WriteDacl).
            SELECT es.object_guid, odo.owner_sid, 0, false, false, false, false, true
            FROM ad_enrollment_service es
            JOIN directory_object odo ON odo.object_guid = es.object_guid AND odo.client_id = es.client_id
            WHERE es.client_id = %(client_id)s AND es.valid_to IS NULL
              AND odo.owner_sid IS NOT NULL
        ),
        -- [v1.4] One row per (CA, trustee); Tier 0 trustees and the CA
        -- host's own computer account (default full control) excluded.
        unexpected_holders AS (
            SELECT da.ca_guid,
                   COALESCE(trustee_do.sam_account_name, da.trustee_sid) AS trustee_label,
                   trustee_do.object_sid AS trustee_sid,
                   trustee_do.object_class AS trustee_object_class,
                   bit_or(da.access_mask) AS access_mask,
                   (SELECT string_agg(x, ', ') FROM (VALUES
                        (CASE WHEN bool_or(da.is_owner) THEN 'Owner' END),
                        (CASE WHEN bool_or(da.is_generic_all) THEN 'GenericAll' END),
                        (CASE WHEN bool_or(da.is_generic_write) AND NOT bool_or(da.is_generic_all) THEN 'GenericWrite' END),
                        (CASE WHEN bool_or(da.is_write_dacl) AND NOT bool_or(da.is_generic_all) THEN 'WriteDacl' END),
                        (CASE WHEN bool_or(da.is_write_owner) AND NOT bool_or(da.is_generic_all) THEN 'WriteOwner' END)
                    ) AS v(x) WHERE x IS NOT NULL) AS rights_label
            FROM dangerous_aces da
            JOIN directory_object trustee_do
                ON trustee_do.object_sid = da.trustee_sid AND trustee_do.client_id = %(client_id)s
               AND NOT trustee_do.is_deleted
            WHERE NOT EXISTS (
                SELECT 1 FROM expected_holders eh WHERE eh.object_guid = trustee_do.object_guid
            )
              AND NOT (trustee_do.object_sid LIKE '%%-500' OR trustee_do.object_sid LIKE '%%-516'
                       OR trustee_do.object_sid LIKE '%%-518' OR trustee_do.object_sid = 'S-1-5-9')
              AND NOT EXISTS (SELECT 1 FROM ad_group pg
                              WHERE pg.object_guid = trustee_do.object_guid AND pg.client_id = trustee_do.client_id
                                AND pg.valid_to IS NULL AND pg.is_protected_group)
              -- Privileged per v_privileged_principal for a reason OTHER than
              -- control of a PKI object: v_tier0_object counts the CAs, CA
              -- hosts, NTAuth store and PKI containers as Tier 0, so a holder
              -- of exactly the rights reported here is "privileged" by that
              -- view -- using it unfiltered would hide every finding.
              AND NOT EXISTS (SELECT 1 FROM v_privileged_principal vp
                              WHERE vp.client_id = trustee_do.client_id
                                AND vp.object_guid = trustee_do.object_guid
                                AND (vp.privilege_source = 'protected_group_member'
                                     OR NOT EXISTS (SELECT 1 FROM v_tier0_object t0
                                                    WHERE t0.client_id = vp.client_id
                                                      AND t0.object_guid = vp.via_object_guid
                                                      AND t0.tier0_reason IN ('enterprise_ca', 'enterprise_ca_host',
                                                                              'ntauth_store', 'pki_container'))))
              AND NOT EXISTS (SELECT 1 FROM ad_enrollment_service es2
                              JOIN ad_computer cah ON lower(cah.dns_hostname) = lower(es2.dns_hostname)
                               AND cah.client_id = es2.client_id AND cah.valid_to IS NULL
                              WHERE es2.object_guid = da.ca_guid AND es2.client_id = %(client_id)s
                                AND es2.valid_to IS NULL
                                AND cah.object_guid = trustee_do.object_guid)
            GROUP BY da.ca_guid, trustee_do.object_guid, trustee_do.sam_account_name,
                     da.trustee_sid, trustee_do.object_sid, trustee_do.object_class
        ),
        -- [fix, applied proactively after the same architectural bug
        -- was found and fixed in plugins 9001/6006/6007 this session --
        -- any CA with more than one over-delegated principal would
        -- collide on identity_guid the same way.]
        aggregated AS (
            SELECT ca_guid,
                   array_agg(trustee_label || ' (' || rights_label || ')' ORDER BY trustee_label, trustee_sid) AS holder_summaries,
                   jsonb_agg(jsonb_build_object(
                       'trustee_sid', trustee_sid,
                       'trustee_sam_account_name', trustee_label,
                       'trustee_object_class', trustee_object_class,
                       'access_mask', access_mask,
                       'rights', rights_label
                   ) ORDER BY trustee_label, trustee_sid) AS holder_details,
                   count(*) AS holder_count
            FROM unexpected_holders
            GROUP BY ca_guid
        )
        SELECT
            'fail' AS status,
            a.ca_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'critical' AS fd_severity,
            a.holder_count || ' unexpected principal(s) hold dangerous rights on Certificate Authority "'
                || COALESCE(es.ca_name, es.dns_hostname, es.object_guid::text) || '" AD object (ESC5): ' || array_to_string(a.holder_summaries, '; ') AS summary,
            jsonb_build_object(
                'ca_name', es.ca_name,
                'dns_hostname', es.dns_hostname,
                'holders', a.holder_details
            ) AS detail
        FROM aggregated a
        JOIN ad_enrollment_service es ON es.object_guid = a.ca_guid AND es.client_id = %(client_id)s
         AND es.valid_to IS NULL
    """,
}
