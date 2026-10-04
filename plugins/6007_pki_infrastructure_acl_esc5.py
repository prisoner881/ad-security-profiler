"""
Plugin 6007: PKI Infrastructure Object ACL Misconfiguration Matches ESC5

ESC5 ("Vulnerable PKI Object Access Control"), from the original
Certified Pre-Owned taxonomy: the ESC4 idea (a non-admin can rewrite
a security-relevant object into an exploitable configuration) applied
to the PKI infrastructure objects the whole certificate ecosystem
depends on, not just individual templates. Confirmed against multiple
independent sources before building this: the object set in scope is
the Public Key Services container, the Certificate Templates
container, the Enrollment Services container, the NTAuthCertificates
object, and each CA's own AD computer object -- control over any of
these gives an attacker a foothold equivalent to controlling the CA
itself (e.g. WriteDacl on the Public Key Services container lets you
grant yourself rights on everything beneath it, including every
existing and future certificate template).

Covers five structurally different object types in one query via
UNION ALL, since they don't share one typed table: the three
containers and NTAuthCertificates are found directly (the containers
by their well-known DN suffix, NTAuthCertificates via its own typed
table), while each CA's computer object is found by cross-referencing
ad_enrollment_service.dns_hostname against ad_computer.dns_hostname --
there's no direct foreign key between a CA's AD registration and its
underlying computer account, so this is the same join adprofiler.py's
own collector already performs to decide which computer object's ACL
to scan in the first place.

Same exclusion set as every other ACL-based plugin in this project.
ESC6 and ESC16 (CA-server registry settings, not AD object ACLs) and
the extended-rights-based half of ESC7 (ManageCA/ManageCertificates as
a specific control-access-right GUID, distinct from the plain
GenericAll/WriteDacl covered by plugin 6008) were all investigated and
are NOT covered by this plugin or this project at all -- the former
two are outside this project's LDAP-only model, and the exact GUID
values for the latter could not be confirmed precisely enough from
available public sources to build a rule around them without risking
either silently matching nothing or silently matching the wrong
thing. Documented here rather than guessed at.

[v1.3] GenericAll/GenericWrite are now recognised in the form AD stores
them. ACE masks are stored already mapped: GenericAll as 0xF01FF and
GenericWrite as 0x20028 (WRITE_PROP with no object type, i.e. write
every property), so the raw GENERIC_ALL (0x10000000) / GENERIC_WRITE
(0x40000000) bits tested before essentially never matched --
GenericWrite-only grants were missed and GenericAll was labelled as
WriteDacl/WriteOwner (raw bits are still matched too). The rights label
names only GenericAll when it is held, since it subsumes the rest.
Inherit-only ACEs are deliberately still counted: an ACE on a PKI
container that flows down to every template or CA object under it is the
ESC5 risk.

[v1.4] Trustees that are already Tier 0 are no longer reported: the
built-in Administrator (RID 500), Domain Controllers (516), Schema Admins
(518), Enterprise Domain Controllers (S-1-5-9), AdminSDHolder-protected
groups and anything privileged per v_privileged_principal for a reason
other than control of a PKI object (that view counts PKI objects as Tier
0, so it is filtered to avoid hiding every finding). This removes the default
false positive on every CA host computer object, whose class
defaultSecurityDescriptor grants Account Operators (S-1-5-32-548, a
protected group) full control. The object's owner (implicit WriteDacl) is
now reported when directory_object.owner_sid is populated for it (the
PKI containers always; the CA computer object when it is adminCount=1).
Rows are aggregated per (object, trustee) first so a trustee with
several ACEs is listed once; the CA-computer join is client-scoped and
deleted trustees are ignored. AIA, CDP, Certification Authorities, KRA
and OID containers are still out of scope (not collected). Correction to
the ESC7 remark above: ManageCA / ManageCertificates are not AD
control-access rights at all -- they live in the CA's registry security
descriptor, so ESC7 cannot be seen over LDAP (see plugin 6008 v1.4, now
re-scoped to ESC5 on the CA's AD object).
"""

PLUGIN = {
    "plugin_id": 6007,
    "category": "Certificate Services",
    "name": "PKI Infrastructure Object ACL Misconfiguration Matches ESC5",
    "version": "1.4",
    "revision_date": "2026-10-04",
    "remediation": (
        "Confirm whether this grant is a deliberate PKI administration "
        "delegation or leftover/overly broad. These objects live in "
        "the Configuration partition (Sites/Services/Public Key "
        "Services in ADSI Edit, not the Certificate Templates console) "
        "-- review their Security tab there, or `dsacls \"<object "
        "DN>\" /R <trustee>`. Control over any of these is equivalent "
        "to controlling the CA itself: the containers let a holder "
        "grant themselves rights on everything beneath them (including "
        "every certificate template, present and future), "
        "NTAuthCertificates lets them add an arbitrary trusted CA "
        "certificate for domain logon, and a CA's own computer object "
        "gives a path to compromising the CA server directly."
    ),
    "control_id": "PKI-501",
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
        "WriteDacl, or WriteOwner on, one of the PKI infrastructure "
        "objects the whole certificate ecosystem depends on: the "
        "Public Key Services, Certificate Templates, or Enrollment "
        "Services containers, the NTAuthCertificates object, or a "
        "CA's own AD computer object. Control over any of these is "
        "equivalent to controlling the CA. Excludes Domain Admins, "
        "Enterprise Admins, Administrators, SYSTEM, the built-in "
        "Administrator, AdminSDHolder-protected groups (e.g. Account "
        "Operators' default control of computer objects) and any "
        "principal already privileged per v_privileged_principal for a "
        "reason other than control of a PKI object."
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
        pki_objects AS (
            -- The three PKI containers: identified by their well-known
            -- DN suffix (no typed table for these -- they're generic
            -- 'container'-class rows registered specifically so their
            -- ACL could be scanned, per adprofiler.py's
            -- collect_well_known_container_acl()).
            SELECT do2.object_guid, do2.dn_current AS label
            FROM directory_object do2
            WHERE do2.client_id = %(client_id)s
              AND do2.object_class = 'container'
              AND (
                do2.dn_current ILIKE 'CN=Public Key Services,CN=Services,%%'
                OR do2.dn_current ILIKE 'CN=Certificate Templates,CN=Public Key Services,CN=Services,%%'
                OR do2.dn_current ILIKE 'CN=Enrollment Services,CN=Public Key Services,CN=Services,%%'
              )
            UNION ALL
            -- NTAuthCertificates: has its own typed table, unlike the
            -- three containers above.
            SELECT n.object_guid, 'NTAuthCertificates' AS label
            FROM ad_ntauth_store n
            WHERE n.client_id = %(client_id)s AND n.valid_to IS NULL
            UNION ALL
            -- Each CA's own computer object, cross-referenced by
            -- dNSHostName -- same join adprofiler.py's collector uses
            -- to decide which computer object's ACL to scan.
            SELECT comp.object_guid, 'CA computer object (' || comp.dns_hostname || ')' AS label
            FROM ad_enrollment_service es
            JOIN ad_computer comp ON lower(comp.dns_hostname) = lower(es.dns_hostname)
                                   AND comp.client_id = es.client_id   -- [v1.4]
                                   AND comp.valid_to IS NULL
            WHERE es.client_id = %(client_id)s AND es.valid_to IS NULL
        ),
        dangerous_aces AS (
            SELECT a.object_guid AS pki_guid, po.label, a.trustee_sid, a.access_mask,
                   ((a.access_mask & 983551) = 983551 OR (a.access_mask & 268435456) <> 0) AS is_generic_all,
                   (((a.access_mask & 32) <> 0 AND a.object_type_guid IS NULL)
                       OR (a.access_mask & 1073741824) <> 0) AS is_generic_write,
                   (a.access_mask & 262144) != 0 AS is_write_dacl,
                   (a.access_mask & 524288) != 0 AS is_write_owner,
                   false AS is_owner
            FROM acl_edge a
            JOIN pki_objects po ON po.object_guid = a.object_guid
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND (
                    (a.access_mask & (268435456 | 1073741824 | 262144 | 524288)) != 0
                    OR (a.access_mask & 983551) = 983551                    -- GenericAll, as stored
                    OR ((a.access_mask & 32) <> 0 AND a.object_type_guid IS NULL)  -- GenericWrite, as stored
                  )
            UNION ALL
            -- [v1.4] The owner can always rewrite the DACL (implicit WriteDacl).
            SELECT po.object_guid, po.label, odo.owner_sid, 0, false, false, false, false, true
            FROM pki_objects po
            JOIN directory_object odo ON odo.object_guid = po.object_guid AND odo.client_id = %(client_id)s
            WHERE odo.owner_sid IS NOT NULL
        ),
        -- [v1.4] One row per (object, trustee), Tier 0 trustees excluded:
        -- well-known admin SIDs (incl. RID 500), AdminSDHolder-protected
        -- groups (Account Operators' default GenericAll on computer
        -- objects) and anything in v_privileged_principal.
        unexpected_holders AS (
            SELECT da.pki_guid, max(da.label) AS label,
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
            GROUP BY da.pki_guid, trustee_do.object_guid, trustee_do.sam_account_name,
                     da.trustee_sid, trustee_do.object_sid, trustee_do.object_class
        ),
        -- [fix, caught via a real production crash at large scale (3
        -- CAs, multiple PKI objects) that this project's own small
        -- test lab never exposed] identity_guid is the PKI object's
        -- object_guid, not the trustee's -- any PKI object with more
        -- than one over-delegated principal collided on identity_guid.
        -- Aggregated here instead, same pattern as plugin 9001's fix.
        aggregated AS (
            SELECT pki_guid, max(label) AS label,
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
            GROUP BY pki_guid
        )
        SELECT
            'fail' AS status,
            a.pki_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'critical' AS fd_severity,
            a.holder_count || ' unexpected principal(s) hold dangerous rights on PKI object "'
                || a.label || '" (ESC5): ' || array_to_string(a.holder_summaries, '; ') AS summary,
            jsonb_build_object(
                'pki_object', a.label,
                'holders', a.holder_details
            ) AS detail
        FROM aggregated a
    """,
}
