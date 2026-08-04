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
"""

PLUGIN = {
    "plugin_id": 6007,
    "category": "Certificate Services",
    "name": "PKI Infrastructure Object ACL Misconfiguration Matches ESC5",
    "version": "1.1",
    "revision_date": "2026-08-04",
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
    "framework_tags": [],
    "references": [
        {"title": "SpecterOps: Certified Pre-Owned -- Abusing Active Directory Certificate Services",
         "url": "https://posts.specterops.io/certified-pre-owned-d95910965cd2"},
        {"title": "BloodHound (SpecterOps): WriteDacl edge",
         "url": "https://bloodhound.specterops.io/resources/edges/write-dacl"},
    ],
    "description": (
        "A non-admin principal holds GenericAll, GenericWrite, "
        "WriteDacl, or WriteOwner on one of the PKI infrastructure "
        "objects the whole certificate ecosystem depends on: the "
        "Public Key Services, Certificate Templates, or Enrollment "
        "Services containers, the NTAuthCertificates object, or a "
        "CA's own AD computer object. Control over any of these is "
        "equivalent to controlling the CA. Excludes the same baseline "
        "well-known holders used elsewhere in this project."
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
                                   AND comp.valid_to IS NULL
            WHERE es.client_id = %(client_id)s AND es.valid_to IS NULL
        ),
        dangerous_aces AS (
            SELECT a.object_guid AS pki_guid, po.label, a.trustee_sid, a.access_mask,
                   (a.access_mask & 268435456) != 0 AS is_generic_all,
                   (a.access_mask & 1073741824) != 0 AS is_generic_write,
                   (a.access_mask & 262144) != 0 AS is_write_dacl,
                   (a.access_mask & 524288) != 0 AS is_write_owner
            FROM acl_edge a
            JOIN pki_objects po ON po.object_guid = a.object_guid
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND (a.access_mask & (268435456 | 1073741824 | 262144 | 524288)) != 0
        ),
        unexpected_holders AS (
            SELECT da.pki_guid, da.label,
                   COALESCE(trustee_do.sam_account_name, da.trustee_sid) AS trustee_label,
                   trustee_do.object_sid AS trustee_sid,
                   trustee_do.object_class AS trustee_object_class,
                   da.access_mask,
                   (SELECT string_agg(x, ', ') FROM (VALUES
                        (CASE WHEN da.is_generic_all THEN 'GenericAll' END),
                        (CASE WHEN da.is_generic_write THEN 'GenericWrite' END),
                        (CASE WHEN da.is_write_dacl THEN 'WriteDacl' END),
                        (CASE WHEN da.is_write_owner THEN 'WriteOwner' END)
                    ) AS v(x) WHERE x IS NOT NULL) AS rights_label
            FROM dangerous_aces da
            JOIN directory_object trustee_do
                ON trustee_do.object_sid = da.trustee_sid AND trustee_do.client_id = %(client_id)s
            WHERE NOT EXISTS (
                SELECT 1 FROM expected_holders eh WHERE eh.object_guid = trustee_do.object_guid
            )
        ),
        -- [fix, caught via a real production crash at large scale (3
        -- CAs, multiple PKI objects) that this project's own small
        -- test lab never exposed] identity_guid is the PKI object's
        -- object_guid, not the trustee's -- any PKI object with more
        -- than one over-delegated principal collided on identity_guid.
        -- Aggregated here instead, same pattern as plugin 9001's fix.
        aggregated AS (
            SELECT pki_guid, max(label) AS label,
                   array_agg(trustee_label || ' (' || rights_label || ')' ORDER BY trustee_label) AS holder_summaries,
                   jsonb_agg(jsonb_build_object(
                       'trustee_sid', trustee_sid,
                       'trustee_sam_account_name', trustee_label,
                       'trustee_object_class', trustee_object_class,
                       'access_mask', access_mask,
                       'rights', rights_label
                   ) ORDER BY trustee_label) AS holder_details,
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
