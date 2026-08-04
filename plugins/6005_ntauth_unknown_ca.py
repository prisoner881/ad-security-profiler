"""
Plugin 6005: Certificate Trusted for Domain Logon Traces to No Known Enterprise CA

NTAuthCertificates (a single, well-known object in the Configuration
NC -- confirmed against Microsoft's own documentation, cross-checked
against multiple independent sources) holds every CA certificate
trusted forest-wide for smart card/certificate-based domain logon
(PKINIT). When a user authenticates with a certificate, the domain
controller doesn't just validate the certificate itself -- it checks
whether the certificate that ISSUED it appears in this object. A
certificate here that doesn't trace back to a currently-known,
collected Enterprise CA (plugin 6001-6004's own ad_enrollment_service
data) is one of two things: an orphaned entry left behind when a CA
was decommissioned without the corresponding cleanup step (a real,
well-documented gap -- uninstalling a CA only removes its
pKIEnrollmentService object, not its NTAuthCertificates entry, per
Microsoft's own guidance), or a "Golden Certificate"-class forgery:
a certificate planted here specifically to be trusted for domain
authentication without ever having been issued by a real, functioning
CA in this forest.

Cross-referenced by subject common name against ad_enrollment_service.
ca_name, which is a reliable match, not a loose heuristic: Microsoft's
own [MS-WCCE] specification confirms a pKIEnrollmentService object's
cn is authoritatively set to the (sanitized) CN of its own CA
certificate's Subject field -- the same value real Enterprise CAs
themselves rely on to match certificate templates to the correct CA.
"""

PLUGIN = {
    "plugin_id": 6005,
    "category": "Certificate Services",
    "name": "Certificate Trusted for Domain Logon Traces to No Known Enterprise CA",
    "version": "1.1",
    "revision_date": "2026-07-31",
    "remediation": (
        "First confirm whether this is a currently-used third-party or "
        "cross-forest CA deliberately imported into NTAuthCertificates "
        "(a supported, documented scenario -- Microsoft's own KB295663 "
        "covers importing third-party CA certificates here) rather than "
        "orphaned or malicious. If it's genuinely orphaned (traces to a "
        "decommissioned CA), remove it with "
        "`certutil -viewdelstore \"ldap:///CN=NTAuthCertificates,CN=Public"
        " Key Services,CN=Services,<Configuration DN>?cACertificate?base"
        "?objectclass=certificationAuthority\"`, selecting the matching "
        "certificate by its thumbprint from this finding's evidence. If "
        "you cannot account for this certificate at all -- no known "
        "decommissioned CA, no documented third-party import -- "
        "investigate as a potential forged trust-anchor before removing "
        "it, since that's a critical, actively-exploitable finding, not "
        "routine cleanup."
    ),
    "control_id": "ADCS-105",
    "framework_tags": [],
    "references": [
        {"title": "Microsoft: Import third-party certification authorities (CAs) into Enterprise NTAuth store",
         "url": "https://learn.microsoft.com/en-us/troubleshoot/windows-server/certificates-and-public-key-infrastructure-pki/import-third-party-ca-to-enterprise-ntauth-store"},
    ],
    "description": (
        "NTAuthCertificates holds every CA certificate trusted forest-"
        "wide for smart card/certificate-based domain logon (PKINIT) -- "
        "a domain controller checks this list when validating a "
        "certificate-based authentication attempt. A certificate here "
        "that doesn't trace back to a currently-known Enterprise CA "
        "(cross-referenced by subject CN against ad_enrollment_service, "
        "a reliable match per Microsoft's own [MS-WCCE] specification) "
        "is either an orphaned entry from a decommissioned CA that was "
        "never cleaned up (uninstalling a CA only removes its "
        "enrollment service object, not this entry -- a well-documented "
        "gap), or a 'Golden Certificate'-class forgery planted to be "
        "trusted for domain authentication without ever having been a "
        "real, functioning CA. Also flags any entry that fails to parse "
        "as a valid X.509 certificate at all -- a malformed trusted "
        "entry is itself worth surfacing."
    ),
    "base_severity": "high",
    "query": """
        WITH ntauth_certs AS (
            SELECT n.object_guid AS ntauth_guid, cert.value AS cert_json
            FROM ad_ntauth_store n, jsonb_array_elements(n.certificates) AS cert(value)
            WHERE n.valid_to IS NULL AND n.client_id = %(client_id)s
        ),
        known_ca_names AS (
            SELECT DISTINCT es.ca_name
            FROM ad_enrollment_service es
            WHERE es.valid_to IS NULL AND es.client_id = %(client_id)s AND es.ca_name IS NOT NULL
        ),
        flagged AS (
            SELECT nc.ntauth_guid, nc.cert_json,
                   CASE
                       WHEN nc.cert_json->>'parse_error' IS NOT NULL THEN
                           'failed to parse as valid X.509 (' || (nc.cert_json->>'parse_error') || ')'
                       ELSE
                           'subject "' || (nc.cert_json->>'subject_cn') || '" traces to no known Enterprise CA'
                   END AS reason
            FROM ntauth_certs nc
            WHERE nc.cert_json->>'parse_error' IS NOT NULL
               OR NOT EXISTS (
                    SELECT 1 FROM known_ca_names kcn WHERE kcn.ca_name = nc.cert_json->>'subject_cn'
                  )
        ),
        -- [fix, caught via a real production crash on a related plugin
        -- (4023) -- same root cause, checked and fixed here
        -- proactively] NTAuthCertificates is a single object holding a
        -- LIST of certificates; the original version produced one row
        -- per flagged certificate, all sharing the one ntauth_guid --
        -- a second orphaned/malformed cert in the same store would
        -- collide on identity_guid exactly like 4023's crash did.
        -- Aggregated here instead: one finding covering every
        -- problematic certificate currently in the store, each
        -- individual certificate's full detail preserved in a JSON
        -- array rather than flattened away.
        aggregated AS (
            SELECT ntauth_guid,
                   array_agg(reason ORDER BY reason) AS reasons,
                   jsonb_agg(cert_json ORDER BY reason) AS certs,
                   count(*) AS flagged_count
            FROM flagged
            GROUP BY ntauth_guid
        )
        SELECT
            'fail' AS status,
            a.ntauth_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            a.flagged_count || ' certificate(s) in NTAuthCertificates need review: '
                || array_to_string(a.reasons, '; ') AS summary,
            jsonb_build_object('certificates', a.certs) AS detail
        FROM aggregated a
    """,
}
