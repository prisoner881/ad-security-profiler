"""
Plugin 6011: Certificate Enrollment Web Service Published over HTTP (ESC8 Indicator)

Detects Enterprise CAs (pKIEnrollmentService objects, ad_enrollment_service)
whose msPKI-Enrollment-Servers attribute advertises a Certificate
Enrollment Web Service (CES) URI over plain http://. Each value has the
form "<priority>\\n<authentication type>\\n<renewal only>\\n<URI>"; the URI
is extracted with a pattern match anywhere in the value, so differences
in line endings or field order do not matter.

Why it matters: HTTP enrollment endpoints that accept NTLM
authentication without TLS and Extended Protection for Authentication
(EPA) are the target of ESC8: an attacker coerces a domain controller to
authenticate (PetitPotam, PrinterBug, DFSCoerce), relays the NTLM
authentication to the web endpoint and obtains a certificate for the DC
-- domain compromise. HTTP also exposes enrollment traffic to
interception. SpecterOps "Certified Pre-Owned" (ESC8), Microsoft
KB5005413 (mitigating NTLM relay attacks on AD CS). high.

Caveats: this is an indicator. LDAP shows only what the CA advertises
for CES; it cannot see the IIS configuration (whether NTLM is enabled,
whether EPA / "Require SSL" are set) nor the legacy Web Enrollment pages
(/certsrv), which are not published in the directory and are the more
common ESC8 target -- check those on the CA hosts. An https:// URI is not
flagged, although HTTPS without EPA is still relayable. CAs whose
enrollment_servers is NULL (none published, or collected before schema
v38) are skipped. One row per CA listing the HTTP URIs.
"""

PLUGIN = {
    "plugin_id": 6011,
    "category": "Certificate Services",
    "name": "Certificate Enrollment Web Service Published over HTTP (ESC8 Indicator)",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "ADCS-6011",
    "framework_tags": [
        "NIST-800-53-CM-6",
        "NIST-800-53-CM-7",
        "NIST-CSF-2.0-PR.PS-01",
        "PCI-DSS-4.0-2.2.4",
        "PCI-DSS-4.0-4.2.1.1",
        "CIS-CSC-8-4.8",
        "CIS-CSC-8-3.10",
        "ISO-27001-2022-A.8.9",
        "ISO-27001-2022-A.8.24",
        "SOC2-CC6.1",
        "HIPAA-164.312(e)(1)",
        "MITRE-ATTCK-T1557.001",
        "MITRE-ATTCK-T1649",
    ],
    "references": [
        {"title": "Microsoft KB5005413: Mitigating NTLM Relay Attacks on Active Directory Certificate Services (AD CS)",
         "url": "https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429"},
        {"title": "SpecterOps: Certified Pre-Owned (AD CS abuse, ESC8)",
         "url": "https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf"},
        {"title": "MITRE ATT&CK T1649: Steal or Forge Authentication Certificates",
         "url": "https://attack.mitre.org/techniques/T1649/"},
    ],
    "description": (
        "Flags Enterprise CAs whose msPKI-Enrollment-Servers advertises a "
        "Certificate Enrollment Web Service URI over http://. HTTP enrollment "
        "endpoints accepting NTLM without TLS/EPA are the target of ESC8 NTLM "
        "relay (coerce a DC, relay to the CA, obtain a DC certificate). "
        "Indicator only: LDAP cannot see the IIS authentication/EPA settings "
        "or the /certsrv web enrollment pages."
    ),
    "remediation": (
        "Republish the CES endpoints over HTTPS only (Install-AdcsEnrollmentWebService "
        "with an SSL certificate; update the CA's msPKI-Enrollment-Servers so it "
        "lists only https:// URIs, e.g. with `certutil -config <CA> "
        "-enrollmentServerURL` / ADSI Edit), remove the HTTP binding in IIS, "
        "enable Extended Protection for Authentication (Required) and disable "
        "NTLM on the CES/CEP and /certsrv applications per KB5005413. Remove "
        "Web Enrollment (certsrv) if it is not needed."
    ),
    "base_severity": "high",
    "query": """
        WITH uris AS (
            SELECT e.object_guid, e.ca_name, e.dns_hostname, v.ord, v.val,
                   (regexp_match(v.val, '([A-Za-z]+://[^[:space:]]+)'))[1] AS uri,
                   NULLIF(split_part(regexp_replace(v.val, '\\r', '', 'g'), E'\\n', 2), '') AS auth_type
            FROM ad_enrollment_service e
            JOIN directory_object o
              ON o.object_guid = e.object_guid AND o.client_id = e.client_id AND NOT o.is_deleted
            CROSS JOIN LATERAL unnest(e.enrollment_servers) WITH ORDINALITY AS v(val, ord)
            WHERE e.client_id = %(client_id)s
              AND e.valid_to IS NULL
              AND e.enrollment_servers IS NOT NULL
        )
        SELECT
            'fail' AS status,
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'Enterprise CA ' || COALESCE(u.ca_name, u.object_guid::text)
                || ' advertises certificate enrollment over HTTP (ESC8 relay indicator): '
                || string_agg(DISTINCT u.uri, ', ' ORDER BY u.uri) AS summary,
            jsonb_build_object(
                'ca_name', u.ca_name,
                'dns_hostname', u.dns_hostname,
                'http_endpoints', jsonb_agg(jsonb_build_object(
                    'uri', u.uri,
                    'authentication_type', u.auth_type,
                    'raw_value', u.val
                ) ORDER BY u.ord)
            ) AS detail
        FROM uris u
        WHERE lower(u.uri) LIKE 'http://%%'
        GROUP BY u.object_guid, u.ca_name, u.dns_hostname
    """,
}
