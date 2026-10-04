"""
Plugin 6013: Weak or Expiring CA Certificates in NTAuth, Root/AIA Stores and Enterprise CAs

Checks every CA certificate the forest publishes for domain trust:
  - the NTAuthCertificates store (ad_ntauth_store.certificates) -- CAs
    trusted to issue smart card / PKINIT / certificate logon credentials;
  - CN=Certification Authorities (trusted roots) and CN=AIA
    (intermediates) under CN=Public Key Services
    (ad_pki_certificate_store.certificates, store 'root' / 'aia');
  - each Enterprise CA's own certificate
    (ad_enrollment_service.ca_certificates).
Each is a JSON array of parsed certificates {subject_cn, issuer_cn,
not_valid_before, not_valid_after, serial_number, thumbprint_sha1,
key_algorithm, key_size, signature_hash_algorithm, parse_error}.

Per certificate:
  - RSA key shorter than 2048 bits                         -> medium
  - signature hash MD5 or SHA-1                            -> medium
    (skipped for a self-signed certificate -- subject CN equal to
    issuer CN -- because a root's signature over itself is not relied on
    for trust; the hash of certificates it ISSUES is what matters)
  - expired (not_valid_after before the collection run)    -> low
  - expires within 90 days of the collection run           -> low
Weak keys and hashes violate NIST SP 800-131A / 800-57 and Microsoft's
SHA-1 deprecation; an attacker able to factor a weak CA key or forge a
SHA-1 signature can mint logon certificates trusted by every DC (the
NTAuth store makes them valid for any account). Expired or expiring CA
certificates cause authentication outages and are often kept trusted
long after the CA is gone. One row per store object (the NTAuth object,
the root/AIA certificationAuthority object, or the Enterprise CA) listing
every affected certificate (thumbprint + issues), worst severity.

Dates are compared with the start time of the collection run being
evaluated (sync_run.started_at for %(run_id)s), so re-evaluating a run
gives the same result. Missing fields are treated as unknown and their
test skipped: NTAuth rows collected before schema v38 have no
key_algorithm / key_size / signature_hash_algorithm / not_valid_before.
Entries with parse_error are skipped (plugin 6005 covers unknown/garbled
NTAuth entries).
"""

PLUGIN = {
    "plugin_id": 6013,
    "category": "Certificate Services",
    "name": "Weak or Expiring CA Certificates in NTAuth, Root/AIA Stores and Enterprise CAs",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "PKI-6013",
    "framework_tags": [
        "NIST-800-53-SC-12",
        "NIST-800-53-SC-13",
        "NIST-800-53-SC-17",
        "NIST-800-53-IA-5(2)",
        "NIST-CSF-2.0-PR.DS-02",
        "PCI-DSS-4.0-4.2.1.1",
        "PCI-DSS-4.0-12.3.3",
        "CIS-CSC-8-3.10",
        "ISO-27001-2022-A.8.24",
        "SOC2-CC6.1",
        "HIPAA-164.312(e)(1)",
    ],
    "references": [
        {"title": "NIST SP 800-131A Rev. 2: Transitioning the Use of Cryptographic Algorithms and Key Lengths",
         "url": "https://csrc.nist.gov/pubs/sp/800/131/a/r2/final"},
        {"title": "Microsoft: Import a third-party CA certificate into the Enterprise NTAuth store",
         "url": "https://learn.microsoft.com/en-us/troubleshoot/windows-server/certificates-and-public-key-infrastructure-pki/import-third-party-ca-to-enterprise-ntauth-store"},
    ],
    "description": (
        "Flags CA certificates published in the NTAuth store, the "
        "Certification Authorities (root) and AIA containers, or as an "
        "Enterprise CA's own certificate that use an RSA key under 2048 bits "
        "or an MD5/SHA-1 signature (medium; self-signed roots' own signature "
        "hash ignored), or that have expired or expire within 90 days of the "
        "collection (low). One finding per store object."
    ),
    "remediation": (
        "Renew weak CAs with a new key pair (RSA 3072+/ECC P-384) and SHA-256+ "
        "signatures (certutil -renewCert ReuseKeys is NOT sufficient for a "
        "weak key: renew with a new key), migrate templates and subordinate "
        "CAs to the new chain, then remove the old certificate from NTAuth "
        "(`certutil -viewdelstore \"ldap:///CN=NTAuthCertificates,CN=Public Key "
        "Services,CN=Services,CN=Configuration,<forest DN>?cACertificate\"`) and "
        "from the root/AIA containers (`certutil -dspublish -f` / ADSI Edit). "
        "Renew CAs well before expiry; remove expired CA certificates that no "
        "longer anchor any valid chain."
    ),
    "base_severity": "medium",
    "query": """
        WITH ref AS (
            SELECT COALESCE(
                       (SELECT sr.started_at FROM sync_run sr
                        WHERE sr.client_id = %(client_id)s AND sr.run_id = %(run_id)s),
                       now()) AS t
        ),
        store AS (
            SELECT n.object_guid, 'NTAuth store'::text AS store_label, n.certificates AS certs
            FROM ad_ntauth_store n
            WHERE n.client_id = %(client_id)s AND n.valid_to IS NULL
            UNION ALL
            SELECT p.object_guid,
                   CASE p.store WHEN 'root' THEN 'Root CA store' WHEN 'aia' THEN 'AIA store'
                                ELSE p.store END
                       || ' entry ' || COALESCE(p.ca_name, p.object_guid::text),
                   p.certificates
            FROM ad_pki_certificate_store p
            WHERE p.client_id = %(client_id)s AND p.valid_to IS NULL
            UNION ALL
            SELECT e.object_guid, 'Enterprise CA ' || COALESCE(e.ca_name, e.object_guid::text),
                   e.ca_certificates
            FROM ad_enrollment_service e
            WHERE e.client_id = %(client_id)s AND e.valid_to IS NULL
              AND e.ca_certificates IS NOT NULL
        ),
        cert AS (
            SELECT s.object_guid, s.store_label, c.ord, c.j,
                   COALESCE(c.j ->> 'thumbprint_sha1', c.j ->> 'serial_number', 'certificate #' || c.ord)
                       AS cert_id,
                   c.j ->> 'subject_cn' AS subject_cn,
                   c.j ->> 'issuer_cn' AS issuer_cn,
                   lower(c.j ->> 'key_algorithm') AS key_alg,
                   CASE WHEN (c.j ->> 'key_size') ~ '^[0-9]+$' THEN (c.j ->> 'key_size')::int END AS key_size,
                   lower(c.j ->> 'signature_hash_algorithm') AS sig_hash,
                   CASE WHEN (c.j ->> 'not_valid_after') ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}'
                        THEN (c.j ->> 'not_valid_after')::timestamptz END AS not_after
            FROM store s
            JOIN directory_object o
              ON o.object_guid = s.object_guid AND o.client_id = %(client_id)s AND NOT o.is_deleted
            CROSS JOIN LATERAL jsonb_array_elements(
                CASE WHEN jsonb_typeof(s.certs) = 'array' THEN s.certs ELSE '[]'::jsonb END
            ) WITH ORDINALITY AS c(j, ord)
            WHERE c.j ->> 'parse_error' IS NULL
        ),
        issue AS (
            SELECT c.*, x.issue, x.sev
            FROM cert c
            CROSS JOIN ref
            CROSS JOIN LATERAL (VALUES
                (CASE WHEN c.key_alg = 'rsa' AND c.key_size < 2048
                      THEN 'RSA ' || c.key_size || '-bit key' END, 2),
                (CASE WHEN c.sig_hash IN ('md5', 'sha1')
                       AND c.subject_cn IS DISTINCT FROM c.issuer_cn
                      THEN upper(c.sig_hash) || ' signature' END, 2),
                (CASE WHEN c.not_after < ref.t THEN 'expired' END, 1),
                (CASE WHEN c.not_after >= ref.t AND c.not_after < ref.t + interval '90 days'
                      THEN 'expires within 90 days' END, 1)
            ) AS x(issue, sev)
            WHERE x.issue IS NOT NULL
        ),
        per_cert AS (
            SELECT i.object_guid, i.store_label, i.cert_id, i.subject_cn, i.issuer_cn, i.not_after,
                   i.key_alg, i.key_size, i.sig_hash,
                   max(i.sev) AS sev,
                   string_agg(i.issue, ', ' ORDER BY i.sev DESC, i.issue) AS issues
            FROM issue i
            GROUP BY i.object_guid, i.store_label, i.cert_id, i.subject_cn, i.issuer_cn, i.not_after,
                     i.key_alg, i.key_size, i.sig_hash
        )
        SELECT
            CASE WHEN max(pc.sev) = 2 THEN 'fail' ELSE 'warn' END AS status,
            pc.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN max(pc.sev) = 2 THEN 'medium' ELSE 'low' END AS fd_severity,
            pc.store_label || ': ' || count(*) || ' CA certificate(s) weak or expiring: '
                || string_agg(COALESCE(pc.subject_cn, '?') || ' [' || pc.cert_id || '] (' || pc.issues || ')',
                              '; ' ORDER BY pc.cert_id) AS summary,
            jsonb_build_object(
                'store', pc.store_label,
                'certificates', jsonb_agg(jsonb_build_object(
                    'thumbprint_sha1', pc.cert_id,
                    'subject_cn', pc.subject_cn,
                    'issuer_cn', pc.issuer_cn,
                    'not_valid_after', pc.not_after,
                    'key_algorithm', pc.key_alg,
                    'key_size', pc.key_size,
                    'signature_hash_algorithm', pc.sig_hash,
                    'issues', pc.issues
                ) ORDER BY pc.cert_id)
            ) AS detail
        FROM per_cert pc
        GROUP BY pc.object_guid, pc.store_label
    """,
}
