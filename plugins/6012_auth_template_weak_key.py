"""
Plugin 6012: Weak Key Size or Exportable Key on Authentication Certificate Templates

Detects published certificate templates (is_enabled: available on at
least one Enterprise CA) that issue certificates usable for domain
authentication (client_authentication_capable: Client Authentication,
Smart Card Logon, PKINIT Client, Any Purpose or no EKU) and either:
  - allow keys shorter than 2048 bits: msPKI-Minimal-Key-Size
    (minimal_key_size, schema v38) below 2048 and not an elliptic-curve
    size (256, 384, 521) -> medium. RSA keys below 2048 bits are
    disallowed for authentication by NIST SP 800-131A / 800-57 and can be
    factored by a well-resourced attacker; a factored logon certificate
    is a persistent credential for the account. Templates with
    minimal_key_size 0 (unset) are not flagged.
  - mark the private key exportable (msPKI-Private-Key-Flag 0x10,
    CT_FLAG_EXPORTABLE_KEY) on a template carrying the Smart Card Logon
    EKU (1.3.6.1.4.1.311.20.2.2) -> low. Smart card logon keys are meant
    to live non-exportably on a card/TPM; an exportable key can be copied
    off the machine (e.g. with mimikatz crypto::certificates /export)
    and reused from anywhere, defeating the hardware-bound assurance.
One row per template, with the worst severity. Templates whose
minimal_key_size / private_key_flag are NULL (not collected, before
schema v38) skip that test. Unpublished templates are not reported:
nobody can enroll in them.

Why: NIST SP 800-131A Rev. 2 and SP 800-57 Part 1 (key length
transitions), DISA PKI requirements, Microsoft AD CS template guidance.
"""

PLUGIN = {
    "plugin_id": 6012,
    "category": "Certificate Services",
    "name": "Weak Key Size or Exportable Key on Authentication Certificate Templates",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "ADCS-6012",
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
        "MITRE-ATTCK-T1649",
    ],
    "references": [
        {"title": "NIST SP 800-131A Rev. 2: Transitioning the Use of Cryptographic Algorithms and Key Lengths",
         "url": "https://csrc.nist.gov/pubs/sp/800/131/a/r2/final"},
        {"title": "MITRE ATT&CK T1649: Steal or Forge Authentication Certificates",
         "url": "https://attack.mitre.org/techniques/T1649/"},
    ],
    "description": (
        "Flags published certificate templates usable for domain "
        "authentication whose minimum key size is below 2048 bits (and not an "
        "elliptic-curve size) -- medium -- or that combine the Smart Card "
        "Logon EKU with an exportable private key -- low. One finding per "
        "template with the worst severity."
    ),
    "remediation": (
        "In the Certificate Templates console (certtmpl.msc), open the "
        "template > Cryptography and set 'Minimum key size' to 2048 or more "
        "(or use an ECC provider with P-256/P-384), and on Request Handling "
        "clear 'Allow private key to be exported' for smart card logon "
        "templates. Then re-enroll affected users/computers (Reenroll All "
        "Certificate Holders) and revoke certificates issued with weak or "
        "exported keys."
    ),
    "base_severity": "medium",
    "query": """
        WITH t AS (
            SELECT ct.object_guid,
                   COALESCE(ct.display_name, ct.template_name, ct.object_guid::text) AS name,
                   ct.template_name, ct.minimal_key_size, ct.private_key_flag,
                   ct.extended_key_usage,
                   (ct.minimal_key_size IS NOT NULL AND ct.minimal_key_size > 0
                    AND ct.minimal_key_size < 2048
                    AND ct.minimal_key_size NOT IN (256, 384, 521)) AS weak_key,
                   (ct.private_key_flag IS NOT NULL AND (ct.private_key_flag & 16) <> 0
                    AND '1.3.6.1.4.1.311.20.2.2' = ANY (COALESCE(ct.extended_key_usage, ARRAY[]::text[])))
                       AS exportable_sc
            FROM ad_cert_template ct
            JOIN directory_object o
              ON o.object_guid = ct.object_guid AND o.client_id = ct.client_id AND NOT o.is_deleted
            WHERE ct.client_id = %(client_id)s
              AND ct.valid_to IS NULL
              AND ct.is_enabled
              AND ct.client_authentication_capable
        )
        SELECT
            CASE WHEN t.weak_key THEN 'fail' ELSE 'warn' END AS status,
            t.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN t.weak_key THEN 'medium' ELSE 'low' END AS fd_severity,
            'Authentication certificate template ' || t.name || ': '
                || concat_ws('; ',
                       CASE WHEN t.weak_key
                            THEN 'minimum key size ' || t.minimal_key_size || ' bits (below 2048)' END,
                       CASE WHEN t.exportable_sc
                            THEN 'Smart Card Logon EKU with an exportable private key' END)
                AS summary,
            jsonb_build_object(
                'template_name', t.template_name,
                'minimal_key_size', t.minimal_key_size,
                'private_key_flag', t.private_key_flag,
                'extended_key_usage', to_jsonb(t.extended_key_usage),
                'weak_key_size', t.weak_key,
                'exportable_smart_card_logon_key', t.exportable_sc
            ) AS detail
        FROM t
        WHERE t.weak_key OR t.exportable_sc
    """,
}
