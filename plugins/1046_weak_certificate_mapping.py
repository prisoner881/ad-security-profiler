"""
Plugin 1046: Weak Explicit Certificate Mapping (ESC14)

altSecurityIdentities lets an administrator map a certificate to an
account explicitly. KB5014754 (the fix for CVE-2022-26923, CVE-2022-26931
and CVE-2022-34691) classifies the X509 mapping formats:

  WEAK   X509IssuerSubject   "X509:<I>IssuerDN<S>SubjectDN"
         X509SubjectOnly     "X509:<S>SubjectDN"
         X509RFC822          "X509:<RFC822>user@example.com"
  STRONG X509IssuerSerialNumber "X509:<I>IssuerDN<SR>SerialNumber"
         X509SKI             "X509:<SKI>SubjectKeyIdentifier"
         X509SHA1PublicKey   "X509:<SHA1-PUKEY>hash"

A weak mapping is satisfied by any certificate whose subject (and, for
IssuerSubject, issuer) or e-mail name matches -- values a requester can
often choose or that many certificates share. Anyone who can obtain such
a certificate (enrol in a template that lets them supply or influence the
subject / RFC822 name, or who controls a mailbox-name-based identity)
authenticates as the mapped account via PKINIT or Schannel: this is the
ESC14 abuse described by SpecterOps (Jonas Knudsen, 2024). Since
KB5014754 Full Enforcement (September 2025) domain controllers reject
weak mappings, so on a patched domain these mappings either already fail
(a broken logon path) or reveal that enforcement was rolled back to
Compatibility mode -- in which case they are live impersonation paths.

Flags ad_user and ad_computer rows with at least one weak X509 mapping
(prefix matching is case-insensitive; IssuerSubject = "<I>" ... "<S>"
without "<SR>"). Strong formats and "Kerberos:" (cross-realm principal)
mappings are ignored. One row per account; the summary lists the weak
mapping TYPES (sorted), and the full weak values go in detail.
NULL/empty alt_security_identities = none (column added in schema v38;
rows collected earlier are NULL and simply not reported).

Severity: critical if the account is a current Tier 0 principal
(v_privileged_principal), high otherwise, low if the account is disabled
(disabled takes precedence: the mapping cannot be used to log on while
the account stays disabled).
"""

PLUGIN = {
    "plugin_id": 1046,
    "category": "User Accounts",
    "name": "Weak Explicit Certificate Mapping (ESC14)",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "PKI-1046",
    "framework_tags": [
        "NIST-800-53-SC-17", "NIST-800-53-IA-5(2)", "NIST-CSF-2.0-PR.DS-02",
        "PCI-DSS-4.0-4.2.1.1", "ISO-27001-2022-A.8.24", "ISO-27001-2022-A.8.5",
        "SOC2-CC6.1", "CVE-2022-26923", "CVE-2022-26931", "CVE-2022-34691",
        "MITRE-ATTCK-T1649",
    ],
    "references": [
        {"title": "KB5014754: Certificate-based authentication changes on Windows domain controllers",
         "url": "https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16"},
        {"title": "Microsoft: Alt-Security-Identities attribute",
         "url": "https://learn.microsoft.com/en-us/windows/win32/adschema/a-altsecurityidentities"},
        {"title": "NVD: CVE-2022-26923",
         "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-26923"},
        {"title": "NVD: CVE-2022-34691",
         "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-34691"},
        {"title": "MITRE ATT&CK T1649: Steal or Forge Authentication Certificates",
         "url": "https://attack.mitre.org/techniques/T1649/"},
    ],
    "description": (
        "The account's altSecurityIdentities contains an explicit certificate "
        "mapping in a format KB5014754 classifies as weak (X509IssuerSubject, "
        "X509SubjectOnly or X509RFC822). Any certificate with a matching "
        "subject/issuer or e-mail name authenticates as this account (ESC14). "
        "Under KB5014754 Full Enforcement such mappings fail; if they still "
        "work, enforcement has been relaxed and they are impersonation paths."
    ),
    "remediation": (
        "Replace each weak mapping with a strong one: "
        "X509:<I>IssuerDN<SR>SerialNumber (serial in reversed byte order), "
        "X509:<SKI>SubjectKeyIdentifier or X509:<SHA1-PUKEY>PublicKeyHash, "
        "or remove the mapping if certificate logon for this account is no "
        "longer needed. Example: Set-ADUser <sam> -Remove @{altSecurityIdentities="
        "'X509:<I>...<S>...'} -Add @{altSecurityIdentities='X509:<I>...<SR>...'}. "
        "Enumerate all mappings with Get-ADObject -LDAPFilter "
        "'(altSecurityIdentities=*)' -Properties altSecurityIdentities. "
        "Confirm that domain controllers run in KB5014754 Full Enforcement "
        "(StrongCertificateBindingEnforcement not set to 0 or 1) and review who "
        "can write altSecurityIdentities on privileged accounts."
    ),
    "base_severity": "high",
    "query": """
        WITH tier0 AS (
            SELECT object_guid,
                   array_agg(DISTINCT privilege_source ORDER BY privilege_source) AS privilege_sources
            FROM v_privileged_principal
            WHERE client_id = %(client_id)s
            GROUP BY object_guid
        ),
        accts AS (
            SELECT u.object_guid, 'User'::text AS kind,
                   COALESCE(u.user_principal_name, u.sam_account_name, u.object_guid::text) AS name,
                   u.sam_account_name, u.is_enabled, u.alt_security_identities AS asi
            FROM ad_user u
            WHERE u.client_id = %(client_id)s AND u.valid_to IS NULL
              AND cardinality(u.alt_security_identities) > 0
            UNION ALL
            SELECT c.object_guid, 'Computer'::text,
                   COALESCE(c.sam_account_name, c.dns_hostname, c.object_guid::text),
                   c.sam_account_name, c.is_enabled, c.alt_security_identities
            FROM ad_computer c
            WHERE c.client_id = %(client_id)s AND c.valid_to IS NULL
              AND cardinality(c.alt_security_identities) > 0
        ),
        classified AS (
            SELECT a.object_guid, a.kind, a.name, a.sam_account_name, a.is_enabled,
                   btrim(m) AS mapping,
                   CASE
                       WHEN lower(btrim(m)) LIKE 'x509:<rfc822>%%' THEN 'X509RFC822'
                       WHEN lower(btrim(m)) LIKE 'x509:<s>%%' THEN 'X509SubjectOnly'
                       WHEN lower(btrim(m)) LIKE 'x509:<i>%%'
                            AND strpos(lower(m), '<s>') > 0
                            AND strpos(lower(m), '<sr>') = 0 THEN 'X509IssuerSubject'
                   END AS weak_type
            FROM accts a
            CROSS JOIN LATERAL unnest(a.asi) AS m
            JOIN directory_object o
              ON o.object_guid = a.object_guid AND o.client_id = %(client_id)s
             AND NOT o.is_deleted
            WHERE m IS NOT NULL
        ),
        agg AS (
            SELECT object_guid, kind, name, sam_account_name, is_enabled,
                   array_agg(DISTINCT weak_type ORDER BY weak_type) AS weak_types,
                   jsonb_agg(jsonb_build_object('type', weak_type, 'value', mapping)
                             ORDER BY weak_type, mapping) AS weak_mappings,
                   count(*) AS weak_count
            FROM classified
            WHERE weak_type IS NOT NULL
            GROUP BY object_guid, kind, name, sam_account_name, is_enabled
        )
        SELECT
            'fail' AS status,
            a.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN a.is_enabled IS FALSE THEN 'low'
                 WHEN t.object_guid IS NOT NULL THEN 'critical'
                 ELSE 'high' END AS fd_severity,
            (CASE WHEN a.is_enabled IS FALSE THEN 'Disabled '
                  WHEN t.object_guid IS NOT NULL THEN 'Tier 0 '
                  ELSE '' END)
                || a.kind || ' account ' || a.name
                || ' has weak explicit certificate mapping(s) (ESC14): '
                || array_to_string(a.weak_types, ', ') AS summary,
            jsonb_build_object(
                'object_type', lower(a.kind),
                'sam_account_name', a.sam_account_name,
                'is_enabled', a.is_enabled,
                'weak_mapping_count', a.weak_count,
                'weak_mappings', a.weak_mappings,
                'tier0', t.object_guid IS NOT NULL,
                'privilege_sources', t.privilege_sources
            ) AS detail
        FROM agg a
        LEFT JOIN tier0 t ON t.object_guid = a.object_guid
    """,
}
