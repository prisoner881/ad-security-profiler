"""
Plugin 6014: Network Device Enrollment Service (NDES) Appears to Be Deployed

Reports Enterprise CAs that publish the templates NDES setup adds for its
registration authority: "CEP Encryption" (CEPEncryption) and "Exchange
Enrollment Agent (Offline request)" (EnrollmentAgentOffline). They are
hard-coded in NDES setup, which publishes them on the CA it is configured
for, so finding them published is a strong sign that an NDES server issues
certificates through that CA. One finding per CA.

Why it matters: NDES (the Microsoft SCEP server) is an IIS application that
issues certificates to devices on presentation of a one-time challenge
password, is often reachable from untrusted networks, and holds an
enrollment-agent certificate that can request certificates on behalf of
others. The October 2026 security update fixed an unauthenticated remote
code execution in NDES (CVE-2026-69802, weak authentication, CVSS 8.1) and
three more NDES flaws (CVE-2026-96861 and CVE-2026-96866, denial of service;
CVE-2026-85323, spoofing). NDES is commonly installed on the CA host; when
that host is a domain controller, compromising NDES compromises the domain.

The NDES server itself is not visible in the directory: the finding names
the CA whose templates it uses, and the CA host. Whether the server is
patched cannot be seen either -- the finding stands as long as NDES is
deployed, as a prompt to confirm it is patched, needed and not exposed.

Severity (status 'warn'):
- high: both registration-authority templates are published and the CA
  host is a domain controller (NDES, if installed with the CA, runs on a DC);
- medium: both published, CA host not a domain controller (or not matched
  to a computer object);
- low: only one of the two published -- a partial or removed NDES
  installation, or templates published by hand; review and unpublish if
  unused.
"IPSec (Offline request)" (IPSECIntermediateOffline), NDES's default
issuing template, is listed in the evidence when published but is not
evidence on its own (it is a built-in template published for other uses).

Data: ad_enrollment_service, cert_template_enabled_edge, ad_cert_template,
ad_computer (CA host matched on dNSHostName). Identity = the CA's
enrollment service object.
"""

PLUGIN = {
    "plugin_id": 6014,
    "category": "Certificate Services",
    "name": "Network Device Enrollment Service (NDES) Appears to Be Deployed",
    "version": "1.0",
    "revision_date": "2026-10-19",
    "control_id": "ADCS-6014",
    "framework_tags": [
        "NIST-800-53-SI-2",
        "NIST-800-53-RA-5",
        "NIST-800-53-CM-7",
        "NIST-800-53-SC-17",
        "NIST-CSF-2.0-ID.RA-01",
        "NIST-CSF-2.0-PR.PS-01",
        "PCI-DSS-4.0-6.3.3",
        "PCI-DSS-4.0-2.2.4",
        "CIS-CSC-8-7.3",
        "CIS-CSC-8-4.8",
        "ISO-27001-2022-A.8.8",
        "ISO-27001-2022-A.8.9",
        "SOC2-CC7.1",
        "MITRE-ATTCK-T1190",
        "MITRE-ATTCK-T1649",
        "CVE-2026-69802",
        "CVE-2026-96861",
        "CVE-2026-96866",
        "CVE-2026-85323",
    ],
    "references": [
        {"title": "Microsoft Security Update Guide: CVE-2026-69802 (NDES Remote Code Execution)",
         "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69802"},
        {"title": "OpenCVE: CVE-2026-69802",
         "url": "https://app.opencve.io/cve/CVE-2026-69802"},
        {"title": "Microsoft: Network Device Enrollment Service (NDES) overview",
         "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/network-device-enrollment-service-overview"},
        {"title": "MITRE ATT&CK T1649: Steal or Forge Authentication Certificates",
         "url": "https://attack.mitre.org/techniques/T1649/"},
    ],
    "description": (
        "An Enterprise CA publishes the registration-authority templates NDES "
        "setup adds (CEP Encryption and Exchange Enrollment Agent (Offline "
        "request)), so an NDES (SCEP) server most likely issues certificates "
        "through it. NDES received an unauthenticated remote code execution "
        "fix in October 2026 (CVE-2026-69802) and three other fixes. High when "
        "the CA host is a domain controller, where NDES is often installed "
        "alongside the CA; medium otherwise; low when only one of the two "
        "templates is published. Patch level is not visible to this check."
    ),
    "remediation": (
        "Find the NDES server (IIS application /certsrv/mscep on a server "
        "with the 'Network Device Enrollment Service' role; its RA certificates "
        "are issued from these templates). Confirm the October 2026 security "
        "update is installed there. If NDES is not needed, remove the role and "
        "unpublish CEPEncryption and EnrollmentAgentOffline from the CA "
        "(certutil -SetCATemplates -<template>). If it is needed: never run it "
        "on a domain controller, keep it off the internet or behind an "
        "authenticating reverse proxy, run it under a dedicated low-privilege "
        "service account, and restrict the templates it may issue."
    ),
    "base_severity": "high",
    "query": """
        WITH
        published AS (
            SELECT es.object_guid AS ca_guid, es.ca_name, es.dns_hostname,
                   array_agg(DISTINCT ct.template_name ORDER BY ct.template_name) AS templates,
                   bool_or(ct.template_name = 'CEPEncryption') AS cep_encryption,
                   bool_or(ct.template_name = 'EnrollmentAgentOffline') AS enrollment_agent_offline
              FROM ad_enrollment_service es
              JOIN cert_template_enabled_edge e
                ON e.ca_guid = es.object_guid AND e.client_id = es.client_id AND e.valid_to IS NULL
              JOIN ad_cert_template ct
                ON ct.object_guid = e.template_guid AND ct.client_id = e.client_id AND ct.valid_to IS NULL
             WHERE es.client_id = %(client_id)s
               AND es.valid_to IS NULL
               AND ct.template_name IN ('CEPEncryption', 'EnrollmentAgentOffline', 'IPSECIntermediateOffline')
             GROUP BY es.object_guid, es.ca_name, es.dns_hostname
        ),
        graded AS (
            SELECT p.*,
                   h.sam_account_name AS host_account,
                   COALESCE(h.is_domain_controller, false) AS host_is_dc,
                   (p.cep_encryption AND p.enrollment_agent_offline) AS both_ra
              FROM published p
              LEFT JOIN LATERAL (
                  SELECT c.sam_account_name, c.is_domain_controller
                    FROM ad_computer c
                   WHERE c.client_id = %(client_id)s AND c.valid_to IS NULL
                     AND lower(c.dns_hostname) = lower(p.dns_hostname)
                   ORDER BY c.is_domain_controller DESC, c.sam_account_name
                   LIMIT 1) h ON true
             WHERE p.cep_encryption OR p.enrollment_agent_offline
        )
        SELECT
            'warn' AS status,
            g.ca_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN g.both_ra AND g.host_is_dc THEN 'high'
                 WHEN g.both_ra THEN 'medium'
                 ELSE 'low' END AS fd_severity,
            'CA "' || COALESCE(g.ca_name, g.dns_hostname, g.ca_guid::text) || '"'
                || CASE WHEN g.host_is_dc THEN ' (on domain controller ' || g.host_account || ')'
                        WHEN g.host_account IS NOT NULL THEN ' (on ' || g.host_account || ')'
                        ELSE '' END
                || CASE WHEN g.both_ra
                        THEN ' publishes the NDES registration-authority templates (CEPEncryption, '
                             || 'EnrollmentAgentOffline): NDES appears to be deployed'
                             || CASE WHEN g.host_is_dc
                                     THEN ', and if it runs on the CA host it runs on a domain controller'
                                     ELSE '' END
                        ELSE ' publishes only one NDES registration-authority template ('
                             || CASE WHEN g.cep_encryption THEN 'CEPEncryption' ELSE 'EnrollmentAgentOffline' END
                             || '): a partial or removed NDES installation' END
                || '. NDES received an unauthenticated remote code execution fix in October 2026 '
                || '(CVE-2026-69802); confirm the NDES server is patched' AS summary,
            jsonb_build_object(
                'ca_guid', g.ca_guid,
                'ca_name', g.ca_name,
                'ca_dns_hostname', g.dns_hostname,
                'ca_host_account', g.host_account,
                'ca_host_is_domain_controller', g.host_is_dc,
                'published_ndes_templates', to_jsonb(g.templates),
                'cep_encryption_published', g.cep_encryption,
                'enrollment_agent_offline_published', g.enrollment_agent_offline,
                'cves', jsonb_build_array('CVE-2026-69802', 'CVE-2026-96861', 'CVE-2026-96866', 'CVE-2026-85323')
            ) AS detail
        FROM graded g
    """,
}
