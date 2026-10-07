"""
Plugin 11028: New Partner Contract or Cross-Tenant Partner Configuration

Change Detection for Microsoft Entra ID. Reports, in the latest Entra
collection:
  * a new partner contract (/contracts: a CSP / reseller relationship that
    can carry delegated administration into the tenant);
  * a new cross-tenant access partner configuration
    (policies/crossTenantAccessPolicy/partners);
  * an existing partner configuration that now allows inbound user
    synchronization (identitySynchronization.userSyncInbound.isSyncAllowed
    changed to true).

Why: every new partner relationship is third-party access added to the
tenant: delegated admin privileges through a reseller (the NOBELIUM supply
chain abuse of DAP), or B2B / cross-tenant trust settings. A partner tenant
allowed to sync users inbound can create accounts in this tenant (Vectra /
Semperis cross-tenant synchronization research). MITRE ATT&CK T1199 Trusted
Relationship; T1484.002 Trust Modification.

Data: entra_change_history entity_type 'partner' (key
'contract:' || contract_object_id with the entra_partner_contract row as
content, or 'cross_tenant:' || partner tenant id with the partner
configuration content, including "identitySynchronization") and
entra_change_baseline. New = no earlier version of the key. Removed
partners and other modifications are not reported. Suppressed on the first
collection; findings stay open until the next Entra collection.

Severity: medium; high when the partner may sync users inbound. One row
per partner key (object_guid = md5('11028:' || client_id || ':' || key)).
"""

PLUGIN = {
    "plugin_id": 11028,
    "category": "Change Detection",
    "name": "New Partner Contract or Cross-Tenant Partner Configuration",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "CHANGE-11028",
    "requires_sources": ["partner_contracts", "cross_tenant_policy"],
    "framework_tags": [
        "NIST-800-53-CM-3", "NIST-800-53-SI-4", "NIST-800-53-AU-6",
        "NIST-800-53-AC-20", "NIST-800-53-AC-4",
        "NIST-CSF-2.0-DE.CM-03", "NIST-CSF-2.0-DE.CM-09",
        "PCI-DSS-4.0-10.2.1.2", "PCI-DSS-4.0-11.5.2", "PCI-DSS-4.0-8.2.7",
        "CIS-CSC-8-8.11",
        "ISO-27001-2022-A.8.16", "ISO-27001-2022-A.5.19",
        "SOC2-CC7.2", "SOC2-CC6.6",
        "HIPAA-164.308(a)(1)(ii)(D)",
        "MITRE-ATTCK-T1199", "MITRE-ATTCK-T1484.002",
    ],
    "references": [
        {"title": "Microsoft: Cross-tenant access settings overview",
         "url": "https://learn.microsoft.com/en-us/entra/external-id/cross-tenant-access-overview"},
        {"title": "Microsoft: Cross-tenant synchronization overview",
         "url": "https://learn.microsoft.com/en-us/entra/identity/multi-tenant-organizations/cross-tenant-synchronization-overview"},
        {"title": "Microsoft Graph: contract resource type",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/contract"},
        {"title": "MITRE ATT&CK T1199: Trusted Relationship",
         "url": "https://attack.mitre.org/techniques/T1199/"},
    ],
    "description": (
        "Reports partner relationships added since the previous Entra collection: new "
        "partner (CSP / reseller) contracts and new cross-tenant access partner "
        "configurations (medium), and partners that are now allowed to synchronize users "
        "into this tenant (high). Each is third-party access to the tenant. Suppressed on "
        "the first Entra collection."
    ),
    "remediation": (
        "Confirm the relationship with the business owner and the partner. Remove unapproved "
        "reseller relationships and delegated admin (GDAP/DAP) access in the Microsoft 365 "
        "admin center (Settings > Partner relationships). Remove or restrict unapproved "
        "cross-tenant partner configurations (Entra admin center > External Identities > "
        "Cross-tenant access settings) and disable inbound cross-tenant synchronization "
        "unless it is an approved multi-tenant organization."
    ),
    "base_severity": "medium",
    "query": """
        WITH b AS (
            SELECT bl.client_id, bl.last_run_at
            FROM entra_change_baseline bl
            WHERE bl.client_id = %(client_id)s AND bl.entity_type = 'partner'
              AND bl.first_run_at < bl.last_run_at
        ),
        cur AS (
            SELECT h.entity_key, h.entity_label, h.content AS new_c,
                   (SELECT o.content FROM entra_change_history o
                    WHERE o.client_id = h.client_id AND o.entity_type = 'partner'
                      AND o.entity_key = h.entity_key AND o.valid_to = b.last_run_at
                    LIMIT 1) AS old_c,
                   EXISTS (SELECT 1 FROM entra_change_history e
                           WHERE e.client_id = h.client_id AND e.entity_type = 'partner'
                             AND e.entity_key = h.entity_key AND e.valid_from < b.last_run_at) AS had_earlier
            FROM entra_change_history h
            JOIN b ON b.client_id = h.client_id
            WHERE h.entity_type = 'partner'
              AND h.valid_from = b.last_run_at
              AND h.valid_to IS NULL
        ),
        cls AS (
            SELECT c.*,
                   (c.new_c #>> '{identitySynchronization,userSyncInbound,isSyncAllowed}') = 'true' AS sync_in,
                   (c.old_c #>> '{identitySynchronization,userSyncInbound,isSyncAllowed}') = 'true' AS old_sync_in,
                   c.entity_key LIKE 'contract:%%' AS is_contract
            FROM cur c
        ),
        f AS (
            SELECT s.*,
                   CASE WHEN NOT s.had_earlier THEN 'new'
                        WHEN s.sync_in AND NOT COALESCE(s.old_sync_in, FALSE) THEN 'sync_enabled'
                   END AS kind
            FROM cls s
        )
        SELECT
            CASE WHEN f.sync_in AND NOT f.is_contract THEN 'fail' ELSE 'warn' END AS status,
            md5('11028:' || %(client_id)s::text || ':' || f.entity_key)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN f.sync_in AND NOT f.is_contract THEN 'high' ELSE 'medium' END AS fd_severity,
            CASE
                WHEN f.is_contract THEN
                    'New partner contract "'
                    || COALESCE(f.new_c->>'display_name', f.new_c->>'default_domain_name',
                                f.entity_label, substr(f.entity_key, 10)) || '"'
                    || CASE WHEN f.new_c->>'contract_type' IS NOT NULL
                            THEN ' (' || (f.new_c->>'contract_type') || ')' ELSE '' END
                WHEN f.kind = 'new' THEN
                    'New cross-tenant access partner configuration for tenant "'
                    || COALESCE(f.entity_label, substr(f.entity_key, 14)) || '"'
                    || CASE WHEN f.sync_in THEN ' that allows inbound user synchronization' ELSE '' END
                ELSE
                    'Cross-tenant partner "' || COALESCE(f.entity_label, substr(f.entity_key, 14))
                    || '" is now allowed to synchronize users into this tenant'
            END || ' since the previous Entra collection' AS summary,
            jsonb_build_object(
                'partner_key', f.entity_key,
                'change', f.kind,
                'inbound_user_sync_allowed', f.sync_in,
                'previous', f.old_c,
                'current', f.new_c,
                'detected_at', (SELECT last_run_at FROM b)
            ) AS detail
        FROM f
        WHERE f.kind IS NOT NULL
    """,
}
