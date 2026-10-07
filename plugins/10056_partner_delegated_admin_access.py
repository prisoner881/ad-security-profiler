"""
Plugin 10056: Partner Delegated Admin (DAP) Access Present

Reports evidence that a Microsoft partner (CSP / reseller / advisor) holds
standing administrative access to the tenant:
- holders of the Partner Tier1 Support (4ba39ca4-527c-499a-b93d-d9b492c50246)
  or Partner Tier2 Support (e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8) directory
  roles, active or eligible (entra_directory_role_member, Tier A) -> high,
  one finding per holder. These legacy roles exist for partner delegated
  administration; Microsoft says not to use them. Partner Tier2 Support can
  reset the password of any user including Global Administrators, i.e. it
  is a Global Administrator equivalent; Tier1 can reset non-administrator
  passwords and manage users, groups and applications;
- partner contracts recorded in the directory (entra_partner_contract,
  Graph /contracts, read only when source partner_contracts is 'ok') ->
  high, one finding per contract: "partner contract present -- check for
  DAP". A contract records a CSP / reseller relationship (contract_type
  'ResellerPartner', 'SyndicationPartner', 'BreadthPartner'); with legacy
  DAP that relationship carried Global Administrator rights for the
  partner's AdminAgents group.

Why it matters: the NOBELIUM (Midnight Blizzard) 2021 campaign compromised
resellers and used their delegated admin privileges to reach downstream
customer tenants (MITRE T1199 Trusted Relationship). Microsoft has been
moving partners from DAP to granular delegated admin privileges (GDAP,
least-privilege, time-bound) since 2022-2023; any remaining standing
partner access is a third party holding tenant-wide control.

Honest scope / data caveats:
- Customer-side visibility of partner access through Microsoft Graph is
  limited. Legacy DAP and GDAP grants are carried by the partner's own
  security groups (foreign principals) and are generally NOT returned as
  members of the customer's /directoryRoles, and GDAP relationships
  (tenantRelationships/delegatedAdminRelationships) are only readable from
  the partner tenant. This plugin therefore reports only the two signals
  above; a clean result does NOT prove there is no partner access. Check
  Microsoft 365 admin center -> Settings -> Partner relationships.
- /contracts is documented for partner tenants (where it lists the
  partner's customers); in a customer tenant it is usually empty. Either
  way a row means a partner relationship exists in the directory and is
  worth reviewing.
- Contracts are optional enrichment (no requires_sources); when
  partner_contracts is not 'ok' only the role holders are evaluated.

object_guid: the role holder's object id, or the contract object id.
"""

PLUGIN = {
    "plugin_id": 10056,
    "category": "Hybrid Identity",
    "name": "Partner Delegated Admin (DAP) Access Present",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10056",
    "framework_tags": [
        "NIST-800-53-AC-6",
        "NIST-800-53-AC-20",
        "NIST-800-53-AC-6(5)",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-8.2.7",
        "CIS-CSC-8-6.7",
        "ISO-27001-2022-A.5.19",
        "SOC2-CC6.3",
        "MITRE-ATTCK-T1199",
        "MITRE-ATTCK-T1078.004",
    ],
    "references": [
        {"title": "Microsoft: Granular delegated admin privileges (GDAP) introduction",
         "url": "https://learn.microsoft.com/en-us/partner-center/customers/gdap-introduction"},
        {"title": "Microsoft: NOBELIUM targeting delegated administrative privileges to facilitate broader attacks",
         "url": "https://www.microsoft.com/en-us/security/blog/2021/10/25/nobelium-targeting-delegated-administrative-privileges-to-facilitate-broader-attacks/"},
        {"title": "Microsoft Graph: contract resource type",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/contract"},
        {"title": "MITRE ATT&CK T1199: Trusted Relationship",
         "url": "https://attack.mitre.org/techniques/T1199/"},
    ],
    "description": (
        "A Microsoft partner appears to hold standing administrative access: "
        "a principal holds the legacy Partner Tier1/Tier2 Support role "
        "(Tier2 can reset Global Administrator passwords), or a partner "
        "contract is recorded in the directory, which with legacy DAP "
        "carries Global Administrator rights for the partner. NOBELIUM "
        "abused reseller DAP to reach customers. Customer-side Graph "
        "visibility of DAP/GDAP is limited, so a clean result does not "
        "prove there is no partner access."
    ),
    "remediation": (
        "Microsoft 365 admin center -> Settings -> Partner relationships: "
        "review each partner; remove 'Delegated admin privileges' (legacy "
        "DAP / 'Global admin' roles) and, where the partner still needs "
        "access, require a GDAP relationship with least-privilege roles and "
        "an end date. Remove members of Partner Tier1 / Tier2 Support "
        "(Remove-MgDirectoryRoleMemberByRef). Ask the partner to confirm "
        "they have no remaining DAP and that their AdminAgents accounts use "
        "phishing-resistant MFA. Monitor sign-ins by partner tenants (cross-"
        "tenant sign-in logs, service provider column)."
    ),
    "base_severity": "high",
    "query": """
        WITH partner_role (template_id, role_name) AS (
            VALUES ('4ba39ca4-527c-499a-b93d-d9b492c50246'::uuid, 'Partner Tier1 Support'),
                   ('e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8'::uuid, 'Partner Tier2 Support')
        ),
        holder AS (
            SELECT rm.member_id,
                   min(rm.member_type) AS member_type,
                   COALESCE(min(rm.member_upn), min(rm.member_display_name), rm.member_id::text) AS label,
                   string_agg(DISTINCT pr.role_name, ', ') AS roles,
                   jsonb_agg(DISTINCT jsonb_build_object(
                       'role', pr.role_name,
                       'assignment_type', rm.assignment_type,
                       'via_group', COALESCE(rm.via_group_display_name, rm.via_group_id::text))) AS assignments,
                   bool_and(rm.account_enabled IS FALSE) AS all_disabled
              FROM entra_directory_role_member rm
              JOIN partner_role pr ON pr.template_id = rm.role_template_id
             WHERE rm.client_id = %(client_id)s
             GROUP BY rm.member_id
        ),
        contract AS (
            SELECT c.*
              FROM entra_partner_contract c
             WHERE c.client_id = %(client_id)s
               AND EXISTS (SELECT 1 FROM entra_collection_status s
                            WHERE s.client_id = %(client_id)s AND s.source = 'partner_contracts'
                              AND s.status = 'ok')
        )
        SELECT
            'fail' AS status,
            h.member_id AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            h.label || ' holds the partner support role(s) ' || h.roles
                || ' (legacy partner delegated administration)' AS summary,
            jsonb_build_object(
                'kind', 'partner_support_role_holder',
                'member_id', h.member_id,
                'member_type', h.member_type,
                'member', h.label,
                'assignments', h.assignments,
                'account_disabled', h.all_disabled,
                'note', 'Customer-side Graph visibility of DAP/GDAP is limited; review Partner relationships in the Microsoft 365 admin center.'
            ) AS detail
        FROM holder h
        UNION ALL
        SELECT
            'fail',
            c.contract_object_id,
            NULL, NULL, NULL, NULL,
            'high',
            'Partner contract present (' || COALESCE(c.contract_type, 'unknown type') || ': '
                || COALESCE(c.display_name, c.default_domain_name, c.customer_id::text, c.contract_object_id::text)
                || ') -- check for legacy DAP',
            jsonb_build_object(
                'kind', 'partner_contract',
                'contract_object_id', c.contract_object_id,
                'contract_type', c.contract_type,
                'customer_id', c.customer_id,
                'default_domain_name', c.default_domain_name,
                'display_name', c.display_name,
                'note', 'A partner contract records a CSP/reseller relationship; with legacy DAP it grants the partner Global Administrator. GDAP relationships are not readable from the customer tenant.'
            )
        FROM contract c
    """,
}
