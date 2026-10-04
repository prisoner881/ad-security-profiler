"""
Plugin 2040: RODC Allowed to Cache Privileged Credentials

Detects read-only domain controllers whose msDS-RevealOnDemandGroup
(rodc_prp_edge relation 'reveal_on_demand') lists a Tier 0 principal,
or a group whose effective members (v_effective_group_membership:
nested and primary-group membership) include a Tier 0 principal. Tier 0
= v_privileged_principal plus AdminSDHolder-protected groups.

Why it matters: the reveal-on-demand list is the RODC's "allowed to
cache" list. Any listed account that authenticates through the RODC has
its password hash replicated to it, so a Tier 0 account in scope can end
up cached on a server that is, by design, in a less trusted location
(see plugin 2037 for credentials already cached). PingCastle rule
P-RODCRevealOnDemand covers the same condition. Broad groups such as
Domain Users in this list are the usual cause: they include every
administrator through primaryGroupID.

The never-reveal list (msDS-NeverRevealGroup, by default containing
"Denied RODC Password Replication Group" with Domain Admins, Enterprise
Admins, ...) takes precedence, so some of the Tier 0 accounts in scope
may still be blocked. detail.tier0_not_denied lists those that are NOT
covered by any never-reveal entry (directly or through group
membership); the finding stays high either way because the allow list
itself is wrong and the deny list is easy to weaken.

The RODC's own computer account and its own krbtgt_NNNNN account are not
counted. Groups are stored unexpanded by the collector; their members
come from group_member_edge, so members of groups the collector could
not read are not seen.

One row per RODC. high.
"""

PLUGIN = {
    "plugin_id": 2040,
    "category": "Computer Accounts",
    "name": "RODC Allowed to Cache Privileged Credentials",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "PRIV-2040",
    "framework_tags": [
        "MITRE-ATTCK-T1003.003",
        "NIST-800-53-AC-6(5)", "NIST-800-53-AC-6", "NIST-CSF-2.0-PR.AA-05", "PCI-DSS-4.0-7.2.2",
        "CIS-CSC-8-5.4", "CIS-CSC-8-3.3", "ISO-27001-2022-A.8.2", "SOC2-CC6.3",
        "NIST-800-53-SC-28", "CIS-CSC-8-3.11",
    ],
    "references": [
        {"title": "Microsoft: ms-DS-Reveal-OnDemand-Group attribute",
         "url": "https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-revealondemandgroup"},
        {"title": "PingCastle health check rules",
         "url": "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
    ],
    "description": (
        "Flags read-only domain controllers whose password replication 'allowed' "
        "list (msDS-RevealOnDemandGroup) includes a Tier 0 account or group, or a "
        "group (such as Domain Users) whose effective members include Tier 0 "
        "accounts -- their password hashes may be cached on the RODC."
    ),
    "remediation": (
        "Remove the listed entries from the RODC's Allowed list (Active Directory "
        "Users and Computers > RODC computer > Password Replication Policy, or "
        "`Remove-ADDomainControllerPasswordReplicationPolicy -Identity <RODC> "
        "-AllowedList <entry>`), and allow only groups holding the branch's own "
        "users and computers. Make sure the Tier 0 accounts are denied: keep "
        "'Denied RODC Password Replication Group' and the built-in admin groups in "
        "the Denied list and add any other Tier 0 group to it. Check what is already "
        "cached with `Get-ADDomainControllerPasswordReplicationPolicyUsage "
        "-Identity <RODC> -RevealedAccounts` and reset the passwords of any Tier 0 "
        "account found there."
    ),
    "base_severity": "high",
    "query": """
        WITH tier0 AS (
            SELECT p.object_guid FROM v_privileged_principal p WHERE p.client_id = %(client_id)s
            UNION
            SELECT g.object_guid FROM ad_group g
             WHERE g.client_id = %(client_id)s AND g.valid_to IS NULL AND g.is_protected_group
        ),
        rodc AS (
            SELECT c.object_guid, c.sam_account_name,
                   (SELECT k.object_guid FROM directory_object k
                     WHERE k.client_id = c.client_id AND NOT k.is_deleted
                       AND lower(k.dn_current) = lower(c.krbtgt_link) LIMIT 1) AS krbtgt_guid
            FROM ad_computer c
            JOIN directory_object d
              ON d.object_guid = c.object_guid AND d.client_id = c.client_id AND NOT d.is_deleted
            WHERE c.client_id = %(client_id)s AND c.valid_to IS NULL
        ),
        prp AS (
            SELECT e.rodc_guid, e.principal_guid, e.relation
            FROM rodc_prp_edge e
            JOIN directory_object pd
              ON pd.object_guid = e.principal_guid AND pd.client_id = e.client_id AND NOT pd.is_deleted
            WHERE e.client_id = %(client_id)s AND e.valid_to IS NULL
        ),
        -- every account/group each PRP entry covers: itself plus its effective members
        covered AS (
            SELECT p.rodc_guid, p.principal_guid AS entry_guid, p.relation, p.principal_guid AS covered_guid
            FROM prp p
            UNION
            SELECT p.rodc_guid, p.principal_guid, p.relation, vem.member_guid
            FROM prp p
            JOIN v_effective_group_membership vem
              ON vem.group_guid = p.principal_guid AND vem.client_id = %(client_id)s
        ),
        allowed_t0 AS (
            SELECT cv.rodc_guid, cv.entry_guid, cv.covered_guid
            FROM covered cv
            JOIN rodc r ON r.object_guid = cv.rodc_guid
            JOIN tier0 t ON t.object_guid = cv.covered_guid
            WHERE cv.relation = 'reveal_on_demand'
              AND cv.covered_guid <> r.object_guid
              AND cv.covered_guid IS DISTINCT FROM r.krbtgt_guid
        ),
        per_entry AS (
            SELECT a.rodc_guid, a.entry_guid,
                   COALESCE(ed.sam_account_name, ed.object_sid, ed.object_guid::text) AS entry_name,
                   ed.object_sid AS entry_sid,
                   bool_or(a.covered_guid = a.entry_guid) AS entry_is_tier0,
                   jsonb_agg(DISTINCT COALESCE(md.sam_account_name, md.object_sid, md.object_guid::text))
                       FILTER (WHERE a.covered_guid <> a.entry_guid) AS tier0_members
            FROM allowed_t0 a
            JOIN directory_object ed ON ed.object_guid = a.entry_guid AND ed.client_id = %(client_id)s
            JOIN directory_object md ON md.object_guid = a.covered_guid AND md.client_id = %(client_id)s
            GROUP BY a.rodc_guid, a.entry_guid, ed.sam_account_name, ed.object_sid, ed.object_guid
        ),
        not_denied AS (
            SELECT a.rodc_guid,
                   jsonb_agg(DISTINCT COALESCE(md.sam_account_name, md.object_sid, md.object_guid::text))
                       AS names
            FROM allowed_t0 a
            JOIN directory_object md ON md.object_guid = a.covered_guid AND md.client_id = %(client_id)s
            WHERE md.object_class IN ('user', 'computer')
              AND NOT EXISTS (SELECT 1 FROM covered n
                               WHERE n.rodc_guid = a.rodc_guid AND n.relation = 'never_reveal'
                                 AND n.covered_guid = a.covered_guid)
            GROUP BY a.rodc_guid
        )
        SELECT
            'fail' AS status,
            pe.rodc_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'RODC ' || COALESCE(r.sam_account_name, pe.rodc_guid::text)
                || ' is allowed to cache Tier 0 credentials via its reveal-on-demand list: '
                || string_agg(pe.entry_name, ', ' ORDER BY pe.entry_name) AS summary,
            jsonb_build_object(
                'rodc', r.sam_account_name,
                'allowed_entries', jsonb_agg(jsonb_build_object(
                    'entry', pe.entry_name,
                    'object_sid', pe.entry_sid,
                    'entry_is_tier0', pe.entry_is_tier0,
                    'tier0_members', pe.tier0_members
                ) ORDER BY pe.entry_name),
                'tier0_not_denied', COALESCE(nd.names, '[]'::jsonb)
            ) AS detail
        FROM per_entry pe
        JOIN rodc r ON r.object_guid = pe.rodc_guid
        LEFT JOIN not_denied nd ON nd.rodc_guid = pe.rodc_guid
        GROUP BY pe.rodc_guid, r.sam_account_name, nd.names
        ORDER BY pe.rodc_guid
    """,
}
