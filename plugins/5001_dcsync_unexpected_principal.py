"""
Plugin 5001: DCSync Replication Rights Held by an Unexpected Principal

The single most classic ACL-derived AD finding, and the flagship
motivation for solving this project's long-deferred ACL-parsing
capability. DS-Replication-Get-Changes and DS-Replication-Get-Changes-All
together grant the ability to impersonate a domain controller and pull
password hashes for any account via DCSync -- Mimikatz's
lsadump::dcsync, and the technique behind MITRE ATT&CK T1003.006.

GUIDs confirmed directly against impacket's own msada_guids reference
table (sourced from Microsoft's MS-ADA1/2/3 specs), not assumed from a
single web source -- a real, resolved discrepancy was found across
public sources during development, and impacket's embedded table
(reinforced by its own real exploitation code in
examples/ntlmrelayx/attacks/ldapattack.py, which grants exactly this
GUID pair to actually perform a working DCSync) was used as the
authoritative tiebreaker.

Excludes the well-known, expected holders: Domain Admins, Enterprise
Admins, Administrators (BUILTIN), and any domain controller computer
account -- flagging only principals outside that expected set.

A trustee SID that doesn't resolve to a collected directory_object
(e.g. a genuinely cross-forest/orphaned SID) is not flagged as an
individual finding here -- control_evidence_fact.object_guid has a hard
foreign key against directory_object, so a finding can only be attached
to a real, collected object, matching the same "count but don't
individually report unresolved references" precedent already
established throughout this project for group membership, delegation
targets, and RBCD trustees.

[v1.1] Fixed two real false positives found against production data
(lab.example): Enterprise Domain Controllers (S-1-5-9) and Enterprise
Read-only Domain Controllers (RID 498) are both confirmed, by
Microsoft's own documentation, to be DEFAULT holders of replication
rights -- not misconfigurations. Deliberately did NOT exclude the
"Domain Controllers" group (RID 516) itself, even though it also showed
up in that same real run: Microsoft's own troubleshooting documentation
explicitly and repeatedly instructs that group's replication rights be
CLEARED, not granted, and dedicated Windows Event IDs (1979-1983) exist
specifically to detect this exact condition as a default-security-
descriptor anomaly. A finding on that group is a genuine, if
lower-confidence, anomaly worth surfacing, not a default to suppress.

[v1.5] Corrected the v1.1 reasoning above: since Windows Server 2012 the
default domain-root DACL grants the Domain Controllers group (RID 516)
DS-Replication-Get-Changes-All, so it is now excluded as a default
holder (it was a critical false positive on every modern domain). The
DCSync test now mirrors v_privileged_principal: only allow ACEs that
apply to the root itself (inherit_only IS NOT TRUE) and carry the
CONTROL_ACCESS bit count, and All Extended Rights / GenericAll (which
include both replication rights) are reported too. A full DCSync grant
is fail / critical; a partial grant (one right only, which cannot
extract secrets on its own) is warn / medium. Read-only DCs (521) and
Enterprise Read-only DCs (498) are excluded unless they hold the full
set.

[v1.6] The ACTIVE Entra Connect (Azure AD Connect) connector account is now an
expected holder, as plugin 10009's documentation always said it was:
password hash synchronization requires DCSync, and plugins 10009 / 10010
report that account's exposure (credential hygiene, sync server on a DC).
"Connector account" = a user account named MSOL_<hex>, or whose description
is the installer's ("Azure Active Directory Connect" / "Azure AD Connect" /
"Entra Connect"). "Active" = enabled and logged on within 30 days of the
collection (lastLogonTimestamp replicates with up to ~14 days' lag). A
connector account that is disabled or has not logged on for 30 days --
typically left behind by an earlier or decommissioned installation -- is
still reported, critical, and named as a stale Entra Connect connector
account: it keeps standing DCSync with nothing using it. Found on a lab
domain with one live connector (MSOL_e8f8..., previously a critical false
positive) and one left from a 2017 installation (MSOL_68bf..., real).
"""

PLUGIN = {
    "plugin_id": 5001,
    "category": "ACLs",
    "name": "DCSync Replication Rights Held by an Unexpected Principal",
    "version": "1.6",
    "revision_date": "2026-10-07",
    "remediation": (
        "Confirm this grant was deliberate and is still needed. "
        "Service accounts frequently accumulate replication rights for "
        "legitimate purposes (Azure AD Connect / Entra Connect, backup "
        "software, directory sync tools), so this is not automatically "
        "an active compromise -- but any account holding it is a "
        "high-value target: compromising it is equivalent to "
        "compromising a domain controller for credential-theft "
        "purposes. If not needed, remove the grant "
        "(`dsacls \"DC=...\" /R DS-Replication-Get-Changes` and the "
        "-All variant, or via ADSI Edit) rather than leaving standing "
        "access broader than required."
    ),
    "control_id": "ACL-001",
    "framework_tags": [
        "NIST-800-53-AC-3",
        "NIST-800-53-AC-6",
        "NIST-800-53-AC-6(1)",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.2",
        "CIS-CSC-8-3.3",
        "CIS-CSC-8-6.8",
        "ISO-27001-2022-A.5.15",
        "ISO-27001-2022-A.8.3",
        "SOC2-CC6.3",
        "HIPAA-164.312(a)(1)",
        "MITRE-ATTCK-T1003.006",
        "CISA-AA26-237A",
    ],
    "references": [
        {"title": "MITRE ATT&CK T1003.006: OS Credential Dumping -- DCSync",
         "url": "https://attack.mitre.org/techniques/T1003/006/"},
    ],
    "description": (
        "DS-Replication-Get-Changes (1131f6aa-9c07-11d1-f79f-"
        "00c04fc2dcd2) and DS-Replication-Get-Changes-All "
        "(1131f6ad-9c07-11d1-f79f-00c04fc2dcd2) together grant the "
        "ability to impersonate a domain controller and pull password "
        "hashes for any account via DCSync -- Mimikatz's "
        "lsadump::dcsync, MITRE ATT&CK T1003.006. By default only "
        "Domain Admins, Enterprise Admins, Administrators, and domain "
        "controller computer accounts (and the Domain Controllers "
        "group) hold this pair. All Extended Rights and GenericAll on "
        "the domain root include both rights and also grant DCSync. "
        "This finding flags any OTHER principal holding DCSync on the "
        "domain root (fail / critical) and, at warn / medium, any "
        "principal holding only one of the two rights, which cannot "
        "extract secrets alone but indicates an incomplete grant or a "
        "misconfiguration."
    ),
    "base_severity": "critical",
    "query": """
        -- [v1.5] Mirrors v_privileged_principal's 'dcsync' definition:
        -- allow ACEs that apply to the domain root itself (inherit_only IS
        -- NOT TRUE) carrying CONTROL_ACCESS (0x100), for Get-Changes /
        -- Get-Changes-All, or All Extended Rights (CONTROL_ACCESS with no
        -- object type -- which GenericAll 0xF01FF includes).
        WITH dcsync_rights AS (
            SELECT
                a.trustee_sid,
                COALESCE(bool_or(a.object_type_guid = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'), false) AS has_get_changes,
                COALESCE(bool_or(a.object_type_guid = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'), false) AS has_get_changes_all,
                bool_or(a.object_type_guid IS NULL) AS has_all_extended_rights,
                bool_or(a.object_type_guid IS NULL
                        AND (a.access_mask & 983551) = 983551) AS has_generic_all
            FROM acl_edge a
            JOIN ad_domain d
              ON d.object_guid = a.object_guid AND d.client_id = a.client_id
             AND d.valid_to IS NULL
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND a.inherit_only IS NOT TRUE
              AND (a.access_mask & 256) <> 0              -- CONTROL_ACCESS
              AND (a.object_type_guid IS NULL
                   OR a.object_type_guid IN ('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
                                             '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'))
            GROUP BY a.trustee_sid
        ),
        classified AS (
            SELECT dr.*,
                   (dr.has_all_extended_rights
                    OR (dr.has_get_changes AND dr.has_get_changes_all)) AS full_dcsync
            FROM dcsync_rights dr
        ),
        -- [v1.6] Entra Connect connector accounts, and whether each is in use.
        collection AS (
            SELECT COALESCE(sr.completed_at, now()) AS collected_at
            FROM sync_run sr WHERE sr.run_id = %(run_id)s
        ),
        connector AS (
            SELECT u.object_guid,
                   (u.is_enabled IS TRUE
                    AND u.last_logon_timestamp >= (SELECT collected_at FROM collection)
                                                  - interval '30 days') AS active,
                   u.is_enabled, u.last_logon_timestamp
            FROM ad_user u
            WHERE u.client_id = %(client_id)s AND u.valid_to IS NULL
              AND (u.sam_account_name LIKE 'MSOL\\_%%'
                   OR u.description ILIKE '%%Azure Active Directory Connect%%'
                   OR u.description ILIKE '%%Azure AD Connect%%'
                   OR u.description ILIKE '%%Entra Connect%%')
        )
        SELECT
            CASE WHEN c.full_dcsync THEN 'fail' ELSE 'warn' END AS status,
            do2.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN c.full_dcsync THEN 'critical' ELSE 'medium' END AS fd_severity,
            CASE WHEN cn.object_guid IS NOT NULL
                 THEN 'Stale Entra Connect connector account '
                 ELSE 'Principal ' END
                || COALESCE(do2.sam_account_name, c.trustee_sid)
                || CASE WHEN c.full_dcsync
                        THEN ' holds DCSync replication rights on the domain root ('
                        ELSE ' holds a partial DCSync grant on the domain root ('
                   END
                || CASE WHEN c.has_generic_all
                        THEN 'GenericAll, which includes All Extended Rights'
                        WHEN c.has_all_extended_rights
                        THEN 'All Extended Rights'
                        WHEN c.has_get_changes AND c.has_get_changes_all
                        THEN 'both DS-Replication-Get-Changes and -All'
                        ELSE 'only ' || (CASE WHEN c.has_get_changes
                                              THEN 'DS-Replication-Get-Changes'
                                              ELSE 'DS-Replication-Get-Changes-All' END)
                   END
                || ')' AS summary,
            jsonb_build_object(
                'trustee_sid', c.trustee_sid,
                'sam_account_name', do2.sam_account_name,
                'object_class', do2.object_class,
                'has_get_changes', c.has_get_changes,
                'has_get_changes_all', c.has_get_changes_all,
                'has_all_extended_rights', c.has_all_extended_rights,
                'has_generic_all', c.has_generic_all,
                'full_dcsync', c.full_dcsync,
                'sync_connector_account', cn.object_guid IS NOT NULL,
                'connector_enabled', cn.is_enabled,
                'connector_last_logon_timestamp', cn.last_logon_timestamp
            ) AS detail
        FROM classified c
        JOIN directory_object do2
            ON do2.object_sid = c.trustee_sid AND do2.client_id = %(client_id)s
           AND NOT do2.is_deleted
        LEFT JOIN connector cn ON cn.object_guid = do2.object_guid
        WHERE
            -- [v1.6] The active Entra Connect connector account is expected
            -- (password hash sync); plugins 10009 / 10010 report it.
            NOT COALESCE(cn.active, FALSE)
            AND
            -- Default holders of the full right set: Domain Admins (512),
            -- Enterprise Admins (519), Administrators (S-1-5-32-544),
            -- Enterprise Domain Controllers (S-1-5-9), and -- since Windows
            -- Server 2012 -- the Domain Controllers group (516), which the
            -- default domain-root DACL grants Get-Changes-All.
            NOT (do2.object_sid LIKE '%%-512' OR do2.object_sid LIKE '%%-519'
                 OR do2.object_sid = 'S-1-5-32-544' OR do2.object_sid = 'S-1-5-9'
                 OR do2.object_sid LIKE '%%-516')
            -- Read-only DCs (521) and Enterprise Read-only DCs (498) hold
            -- only Get-Changes by default; flag them only if they can DCSync.
            AND NOT ((do2.object_sid LIKE '%%-521' OR do2.object_sid LIKE '%%-498')
                     AND NOT c.full_dcsync)
            -- Domain controller computer accounts (writable and read-only).
            AND NOT EXISTS (
                SELECT 1 FROM ad_computer dc
                WHERE dc.client_id = do2.client_id AND dc.valid_to IS NULL
                  AND dc.object_guid = do2.object_guid AND dc.is_domain_controller
            )
    """,
}
