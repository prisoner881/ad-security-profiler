"""
Plugin 10096: Unexpected Holder of the Directory Synchronization Accounts Role

Reports holders of the Directory Synchronization Accounts role (template
d29b2b05-8046-44ba-8758-1e26182fcf32) or the On Premises Directory Sync
Account role (a92aed5d-d78a-4d16-b381-09adb37eb3b0) that do not look like
the service accounts Entra Connect / Cloud Sync create (Tier A:
entra_directory_role_member, active or eligible, direct or via a group).

A holder is unexpected when any of:
- it is a guest (entra_user.user_type 'Guest' or an #EXT# UPN);
- it is a user whose UPN does not start with 'Sync_' (Entra Connect Sync:
  Sync_<server>_<hex>@<tenant>.onmicrosoft.com) or
  'ADToAADSyncServiceAccount' (Cloud Sync), compared case-insensitively;
  a service principal whose display name does not start with
  'ConnectSyncProvisioning_' (Entra Connect application-based
  authentication); any group or other member type;
- the two roles together have more than 2 distinct holders (one active
  and one staging server is the normal maximum) -- then every holder is
  reported, since the data cannot tell which one is stale.

Why: these roles can write almost every synchronized object and
historically could reset cloud-only users' passwords; they are excluded
from many CA policies and admin reviews because they are "system"
accounts. An extra holder is a stealthy persistence path (AADInternals
documents abusing the sync account; MITRE T1098.003, T1556.007).

One finding per unexpected holder (object_guid = the holder's Entra
object id), high, every reason and role path listed.
"""

PLUGIN = {
    "plugin_id": 10096,
    "category": "Hybrid Identity",
    "name": "Unexpected Holder of the Directory Synchronization Accounts Role",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10096",
    "framework_tags": [
        "NIST-800-53-AC-2(7)",
        "NIST-800-53-AC-6(5)",
        "NIST-800-53-AC-2",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-8.6.1",
        "CIS-CSC-8-5.4",
        "CIS-CSC-8-5.5",
        "ISO-27001-2022-A.8.2",
        "SOC2-CC6.3",
        "MITRE-ATTCK-T1098.003",
        "MITRE-ATTCK-T1556.007",
    ],
    "references": [
        {"title": "Microsoft: Microsoft Entra built-in roles: Directory Synchronization Accounts",
         "url": "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#directory-synchronization-accounts"},
        {"title": "Microsoft: Microsoft Entra Connect: Accounts and permissions",
         "url": "https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions"},
        {"title": "MITRE ATT&CK T1098.003 Account Manipulation: Additional Cloud Roles",
         "url": "https://attack.mitre.org/techniques/T1098/003/"},
    ],
    "description": (
        "A Directory Synchronization Accounts / On Premises Directory Sync "
        "Account role holder is a guest, is not named like an Entra "
        "Connect (Sync_*) or Cloud Sync (ADToAADSyncServiceAccount*) "
        "service account, or the roles have more than 2 holders. These "
        "roles write almost every synced object and are rarely reviewed; "
        "an extra holder is a stealthy backdoor. High, one finding per "
        "unexpected holder."
    ),
    "remediation": (
        "Compare holders with your Entra Connect / Cloud Sync servers "
        "(Get-ADSyncAADCompanyFeature / the Synchronization Service "
        "Manager connector account; Cloud Sync agent configuration). "
        "Remove the role from anything else "
        "(Remove-MgDirectoryRoleMemberByRef, or remove the PIM "
        "eligibility), delete accounts left behind by decommissioned "
        "sync servers, and investigate how an unexpected holder got the "
        "role (audit log 'Add member to role'). Never assign these roles "
        "to people or guests."
    ),
    "base_severity": "high",
    "query": """
        WITH holder_row AS (
            SELECT rm.*, eu.user_type, eu.user_principal_name AS eu_upn, eu.account_enabled AS eu_enabled,
                   (COALESCE(rm.role_display_name, rm.role_template_id::text) || ' ('
                    || CASE WHEN rm.assignment_type = 'eligible' THEN 'PIM-eligible' ELSE 'active' END
                    || CASE WHEN rm.via_group_id IS NOT NULL
                            THEN ' via group ' || COALESCE(rm.via_group_display_name, rm.via_group_id::text)
                            ELSE '' END || ')') COLLATE "C" AS path
              FROM entra_directory_role_member rm
              LEFT JOIN entra_user eu ON eu.client_id = rm.client_id AND eu.entra_object_id = rm.member_id
             WHERE rm.client_id = %(client_id)s
               AND rm.role_template_id IN ('d29b2b05-8046-44ba-8758-1e26182fcf32',
                                           'a92aed5d-d78a-4d16-b381-09adb37eb3b0')
        ),
        holder AS (
            SELECT h.member_id,
                   min(h.member_type) AS member_type,
                   COALESCE(min(h.eu_upn), min(h.member_upn)) AS upn,
                   min(h.member_display_name) AS display_name,
                   COALESCE(bool_or(h.eu_enabled), bool_or(h.account_enabled)) AS account_enabled,
                   bool_or(h.user_type = 'Guest'
                           OR COALESCE(h.eu_upn, h.member_upn) ILIKE '%%#EXT#%%') AS is_guest,
                   jsonb_agg(DISTINCT h.path ORDER BY h.path) AS role_paths
              FROM holder_row h
             GROUP BY h.member_id
        ),
        stats AS (SELECT count(*) AS holders FROM holder),
        judged AS (
            SELECT h.*,
                   CASE
                     WHEN h.member_type = '#microsoft.graph.user' THEN
                          lower(COALESCE(h.upn, '')) LIKE 'sync\\_%%'
                       OR lower(COALESCE(h.upn, '')) LIKE 'adtoaadsyncserviceaccount%%'
                     WHEN h.member_type = '#microsoft.graph.servicePrincipal' THEN
                          lower(COALESCE(h.display_name, '')) LIKE 'connectsyncprovisioning\\_%%'
                     ELSE FALSE
                   END AS name_expected
              FROM holder h
        ),
        reasons AS (
            SELECT j.member_id,
                   array_remove(ARRAY[
                       CASE WHEN j.is_guest THEN 'is a guest' END,
                       CASE WHEN NOT j.name_expected
                            THEN 'is not named like an Entra Connect or Cloud Sync service account' END,
                       CASE WHEN s.holders > 2
                            THEN 'the directory synchronization roles have more than 2 holders' END
                   ], NULL) AS why
              FROM judged j CROSS JOIN stats s
        )
        SELECT
            'fail' AS status,
            j.member_id AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'Unexpected directory synchronization role holder '
                || COALESCE(j.upn, j.display_name, j.member_id::text) || ': '
                || array_to_string(r.why, '; ') AS summary,
            jsonb_build_object(
                'member_id', j.member_id,
                'member_type', j.member_type,
                'user_principal_name', j.upn,
                'display_name', j.display_name,
                'account_enabled', j.account_enabled,
                'is_guest', j.is_guest,
                'reasons', to_jsonb(r.why),
                'role_paths', j.role_paths,
                'holder_count', s.holders
            ) AS detail
        FROM judged j
        JOIN reasons r ON r.member_id = j.member_id
        CROSS JOIN stats s
        WHERE cardinality(r.why) > 0
    """,
}
