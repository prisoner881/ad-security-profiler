"""
Plugin 9039: Organizational Unit Not Protected From Accidental Deletion

Reports organizational units whose ACL lacks the "Protect object from
accidental deletion" entry: a deny ACE for Everyone (S-1-1-0) covering
DELETE (0x10000) and DELETE_TREE (0x40) on the OU itself. One row per OU
(object_guid = the OU).

Why it matters: without it, one mistaken right-click (or a script with a
wrong distinguished name) deletes the OU and everything below it --
users, groups, computers, GPO links -- in a single operation. Recovery then
depends on the AD Recycle Bin (plugin 4031) or an authoritative restore.
Active Directory Users and Computers sets the protection on every new OU by
default since Windows Server 2008, so an unprotected OU is usually an old
or script-created one (PingCastle P-UnprotectedOU, informative).

Severity ('warn'): low for an OU that contains Tier 0 objects (a domain
controller, or a privileged account or group per v_privileged_principal);
info otherwise. OUs whose ACL was not collected (no acl_edge rows) are
skipped rather than reported.
"""

PLUGIN = {
    "plugin_id": 9039,
    "category": "Organizational Units",
    "name": "Organizational Unit Not Protected From Accidental Deletion",
    "version": "1.0",
    "revision_date": "2026-10-20",
    "control_id": "OU-9039",
    "framework_tags": [
        "NIST-800-53-CP-9",
        "NIST-800-53-CP-10",
        "NIST-800-53-CM-6",
        "NIST-CSF-2.0-PR.DS-11",
        "NIST-CSF-2.0-PR.PS-01",
        "CIS-CSC-8-11.2",
        "CIS-CSC-8-4.1",
        "ISO-27001-2022-A.8.13",
        "ISO-27001-2022-A.8.9",
        "SOC2-A1.2",
        "SOC2-CC7.1",
    ],
    "references": [
        {"title": "Microsoft: Protect an OU from accidental deletion (Set-ADOrganizationalUnit -ProtectedFromAccidentalDeletion)",
         "url": "https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adorganizationalunit"},
        {"title": "PingCastle health check rules (P-UnprotectedOU)",
         "url": "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
    ],
    "description": (
        "An OU has no 'protect from accidental deletion' deny ACE (Everyone: "
        "deny Delete and Delete subtree), so a single mistaken delete removes "
        "it with everything below it. Low when the OU holds Tier 0 objects, "
        "info otherwise."
    ),
    "remediation": (
        "Protect every OU: Get-ADOrganizationalUnit -Filter * | "
        "Set-ADOrganizationalUnit -ProtectedFromAccidentalDeletion $true. "
        "Make sure the AD Recycle Bin is enabled as well (plugin 4031)."
    ),
    "base_severity": "low",
    "query": """
        WITH ou AS (
            SELECT o.object_guid, o.ou_name, d.dn_current, lower(d.dn_current) AS dn
            FROM ad_ou o
            JOIN directory_object d
              ON d.object_guid = o.object_guid AND d.client_id = o.client_id AND NOT d.is_deleted
            WHERE o.client_id = %(client_id)s AND o.valid_to IS NULL
              AND EXISTS (SELECT 1 FROM acl_edge a
                          WHERE a.client_id = %(client_id)s AND a.object_guid = o.object_guid
                            AND a.valid_to IS NULL)
        ),
        protected AS (
            SELECT a.object_guid
            FROM acl_edge a
            JOIN ou ON ou.object_guid = a.object_guid
            WHERE a.client_id = %(client_id)s AND a.valid_to IS NULL
              AND a.ace_type = 'deny' AND a.trustee_sid = 'S-1-1-0'
              AND a.inherit_only IS NOT TRUE
            GROUP BY a.object_guid
            HAVING (bit_or(a.access_mask) & 65600) = 65600
        ),
        tier0_guid AS (
            SELECT p.object_guid FROM v_privileged_principal p WHERE p.client_id = %(client_id)s
            UNION
            SELECT c.object_guid FROM ad_computer c
            WHERE c.client_id = %(client_id)s AND c.valid_to IS NULL AND c.is_domain_controller
        ),
        tier0 AS (
            SELECT lower(d.dn_current) AS dn
            FROM tier0_guid t
            JOIN directory_object d
              ON d.object_guid = t.object_guid AND d.client_id = %(client_id)s AND NOT d.is_deleted
        ),
        holds AS (
            SELECT DISTINCT ou.object_guid
            FROM ou JOIN tier0 x ON x.dn LIKE '%%,' || ou.dn
        )
        SELECT
            'warn' AS status,
            ou.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN h.object_guid IS NOT NULL THEN 'low' ELSE 'info' END AS fd_severity,
            'OU ' || ou.dn_current || ' is not protected from accidental deletion'
                || CASE WHEN h.object_guid IS NOT NULL THEN ' and contains Tier 0 objects' ELSE '' END AS summary,
            jsonb_build_object(
                'ou_name', ou.ou_name,
                'distinguished_name', ou.dn_current,
                'contains_tier0_objects', h.object_guid IS NOT NULL
            ) AS detail
        FROM ou
        LEFT JOIN holds h ON h.object_guid = ou.object_guid
        WHERE ou.object_guid NOT IN (SELECT object_guid FROM protected)
    """,
}
