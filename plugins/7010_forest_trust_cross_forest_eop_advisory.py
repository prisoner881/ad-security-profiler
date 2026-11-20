"""
Plugin 7010: Forest Trust Exposed to Cross-Forest Kerberos Elevation of Privilege (CVE-2026-122164)

CVE-2026-122164 (Windows Kerberos elevation of privilege, CVSS 8.0,
November 2026): "An attacker who controls authentication in a trusted
forest could send specially crafted authentication information to the
target forest ... raise the integrity level of the attacker's identity to
System." It "requires an existing trust relationship between the
attacker's forest and the target forest, together with resource
permissions that already allow the attacker's identity access." The fix is
the November 2026 update on the domain controllers and on the servers that
accept the partner forest's users.

Patch level is not visible in the directory: the finding stands while such
a trust exists, as a prompt to confirm the update (like plugin 5022 for
AD FS). Which trusts: forest trusts (trust_attributes bit 0x8,
FOREST_TRANSITIVE) through which the partner forest authenticates into this
one -- trust_direction 2 (outbound: this domain trusts the partner) or 3
(bidirectional), the same filter as plugin 7006.

One finding per trust, status 'warn':
  * high: Selective Authentication is off (trust_attributes bit 0x10,
    CROSS_ORGANIZATION, clear) -- every user of the partner forest can
    authenticate to every server here, so "resource permissions that
    already allow the attacker's identity access" are broad;
  * medium: Selective Authentication is on -- only accounts granted
    "Allowed to Authenticate" on a computer can reach it.
The detail counts the foreign security principals from other domains
(S-1-5-21-... SIDs) that are present in this domain and how many of them are
group members -- the identities from trusted domains that already hold
access. They cannot be attributed to a single trust (the trust's domain SID
is not collected).

Data: ad_trust, ad_foreign_security_principal, directory_object,
v_effective_group_membership. Identity = the trust object. Related: 7006
(no Selective Authentication), 7001 (SID filtering), 3026 (foreign
principals in privileged groups).
"""

PLUGIN = {
    "plugin_id": 7010,
    "category": "Trusts",
    "name": "Forest Trust Exposed to Cross-Forest Kerberos Elevation of Privilege (CVE-2026-122164)",
    "version": "1.0",
    "revision_date": "2026-11-20",
    "control_id": "TRUST-7010",
    "framework_tags": [
        "NIST-800-53-SI-2",
        "NIST-800-53-RA-5",
        "NIST-800-53-AC-4",
        "NIST-800-53-AC-20",
        "NIST-CSF-2.0-ID.RA-01",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-6.3.3",
        "CIS-CSC-8-7.3",
        "CIS-CSC-8-12.2",
        "ISO-27001-2022-A.8.8",
        "ISO-27001-2022-A.8.22",
        "SOC2-CC6.6",
        "SOC2-CC7.1",
        "MITRE-ATTCK-T1199",
        "MITRE-ATTCK-T1068",
        "CVE-2026-122164",
    ],
    "references": [
        {"title": "Microsoft Security Update Guide: CVE-2026-122164 (Windows Kerberos Elevation of Privilege)",
         "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-122164"},
        {"title": "Microsoft [MS-ADTS]: trustAttributes",
         "url": "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c"},
        {"title": "MITRE ATT&CK T1199: Trusted Relationship",
         "url": "https://attack.mitre.org/techniques/T1199/"},
    ],
    "description": (
        "This domain trusts another forest (an outbound or two-way forest trust), so the partner "
        "forest's users authenticate here. CVE-2026-122164 (November 2026, CVSS 8.0) lets an "
        "attacker who controls authentication in the trusted forest raise an identity that already "
        "has access here to SYSTEM. High when Selective Authentication is off (every partner user "
        "can authenticate to every server); medium when it is on. Patch level is not visible to "
        "this check."
    ),
    "remediation": (
        "Confirm the November 2026 security update (or later) is installed on every domain "
        "controller and on every server that accepts users from the partner forest. Enable "
        "Selective Authentication on the trust (plugin 7006) and grant \"Allowed to Authenticate\" "
        "only on the computers the partner's users need. Review what the partner forest's "
        "accounts and groups hold here (foreign security principals in groups and ACLs, plugin "
        "3026 for privileged groups), remove what is not needed, and remove the trust if it is no "
        "longer used (plugin 7009). Treat the security of the partner forest as part of this "
        "forest's: a compromise there is the precondition for this attack."
    ),
    "base_severity": "high",
    "query": """
        WITH
        tr AS (
            SELECT t.object_guid, t.trust_partner, t.trust_direction, t.trust_type, t.trust_attributes,
                   t.sid_filtering_enabled,
                   (COALESCE(t.trust_attributes, 0) & 16) <> 0 AS selective_auth
              FROM ad_trust t
             WHERE t.client_id = %(client_id)s
               AND t.valid_to IS NULL
               AND (COALESCE(t.trust_attributes, 0) & 8) <> 0
               AND t.trust_direction IN (2, 3)
        ),
        fsp AS (
            SELECT f.object_guid,
                   EXISTS (SELECT 1 FROM v_effective_group_membership m
                            WHERE m.client_id = f.client_id AND m.member_guid = f.object_guid) AS is_member
              FROM ad_foreign_security_principal f
              JOIN directory_object o
                ON o.object_guid = f.object_guid AND o.client_id = f.client_id AND NOT o.is_deleted
             WHERE f.client_id = %(client_id)s
               AND f.valid_to IS NULL
               AND o.object_sid LIKE 'S-1-5-21-%%'
        ),
        fsp_sum AS (
            SELECT count(*) AS fsp_count, count(*) FILTER (WHERE is_member) AS fsp_member_count
              FROM fsp
        )
        SELECT
            'warn' AS status,
            t.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN t.selective_auth THEN 'medium' ELSE 'high' END AS fd_severity,
            CASE WHEN t.trust_direction = 3 THEN 'Two-way' ELSE 'Outbound' END
                || ' forest trust with "' || COALESCE(t.trust_partner, '(unknown)')
                || '" lets the partner forest authenticate here'
                || CASE WHEN t.selective_auth
                        THEN ' (Selective Authentication on)'
                        ELSE ' to every server (Selective Authentication off)' END
                || '. Confirm the November 2026 update for CVE-2026-122164 (cross-forest Kerberos '
                || 'elevation to SYSTEM) is installed on the domain controllers and the servers the '
                || 'partner''s users reach' AS summary,
            jsonb_build_object(
                'trust_partner', t.trust_partner,
                'trust_direction', t.trust_direction,
                'trust_type', t.trust_type,
                'trust_attributes', t.trust_attributes,
                'selective_authentication', t.selective_auth,
                'sid_filtering_enabled', t.sid_filtering_enabled,
                'foreign_domain_principals_in_this_domain', s.fsp_count,
                'foreign_domain_principals_in_groups', s.fsp_member_count,
                'cve', 'CVE-2026-122164',
                'note', 'Patch level is not visible in the directory. Foreign principals are counted '
                        'for all trusted domains together: the trust''s domain SID is not collected.'
            ) AS detail
        FROM tr t
        CROSS JOIN fsp_sum s
    """,
}
