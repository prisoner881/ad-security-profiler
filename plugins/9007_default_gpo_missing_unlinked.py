"""
Plugin 9007: Default Domain Policy / Default Domain Controllers Policy Missing, Unlinked or Disabled

The two well-known GPOs every domain is created with carry baseline security
settings:
  * Default Domain Policy {31B2F340-016D-11D2-945F-00C04FB984F9}, linked to
    the domain root: the domain password, lockout and Kerberos policy (only a
    GPO linked at the domain root can set these for domain accounts) and
    often other domain-wide hardening;
  * Default Domain Controllers Policy {6AC1786C-016F-11D2-945F-00C04FB984F9},
    linked to OU=Domain Controllers: the DCs' user rights assignments (who
    may log on locally, back up files, debug programs...), audit policy and
    security options such as LDAP/SMB signing.
If either is deleted, unlinked from its container, has its link disabled, or
has its computer settings disabled (flags 2 or 3), these baselines silently
stop applying (or fall back to whatever another GPO or the local policy
says). Restoring them after deletion needs dcgpofix, which resets their
content. Microsoft, PingCastle and the DISA Windows DC STIG all rely on
these policies being in force.

Detection, one finding per affected policy:
  * the GPO (ad_gpo.gpo_guid) does not exist (object_guid NULL; summary
    stable);
  * there is no link (gpo_link_edge) from the domain root / from
    OU=Domain Controllers,<domain DN> to it, or every such link is disabled
    (link_enabled FALSE);
  * gpo_flags is 2 (computer settings disabled) or 3 (all settings
    disabled). NULL flags (pre-v38 row) are not judged.
Severity high. If the DCs were moved to another OU that links the policy,
this is still reported: the policy is expected on OU=Domain Controllers.
"""

PLUGIN = {
    "plugin_id": 9007,
    "category": "Organizational Units",
    "name": "Default Domain Policy or Default Domain Controllers Policy Missing, Unlinked or Disabled",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "GPO-9007",
    "framework_tags": [
        "NIST-800-53-CM-6", "NIST-800-53-CM-2", "NIST-CSF-2.0-PR.PS-01",
        "PCI-DSS-4.0-2.2.1", "CIS-CSC-8-4.1", "ISO-27001-2022-A.8.9",
        "SOC2-CC7.1", "NIST-800-53-IA-5(1)", "NIST-800-53-AC-7",
    ],
    "references": [
        {"title": "Microsoft: Group Policy processing",
         "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-policy/group-policy-processing"},
        {"title": "PingCastle health check rules",
         "url": "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
    ],
    "description": (
        "The Default Domain Policy is missing, not linked (or link disabled) "
        "at the domain root, or the Default Domain Controllers Policy is "
        "missing, not linked (or link disabled) at OU=Domain Controllers, or "
        "either has its computer settings disabled. The domain password, "
        "lockout and Kerberos policy or the domain controllers' user rights "
        "and security options then no longer apply."
    ),
    "remediation": (
        "In Group Policy Management: re-link the policy (right-click the "
        "domain / the Domain Controllers OU -> Link an Existing GPO), enable "
        "a disabled link (Link Enabled), and set GPO Status to 'Enabled' "
        "(or New-GPLink -Guid <guid> -Target '<DN>' -LinkEnabled Yes; "
        "(Get-GPO -Guid <guid>).GpoStatus = 'AllSettingsEnabled'). If a "
        "policy was deleted, restore it from a GPO backup "
        "(Restore-GPO / Import-GPO) or, as a last resort, run "
        "dcgpofix /target:Domain or /target:DC, which recreates it with "
        "default settings -- then re-apply your customisations. Review "
        "event logs and change records to find out why it was changed."
    ),
    "base_severity": "high",
    "query": """
        WITH dom AS (
            SELECT d.object_guid, d.dns_root, o.dn_current
            FROM ad_domain d
            JOIN directory_object o
              ON o.object_guid = d.object_guid AND o.client_id = d.client_id AND NOT o.is_deleted
            WHERE d.client_id = %(client_id)s AND d.valid_to IS NULL
        ),
        pol AS (
            SELECT * FROM (VALUES
                ('31b2f340-016d-11d2-945f-00c04fb984f9'::uuid, 'Default Domain Policy', 'domain'),
                ('6ac1786c-016f-11d2-945f-00c04fb984f9'::uuid, 'Default Domain Controllers Policy', 'dc_ou')
            ) v(gpo_guid, policy_name, target_kind)
        ),
        target AS (
            SELECT p.gpo_guid, p.policy_name, p.target_kind, dm.dns_root,
                   CASE WHEN p.target_kind = 'domain' THEN dm.object_guid ELSE ou.object_guid END AS target_guid,
                   CASE WHEN p.target_kind = 'domain' THEN 'the domain root'
                        ELSE 'OU=Domain Controllers' END AS target_label,
                   CASE WHEN p.target_kind = 'domain' THEN dm.dn_current
                        ELSE 'OU=Domain Controllers,' || dm.dn_current END AS target_dn
            FROM pol p
            CROSS JOIN dom dm
            LEFT JOIN LATERAL (
                SELECT x.object_guid FROM directory_object x
                WHERE x.client_id = %(client_id)s AND NOT x.is_deleted
                  AND lower(x.dn_current) = lower('OU=Domain Controllers,' || dm.dn_current)
                ORDER BY x.object_guid LIMIT 1
            ) ou ON p.target_kind = 'dc_ou'
        ),
        state AS (
            SELECT t.*, g.object_guid AS gpo_object_guid, g.display_name, g.gpo_flags,
                   lk.link_count, lk.enabled_link_count, lk.enforced
            FROM target t
            LEFT JOIN LATERAL (
                SELECT g.object_guid, g.display_name, g.gpo_flags
                FROM ad_gpo g
                JOIN directory_object go
                  ON go.object_guid = g.object_guid AND go.client_id = g.client_id AND NOT go.is_deleted
                WHERE g.client_id = %(client_id)s AND g.valid_to IS NULL
                  AND g.gpo_guid = t.gpo_guid
                ORDER BY g.object_guid LIMIT 1
            ) g ON TRUE
            LEFT JOIN LATERAL (
                SELECT count(*) AS link_count,
                       count(*) FILTER (WHERE e.link_enabled) AS enabled_link_count,
                       bool_or(e.link_enforced) AS enforced
                FROM gpo_link_edge e
                WHERE e.client_id = %(client_id)s AND e.valid_to IS NULL
                  AND e.gpo_guid = g.object_guid
                  AND e.container_guid = t.target_guid
            ) lk ON TRUE
        ),
        issues AS (
            SELECT s.*,
                   ARRAY_REMOVE(ARRAY[
                       CASE WHEN s.gpo_object_guid IS NULL THEN 'does not exist' END,
                       CASE WHEN s.gpo_object_guid IS NOT NULL AND COALESCE(s.link_count, 0) = 0
                            THEN 'is not linked to ' || s.target_label
                                 || CASE WHEN s.target_guid IS NULL THEN ' (container not found)' ELSE '' END END,
                       CASE WHEN s.gpo_object_guid IS NOT NULL AND s.link_count > 0
                                 AND s.enabled_link_count = 0
                            THEN 'has its link to ' || s.target_label || ' disabled' END,
                       CASE WHEN s.gpo_flags = 3 THEN 'has all settings disabled'
                            WHEN s.gpo_flags = 2 THEN 'has its computer settings disabled' END
                   ], NULL) AS problems
            FROM state s
        )
        SELECT
            'fail' AS status,
            i.gpo_object_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            i.policy_name || ' {' || upper(i.gpo_guid::text) || '} of domain '
                || COALESCE(i.dns_root, '(unknown)') || ' '
                || array_to_string(i.problems, ' and ') AS summary,
            jsonb_build_object(
                'policy', i.policy_name,
                'gpo_guid', upper(i.gpo_guid::text),
                'display_name', i.display_name,
                'exists', i.gpo_object_guid IS NOT NULL,
                'expected_link_target', i.target_dn,
                'link_target_found', i.target_guid IS NOT NULL,
                'link_count', i.link_count,
                'enabled_link_count', i.enabled_link_count,
                'link_enforced', i.enforced,
                'gpo_flags', i.gpo_flags,
                'problems', to_jsonb(i.problems)
            ) AS detail
        FROM issues i
        WHERE cardinality(i.problems) > 0
    """,
}
