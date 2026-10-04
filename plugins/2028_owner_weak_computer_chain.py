"""
Plugin 2028: Domain Root or AdminSDHolder Owned by an Unsupported or Dormant Computer

Refines plugin 5006 (any unexpected owner) with the computer-side
equivalent of plugin 1032: the owner is a computer account that is
itself independently weak -- unsupported OS or dormant. A computer
owning either object is already highly unusual on its own (5006 already
flags it); this adds specific, actionable context about exactly how
exploitable that owner is.

[v1.2] Emits one finding per owning computer rather than one per owned
object. A computer owning both the domain root and AdminSDHolder produced
two rows with the same object_guid and broke the one-open-version-per-
identity constraint; both are now named in one summary (in a stable
order) and listed in detail.object_dns, which replaces detail.object_dn.

[v1.3] Unsupported-OS list aligned with plugins 2024/2025/2027: Windows
10 Enterprise LTSC (2019/2021 and IoT LTSC are still in support) is no
longer matched, Windows 2000 and Windows NT now are. The ad_domain test
is client-scoped, deleted owner objects are excluded, and the owner's
name in the summary is NULL-safe.
"""

PLUGIN = {
    "plugin_id": 2028,
    "category": "Computer Accounts",
    "name": "Domain Root or AdminSDHolder Owned by an Unsupported or Dormant Computer",
    "version": "1.3",
    "revision_date": "2026-10-04",
    "remediation": (
        "Take ownership back to a recognized default holder immediately "
        "(see plugin 5006's remediation) -- this is a higher-priority "
        "case than an ordinary unexpected-owner finding, since the "
        "owning machine itself has an independent, exploitable "
        "weakness. Investigate whether this machine's own weakness has "
        "already been exploited to reach this ownership."
    ),
    "control_id": "CHAIN-206",
    "framework_tags": [
        "NIST-800-53-AC-3",
        "NIST-800-53-AC-6",
        "NIST-800-53-AC-6(1)",
        "NIST-800-53-SI-2",
        "NIST-800-53-RA-5",
        "NIST-800-53-SA-22",
        "NIST-800-53-AC-2",
        "NIST-800-53-AC-2(3)",
        "NIST-CSF-2.0-PR.AA-05",
        "NIST-CSF-2.0-ID.RA-01",
        "NIST-CSF-2.0-PR.PS-02",
        "NIST-CSF-2.0-PR.AA-01",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.2",
        "PCI-DSS-4.0-6.3.3",
        "PCI-DSS-4.0-12.3.4",
        "PCI-DSS-4.0-8.2.6",
        "CIS-CSC-8-3.3",
        "CIS-CSC-8-6.8",
        "CIS-CSC-8-2.2",
        "CIS-CSC-8-7.3",
        "CIS-CSC-8-5.3",
        "ISO-27001-2022-A.5.15",
        "ISO-27001-2022-A.8.3",
        "ISO-27001-2022-A.8.8",
        "ISO-27001-2022-A.5.18",
        "SOC2-CC6.3",
        "SOC2-CC7.1",
        "SOC2-CC6.2",
        "HIPAA-164.312(a)(1)",
        "HIPAA-164.308(a)(3)(ii)(C)",
        "MITRE-ATTCK-T1003.006",
    ],
    "references": [
        {"title": "BloodHound (SpecterOps): WriteOwner edge",
         "url": "https://bloodhound.specterops.io/resources/edges/write-owner"},
    ],
    "description": (
        "Refines plugin 5006 (any unexpected owner of the domain root "
        "or AdminSDHolder) with the computer-side equivalent of plugin "
        "1032: the owner is a computer account that is itself "
        "independently weak (unsupported OS, plugin 2003, or dormant, "
        "plugin 2006). A computer owning either object is already "
        "highly unusual; an easy-to-compromise owning machine makes it "
        "meaningfully worse than an unexpected-but-otherwise-solid one."
    ),
    "base_severity": "critical",
    "query": """
        -- [v1.2] One row per owning computer. The finding is keyed on the
        -- owner's GUID, so a computer owning both the domain root and
        -- AdminSDHolder (or more than one domain root) used to emit one row
        -- per owned object with the same object_guid and collide on
        -- idx_cef_one_open_version. Owned objects are now aggregated, sorted,
        -- into the summary and detail.object_dns. The owner is also resolved
        -- with a join rather than a scalar subquery, which raised an error if
        -- two directory objects ever carried the same SID.
        WITH owned AS (
            SELECT owner.object_guid AS owner_guid,
                   string_agg(DISTINCT CASE WHEN target.dn_current ILIKE 'CN=AdminSDHolder,%%'
                                            THEN 'AdminSDHolder' ELSE 'the domain root' END,
                              ' and '
                              ORDER BY CASE WHEN target.dn_current ILIKE 'CN=AdminSDHolder,%%'
                                            THEN 'AdminSDHolder' ELSE 'the domain root' END)
                       AS owned_list,
                   jsonb_agg(target.dn_current ORDER BY target.dn_current, target.object_guid)
                       AS object_dns
            FROM directory_object target
            JOIN directory_object owner
                ON owner.object_sid = target.owner_sid AND owner.client_id = target.client_id
               AND NOT owner.is_deleted
            WHERE target.client_id = %(client_id)s
              AND target.owner_sid IS NOT NULL
              AND (
                    target.dn_current ILIKE 'CN=AdminSDHolder,%%'
                    OR EXISTS (SELECT 1 FROM ad_domain d WHERE d.object_guid = target.object_guid AND d.client_id = target.client_id AND d.valid_to IS NULL)
                  )
            GROUP BY owner.object_guid
        )
        SELECT
            'fail' AS status,
            owner.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'critical' AS fd_severity,
            'Computer Account ' || COALESCE(owner.sam_account_name, owner.object_guid::text)
                || ' owns ' || ow.owned_list
                || ' and is independently weak: '
                || (SELECT string_agg(x, ', ') FROM (VALUES
                        (CASE WHEN (owner.operating_system ILIKE '%%windows 10%%' AND owner.operating_system NOT ILIKE '%%LTSC%%') OR owner.operating_system ILIKE '%%server 2012%%'
                              OR owner.operating_system ILIKE '%%server 2008%%' OR owner.operating_system ILIKE '%%server 2003%%'
                              OR owner.operating_system ILIKE '%%windows 7%%' OR owner.operating_system ILIKE '%%windows 8%%'
                              OR owner.operating_system ILIKE '%%windows xp%%' OR owner.operating_system ILIKE '%%windows vista%%'
                              OR owner.operating_system ILIKE '%%windows 2000%%' OR owner.operating_system ILIKE '%%windows nt%%'
                              THEN 'unsupported OS (' || owner.operating_system || ')' END),
                        (CASE WHEN owner.last_logon_timestamp IS NULL OR owner.last_logon_timestamp < now() - interval '90 days'
                              THEN 'dormant' END)
                    ) AS v(x) WHERE x IS NOT NULL) AS summary,
            jsonb_build_object(
                'sam_account_name', owner.sam_account_name,
                'object_dns', ow.object_dns,
                'operating_system', owner.operating_system,
                'last_logon_timestamp', owner.last_logon_timestamp
            ) AS detail
        FROM owned ow
        JOIN ad_computer owner
            ON owner.object_guid = ow.owner_guid
           AND owner.client_id = %(client_id)s
           AND owner.valid_to IS NULL
        WHERE (
                (owner.operating_system ILIKE '%%windows 10%%' AND owner.operating_system NOT ILIKE '%%LTSC%%') OR owner.operating_system ILIKE '%%server 2012%%'
                OR owner.operating_system ILIKE '%%server 2008%%' OR owner.operating_system ILIKE '%%server 2003%%'
                OR owner.operating_system ILIKE '%%windows 7%%' OR owner.operating_system ILIKE '%%windows 8%%'
                OR owner.operating_system ILIKE '%%windows xp%%' OR owner.operating_system ILIKE '%%windows vista%%'
                OR owner.operating_system ILIKE '%%windows 2000%%' OR owner.operating_system ILIKE '%%windows nt%%'
                OR owner.last_logon_timestamp IS NULL OR owner.last_logon_timestamp < now() - interval '90 days'
              )
    """,
}
