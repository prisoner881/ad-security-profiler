"""
Plugin 4007: Domain Account Lockout Duration Too Short

Distinct from lockout being disabled entirely (plugin 4003): this fires
when lockout IS enabled but auto-unlocks quickly enough to provide only
token protection against sustained password-guessing. DISA STIG
guidance commonly specifies a minimum lockout duration of 15 minutes.
Only evaluated when lockout is actually enabled, to avoid double-
reporting the same underlying condition as plugin 4003.

[v1.2] Collector 0.5.15 stores a lockoutDuration of 0 as 0 instead of
NULL. 0 means "locked until an administrator unlocks", the strictest
setting and compliant with STIG V-254285, so it is now excluded
explicitly; otherwise this version would have reported it as
"0 minutes". Durations under a minute are shown in seconds instead of
"0 minutes". The detail also reports enabled_users_on_domain_default
(enabled users with no Fine-Grained Password Policy).
"""

PLUGIN = {
    "plugin_id": 4007,
    "category": "Domain",
    "name": "Domain Account Lockout Duration Too Short",
    "version": "1.2",
    "revision_date": "2026-10-04",
    "remediation": (
        "Increase the domain-wide account lockout duration to at least "
        "15 minutes (Computer Configuration >> Windows Settings >> "
        "Security Settings >> Account Policies >> Account Lockout "
        "Policy >> \"Account lockout duration\"). A very short duration "
        "provides only token protection against a sustained "
        "password-guessing attempt -- the attacker simply waits out the "
        "auto-unlock and resumes."
    ),
    "control_id": "POLICY-007",
    "framework_tags": [
        "NIST-800-53-AC-7",
        "NIST-800-53-IA-5",
        "NIST-CSF-2.0-PR.AA-01",
        "PCI-DSS-4.0-8.3.4",
        "CIS-CSC-8-5.2",
        "ISO-27001-2022-A.5.17",
        "SOC2-CC6.1",
        "HIPAA-164.308(a)(5)(ii)(D)",
        "DISA-STIG-V-254285",
        "MITRE-ATTCK-T1110.001",
    ],
    "references": [
        {"title": "Microsoft: Account lockout duration",
         "url": "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-duration"},
    ],
    "description": (
        "DISA STIG guidance commonly specifies a minimum account "
        "lockout duration of 15 minutes. A shorter duration provides "
        "only token protection -- an attacker running a sustained "
        "password-guessing attempt simply waits out the auto-unlock and "
        "resumes. Only evaluated when lockout is actually enabled "
        "(lockout_threshold > 0); a domain with lockout disabled "
        "entirely is a distinct, more severe condition already covered "
        "by plugin 4003, and this check deliberately doesn't also fire "
        "for that same underlying state. A duration of 0 (locked "
        "until an administrator unlocks) is compliant and not reported."
    ),
    "base_severity": "low",
    "query": """
        -- [v1.2] Users a PSO reaches through a global security group (PSOs
        -- ignore other group types), nested and primary-group membership
        -- included, plus users a PSO targets directly. Everyone else gets
        -- the domain default.
        WITH RECURSIVE pso_group_members AS (
            SELECT gme.member_guid
            FROM fgpp_applies_to_edge e
            JOIN ad_fgpp f ON f.object_guid = e.pso_guid AND f.client_id = e.client_id AND f.valid_to IS NULL
            JOIN ad_group g ON g.object_guid = e.target_guid AND g.client_id = e.client_id AND g.valid_to IS NULL
            JOIN group_member_edge gme ON gme.group_guid = g.object_guid AND gme.client_id = g.client_id
                                      AND gme.valid_to IS NULL
            WHERE e.client_id = %(client_id)s AND e.valid_to IS NULL
              AND (g.group_type & 2) <> 0 AND g.group_type < 0
            UNION
            SELECT gme.member_guid
            FROM pso_group_members m
            JOIN group_member_edge gme ON gme.group_guid = m.member_guid AND gme.client_id = %(client_id)s
                                      AND gme.valid_to IS NULL
        ),
        pso_covered_users AS (
            SELECT member_guid AS user_guid FROM pso_group_members
            UNION
            SELECT e.target_guid
            FROM fgpp_applies_to_edge e
            JOIN ad_fgpp f ON f.object_guid = e.pso_guid AND f.client_id = e.client_id AND f.valid_to IS NULL
            WHERE e.client_id = %(client_id)s AND e.valid_to IS NULL
        )
        SELECT
            'warn' AS status,
            d.object_guid,
            'CAT_III' AS stig_severity,
            'DISA Windows Server STIG V-254285: account lockout duration must be 15 '
                'minutes or greater, or 0 (until an administrator unlocks)' AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'Domain ' || COALESCE(d.dns_root, '(this domain)')
                || ' account lockout duration is '
                || CASE WHEN d.lockout_duration_seconds < 60
                        THEN d.lockout_duration_seconds || ' seconds'
                        ELSE (d.lockout_duration_seconds / 60) || ' minutes'
                   END
                || ', below the recommended 15-minute minimum' AS summary,
            jsonb_build_object(
                'dns_root', d.dns_root,
                'lockout_duration_seconds', d.lockout_duration_seconds,
                'lockout_duration_minutes', d.lockout_duration_seconds / 60,
                'enabled_users_on_domain_default', (
                    SELECT count(*) FROM ad_user u
                    WHERE u.client_id = d.client_id AND u.valid_to IS NULL AND u.is_enabled
                      AND NOT EXISTS (SELECT 1 FROM pso_covered_users c WHERE c.user_guid = u.object_guid))
            ) AS detail
        FROM ad_domain d
        WHERE d.valid_to IS NULL
          AND d.client_id = %(client_id)s
          AND d.lockout_threshold > 0
          -- [v1.2] 0 = locked until an administrator unlocks (compliant)
          AND d.lockout_duration_seconds > 0
          AND d.lockout_duration_seconds < 15 * 60
    """,
}
