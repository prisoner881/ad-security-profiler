"""
Plugin 4002: Effective Minimum Password Length Below Recommended Threshold

Directly cited against DISA Windows Server STIG V-254291 (minimum 14
characters), confirmed across multiple STIG versions (Server 2016, 2019,
2022, and the Windows 10/11 client equivalents all specify the same 14).

[v2.0, corrected] The previous version checked only the domain-wide
default policy (ad_domain.pwd_policy_min_length), ignoring Fine-Grained
Password Policies (FGPPs/PSOs) entirely -- even though adprofiler.py
already collects full FGPP detail (msDS-MinimumPasswordLength,
precedence, and resolved msDS-PSOAppliesTo targets). A real production
domain where the visible domain-wide default was weak, but an FGPP
correctly enforced a strong effective policy for the actual user
population, produced a false FAIL under that version -- the domain
default was accurately reported, but it wasn't the policy actually in
effect for anyone.

Rebuilt here to compute each enabled user's genuinely EFFECTIVE minimum
password length, following Microsoft's own documented resolution rules
exactly (confirmed across multiple independent primary and technical
sources, not assumed): a PSO applied directly to a user always takes
precedence over one applied via group membership, regardless of either
PSO's precedence number; among PSOs of the same kind (direct, or via
group) that apply to the same user, the one with the lowest
msDS-PasswordSettingsPrecedence value wins; a user with no applicable
PSO at all falls back to the domain-wide default. Group-based PSO
targets are resolved via v_effective_group_membership, so nested group
membership is accounted for the same way it already is everywhere else
in this project.

Reports one row per DISTINCT effective policy actually in force (a
specific FGPP, or "domain default") that leaves at least one enabled
user below the threshold -- not one row per user, which could mean
thousands of rows on a large domain, and not a single domain-wide row,
which is exactly the framing that produced the original false positive.
"""

PLUGIN = {
    "plugin_id": 4002,
    "category": "Domain",
    "name": "Effective Minimum Password Length Below Recommended Threshold",
    "version": "2.0",
    "revision_date": "2026-08-05",
    "remediation": (
        "For the specific policy source named in this finding "
        "(a Fine-Grained Password Policy, or the domain-wide default), "
        "increase MinPasswordLength / \"Minimum password length\" to at "
        "least 14 characters -- `Set-ADFineGrainedPasswordPolicy "
        "-Identity <policy> -MinPasswordLength 14` for an FGPP, or "
        "Computer Configuration >> Windows Settings >> Security "
        "Settings >> Account Policies >> Password Policy for the "
        "domain-wide default. Confirm which population is actually "
        "affected via `Get-ADUserResultantPasswordPolicy` for a sample "
        "of users before assuming the domain-wide default is what "
        "matters -- an FGPP may already be doing the right thing for "
        "most users even when the visible domain default looks weak."
    ),
    "control_id": "POLICY-002",
    "framework_tags": ["DISA-STIG"],
    "references": [
        {"title": "Microsoft: Minimum password length",
         "url": "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/minimum-password-length"},
        {"title": "Microsoft: Fine-Grained Password Policies -- precedence and resultant PSO",
         "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/introduction-to-active-directory-administrative-center-enhancements--level-100-"},
    ],
    "description": (
        "Directly cited against DISA Windows Server STIG V-254291: "
        "\"If the value for the Minimum password length is less than "
        "14 characters, this is a finding.\" Computes each enabled "
        "user's genuinely effective minimum password length -- "
        "following a directly-assigned FGPP, then a group-assigned "
        "FGPP (lowest precedence wins), then the domain-wide default, "
        "in that order, matching Microsoft's own documented resolution "
        "rules -- rather than assuming the domain-wide default is what "
        "everyone actually gets."
    ),
    "base_severity": "medium",
    "query": """
        WITH domain_default AS (
            SELECT d.object_guid AS domain_guid, d.dns_root, d.pwd_policy_min_length AS min_length
            FROM ad_domain d
            WHERE d.client_id = %(client_id)s AND d.valid_to IS NULL
        ),
        active_fgpps AS (
            SELECT f.object_guid AS pso_guid, f.policy_name, f.precedence, f.min_pwd_length
            FROM ad_fgpp f
            WHERE f.client_id = %(client_id)s AND f.valid_to IS NULL
              AND f.min_pwd_length IS NOT NULL
        ),
        direct_assignments AS (
            SELECT e.target_guid AS user_guid, af.pso_guid, af.policy_name, af.precedence, af.min_pwd_length
            FROM fgpp_applies_to_edge e
            JOIN active_fgpps af ON af.pso_guid = e.pso_guid
            JOIN ad_user u ON u.object_guid = e.target_guid AND u.client_id = e.client_id AND u.valid_to IS NULL
            WHERE e.client_id = %(client_id)s AND e.valid_to IS NULL
        ),
        group_assignments AS (
            SELECT vem.member_guid AS user_guid, af.pso_guid, af.policy_name, af.precedence, af.min_pwd_length
            FROM fgpp_applies_to_edge e
            JOIN active_fgpps af ON af.pso_guid = e.pso_guid
            JOIN v_effective_group_membership vem ON vem.group_guid = e.target_guid AND vem.client_id = e.client_id
            WHERE e.client_id = %(client_id)s AND e.valid_to IS NULL
        ),
        best_direct AS (
            SELECT DISTINCT ON (user_guid) user_guid, pso_guid, policy_name, min_pwd_length
            FROM direct_assignments
            ORDER BY user_guid, precedence ASC, pso_guid ASC
        ),
        best_group AS (
            SELECT DISTINCT ON (user_guid) user_guid, pso_guid, policy_name, min_pwd_length
            FROM group_assignments
            ORDER BY user_guid, precedence ASC, pso_guid ASC
        ),
        -- [v2.0] Per Microsoft's documented resolution order: a PSO
        -- applied directly to the user always wins over one applied
        -- via group membership, regardless of precedence -- so
        -- best_direct is only overridden by best_group when no direct
        -- assignment exists at all, and the domain default only
        -- applies when neither does.
        effective_per_user AS (
            SELECT u.object_guid AS user_guid,
                   COALESCE(bd.pso_guid, bg.pso_guid, dd.domain_guid) AS source_guid,
                   COALESCE(bd.policy_name, bg.policy_name, 'Domain Default Policy') AS source_name,
                   COALESCE(bd.min_pwd_length, bg.min_pwd_length, dd.min_length) AS effective_min_length
            FROM ad_user u
            CROSS JOIN domain_default dd
            LEFT JOIN best_direct bd ON bd.user_guid = u.object_guid
            LEFT JOIN best_group bg ON bg.user_guid = u.object_guid
            WHERE u.client_id = %(client_id)s AND u.valid_to IS NULL AND u.is_enabled
        ),
        affected_populations AS (
            SELECT source_guid, source_name, effective_min_length, count(*) AS affected_user_count
            FROM effective_per_user
            WHERE effective_min_length IS NOT NULL AND effective_min_length < 14
            GROUP BY source_guid, source_name, effective_min_length
        )
        SELECT
            'fail' AS status,
            ap.source_guid AS object_guid,
            'CAT_II' AS stig_severity,
            'DISA Windows Server STIG V-254291: minimum password length must be '
                'at least 14 characters' AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN ap.effective_min_length < 8 THEN 'high' ELSE 'medium' END AS fd_severity,
            ap.affected_user_count || ' enabled user(s) have an effective minimum password length of '
                || ap.effective_min_length || ' characters via "' || ap.source_name
                || '", below the 14-character STIG minimum' AS summary,
            jsonb_build_object(
                'policy_source', ap.source_name,
                'effective_min_length', ap.effective_min_length,
                'affected_user_count', ap.affected_user_count
            ) AS detail
        FROM affected_populations ap
    """,
}
