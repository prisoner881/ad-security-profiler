"""
Plugin 3001: Group Has SID History

Same technique as user-account plugin 1008 and computer-account plugin
2014, applied to group objects. Legitimate during domain/forest
migrations, but also a well-documented persistence and
privilege-escalation mechanism -- and arguably more consequential on a
group than an individual account, since group membership propagates to
everyone who is (or later becomes) a member.
"""

PLUGIN = {
    "plugin_id": 3001,
    "category": "Groups",
    "name": "Group Has SID History",
    "version": "1.2",
    "revision_date": "2026-07-15",
    "remediation": (
        "Investigate and confirm whether this is legitimate residue from "
        "a completed domain/forest migration. If migration is fully "
        "complete and SID history is no longer needed, clear it "
        "(`Set-ADGroup -Clear SIDHistory`). If found on a group with no "
        "known migration history, treat it as a probable compromise "
        "indicator and escalate to incident response rather than "
        "clearing it first -- a privileged SID injected into a group's "
        "history grants that privilege to every current and future "
        "member of the group, not just one account."
    ),
    "control_id": "PRIV-301",
    "framework_tags": ["MITRE-ATTCK-T1134.005"],
    "references": [
        {"title": "MITRE ATT&CK T1134.005: Access Token Manipulation -- SID-History Injection",
         "url": "https://attack.mitre.org/techniques/T1134/005/"},
        {"title": "Microsoft Defender for Identity: Unsecure SID-History attribute",
         "url": "https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-unsecure-sid-history-attribute"},
    ],
    "description": (
        "sIDHistory is legitimately populated during domain/forest "
        "migrations, but is also a well-documented persistence and "
        "privilege-escalation technique (MITRE ATT&CK T1134.005) -- the "
        "same reasoning as plugins 1008 and 2014, applied here to group "
        "objects. Arguably more consequential on a group than an "
        "individual account: a privileged SID injected into a group's "
        "history is inherited by every current and future member of "
        "that group, not just a single compromised principal."
    ),
    "base_severity": "high",
    "query": """
        SELECT
            'fail' AS status,
            g.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN g.is_protected_group THEN 'critical' ELSE 'high' END AS fd_severity,
            (CASE WHEN g.is_protected_group THEN 'Privileged ' ELSE '' END)
                || 'Group ' || g.sam_account_name
                || ' has SID history populated (' || array_length(g.sid_history, 1)
                || ' entrie(s))' AS summary,
            jsonb_build_object(
                'sam_account_name', g.sam_account_name,
                'sid_history', g.sid_history,
                'is_protected_group', g.is_protected_group,
                'member_count_direct', g.member_count_direct
            ) AS detail
        FROM ad_group g
        WHERE g.valid_to IS NULL
          AND g.client_id = %(client_id)s
          AND g.sid_history IS NOT NULL
          AND array_length(g.sid_history, 1) > 0
    """,
}
