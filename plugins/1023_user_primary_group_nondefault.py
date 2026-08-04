"""
Plugin 1023: User Primary Group ID Set to a Non-Default, Non-Privileged Value

Complements plugin 1016 (which flags the WORST case: primaryGroupID set
to a privileged group). PingCastle's own version of this check is
broader: primaryGroupID is a hidden group-membership channel distinct
from the member/memberOf attribute pair and rarely reviewed, so ANY
deviation from a legitimate default is worth surfacing, not just the
privileged case. Deliberately excludes anything already covered by 1016
to avoid double-reporting the same underlying condition under two
plugin IDs.

[v1.1] Fixed a real false positive found against production data: the
built-in Guest account correctly has primaryGroupID=514 (Domain Guests),
not 513 (Domain Users) -- a genuine, expected default for that account,
not a stealth-membership anomaly. PingCastle's own remediation text
actually says "513 or 514 for users"; v1.0 noted that in its docstring
but failed to actually encode 514 as an acceptable value in the query
itself.
"""

PLUGIN = {
    "plugin_id": 1023,
    "category": "User Accounts",
    "name": "User Primary Group ID Set to a Non-Default, Non-Privileged Value",
    "version": "1.3",
    "revision_date": "2026-07-15",
    "remediation": (
        "Unless strongly justified, change the primary group back to "
        "its default (Domain Users, RID 513) via Active Directory Users "
        "and Computers: open the account, go to the Member Of tab, add "
        "Domain Users if not already present, select it, and click "
        "\"Set Primary Group.\" Investigate why it was set to a "
        "non-default value in the first place -- this attribute is a "
        "hidden group-membership channel separate from the ordinary "
        "member/memberOf pair and is rarely reviewed."
    ),
    "control_id": "PRIV-108",
    "framework_tags": [],
    "references": [],
    "description": (
        "PingCastle's own check for this condition (S-PrimaryGroup) is "
        "broader than plugin 1016: primaryGroupID is a hidden group-"
        "membership channel, separate from and rarely cross-checked "
        "against the ordinary member/memberOf attribute pair, and can "
        "be used to grant membership that standard group-membership "
        "reviews simply never look at. This flags any deviation from "
        "the true default (513, Domain Users) that isn't already "
        "covered by plugin 1016's privileged-RID case -- lower severity "
        "than that plugin's finding, since the specific value here "
        "isn't itself a known-privileged group, but still worth "
        "investigating precisely because this attribute is so rarely "
        "reviewed by normal tooling."
    ),
    "base_severity": "low",
    "query": """
        SELECT
            'warn' AS status,
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'User Account ' || COALESCE(u.user_principal_name, u.sam_account_name)
                || ' has an unusual primaryGroupID (' || u.primary_group_id || ')' AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'user_principal_name', u.user_principal_name,
                'primary_group_id', u.primary_group_id
            ) AS detail
        FROM ad_user u
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          AND u.primary_group_id IS NOT NULL
          AND u.primary_group_id NOT IN (513, 514)
          AND u.primary_group_id NOT IN (512, 518, 519, 520, 544)
    """,
}
