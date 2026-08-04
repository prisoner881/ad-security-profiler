"""
Plugin 2017: Computer Primary Group ID Set to a Non-Default, Non-Privileged Value

Complements plugin 2015 (which flags the worst case: primaryGroupID set
to a privileged group). Default for an ordinary computer is 515 (Domain
Computers); default for a genuine domain controller is 516 (Domain
Controllers) or 521 (Read-only Domain Controllers). Deliberately
excludes anything already covered by 2015 to avoid double-reporting the
same underlying condition under two plugin IDs.
"""

PLUGIN = {
    "plugin_id": 2017,
    "category": "Computer Accounts",
    "name": "Computer Primary Group ID Set to a Non-Default, Non-Privileged Value",
    "version": "1.2",
    "revision_date": "2026-07-15",
    "remediation": (
        "Unless strongly justified, change the primary group back to "
        "its default: Domain Computers (RID 515) for an ordinary "
        "computer, or Domain Controllers (RID 516) / Read-only Domain "
        "Controllers (RID 521) for a genuine DC. Investigate why it was "
        "set to a non-default value in the first place -- this "
        "attribute is a hidden group-membership channel separate from "
        "the ordinary member/memberOf pair and is rarely reviewed. This "
        "rule also fires if a domain controller's computer object is "
        "not in the default \"Domain Controllers\" container, which is "
        "itself a non-recommended configuration worth investigating."
    ),
    "control_id": "PRIV-204",
    "framework_tags": [],
    "references": [],
    "description": (
        "Same reasoning as plugin 1023, applied to computer accounts. "
        "PingCastle's own version of this check (S-C-PrimaryGroup) "
        "notes it can also fire when a domain controller isn't in the "
        "default \"Domain Controllers\" container -- a separate, "
        "non-recommended configuration worth investigating in its own "
        "right, distinct from the primaryGroupID value itself. Flags "
        "any deviation from the correct default for the account's "
        "actual role (515 for an ordinary computer, 516/521 for a "
        "genuine DC) that isn't already covered by plugin 2015's "
        "privileged-RID case."
    ),
    "base_severity": "low",
    "query": """
        SELECT
            'warn' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'Computer Account ' || c.sam_account_name
                || ' has an unusual primaryGroupID (' || c.primary_group_id || ')' AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'primary_group_id', c.primary_group_id,
                'is_domain_controller', c.is_domain_controller
            ) AS detail
        FROM ad_computer c
        WHERE c.valid_to IS NULL
          AND c.client_id = %(client_id)s
          AND c.primary_group_id IS NOT NULL
          AND NOT (
                (c.is_domain_controller AND c.primary_group_id IN (516, 521))
                OR (NOT c.is_domain_controller AND c.primary_group_id = 515)
              )
          AND c.primary_group_id NOT IN (512, 518, 519, 520, 544)
    """,
}
