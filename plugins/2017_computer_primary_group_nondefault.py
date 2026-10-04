"""
Plugin 2017: Computer Primary Group ID Set to a Non-Default, Non-Privileged Value

Complements plugin 2015 (which flags the worst case: primaryGroupID set
to a privileged group). Default for an ordinary computer is 515 (Domain
Computers); default for a genuine domain controller is 516 (Domain
Controllers) or 521 (Read-only Domain Controllers). Deliberately
excludes anything already covered by 2015 to avoid double-reporting the
same underlying condition under two plugin IDs.

[v1.3] Role is now taken per DC type: a writable DC expects 516, a
read-only DC 521 (ad_computer.is_read_only_dc, schema v36) and any other
computer 515. Before, RODCs (no SERVER_TRUST_ACCOUNT bit) were treated as
ordinary computers and every RODC was reported for its default 521. The
exclusion list now mirrors plugin 2015 exactly, so 516 on a non-DC (DCSync
persistence) and 521/498 on a non-DC go to 2015 at critical/high instead
of being reported here at low. Dropped the claim that this rule fires for
a DC outside the Domain Controllers OU: the query never looked at the DN.
"""

PLUGIN = {
    "plugin_id": 2017,
    "category": "Computer Accounts",
    "name": "Computer Primary Group ID Set to a Non-Default, Non-Privileged Value",
    "version": "1.3",
    "revision_date": "2026-10-04",
    "remediation": (
        "Unless strongly justified, change the primary group back to "
        "its default: Domain Computers (RID 515) for an ordinary "
        "computer, Domain Controllers (RID 516) for a writable DC, or "
        "Read-only Domain Controllers (RID 521) for an RODC. Investigate "
        "why it was set to a non-default value in the first place -- this "
        "attribute is a hidden group-membership channel separate from "
        "the ordinary member/memberOf pair and is rarely reviewed."
    ),
    "control_id": "PRIV-204",
    "framework_tags": [],
    "references": [],
    "description": (
        "Same reasoning as plugin 1023, applied to computer accounts. "
        "Flags any deviation from the correct default for the account's "
        "actual role (515 for an ordinary computer, 516 for a writable "
        "DC, 521 for a read-only DC) that isn't already covered by "
        "plugin 2015 (privileged RIDs, including 516/521/498 on a "
        "computer that is not that kind of DC). Unlike PingCastle's "
        "S-C-PrimaryGroup, DC placement outside the Domain Controllers "
        "OU is not checked here."
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
            'Computer Account ' || COALESCE(c.sam_account_name, c.object_guid::text)
                || ' has an unusual primaryGroupID (' || c.primary_group_id || ')' AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'primary_group_id', c.primary_group_id,
                'is_domain_controller', c.is_domain_controller,
                'is_read_only_dc', c.is_read_only_dc
            ) AS detail
        FROM ad_computer c
        WHERE c.valid_to IS NULL
          AND c.client_id = %(client_id)s
          AND c.primary_group_id IS NOT NULL
          AND NOT (
                (c.is_domain_controller AND NOT c.is_read_only_dc AND c.primary_group_id = 516)
                OR (c.is_read_only_dc AND c.primary_group_id = 521)
                OR (NOT c.is_domain_controller AND c.primary_group_id = 515)
              )
          -- exactly plugin 2015's set
          AND NOT (c.primary_group_id IN (512, 518, 519, 520)
                   OR (c.primary_group_id = 516
                       AND (NOT c.is_domain_controller OR c.is_read_only_dc))
                   OR (c.primary_group_id IN (498, 521) AND NOT c.is_domain_controller))
    """,
}
