"""
Plugin 2034: Constrained Delegation Configured to a Non-Existent ("Ghost") SPN

Confirmed as a genuine gap via a real Purple Knight (Semperis) sample
report reviewed during this project's tooling comparison: an object's
msDS-AllowedToDelegateTo can list a service principal name that
doesn't actually exist anywhere in the domain -- adprofiler.py already
had to resolve every constrained-delegation target SPN against the
domain's collected SPNs to build a proper delegation_edge row (see
collect_delegation_edges()), but before this plugin's supporting
collector change, an unresolved SPN was simply discarded, tallied only
as an anonymous counter in the console summary.

This is worth surfacing because a "ghost SPN" is a pre-staging or
clean-up artifact an attacker can exploit directly: register a
computer account (or otherwise obtain control of a principal) whose
own SPN happens to match the dangling reference, and the existing,
already-granted constrained delegation right becomes usable against
that newly-registered target -- no ACL change, no approval, nothing
else needs to happen. This is exactly as viable whether the ghost SPN
is leftover from a decommissioned server nobody cleaned up after, or
was deliberately pre-staged.
"""

PLUGIN = {
    "plugin_id": 2034,
    "category": "Computer Accounts",
    "name": "Constrained Delegation Configured to a Non-Existent (\"Ghost\") SPN",
    "version": "1.0",
    "revision_date": "2026-07-31",
    "remediation": (
        "Remove the dangling entry from msDS-AllowedToDelegateTo "
        "(Attribute Editor tab in ADUC, or `Set-ADComputer -Identity "
        "<name> -Remove @{'msDS-AllowedToDelegateTo'='<the SPN>'}`) "
        "unless a specific, currently-planned reason exists to keep it "
        "-- for example, a server rebuild in progress that will "
        "shortly re-register the exact same SPN. If kept intentionally, "
        "document why and revisit once the target is back in service; "
        "otherwise, treat this the same as any other unused, "
        "over-broad grant and remove it."
    ),
    "control_id": "CHAIN-108",
    "framework_tags": [],
    "references": [
        {"title": "Semperis Purple Knight -- Indicators of Exposure",
         "url": "https://www.semperis.com/purple-knight/"},
    ],
    "description": (
        "An object's constrained delegation configuration "
        "(msDS-AllowedToDelegateTo) references a service principal "
        "name that does not currently exist anywhere in the domain. "
        "An attacker who can register or take control of a principal "
        "whose SPN happens to match the dangling reference can use "
        "the existing delegation grant against it directly -- no ACL "
        "change or approval needed."
    ),
    "base_severity": "medium",
    "query": """
        SELECT
            'fail' AS status,
            u.source_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Account ' || COALESCE(do2.sam_account_name, u.source_guid::text)
                || ' has constrained delegation configured to a non-existent SPN: "'
                || u.target_spn || '"' AS summary,
            jsonb_build_object(
                'sam_account_name', do2.sam_account_name,
                'object_class', do2.object_class,
                'target_spn', u.target_spn
            ) AS detail
        FROM unresolved_delegation_target_edge u
        JOIN directory_object do2 ON do2.object_guid = u.source_guid AND do2.client_id = u.client_id
        WHERE u.client_id = %(client_id)s
          AND u.valid_to IS NULL
    """,
}
