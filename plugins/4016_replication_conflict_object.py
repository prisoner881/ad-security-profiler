"""
Plugin 4016: Replication Conflict Object Present

When two domain controllers each independently create or rename an
object to the same distinguished name (or, separately, the same
sAMAccountName) before replicating with each other, Active Directory's
conflict resolution keeps both objects rather than silently discarding
one: the "losing" copy (chosen deterministically, not necessarily the
less important one) is automatically renamed by appending a
CNF:<original-GUID> suffix to its RDN, or, for a sAMAccountName clash
specifically, by prefixing the value with $duplicate-. Confirmed
against PingCastle's own equivalent check (S-Duplicate, Replication
category) and directly derivable from data this project already
collects: dn_current and sam_account_name are both stored verbatim on
every directory_object row, and the CNF:/$duplicate- markers are
literal, unambiguous substrings within them.
"""

PLUGIN = {
    "plugin_id": 4016,
    "category": "Domain",
    "name": "Replication Conflict Object Present",
    "version": "1.0",
    "revision_date": "2026-07-18",
    "remediation": (
        "Identify why two domain controllers independently created or "
        "renamed an object to the same name before replicating -- this "
        "is usually a process failure (e.g. a provisioning script or "
        "helpdesk tool running against two DCs without coordination, or "
        "a WAN partition during a bulk operation), not by itself a "
        "sign of compromise. Review both the conflict object and "
        "whatever object it collided with, confirm which one should "
        "remain, and remove the other -- the conflict-renamed copy is "
        "rarely the one anyone intended to keep using under that name. "
        "Once resolved, review the process that caused the collision to "
        "prevent recurrence."
    ),
    "control_id": "HYGIENE-401",
    "framework_tags": [],
    "references": [],
    "description": (
        "When two domain controllers each independently create or "
        "rename an object to the same distinguished name (or the same "
        "sAMAccountName) before replicating with each other, Active "
        "Directory's conflict resolution keeps both objects: the "
        "'losing' copy (chosen deterministically by the replication "
        "algorithm, not necessarily the less important object) is "
        "automatically renamed with a CNF:<original-GUID> suffix on its "
        "RDN, or, for a sAMAccountName clash specifically, a "
        "$duplicate-<GUID> prefix on the value. Genuinely indicates a "
        "process failure in how objects are being created or modified "
        "against multiple domain controllers, and is worth "
        "investigating and cleaning up even though it isn't itself an "
        "active vulnerability. Confirmed against PingCastle's own "
        "equivalent check (S-Duplicate)."
    ),
    "base_severity": "low",
    "query": """
        SELECT
            'warn' AS status,
            o.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'Object "' || COALESCE(o.sam_account_name, o.dn_current)
                || '" appears to be a replication conflict object' AS summary,
            jsonb_build_object(
                'dn_current', o.dn_current,
                'sam_account_name', o.sam_account_name,
                'object_class', o.object_class,
                'matched_via', (CASE
                    WHEN o.dn_current ILIKE '%%CNF:%%' THEN 'dn_cnf_marker'
                    ELSE 'samaccountname_duplicate_marker'
                END)
            ) AS detail
        FROM directory_object o
        WHERE o.client_id = %(client_id)s
          AND NOT o.is_deleted
          AND (
                o.dn_current ILIKE '%%CNF:%%'
                OR o.sam_account_name ILIKE '$duplicate-%%'
              )
    """,
}
