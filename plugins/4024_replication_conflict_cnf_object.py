"""
Plugin 4024: Replication Conflict (CNF:) Object Present

Confirmed against multiple independent sources (Microsoft Q&A,
ITPro Today, and direct technical write-ups of the mechanism) before
building this: when two domain controllers each create or rename an
object to the same name in the same container before replicating with
each other, AD resolves the resulting naming collision by appending
"CNF:<objectGUID>" to the losing object's RDN, rather than silently
dropping either object. This is normal, automatic conflict resolution
-- not evidence of compromise by itself -- but a surviving CNF object
means something didn't get cleanly reconciled and is sitting in the
directory under an unexpected, GUID-suffixed name until someone
resolves it manually (AD does not do this automatically).

Detected via a substring match against dn_current, which is already
universally collected for every object -- no new collector work
needed. This catches the well-documented, most common conflict
signature; a minority of conflicts instead surface as a duplicate
sAMAccountName or a $DUPLICATE-<hex RID> value with no CNF: marker at
all, which this plugin does not attempt to detect -- a known,
documented gap rather than a silent one.
"""

PLUGIN = {
    "plugin_id": 4024,
    "category": "Domain",
    "name": "Replication Conflict (CNF:) Object Present",
    "version": "1.0",
    "revision_date": "2026-08-05",
    "remediation": (
        "Investigate why the conflict occurred -- most commonly two "
        "DCs creating/renaming an object with the same name in the "
        "same container before replicating with each other, or a DC "
        "returning from an extended outage with stale (lingering) "
        "data. Confirm which of the two objects (the CNF-suffixed one, "
        "or its non-suffixed counterpart) is the one actually wanted, "
        "then either rename the CNF object to something meaningful and "
        "keep it, or delete it if it's a genuine duplicate. Multiple "
        "CNF objects appearing together can indicate a broader "
        "replication health problem (e.g. a DC offline longer than the "
        "tombstone lifetime) worth investigating with `repadmin "
        "/showrepl` and `repadmin /replsummary` across all DCs, not "
        "just resolving object-by-object."
    ),
    "control_id": "DOM-424",
    "framework_tags": [],
    "references": [
        {"title": "PingCastle: Replication rules -- S-Duplicate",
         "url": "https://pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
        {"title": "Microsoft Q&A: All about Active Directory CNF object finding, validation and removing",
         "url": "https://learn.microsoft.com/en-us/answers/questions/101494/all-about-active-directory-cnf-object-finding-vali"},
    ],
    "description": (
        "An object's distinguished name contains a 'CNF:<GUID>' "
        "conflict-resolution marker, meaning two domain controllers "
        "created or renamed an object to the same name in the same "
        "container before replicating with each other. AD's own "
        "conflict resolution renamed the losing object automatically "
        "rather than dropping it -- a surviving CNF object means the "
        "situation wasn't cleanly reconciled and needs manual review. "
        "Not evidence of compromise by itself, but worth understanding "
        "why it happened, especially if multiple appear together."
    ),
    "base_severity": "low",
    "query": """
        SELECT
            'warn' AS status,
            do2.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'Object "' || COALESCE(do2.sam_account_name, do2.dn_current)
                || '" carries a replication conflict marker (CNF:) in its distinguished name' AS summary,
            jsonb_build_object(
                'sam_account_name', do2.sam_account_name,
                'object_class', do2.object_class,
                'dn_current', do2.dn_current
            ) AS detail
        FROM directory_object do2
        WHERE do2.client_id = %(client_id)s
          AND do2.dn_current LIKE '%%CNF:%%'
          AND NOT COALESCE(do2.is_deleted, false)
    """,
}
