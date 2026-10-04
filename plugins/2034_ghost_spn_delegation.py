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

[v1.1] One row per delegating account. The query used to emit one row
per unresolved SPN while keying the finding on the account's GUID, so an
account with two or more ghost SPNs -- the normal case, since KCD lists
usually carry both the NetBIOS and FQDN forms -- produced duplicate
identities and the whole plugin errored. The SPNs are now aggregated:
the summary lists them sorted (unchanged wording for a single SPN) and
detail.target_spns carries the list. Since collector v0.5.15 targets
resolve through the default sPNMappings HOST alias set (cifs/x is
answered by HOST/x), so the former flood of false "ghosts" for valid
cifs/http/... targets is gone. krbtgt/<DOMAIN> entries are excluded:
krbtgt is never a registered SPN, so such an entry is not a ghost but
delegation to the KDC itself, reported by plugin 1035. Deleted source
objects are excluded.

[v1.2] No query change. Since collector 0.5.16 targets resolve through
the forest's own sPNMappings (CN=Directory Service, stored as
ad_domain.spn_mappings), falling back to the default HOST alias set only
when that attribute is absent or unreadable -- exactly as the KDC
resolves them. A forest that added its own alias (e.g. a custom service
class mapped to host) therefore no longer produces false ghosts for it,
and a target whose class a forest REMOVED from sPNMappings is now
correctly reported as a ghost. Caveat: data collected by older
collectors was resolved against the default set only; the description
now states this.
"""

PLUGIN = {
    "plugin_id": 2034,
    "category": "Computer Accounts",
    "name": "Constrained Delegation Configured to a Non-Existent (\"Ghost\") SPN",
    "version": "1.2",
    "revision_date": "2026-10-04",
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
    "framework_tags": [
        "NIST-800-53-AC-3",
        "NIST-800-53-AC-6",
        "NIST-800-53-AC-6(1)",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.2",
        "CIS-CSC-8-3.3",
        "CIS-CSC-8-6.8",
        "ISO-27001-2022-A.5.15",
        "ISO-27001-2022-A.8.3",
        "SOC2-CC6.3",
        "HIPAA-164.312(a)(1)",
        "MITRE-ATTCK-T1550.003",
    ],
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
        "change or approval needed. Targets are resolved as the KDC "
        "resolves them: an exact SPN first, then the host's HOST/ SPN for "
        "service classes the forest's sPNMappings alias to host (collector "
        "0.5.16+; the default alias set when sPNMappings is unreadable or "
        "for data from older collectors, so a forest with customised "
        "mappings may show stale results until re-collected)."
    ),
    "base_severity": "medium",
    "query": """
        WITH ghost AS (
            SELECT DISTINCT u.source_guid, u.target_spn
            FROM unresolved_delegation_target_edge u
            WHERE u.client_id = %(client_id)s
              AND u.valid_to IS NULL
              -- krbtgt/<DOMAIN> is never a registered SPN: delegation to the KDC (plugin 1035)
              AND u.target_spn NOT ILIKE 'krbtgt/%%'
        )
        SELECT
            'fail' AS status,
            g.source_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Account ' || COALESCE(do2.sam_account_name, g.source_guid::text)
                || ' has constrained delegation configured to '
                || CASE WHEN count(*) = 1 THEN 'a non-existent SPN: '
                        ELSE count(*) || ' non-existent SPNs: ' END
                || string_agg('"' || g.target_spn || '"', ', ' ORDER BY lower(g.target_spn), g.target_spn)
                AS summary,
            jsonb_build_object(
                'sam_account_name', do2.sam_account_name,
                'object_class', do2.object_class,
                'target_spns', jsonb_agg(g.target_spn ORDER BY lower(g.target_spn), g.target_spn)
            ) AS detail
        FROM ghost g
        JOIN directory_object do2
          ON do2.object_guid = g.source_guid
         AND do2.client_id = %(client_id)s
         AND NOT do2.is_deleted
        GROUP BY g.source_guid, do2.sam_account_name, do2.object_class
        ORDER BY g.source_guid
    """,
}
