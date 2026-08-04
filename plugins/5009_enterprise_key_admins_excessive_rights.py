"""
Plugin 5009: Enterprise Key Admins Holds Excessive Rights on the Domain Root

A specific, well-documented, Microsoft-acknowledged bug, not a generic
"unexpected principal" case already covered by plugin 5003 in spirit --
built as its own dedicated finding because the SPECIFIC pattern here
has a known cause and a known, precise fix, which a generic finding
can't offer.

Running adprep /domainprep from Windows Server 2016 installation media
adds an unintended ACE to the domain naming context's security
descriptor for the Enterprise Key Admins group (RID 527): FullControl,
with no object-type restriction at all. The INTENDED grant -- what
Enterprise Key Admins is actually supposed to have -- is narrowly
scoped ReadProperty/WriteProperty on exactly one attribute,
msDS-KeyCredentialLink (schemaIdGuid 5b47d60f-6090-40b2-9f37-2a4de88f3063,
confirmed directly against Microsoft's own [MS-ADA2] specification).
Microsoft has confirmed this is a bug in adprep itself, not a
deliberate design choice, and it affects every domain that was ever
promoted or upgraded through Server 2016 media -- which is a large
share of AD installations still running today, given how long AD
domains typically persist without being rebuilt from scratch.

Unlike the group-membership finding (plugin 3022), this doesn't
require anyone to actually be a MEMBER of Enterprise Key Admins to be
a real, present risk -- the ACE exists on the domain naming context
itself regardless of membership, and would become immediately
exploitable the moment anyone is added.
"""

PLUGIN = {
    "plugin_id": 5009,
    "category": "ACLs",
    "name": "Enterprise Key Admins Holds Excessive Rights on the Domain Root",
    "version": "1.1",
    "revision_date": "2026-08-04",
    "remediation": (
        "Remove the overly broad ACE and replace it with the correctly-"
        "scoped one Microsoft's own remediation guidance specifies: "
        "`dsacls \"<domain DN>\" /R \"<domain>\\Enterprise Key Admins\"` "
        "to remove the existing grant, then "
        "`dsacls \"<domain DN>\" /G \"<domain>\\Enterprise Key Admins\""
        ":RPWP;msDS-KeyCredentialLink /I:T` to add back only the "
        "intended Read/WriteProperty rights scoped to that one "
        "attribute. Confirm the fix by re-running this check -- the "
        "finding should clear once the ACE is correctly scoped, "
        "without needing to touch group membership at all."
    ),
    "control_id": "ACL-009",
    "framework_tags": [],
    "references": [
        {"title": "Microsoft: Unwanted access control entry after running adprep or dcpromo (KB4469393)",
         "url": "https://mskb.pkisolutions.com/kb/4469393"},
    ],
    "description": (
        "A specific, Microsoft-acknowledged bug in adprep /domainprep "
        "run from Windows Server 2016 media: an unintended ACE grants "
        "Enterprise Key Admins (RID 527) FullControl on the domain "
        "naming context with no object-type restriction, rather than "
        "the intended narrow ReadProperty/WriteProperty scoped to only "
        "msDS-KeyCredentialLink (schemaIdGuid confirmed against "
        "Microsoft's [MS-ADA2] spec). Affects every domain ever "
        "promoted or upgraded through Server 2016 media -- a large "
        "share of AD installations still running today. Distinct from "
        "plugin 5003's generic 'unexpected principal' check: this "
        "finding identifies a specific, known root cause with a "
        "specific, known fix, which flagging RID 527 alongside every "
        "other unexpected trustee wouldn't communicate. Present "
        "regardless of whether anyone is currently a member of "
        "Enterprise Key Admins (see plugin 3022 for that separate "
        "check) -- the ACE itself is the risk, immediately exploitable "
        "the moment membership changes."
    ),
    "base_severity": "critical",
    "query": """
        WITH matches AS (
            SELECT a.object_guid, a.trustee_sid, a.access_mask, a.object_type_guid,
                   (a.access_mask & 268435456) != 0 AS is_generic_all
            FROM acl_edge a
            JOIN ad_domain d ON d.object_guid = a.object_guid AND d.valid_to IS NULL
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND a.trustee_sid LIKE '%%-527'
              AND (a.object_type_guid IS NULL
                   OR a.object_type_guid != '5b47d60f-6090-40b2-9f37-2a4de88f3063')
        ),
        -- [fix, applied proactively after the same architectural bug
        -- was found and fixed elsewhere this session] A single trustee
        -- can legitimately carry more than one separate ACE on the
        -- same object (e.g. two Allow ACEs with different
        -- object_type_guid values, both failing this check) -- the
        -- original version would produce one row per matching ACE, all
        -- sharing the domain root's object_guid. Aggregated to one row
        -- here, even though in practice this specific known-bug
        -- pattern rarely produces more than one matching ACE.
        aggregated AS (
            SELECT object_guid, trustee_sid,
                   bool_or(is_generic_all) AS any_generic_all,
                   jsonb_agg(jsonb_build_object(
                       'access_mask', access_mask,
                       'object_type_guid', object_type_guid
                   ) ORDER BY access_mask) AS matching_aces,
                   count(*) AS ace_count
            FROM matches
            GROUP BY object_guid, trustee_sid
        )
        SELECT
            'fail' AS status,
            a.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'critical' AS fd_severity,
            'Enterprise Key Admins holds excessive rights on the domain root ('
                || a.ace_count || ' ACE(s) not scoped to msDS-KeyCredentialLink -- '
                || 'matches the known ADPREP 2016 bug pattern)' AS summary,
            jsonb_build_object(
                'trustee_sid', a.trustee_sid,
                'matching_aces', a.matching_aces,
                'is_generic_all', a.any_generic_all
            ) AS detail
        FROM aggregated a
    """,
}
