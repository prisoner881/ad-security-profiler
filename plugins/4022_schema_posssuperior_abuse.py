"""
Plugin 4022: Schema Class Allows Computer or User to Create Container-Like Objects

Confirmed as a genuine gap via PingCastle's own
S-ADRegistrationSchema (PossSuperiorComputer/PossSuperiorUser) rule:
a schema class whose possSuperiors includes "computer" or "user", AND
which itself inherits (subClassOf) from "container", means any
computer or user account in the domain can create an instance of that
class as a child object -- effectively an unrestricted object-creation
foothold bypassing normal delegation/ACL-based restrictions on where
new objects can be created.

This is the mechanism behind CVE-2021-34470: Exchange's own
msExchStorageGroup class shipped with exactly this schema shape,
letting any authenticated computer or user create arbitrary child
containers, exploitable even after Exchange itself is fully
uninstalled (schema changes are not undone by uninstalling the
product that made them). Any OTHER class matching the same pattern --
whether from a different product's schema extension, or a mistake in
a custom schema modification -- carries the identical risk.

[v1.1] Wording corrected and inheritance resolved. possSuperiors only
says an instance may be created *beneath* a computer/user object; who
can create it is decided by CreateChild rights on that parent -- e.g.
the creator/owner of a computer added through MachineAccountQuota,
which is the CVE's abuse path. The summary and description no longer
claim "any computer or user account can create it". The subClassOf
chain is now walked recursively over the collected classSchema rows (a
class that reaches 'container' through an intermediate class is no
longer missed), and possSuperiors inherited from superclasses count
too. Only cn is collected for classSchema objects, not lDAPDisplayName,
so a subClassOf value is matched against a class's cn with hyphens
removed, case-insensitively (AD's default cn -> lDAPDisplayName
derivation: ms-Exch-Storage-Group -> msExchStorageGroup).
"""

PLUGIN = {
    "plugin_id": 4022,
    "category": "Domain",
    "name": "Schema Class Allows Container-Like Objects Beneath Computer or User Objects",
    "version": "1.1",
    "revision_date": "2026-10-04",
    "remediation": (
        "Identify what created this schema class (a product's schema "
        "extension, most commonly historically Exchange via "
        "CVE-2021-34470's msExchStorageGroup, but any other schema "
        "extension could introduce the same shape). Schema classes "
        "cannot be deleted once created, but the specific vulnerable "
        "combination can be neutralized by removing 'computer' and "
        "'user' from the class's possSuperiors attribute via ADSI Edit "
        "(Schema partition), provided nothing legitimate currently "
        "depends on being able to create this class as a child of a "
        "computer or user object -- confirm in a lab first, this is a "
        "forest-wide, Schema Admins-only change."
    ),
    "control_id": "DOM-423",
    "framework_tags": [],
    "references": [
        {"title": "PingCastle: Stale Objects rules -- S-ADRegistrationSchema",
         "url": "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
        {"title": "Microsoft: CVE-2021-34470",
         "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34470"},
    ],
    "description": (
        "A schema class derives (directly or through intermediate "
        "classes) from 'container' and has 'computer' and/or 'user' in "
        "its own or inherited possSuperiors -- meaning instances of it "
        "may be created beneath computer or user objects. Anyone with "
        "CreateChild on such an object can then create container-like "
        "children there, e.g. the creator/owner of a computer account "
        "added through MachineAccountQuota, which needs no delegated "
        "rights at all -- an object-creation foothold outside the "
        "normal delegation model. This is the mechanism behind "
        "CVE-2021-34470 (Exchange's msExchStorageGroup class), "
        "exploitable even after the product that introduced the schema "
        "class is fully uninstalled."
    ),
    "base_severity": "high",
    "query": """
        WITH RECURSIVE cls AS (
            SELECT s.object_guid, s.schema_cn, s.poss_superiors, s.sub_class_of,
                   lower(replace(s.schema_cn, '-', '')) AS name_key
            FROM ad_schema_object s
            WHERE s.client_id = %(client_id)s
              AND s.valid_to IS NULL
              AND s.schema_object_type = 'classSchema'
        ),
        -- [v1.1] walk the subClassOf chain (cn matched hyphen-less,
        -- case-insensitively, against the lDAPDisplayName in subClassOf)
        chain AS (
            SELECT c.object_guid AS class_guid,
                   lower(c.sub_class_of) AS ancestor_key,
                   ARRAY[c.name_key] AS path,
                   1 AS depth
            FROM cls c
            WHERE c.sub_class_of IS NOT NULL
            UNION ALL
            SELECT ch.class_guid,
                   lower(p.sub_class_of),
                   ch.path || p.name_key,
                   ch.depth + 1
            FROM chain ch
            JOIN cls p ON p.name_key = ch.ancestor_key
            WHERE p.sub_class_of IS NOT NULL
              AND ch.ancestor_key NOT IN ('top', 'container')
              AND NOT p.name_key = ANY (ch.path)
              AND ch.depth < 30
        ),
        container_derived AS (
            SELECT class_guid,
                   min(depth) AS container_depth
            FROM chain
            WHERE ancestor_key = 'container'
            GROUP BY class_guid
        ),
        -- own possSuperiors plus those inherited from any ancestor
        -- (the 'container' class itself never includes computer/user)
        effective_ps AS (
            SELECT c.object_guid AS class_guid, ps.v AS poss_superior
            FROM cls c
            CROSS JOIN LATERAL jsonb_array_elements_text(COALESCE(c.poss_superiors, '[]'::jsonb)) ps(v)
            UNION
            SELECT ch.class_guid, ps.v
            FROM chain ch
            JOIN cls p ON p.name_key = ch.ancestor_key
            CROSS JOIN LATERAL jsonb_array_elements_text(COALESCE(p.poss_superiors, '[]'::jsonb)) ps(v)
        ),
        risky AS (
            SELECT e.class_guid,
                   bool_or(lower(e.poss_superior) = 'computer') AS has_computer,
                   bool_or(lower(e.poss_superior) = 'user') AS has_user
            FROM effective_ps e
            GROUP BY e.class_guid
            HAVING bool_or(lower(e.poss_superior) IN ('computer', 'user'))
        )
        SELECT
            'fail' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'Schema class "' || c.schema_cn || '" inherits from container and can be instantiated beneath '
                || CASE
                     WHEN r.has_computer AND r.has_user THEN 'computer and user'
                     WHEN r.has_computer THEN 'computer'
                     ELSE 'user'
                   END
                || ' objects (exploitable by anyone with CreateChild on such an object, e.g. via MachineAccountQuota)' AS summary,
            jsonb_build_object(
                'schema_cn', c.schema_cn,
                'poss_superiors', c.poss_superiors,
                'sub_class_of', c.sub_class_of,
                'container_inheritance_depth', cd.container_depth,
                'computer_or_user_inherited', NOT (
                    COALESCE(c.poss_superiors, '[]'::jsonb) ? 'computer'
                    OR COALESCE(c.poss_superiors, '[]'::jsonb) ? 'user')
            ) AS detail
        FROM cls c
        JOIN container_derived cd ON cd.class_guid = c.object_guid
        JOIN risky r ON r.class_guid = c.object_guid
    """,
}
