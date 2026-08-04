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
"""

PLUGIN = {
    "plugin_id": 4022,
    "category": "Domain",
    "name": "Schema Class Allows Computer or User to Create Container-Like Objects",
    "version": "1.0",
    "revision_date": "2026-07-31",
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
        "A schema class inherits from 'container' and has 'computer' "
        "and/or 'user' in its possSuperiors -- meaning any computer or "
        "user account in the domain can create an instance of it as a "
        "child object, an unrestricted object-creation foothold "
        "bypassing normal delegation/ACL restrictions. This is the "
        "mechanism behind CVE-2021-34470 (Exchange's "
        "msExchStorageGroup class), exploitable even after the "
        "product that introduced the schema class is fully "
        "uninstalled."
    ),
    "base_severity": "high",
    "query": """
        SELECT
            'fail' AS status,
            s.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'Schema class "' || s.schema_cn || '" inherits from container and permits '
                || (SELECT string_agg(x, ' and ') FROM (VALUES
                        (CASE WHEN s.poss_superiors ? 'computer' THEN 'computer' END),
                        (CASE WHEN s.poss_superiors ? 'user' THEN 'user' END)
                    ) AS v(x) WHERE x IS NOT NULL)
                || ' accounts to create it as a child object' AS summary,
            jsonb_build_object(
                'schema_cn', s.schema_cn,
                'poss_superiors', s.poss_superiors,
                'sub_class_of', s.sub_class_of
            ) AS detail
        FROM ad_schema_object s
        WHERE s.client_id = %(client_id)s
          AND s.valid_to IS NULL
          AND s.schema_object_type = 'classSchema'
          AND lower(s.sub_class_of) = 'container'
          AND (s.poss_superiors ? 'computer' OR s.poss_superiors ? 'user')
    """,
}
