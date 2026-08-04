"""
Plugin 4021: Java RFC 2713 Schema Extension Present in the Forest

Confirmed as a genuine gap via PingCastle's own S-JavaSchema rule: the
RFC 2713 Java-object-representation schema extension (javaClassName,
javaCodeBase, javaFactory, javaObject, javaSerializedObject) is the
log4shell-adjacent LDAP attack surface -- a malicious LDAP server (or
a compromised legitimate one) can serve a specially-crafted response
referencing one of these attributes to trigger Java deserialization in
a vulnerable client application that queries LDAP and doesn't validate
what it gets back. Its mere presence in the schema doesn't mean
anything is actively exploitable today, but it's dormant attack
surface most organizations have no reason to still carry -- this
schema extension was historically added by some now-uncommon Java/LDAP
integration tooling and is rarely something anyone still depends on.

Collected via a narrow, targeted schema-partition filter
(SCHEMA_JAVA_FILTER) rather than pulling the entire schema for one
check.
"""

PLUGIN = {
    "plugin_id": 4021,
    "category": "Domain",
    "name": "Java RFC 2713 Schema Extension Present in the Forest",
    "version": "1.0",
    "revision_date": "2026-07-31",
    "remediation": (
        "Confirm whether any current application actually depends on "
        "this schema extension -- most environments carrying it do so "
        "from historical Java/LDAP integration tooling nobody currently "
        "uses. If nothing depends on it, these attributeSchema objects "
        "cannot be safely deleted (AD does not support removing schema "
        "attributes once created), but marking them isDefunct=TRUE "
        "prevents them from being used going forward. This is forest-"
        "wide, irreversible, and requires Schema Admins rights -- test "
        "in a lab first and confirm no legitimate dependency exists."
    ),
    "control_id": "DOM-422",
    "framework_tags": [],
    "references": [
        {"title": "PingCastle: Stale Objects rules -- S-JavaSchema",
         "url": "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
    ],
    "description": (
        "The RFC 2713 Java-object-representation schema extension is "
        "present in the forest schema -- the log4shell-adjacent LDAP "
        "attack surface (a malicious or compromised LDAP response "
        "referencing these attributes can trigger Java deserialization "
        "in a vulnerable client). Presence alone doesn't confirm active "
        "exploitability, but it's dormant attack surface most "
        "environments have no ongoing reason to carry."
    ),
    "base_severity": "low",
    "query": """
        SELECT
            'fail' AS status,
            s.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'Java RFC 2713 schema attribute "' || s.schema_cn || '" is present in the forest schema' AS summary,
            jsonb_build_object(
                'schema_cn', s.schema_cn
            ) AS detail
        FROM ad_schema_object s
        WHERE s.client_id = %(client_id)s
          AND s.valid_to IS NULL
          AND s.schema_object_type = 'attributeSchema'
    """,
}
