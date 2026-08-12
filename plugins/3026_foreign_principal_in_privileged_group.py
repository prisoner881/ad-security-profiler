"""
Plugin 3026: Account From an Outside Directory Holds Membership in a Highly Privileged Group

Directly cited against DISA Active Directory Domain STIG V-243496
(CAT II): "If any account in a privileged group is from a domain
outside the forest being reviewed and that outside forest is not
maintained by the same organization [...] or subject to the same
security policies, then this is a finding." Confirmed against the
current STIG text (V3R7) directly.

The STIG's check text explicitly lists the groups in scope: Domain
Admins, Enterprise Admins, Schema Admins, Group Policy Creator Owners,
and Incoming Forest Trust Builders. Checked here via a Foreign
Security Principal (FSP) object as the marker: an FSP is exactly what
AD creates to represent a SID from an outside, trusted domain when
that SID is added to a local group -- so any FSP appearing as a member
of one of these five groups is, by construction, "an account from an
outside directory" in this group. Whether that outside forest belongs
to the same organization and security policy is something this plugin
cannot determine (that context lives outside AD entirely) -- reported
here as evidence for a human to make that determination, matching the
STIG's own two-part test (foreign membership exists, AND it's from an
unrelated/lower-trust organization).
"""

PLUGIN = {
    "plugin_id": 3026,
    "category": "Groups",
    "name": "Account From an Outside Directory Holds Membership in a Highly Privileged Group",
    "version": "1.0",
    "revision_date": "2026-08-12",
    "remediation": (
        "Confirm whether the outside forest this account originates "
        "from is maintained by the same organization and subject to "
        "the same security policies as this domain. If not, remove "
        "the account from this privileged group -- a security "
        "weakness or compromise in the outside forest would otherwise "
        "translate directly into privileged access here, since trust "
        "relationships don't guarantee the trusted side maintains "
        "equivalent security rigor."
    ),
    "control_id": "STIG-V-243496",
    "framework_tags": ["DISA-STIG"],
    "references": [
        {"title": "DISA Active Directory Domain STIG V3R7: V-243496",
         "url": "https://cyber.trackr.live/stig/Active_Directory_Domain/3/7#V-243496"},
    ],
    "description": (
        "DISA Active Directory Domain STIG V-243496 (CAT II): accounts "
        "from outside directories that aren't part of the same "
        "organization or subject to the same security policies must "
        "be removed from highly privileged groups (Domain Admins, "
        "Enterprise Admins, Schema Admins, Group Policy Creator "
        "Owners, Incoming Forest Trust Builders). A Foreign Security "
        "Principal appearing in one of these groups is, by "
        "construction, an account from an outside, trusted domain -- "
        "whether that domain belongs to the same organization is "
        "outside what AD data alone can determine."
    ),
    "base_severity": "high",
    "query": """
        SELECT
            'warn' AS status,
            fsp.object_guid,
            'CAT_II' AS stig_severity,
            'DISA Active Directory Domain STIG V-243496' AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'Foreign Security Principal ' || COALESCE(fdo.sam_account_name, fdo.object_sid, fsp.object_guid::text)
                || ' is a member of privileged group "' || gdo.sam_account_name || '"' AS summary,
            jsonb_build_object(
                'foreign_principal_sid', fdo.object_sid,
                'privileged_group', gdo.sam_account_name
            ) AS detail
        FROM v_effective_group_membership vem
        JOIN directory_object gdo ON gdo.object_guid = vem.group_guid AND gdo.client_id = vem.client_id
        JOIN ad_foreign_security_principal fsp
            ON fsp.object_guid = vem.member_guid AND fsp.client_id = vem.client_id AND fsp.valid_to IS NULL
        LEFT JOIN directory_object fdo ON fdo.object_guid = fsp.object_guid AND fdo.client_id = fsp.client_id
        WHERE vem.client_id = %(client_id)s
          AND (gdo.object_sid LIKE '%%-512' OR gdo.object_sid LIKE '%%-519'
               OR gdo.object_sid LIKE '%%-518' OR gdo.object_sid LIKE '%%-520'
               OR gdo.object_sid LIKE '%%-557')
    """,
}
