"""
Plugin 9002: Organizational Unit Owned by an Unexpected Principal

Same reasoning as plugin 5006 (domain root/AdminSDHolder ownership),
applied per-OU: an object's owner implicitly holds WRITE_DAC-equivalent
rights over it regardless of what the DACL itself explicitly grants --
an owner can always rewrite the DACL to add themselves any other
right. This makes ownership a distinct, real finding (BloodHound's
"Owns" edge) independent of plugin 9001's explicit-ACE check: an
unexpected owner could hold no dangerous ACE at all today and still
trivially grant one to themselves whenever they choose.
"""

PLUGIN = {
    "plugin_id": 9002,
    "category": "Organizational Units",
    "name": "Organizational Unit Owned by an Unexpected Principal",
    "version": "1.0",
    "revision_date": "2026-07-18",
    "remediation": (
        "Take ownership back to a recognized default holder (ADSI "
        "Edit's Security tab on the OU -> Advanced -> Owner tab -> "
        "change owner, requires WriteOwner or being a current "
        "administrator). Investigate how ownership changed in the "
        "first place before assuming it was benign -- taking ownership "
        "of an object is itself frequently the first step in an ACL-"
        "based privilege escalation chain, since an owner can always "
        "grant themselves WriteDacl regardless of the object's current "
        "ACL."
    ),
    "control_id": "ACL-902",
    "framework_tags": [],
    "references": [
        {"title": "BloodHound (SpecterOps): WriteOwner edge",
         "url": "https://bloodhound.specterops.io/resources/edges/write-owner"},
    ],
    "description": (
        "Same reasoning as plugin 5006, applied per-OU: an object's "
        "owner implicitly holds WRITE_DAC-equivalent rights regardless "
        "of the explicit DACL, since an owner can always rewrite it. "
        "Independent of plugin 9001's explicit-ACE check -- an "
        "unexpected owner could hold no dangerous ACE today and still "
        "trivially grant one whenever they choose. Excludes the same "
        "baseline well-known holders (Domain Admins, Enterprise Admins, "
        "Administrators, SYSTEM) used elsewhere in this project."
    ),
    "base_severity": "high",
    "query": """
        SELECT
            'fail' AS status,
            target.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'OU "' || o.ou_name || '" is owned by ' || COALESCE(owner.sam_account_name, target.owner_sid) AS summary,
            jsonb_build_object(
                'ou_name', o.ou_name,
                'object_dn', target.dn_current,
                'owner_sid', target.owner_sid,
                'owner_sam_account_name', owner.sam_account_name,
                'owner_object_class', owner.object_class
            ) AS detail
        FROM directory_object target
        JOIN ad_ou o ON o.object_guid = target.object_guid AND o.valid_to IS NULL
        LEFT JOIN directory_object owner
            ON owner.object_sid = target.owner_sid AND owner.client_id = %(client_id)s
        WHERE target.client_id = %(client_id)s
          AND target.owner_sid IS NOT NULL
          AND NOT (target.owner_sid LIKE '%%-512' OR target.owner_sid LIKE '%%-519'
                   OR target.owner_sid LIKE '%%-544' OR target.owner_sid = 'S-1-5-18')
    """,
}
