"""
Plugin 5006: Domain Root or AdminSDHolder Owned by an Unexpected Principal

Uses directory_object.owner_sid, added specifically to stop discarding
data this project's own SD parser was already computing every run since
v0.3.0. An object's owner implicitly holds WRITE_DAC-equivalent rights
over it regardless of what the DACL itself says -- an owner can always
rewrite the DACL to grant themselves anything else, making ownership
itself a distinct, real finding (BloodHound's "Owns" edge) independent
of whatever explicit ACEs plugins 5002/5003 already check.
"""

PLUGIN = {
    "plugin_id": 5006,
    "category": "ACLs",
    "name": "Domain Root or AdminSDHolder Owned by an Unexpected Principal",
    "version": "1.2",
    "revision_date": "2026-07-17",
    "remediation": (
        "Take ownership back to a recognized default holder "
        "(`takeown`-equivalent via ADSI Edit's Security tab, Advanced, "
        "Owner tab -- change owner, requires WriteOwner or being a "
        "current administrator). Investigate how ownership changed in "
        "the first place before assuming it was benign -- taking "
        "ownership of an object is itself frequently the first step in "
        "an ACL-based privilege escalation chain, since an owner can "
        "always grant themselves WriteDacl regardless of the object's "
        "current ACL."
    ),
    "control_id": "ACL-006",
    "framework_tags": [],
    "references": [
        {"title": "BloodHound (SpecterOps): WriteOwner edge",
         "url": "https://bloodhound.specterops.io/resources/edges/write-owner"},
    ],
    "description": (
        "An object's owner implicitly holds WRITE_DAC-equivalent rights "
        "over it regardless of what the DACL itself explicitly grants -- "
        "an owner can always rewrite the DACL to add themselves any "
        "other right. This makes ownership a distinct, real finding "
        "(BloodHound's \"Owns\" edge) independent of the explicit-ACE "
        "checks in plugins 5002/5003: an unexpected owner could hold no "
        "dangerous ACE at all today and still trivially grant one to "
        "themselves whenever they choose. Excludes the well-known, "
        "expected owners (Domain Admins, Enterprise Admins, "
        "Administrators, SYSTEM)."
    ),
    "base_severity": "critical",
    "query": """
        SELECT
            'fail' AS status,
            target.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'critical' AS fd_severity,
            (CASE WHEN target.dn_current ILIKE 'CN=AdminSDHolder,%%' THEN 'AdminSDHolder' ELSE 'The domain root' END)
                || ' is owned by ' || COALESCE(owner.sam_account_name, target.owner_sid) AS summary,
            jsonb_build_object(
                'object_dn', target.dn_current,
                'owner_sid', target.owner_sid,
                'owner_sam_account_name', owner.sam_account_name,
                'owner_object_class', owner.object_class
            ) AS detail
        FROM directory_object target
        LEFT JOIN directory_object owner
            ON owner.object_sid = target.owner_sid AND owner.client_id = %(client_id)s
        WHERE target.client_id = %(client_id)s
          AND target.owner_sid IS NOT NULL
          AND (
                target.dn_current ILIKE 'CN=AdminSDHolder,%%'
                OR EXISTS (SELECT 1 FROM ad_domain d WHERE d.object_guid = target.object_guid AND d.valid_to IS NULL)
              )
          -- Matched directly against the SID pattern rather than requiring
          -- the expected group to resolve through a directory_object JOIN
          -- -- that indirection failed silently in testing when the
          -- expected group wasn't itself a collected object, which would
          -- be a real, if rare, exposure in production too (this check
          -- shouldn't depend on Domain Admins/Enterprise Admins/
          -- Administrators happening to already be collected).
          AND NOT (target.owner_sid LIKE '%%-512' OR target.owner_sid LIKE '%%-519'
                   OR target.owner_sid LIKE '%%-544' OR target.owner_sid = 'S-1-5-18')
    """,
}
