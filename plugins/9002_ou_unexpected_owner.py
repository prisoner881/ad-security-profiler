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

[v1.1] ad_ou and the owner lookup are client-scoped, the owner is
resolved with a LATERAL ... LIMIT 1 (preferring a non-deleted object) so
two directory_object rows with the owner's SID can no longer duplicate the
finding identity, deleted OUs are excluded, and the expected owners are
matched by exact SID: SYSTEM S-1-5-18, Administrators S-1-5-32-544, this
domain's Domain Admins (client.domain_sid || '-512'; any -512 when the
domain SID is unknown) and Enterprise Admins (-519 of any domain, since
the forest root's SID is not known here). Previously a Domain Admins
group of a trusted domain owning an OU was treated as expected.
"""

PLUGIN = {
    "plugin_id": 9002,
    "category": "Organizational Units",
    "name": "Organizational Unit Owned by an Unexpected Principal",
    "version": "1.1",
    "revision_date": "2026-10-04",
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
            'OU "' || COALESCE(o.ou_name, target.dn_current) || '" is owned by '
                || COALESCE(owner.sam_account_name, target.owner_sid) AS summary,
            jsonb_build_object(
                'ou_name', o.ou_name,
                'object_dn', target.dn_current,
                'owner_sid', target.owner_sid,
                'owner_sam_account_name', owner.sam_account_name,
                'owner_object_class', owner.object_class
            ) AS detail
        FROM directory_object target
        JOIN ad_ou o ON o.object_guid = target.object_guid AND o.client_id = target.client_id
                    AND o.valid_to IS NULL
        LEFT JOIN client cl ON cl.client_id = target.client_id
        LEFT JOIN LATERAL (
            SELECT d.sam_account_name, d.object_class
            FROM directory_object d
            WHERE d.client_id = target.client_id
              AND d.object_sid = target.owner_sid
            ORDER BY d.is_deleted, d.object_guid
            LIMIT 1
        ) owner ON TRUE
        WHERE target.client_id = %(client_id)s
          AND NOT target.is_deleted
          AND target.owner_sid IS NOT NULL
          -- [v1.1] expected owners by exact SID
          AND target.owner_sid NOT IN ('S-1-5-18', 'S-1-5-32-544')
          AND target.owner_sid !~ '^S-1-5-21-[0-9-]+-519$'
          AND NOT (
                (cl.domain_sid IS NOT NULL AND target.owner_sid = cl.domain_sid || '-512')
                OR (cl.domain_sid IS NULL AND target.owner_sid ~ '^S-1-5-21-[0-9-]+-512$')
              )
    """,
}
