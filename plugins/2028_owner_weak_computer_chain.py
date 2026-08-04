"""
Plugin 2028: Domain Root or AdminSDHolder Owned by an Unsupported or Dormant Computer

Refines plugin 5006 (any unexpected owner) with the computer-side
equivalent of plugin 1032: the owner is a computer account that is
itself independently weak -- unsupported OS or dormant. A computer
owning either object is already highly unusual on its own (5006 already
flags it); this adds specific, actionable context about exactly how
exploitable that owner is.
"""

PLUGIN = {
    "plugin_id": 2028,
    "category": "Computer Accounts",
    "name": "Domain Root or AdminSDHolder Owned by an Unsupported or Dormant Computer",
    "version": "1.1",
    "revision_date": "2026-07-17",
    "remediation": (
        "Take ownership back to a recognized default holder immediately "
        "(see plugin 5006's remediation) -- this is a higher-priority "
        "case than an ordinary unexpected-owner finding, since the "
        "owning machine itself has an independent, exploitable "
        "weakness. Investigate whether this machine's own weakness has "
        "already been exploited to reach this ownership."
    ),
    "control_id": "CHAIN-206",
    "framework_tags": [],
    "references": [
        {"title": "BloodHound (SpecterOps): WriteOwner edge",
         "url": "https://bloodhound.specterops.io/resources/edges/write-owner"},
    ],
    "description": (
        "Refines plugin 5006 (any unexpected owner of the domain root "
        "or AdminSDHolder) with the computer-side equivalent of plugin "
        "1032: the owner is a computer account that is itself "
        "independently weak (unsupported OS, plugin 2003, or dormant, "
        "plugin 2006). A computer owning either object is already "
        "highly unusual; an easy-to-compromise owning machine makes it "
        "meaningfully worse than an unexpected-but-otherwise-solid one."
    ),
    "base_severity": "critical",
    "query": """
        SELECT
            'fail' AS status,
            owner.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'critical' AS fd_severity,
            'Computer Account ' || owner.sam_account_name
                || ' owns ' || (CASE WHEN target.dn_current ILIKE 'CN=AdminSDHolder,%%' THEN 'AdminSDHolder' ELSE 'the domain root' END)
                || ' and is independently weak: '
                || (SELECT string_agg(x, ', ') FROM (VALUES
                        (CASE WHEN owner.operating_system ILIKE '%%windows 10%%' OR owner.operating_system ILIKE '%%server 2012%%'
                              OR owner.operating_system ILIKE '%%server 2008%%' OR owner.operating_system ILIKE '%%server 2003%%'
                              OR owner.operating_system ILIKE '%%windows 7%%' OR owner.operating_system ILIKE '%%windows 8%%'
                              OR owner.operating_system ILIKE '%%windows xp%%' OR owner.operating_system ILIKE '%%windows vista%%'
                              THEN 'unsupported OS (' || owner.operating_system || ')' END),
                        (CASE WHEN owner.last_logon_timestamp IS NULL OR owner.last_logon_timestamp < now() - interval '90 days'
                              THEN 'dormant' END)
                    ) AS v(x) WHERE x IS NOT NULL) AS summary,
            jsonb_build_object(
                'sam_account_name', owner.sam_account_name,
                'object_dn', target.dn_current,
                'operating_system', owner.operating_system,
                'last_logon_timestamp', owner.last_logon_timestamp
            ) AS detail
        FROM directory_object target
        JOIN ad_computer owner ON owner.object_guid = (
            SELECT o.object_guid FROM directory_object o
            WHERE o.object_sid = target.owner_sid AND o.client_id = target.client_id
        ) AND owner.valid_to IS NULL
        WHERE target.client_id = %(client_id)s
          AND target.owner_sid IS NOT NULL
          AND (
                target.dn_current ILIKE 'CN=AdminSDHolder,%%'
                OR EXISTS (SELECT 1 FROM ad_domain d WHERE d.object_guid = target.object_guid AND d.valid_to IS NULL)
              )
          AND (
                owner.operating_system ILIKE '%%windows 10%%' OR owner.operating_system ILIKE '%%server 2012%%'
                OR owner.operating_system ILIKE '%%server 2008%%' OR owner.operating_system ILIKE '%%server 2003%%'
                OR owner.operating_system ILIKE '%%windows 7%%' OR owner.operating_system ILIKE '%%windows 8%%'
                OR owner.operating_system ILIKE '%%windows xp%%' OR owner.operating_system ILIKE '%%windows vista%%'
                OR owner.last_logon_timestamp IS NULL OR owner.last_logon_timestamp < now() - interval '90 days'
              )
    """,
}
