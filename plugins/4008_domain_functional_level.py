"""
Plugin 4008: Domain Functional Level Indicates Outdated Compatibility Floor

Direct analog to computer-account plugin 2003 (unsupported OS), applied
to the domain's configured compatibility floor rather than what any
individual DC happens to be running. Integer-to-version mapping verified
directly against Microsoft's own protocol specification (MS-ADTS
6.1.4.4), not assumed.

Important distinction from plugin 2003, stated explicitly: functional
level is a configured CEILING/FLOOR, not necessarily "what OS the DCs
currently run" -- a domain can run exclusively on brand-new DCs while
still sitting at an old functional level simply because nobody raised
it. A low functional level is still a genuine, distinct finding: it
means certain modern AD security features requiring a higher floor
(Kerberos improvements, Authentication Policies/Silos, and others tied
to specific functional levels) are unavailable domain-wide, regardless
of what the actual DC hardware/OS looks like.
"""

PLUGIN = {
    "plugin_id": 4008,
    "category": "Domain",
    "name": "Domain Functional Level Indicates Outdated Compatibility Floor",
    "version": "1.2",
    "revision_date": "2026-07-15",
    "remediation": (
        "Raise the domain functional level (`Set-ADDomainMode`) once "
        "every DC in the domain is confirmed running an OS that "
        "supports a higher level -- this is a one-way operation within "
        "a given AD version lineage, so confirm compatibility first. "
        "Raising the functional level unlocks security features gated "
        "behind that floor without requiring any change to the DCs "
        "themselves, if they already support it; check current DC OS "
        "versions against plugin 2003's findings first."
    ),
    "control_id": "POLICY-008",
    "framework_tags": ["DISA-STIG"],
    "references": [
        {"title": "Microsoft: Active Directory Domain Services functional levels",
         "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-functional-levels"},
        {"title": "DISA Active Directory Domain STIG V-243480: The domain functional level must be at a Windows Server version still supported by Microsoft",
         "url": "https://cyber.trackr.live/stig/Active_Directory_Domain/3/7#V-243480"},
    ],
    "description": (
        "Direct analog to computer-account plugin 2003, applied to the "
        "domain's configured compatibility floor. Integer-to-version "
        "mapping verified directly against Microsoft's own protocol "
        "specification (MS-ADTS 6.1.4.4): 0=Windows 2000, 1/2=Server "
        "2003, 3=Server 2008, 4=Server 2008 R2, 5=Server 2012, "
        "6=Server 2012 R2, 7=Server 2016 (the highest level confirmed "
        "against that specification; this check does not yet "
        "distinguish any potential functional level beyond 7 that may "
        "exist for newer Windows Server releases, rather than assert "
        "false precision about a value not directly confirmed). "
        "Important distinction from plugin 2003, stated explicitly here "
        "rather than left implicit: functional level is a configured "
        "ceiling/floor, not necessarily what OS the DCs currently run -- "
        "a domain can run exclusively on brand-new DCs while still "
        "sitting at an old functional level simply because nobody "
        "raised it. A low level is still a genuine, distinct finding: "
        "certain modern AD security features gated behind a higher "
        "floor are unavailable domain-wide regardless of actual DC "
        "hardware."
    ),
    "base_severity": "medium",
    "query": """
        SELECT
            'fail' AS status,
            d.object_guid,
            'CAT_II' AS stig_severity,
            'DISA Active Directory Domain STIG V-243480' AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE
                WHEN d.functional_level <= 2 THEN 'critical'
                WHEN d.functional_level <= 4 THEN 'high'
                ELSE 'medium'
            END AS fd_severity,
            'Domain ' || COALESCE(d.dns_root, '(this domain)')
                || ' functional level is ' || d.functional_level || ' ('
                || CASE d.functional_level
                     WHEN 0 THEN 'Windows 2000' WHEN 1 THEN 'Server 2003 (mixed)'
                     WHEN 2 THEN 'Server 2003' WHEN 3 THEN 'Server 2008'
                     WHEN 4 THEN 'Server 2008 R2' WHEN 5 THEN 'Server 2012'
                     ELSE 'Server 2012 R2' END
                || ')' AS summary,
            jsonb_build_object('dns_root', d.dns_root, 'functional_level', d.functional_level) AS detail
        FROM ad_domain d
        WHERE d.valid_to IS NULL
          AND d.client_id = %(client_id)s
          AND d.functional_level IS NOT NULL
          AND d.functional_level <= 6
    """,
}
