"""
Plugin 3012: Pre-Windows 2000 Compatible Access Group Contains Everyone or Anonymous Logon

Directly cited from DISA STIG SV-9044r3 and confirmed against Microsoft's
own protocol specification (MS-ADTS). The Pre-Windows 2000 Compatible
Access group (RID 554, a legacy NT4-compatibility group) grants broad
READ access to most attributes of most domain objects. If Everyone
(S-1-1-0) or Anonymous Logon (S-1-5-7) are members, that read access
extends to literally anyone -- including, in the Anonymous Logon case,
unauthenticated network callers who never even logged on. Requires the
foreignSecurityPrincipal collection added specifically to make this
check possible: well-known SIDs added to a group's membership are
represented as real AD objects (under CN=ForeignSecurityPrincipals), not
literal accounts, and could not be resolved without it.
"""

PLUGIN = {
    "plugin_id": 3012,
    "category": "Groups",
    "name": "Pre-Windows 2000 Compatible Access Group Contains Everyone or Anonymous Logon",
    "version": "1.2",
    "revision_date": "2026-07-15",
    "remediation": (
        "Remove Everyone and/or Anonymous Logon from the Pre-Windows "
        "2000 Compatible Access group (Builtin container in ADUC, or "
        "`Remove-ADGroupMember -Identity \"Pre-Windows 2000 Compatible "
        "Access\" -Members \"Everyone\"` / `\"NT AUTHORITY\\ANONYMOUS "
        "LOGON\"`). Test before removing in production -- some legacy "
        "or third-party authentication integrations (observed in real "
        "incident reports to depend on this, e.g. certain Okta and "
        "other third-party auth flows) may rely on it; enable logon "
        "auditing first to identify what's actually depending on "
        "anonymous/broad read access before removing it outright."
    ),
    "control_id": "ANOM-105",
    "framework_tags": ["DISA-STIG"],
    "references": [
        {"title": "DISA STIG V-243486: The Anonymous Logon and Everyone groups must not be members of the Pre-Windows 2000 Compatible Access group",
         "url": "https://www.stigviewer.com/stigs/active_directory_domain/2024-09-13/finding/V-243486"},
    ],
    "description": (
        "Directly cited from DISA STIG SV-9044r3: \"Ensure the "
        "'Anonymous Logon' and 'Everyone' groups are not members of "
        "the 'Pre-Windows 2000 Compatible Access group'... By default, "
        "these groups are not included in current Windows versions.\" "
        "Confirmed against Microsoft's own protocol specification "
        "(MS-ADTS) that this group (RID 554) grants broad read access "
        "to most attributes of most domain objects -- including, per "
        "independent security research, the userAccountControl "
        "attribute, meaning an attacker with this level of access can "
        "identify PASSWD_NOTREQD accounts and other soft targets "
        "directly. Everyone (S-1-1-0) or Anonymous Logon (S-1-5-7) "
        "membership extends that read access to literally anyone, "
        "including in the Anonymous Logon case unauthenticated network "
        "callers. Deliberately does not flag Authenticated Users "
        "membership, which remains the accepted default even in "
        "current, fully-patched Windows Server versions per this same "
        "STIG's own baseline -- flagging it would mean this check fires "
        "in nearly every real domain regardless of hardening effort."
    ),
    "base_severity": "high",
    "query": """
        SELECT
            'fail' AS status,
            fsp.object_guid,
            'CAT_I' AS stig_severity,
            'DISA STIG SV-9044r3: Anonymous Logon and Everyone must not be members of '
                'the Pre-Windows 2000 Compatible Access group' AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            fsp.well_known_name || ' is a member of the Pre-Windows 2000 Compatible '
                'Access group' AS summary,
            jsonb_build_object('well_known_name', fsp.well_known_name, 'well_known_sid', fspdo.object_sid) AS detail
        FROM group_member_edge gme
        JOIN directory_object gdo
            ON gdo.object_guid = gme.group_guid AND gdo.client_id = gme.client_id
        JOIN ad_foreign_security_principal fsp
            ON fsp.object_guid = gme.member_guid AND fsp.valid_to IS NULL
        JOIN directory_object fspdo
            ON fspdo.object_guid = fsp.object_guid AND fspdo.client_id = gme.client_id
        WHERE gme.valid_to IS NULL
          AND gme.client_id = %(client_id)s
          AND gdo.object_sid = 'S-1-5-32-554'
          AND fsp.well_known_name IN ('Everyone', 'Anonymous Logon')
    """,
}
