"""
Plugin 10006: Guest Account Holds a Privileged Directory Role

A guest account (Graph's own userType: Guest -- an external identity,
typically from another organization's tenant via B2B collaboration,
not an account this tenant's own administrators provisioned or fully
control) holding any activated directory role is worth surfacing
regardless of which specific role. Guest accounts exist for
collaboration scenarios -- sharing a document, joining a Teams channel
-- not for tenant administration, and their credentials, MFA
enforcement, and lifecycle are governed by whatever security posture
their HOME organization maintains, not this one. This tenant has no
direct control over that.

Cross-referenced entirely from data this project already collects --
entra_directory_role_member (built for plugins 10002/10003) joined
against entra_user.user_type (added specifically to enable this
check) -- no new Graph collection needed beyond the one new field.
"""

PLUGIN = {
    "plugin_id": 10006,
    "category": "Hybrid Identity",
    "name": "Guest Account Holds a Privileged Directory Role",
    "version": "1.0",
    "revision_date": "2026-07-19",
    "remediation": (
        "Confirm this is intentional and necessary -- a genuine "
        "external-partner administration scenario is possible but "
        "uncommon. If it's not necessary, remove the role assignment: "
        "Entra admin center -> Roles and administrators -> select the "
        "role -> remove the guest account. If ongoing external "
        "collaboration access is genuinely needed, consider whether a "
        "narrower, purpose-built role would serve instead of whatever "
        "broad role is currently assigned, and confirm the guest's home "
        "organization enforces MFA on their end, since this tenant has "
        "no direct control over that account's authentication security."
    ),
    "control_id": "HYBRID-006",
    "framework_tags": [],
    "references": [],
    "description": (
        "A guest account (an external identity via B2B collaboration, "
        "not provisioned or fully controlled by this tenant) holds an "
        "activated directory role. Guest accounts exist for "
        "collaboration, not tenant administration -- their credential "
        "security and lifecycle are governed by their home "
        "organization, outside this tenant's control. Worth surfacing "
        "regardless of which specific role is held. Built entirely from "
        "data already collected for plugins 10002/10003 "
        "(entra_directory_role_member) plus one added field "
        "(entra_user.user_type) -- no new Graph collection required."
    ),
    "base_severity": "high",
    "query": """
        SELECT
            'fail' AS status,
            NULL::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'Guest account ' || COALESCE(rm.member_display_name, rm.member_upn)
                || ' holds the "' || rm.role_display_name || '" directory role' AS summary,
            jsonb_build_object(
                'member_display_name', rm.member_display_name,
                'member_upn', rm.member_upn,
                'role_display_name', rm.role_display_name,
                'account_enabled', rm.account_enabled
            ) AS detail
        FROM entra_directory_role_member rm
        JOIN entra_user eu ON eu.entra_object_id = rm.member_id AND eu.client_id = rm.client_id
        WHERE rm.client_id = %(client_id)s
          AND rm.member_type = '#microsoft.graph.user'
          AND eu.user_type = 'Guest'
    """,
}
