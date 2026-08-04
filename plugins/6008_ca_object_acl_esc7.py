"""
Plugin 6008: Certificate Authority Object ACL Misconfiguration Matches ESC7

ESC7 is most precisely defined as a non-admin holding the ManageCA or
ManageCertificates control-access rights on a CA's own AD object
(pKIEnrollmentService) -- ManageCA lets a holder reconfigure the CA
(including flipping the EDITF_ATTRIBUTESUBJECTALTNAME2 flag to chain
into ESC6, or enabling/publishing an ESC1-shaped template like the
built-in SubCA), and ManageCertificates lets a holder approve a
pending certificate request, bypassing manager-approval protections.

This plugin deliberately covers a NARROWER, but confidently-verified,
slice of that: GenericAll/GenericWrite/WriteDacl/WriteOwner on the CA
object, which always implies ManageCA/ManageCertificates along with
everything else (the same reasoning plugins 6006/6007 already use for
ESC4/ESC5). The full ESC7 definition also includes a principal holding
JUST the specific ManageCA/ManageCertificates control-access right
(not full control) -- multiple independent sources confirm these are
represented as object-type ACEs with the ADS_RIGHT_DS_CONTROL_ACCESS
flag plus a specific ObjectType GUID, the same general mechanism as a
certificate template's own Enroll/AutoEnroll extended rights, but the
exact GUID values for ManageCA/ManageCertificates specifically could
not be confirmed precisely enough from available public sources to
build a rule around safely. Documented as a known, narrower gap rather
than guessed at -- a principal with ONLY the narrow extended right
(not full control) will not be caught by this plugin.
"""

PLUGIN = {
    "plugin_id": 6008,
    "category": "Certificate Services",
    "name": "Certificate Authority Object ACL Misconfiguration Matches ESC7",
    "version": "1.1",
    "revision_date": "2026-08-04",
    "remediation": (
        "Confirm whether this grant is a deliberate PKI administration "
        "delegation or leftover/overly broad. Review via the CA's own "
        "Security tab in the Certification Authority console "
        "(certsrv.msc, right-click the CA -> Properties -> Security), "
        "or `certutil -config \"<CA>\" -getreg CA\\\\Security` for the "
        "current ACL. GenericAll/WriteDacl/WriteOwner here implies the "
        "holder can reconfigure the CA at will, including publishing "
        "or enabling an ESC1-shaped template (e.g. the built-in SubCA "
        "template) or approving certificate requests that would "
        "otherwise require manager sign-off."
    ),
    "control_id": "PKI-701",
    "framework_tags": [],
    "references": [
        {"title": "BloodHound (SpecterOps): ManageCA edge",
         "url": "https://bloodhound.specterops.io/resources/edges/manage-ca"},
        {"title": "BloodHound (SpecterOps): ManageCertificates edge",
         "url": "https://bloodhound.specterops.io/resources/edges/manage-certificates"},
    ],
    "description": (
        "A non-admin principal holds GenericAll, GenericWrite, "
        "WriteDacl, or WriteOwner on a CA's own AD object -- a "
        "conservative, confidently-verified subset of the full ESC7 "
        "definition (which also includes holding just the specific "
        "ManageCA/ManageCertificates control-access right without full "
        "control; that narrower case is not covered here -- see this "
        "plugin's own docstring for why). Excludes the same baseline "
        "well-known holders used elsewhere in this project."
    ),
    "base_severity": "critical",
    "query": """
        WITH expected_holders AS (
            SELECT do2.object_guid
            FROM directory_object do2
            WHERE do2.client_id = %(client_id)s
              AND (do2.object_sid LIKE '%%-512' OR do2.object_sid LIKE '%%-519'
                   OR do2.object_sid LIKE '%%-544')
            UNION
            SELECT fsp.object_guid
            FROM ad_foreign_security_principal fsp
            WHERE fsp.client_id = %(client_id)s AND fsp.valid_to IS NULL
              AND fsp.well_known_name = 'Local System'
        ),
        dangerous_aces AS (
            SELECT a.object_guid AS ca_guid, a.trustee_sid, a.access_mask,
                   (a.access_mask & 268435456) != 0 AS is_generic_all,
                   (a.access_mask & 1073741824) != 0 AS is_generic_write,
                   (a.access_mask & 262144) != 0 AS is_write_dacl,
                   (a.access_mask & 524288) != 0 AS is_write_owner
            FROM acl_edge a
            JOIN ad_enrollment_service es ON es.object_guid = a.object_guid AND es.valid_to IS NULL
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND (a.access_mask & (268435456 | 1073741824 | 262144 | 524288)) != 0
        ),
        unexpected_holders AS (
            SELECT da.ca_guid,
                   COALESCE(trustee_do.sam_account_name, da.trustee_sid) AS trustee_label,
                   trustee_do.object_sid AS trustee_sid,
                   trustee_do.object_class AS trustee_object_class,
                   da.access_mask,
                   (SELECT string_agg(x, ', ') FROM (VALUES
                        (CASE WHEN da.is_generic_all THEN 'GenericAll' END),
                        (CASE WHEN da.is_generic_write THEN 'GenericWrite' END),
                        (CASE WHEN da.is_write_dacl THEN 'WriteDacl' END),
                        (CASE WHEN da.is_write_owner THEN 'WriteOwner' END)
                    ) AS v(x) WHERE x IS NOT NULL) AS rights_label
            FROM dangerous_aces da
            JOIN directory_object trustee_do
                ON trustee_do.object_sid = da.trustee_sid AND trustee_do.client_id = %(client_id)s
            WHERE NOT EXISTS (
                SELECT 1 FROM expected_holders eh WHERE eh.object_guid = trustee_do.object_guid
            )
        ),
        -- [fix, applied proactively after the same architectural bug
        -- was found and fixed in plugins 9001/6006/6007 this session --
        -- any CA with more than one over-delegated principal would
        -- collide on identity_guid the same way.]
        aggregated AS (
            SELECT ca_guid,
                   array_agg(trustee_label || ' (' || rights_label || ')' ORDER BY trustee_label) AS holder_summaries,
                   jsonb_agg(jsonb_build_object(
                       'trustee_sid', trustee_sid,
                       'trustee_sam_account_name', trustee_label,
                       'trustee_object_class', trustee_object_class,
                       'access_mask', access_mask,
                       'rights', rights_label
                   ) ORDER BY trustee_label) AS holder_details,
                   count(*) AS holder_count
            FROM unexpected_holders
            GROUP BY ca_guid
        )
        SELECT
            'fail' AS status,
            a.ca_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'critical' AS fd_severity,
            a.holder_count || ' unexpected principal(s) hold dangerous rights on Certificate Authority "'
                || es.ca_name || '" (ESC7): ' || array_to_string(a.holder_summaries, '; ') AS summary,
            jsonb_build_object(
                'ca_name', es.ca_name,
                'dns_hostname', es.dns_hostname,
                'holders', a.holder_details
            ) AS detail
        FROM aggregated a
        JOIN ad_enrollment_service es ON es.object_guid = a.ca_guid AND es.valid_to IS NULL
    """,
}
