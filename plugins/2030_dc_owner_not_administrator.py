"""
Plugin 2030: Domain Controller Computer Object Owned by an Unexpected Principal

Distinct from plugins 5006 and 2028 (which check ownership of the
domain root/AdminSDHolder, and ownership combined with an independent
weakness on the computer, respectively): this checks the owner of
every Domain Controller's own computer object directly, regardless of
any other condition. An owner can always rewrite an object's ACL
outright, no matter what the object's current explicit permissions
say -- gaining control of a DC's own computer account object is a
direct, uncomplicated path to compromising that DC and, from there,
the domain. Confirmed against Purple Knight's own equivalent check.

[v1.1] Absorbs plugin 4023 (Domain Controller Computer Object Not Owned
by an Expected Principal), now retired with superseded_by=2030. The two
checked the same owner_sid on the same DC object_guid with conflicting
allow-lists (4023 flagged the RID-500 Administrator and
BUILTIN\\Administrators owners this plugin accepted). Consolidated into
one tiered model, matching the dcpromo default and PingCastle P-DCOwner:

  - Domain Admins (-512) or Enterprise Admins (-519): expected, nothing
    reported.
  - BUILTIN\\Administrators (S-1-5-32-544), the RID-500 Administrator
    account, or SYSTEM (S-1-5-18): already Tier 0, so not an escalation
    path, but a deviation from the default -- LOW, status 'warn'. The
    owner should be a group, consistent across DCs.
  - Any other owner that is privileged per v_privileged_principal:
    MEDIUM, status 'warn'. Privilege that comes only from owning a DC
    computer object (tier0_ownership via a DC) is ignored for this test,
    since every DC owner would otherwise qualify through this very
    finding.
  - A non-Tier-0 owner: CRITICAL, status 'fail' -- it can take over the
    DC through its owner rights. Summary wording unchanged from v1.0.
  - An owner SID that resolves to no live collected object: CRITICAL,
    status 'fail', summary shows the raw SID (unchanged from v1.0).
  Both 'fail' tiers were HIGH in v1.0; raised to CRITICAL to match
  plugin 5006 (domain root / AdminSDHolder owned by an unexpected
  principal) -- an unexpected owner of a DC's computer object is the
  same takeover path one step removed.
Carried over from 4023: the PingCastle reference, the dns_hostname
detail key and the promotion-residue explanation. detail gains
owner_tier, owner_resolved and owner_privilege_sources. Owner data
comes from adprofiler's targeted DC-only security descriptor read.
"""

PLUGIN = {
    "plugin_id": 2030,
    "category": "Computer Accounts",
    "name": "Domain Controller Computer Object Owned by an Unexpected Principal",
    "version": "1.1",
    "revision_date": "2026-10-03",
    "remediation": (
        "Reassign ownership of this Domain Controller's computer object "
        "to Domain Admins (the dcpromo default): in Active Directory "
        "Users and Computers with Advanced Features enabled (or ADSI "
        "Edit), open the object -> Properties -> Security -> Advanced "
        "-> Owner -> change to Domain Admins. A different owner is most "
        "commonly residue from how the DC was promoted (by an account "
        "that was privileged at the time but isn't now, or from a "
        "computer object pre-created or joined by someone else). For a "
        "non-Tier-0 or unresolvable owner, treat it as a possible "
        "compromise path: review the object's full ACL, and anything "
        "else the previous owner may have granted or changed, before "
        "assuming the ownership was benign. For BUILTIN\\Administrators "
        "or the built-in Administrator account, this is hygiene: set "
        "the same group owner on every DC."
    ),
    "control_id": "PRIV-205",
    "framework_tags": [],
    "references": [
        {"title": "PingCastle: ACL Check rules -- P-DCOwner",
         "url": "https://pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
    ],
    "description": (
        "Checks the owner of every Domain Controller's own computer "
        "object. An owner can always rewrite an object's ACL regardless "
        "of its current explicit permissions, so control of a DC's "
        "computer object is a direct path to compromising that DC and "
        "the domain. Domain Admins or Enterprise Admins is the expected "
        "owner and is not reported. BUILTIN\\Administrators, the "
        "built-in Administrator account or SYSTEM is reported as a "
        "low-severity deviation (already Tier 0); another privileged "
        "principal as medium; a non-Tier-0 or unresolvable owner as "
        "critical."
    ),
    "base_severity": "critical",
    "query": """
        WITH dc AS (
            SELECT c.object_guid, c.client_id, c.sam_account_name, c.dns_hostname,
                   cdo.owner_sid
            FROM ad_computer c
            JOIN directory_object cdo ON cdo.object_guid = c.object_guid AND cdo.client_id = c.client_id
            WHERE c.valid_to IS NULL
              AND c.client_id = %(client_id)s
              AND c.is_domain_controller
              AND cdo.owner_sid IS NOT NULL
              -- Domain Admins / Enterprise Admins: the dcpromo default.
              AND cdo.owner_sid NOT LIKE '%%-512'
              AND cdo.owner_sid NOT LIKE '%%-519'
        ),
        dc_guids AS (
            SELECT object_guid
            FROM ad_computer
            WHERE client_id = %(client_id)s AND valid_to IS NULL AND is_domain_controller
        ),
        owner_privilege AS (
            -- Privilege from owning a DC computer object is exactly what
            -- this plugin reports, so it does not make the owner Tier 0.
            SELECT object_guid,
                   array_agg(DISTINCT privilege_source ORDER BY privilege_source) AS privilege_sources
            FROM v_privileged_principal
            WHERE client_id = %(client_id)s
              AND NOT (privilege_source IN ('tier0_ownership', 'tier0_ownership_via_group')
                       AND via_object_guid IN (SELECT object_guid FROM dc_guids))
            GROUP BY object_guid
        ),
        classified AS (
            SELECT d.*, o.object_guid AS owner_guid, o.sam_account_name AS owner_sam_account_name,
                   o.object_class AS owner_object_class,
                   (o.object_guid IS NOT NULL AND NOT o.is_deleted) AS owner_resolved,
                   op.privilege_sources,
                   CASE
                       WHEN d.owner_sid = 'S-1-5-32-544' OR d.owner_sid LIKE '%%-500'
                            OR d.owner_sid = 'S-1-5-18'
                           THEN 'tier0_builtin'
                       WHEN o.object_guid IS NULL OR o.is_deleted THEN 'unresolved'
                       WHEN op.object_guid IS NOT NULL THEN 'privileged'
                       ELSE 'non_tier0'
                   END AS owner_tier
            FROM dc d
            -- One owner row per DC: a SID can match more than one
            -- directory_object row (e.g. a deleted object and a live one),
            -- and two rows for one DC object_guid would collide on
            -- finding identity. Prefer the live object.
            LEFT JOIN LATERAL (
                SELECT x.object_guid, x.sam_account_name, x.object_class, x.is_deleted
                FROM directory_object x
                WHERE x.object_sid = d.owner_sid AND x.client_id = d.client_id
                ORDER BY x.is_deleted, x.object_guid
                LIMIT 1
            ) o ON true
            LEFT JOIN owner_privilege op ON op.object_guid = o.object_guid AND NOT o.is_deleted
        )
        SELECT
            CASE WHEN k.owner_tier IN ('tier0_builtin', 'privileged') THEN 'warn' ELSE 'fail' END AS status,
            k.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE k.owner_tier
                WHEN 'tier0_builtin' THEN 'low'
                WHEN 'privileged' THEN 'medium'
                ELSE 'critical'
            END AS fd_severity,
            'Domain Controller ' || k.sam_account_name || ' is owned by '
                || COALESCE(k.owner_sam_account_name,
                            CASE k.owner_sid
                                WHEN 'S-1-5-32-544' THEN 'BUILTIN\\Administrators'
                                WHEN 'S-1-5-18' THEN 'SYSTEM'
                            END,
                            k.owner_sid)
                || CASE k.owner_tier
                       WHEN 'tier0_builtin'
                           THEN ' (Tier 0, but not the default Domain Admins/Enterprise Admins owner)'
                       WHEN 'privileged'
                           THEN ' (privileged, but not the default Domain Admins/Enterprise Admins owner)'
                       ELSE ''
                   END AS summary,
            jsonb_build_object(
                'sam_account_name', k.sam_account_name,
                'dns_hostname', k.dns_hostname,
                'owner_sid', k.owner_sid,
                'owner_sam_account_name', k.owner_sam_account_name,
                'owner_object_class', k.owner_object_class,
                'owner_resolved', k.owner_resolved,
                'owner_tier', k.owner_tier,
                'owner_privilege_sources', k.privilege_sources
            ) AS detail
        FROM classified k
    """,
}
