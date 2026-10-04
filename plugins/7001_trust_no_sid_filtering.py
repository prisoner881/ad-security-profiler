"""
Plugin 7001: Trust Relationship Does Not Have SID Filtering Enabled

SID filtering (trustAttributes bit TRUST_ATTRIBUTE_QUARANTINED_DOMAIN,
0x00000004, confirmed against Microsoft's own [MS-ADTS] specification)
restricts which SIDs a trusted domain is permitted to present in an
authenticated user's token. Without it, a compromise of the trusted
side of the relationship can inject SID history entries (or otherwise
forge a token) claiming membership in a privileged group on THIS side
of the trust -- a well-documented cross-domain/cross-forest escalation
path.

Deliberately excludes trusts where TRUST_ATTRIBUTE_WITHIN_FOREST is set
(SID filtering is not meaningful within a single forest, since intra-
forest trusts share the same security boundary by design) and excludes
disabled trusts (trustDirection=0, covered separately by plugin 7004).

Known limitation, documented rather than silently assumed away: real-
world research (see reference) has found that legitimate, long-standing
intra-forest parent-child trusts can show trustAttributes=0 -- the
WITHIN_FOREST bit was introduced in Windows Server 2003 and was never
retroactively backfilled onto trusts created before that, even after
the domain itself is fully upgraded. Such a trust is indistinguishable
at the attribute level from a genuinely unfiltered external trust. This
finding's evidence includes the trust partner's name specifically so
the auditor can make that judgment call -- a name that's clearly a
child of this domain warrants a different read than an unrelated
external domain name.

[v1.1] Scoped to the trusts where bit 0x4 actually governs SID filtering:
external (non-forest) Windows trusts -- trustType 1 (downlevel) or 2
(uplevel), FOREST_TRANSITIVE (0x8) not set -- whose direction includes
outbound (trustDirection & 2), i.e. where this domain trusts the partner
and so is the side exposed to injected SIDs. Forest trusts are filtered
to the trusted forest's SIDs by default without 0x4; their relaxation
(TREAT_AS_EXTERNAL, 0x40) is plugin 7002's check, so every healthy forest
trust (trustAttributes = 0x8) was previously a false positive here. MIT
Kerberos realm trusts (trustType 3), where SID filtering does not apply,
and inbound-only trusts, where the filtering is done by the partner, are
no longer reported.
"""

PLUGIN = {
    "plugin_id": 7001,
    "category": "Trusts",
    "name": "Trust Relationship Does Not Have SID Filtering Enabled",
    "version": "1.1",
    "revision_date": "2026-10-04",
    "remediation": (
        "First, confirm whether this trust is a genuine external/cross-"
        "forest relationship or a legacy intra-forest parent-child trust "
        "that predates Windows Server 2003 and was never retroactively "
        "flagged (see this finding's description for why that matters). "
        "For a genuine external or cross-forest trust, enable SID "
        "filtering/quarantine: `netdom trust <TrustingDomain> /domain:"
        "<TrustedDomain> /quarantine:yes` (or the equivalent in Active "
        "Directory Domains and Trusts). Test before enforcing in "
        "production -- SID filtering can break access for accounts that "
        "legitimately rely on SID history from a prior migration across "
        "that same trust boundary."
    ),
    "control_id": "TRUST-101",
    "framework_tags": [
        "NIST-800-53-AC-4",
        "NIST-800-53-AC-20",
        "NIST-800-53-SC-7",
        "NIST-CSF-2.0-PR.AA-05",
        "CIS-CSC-8-12.2",
        "ISO-27001-2022-A.8.20",
        "ISO-27001-2022-A.8.22",
        "SOC2-CC6.6",
        "DISA-STIG",
        "DISA-STIG-V-243484",
        "MITRE-ATTCK-T1134.005",
    ],
    "references": [
        {"title": "dirkjanm.io: Active Directory forest trusts -- How does SID filtering work?",
         "url": "https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/"},
        {"title": "DISA Active Directory Domain STIG V-243484: Security identifiers (SIDs) must be configured to use only authentication data of directly trusted external or forest trust",
         "url": "https://cyber.trackr.live/stig/Active_Directory_Domain/3/7#V-243484"},
    ],
    "description": (
        "SID filtering (trustAttributes bit TRUST_ATTRIBUTE_QUARANTINED_"
        "DOMAIN, 0x00000004, confirmed against Microsoft's own [MS-ADTS] "
        "specification) restricts which SIDs a trusted domain can "
        "present in an authenticated token. Without it, a compromise on "
        "the trusted side can inject SID history claiming membership in "
        "a privileged group on this side of the trust. Applies to "
        "external (non-forest) Windows trusts that are outbound or "
        "bidirectional, where this domain trusts the partner. Excludes "
        "forest trusts (SID filtering is on by default there; relaxing it "
        "via TREAT_AS_EXTERNAL is plugin 7002), MIT Kerberos realm trusts, "
        "inbound-only trusts (filtering is the partner's side), intra-"
        "forest trusts (TRUST_ATTRIBUTE_WITHIN_FOREST set), where SID "
        "filtering isn't meaningful, and disabled trusts (covered by "
        "plugin 7004). Known limitation: legitimate, long-standing "
        "parent-child trusts predating Windows Server 2003 can show "
        "trustAttributes=0 and are indistinguishable at the attribute "
        "level from a genuinely unfiltered external trust -- review the "
        "trust partner name in this finding's evidence before treating "
        "this as a confirmed issue."
    ),
    "base_severity": "high",
    "query": """
        SELECT
            'fail' AS status,
            t.object_guid,
            'CAT_II' AS stig_severity,
            'DISA Active Directory Domain STIG V-243484' AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'Trust with "' || COALESCE(t.trust_partner, '(unknown)')
                || '" does not have SID filtering enabled' AS summary,
            jsonb_build_object(
                'trust_partner', t.trust_partner,
                'trust_direction', t.trust_direction,
                'trust_type', t.trust_type,
                'trust_attributes', t.trust_attributes,
                'is_forest_transitive', (COALESCE(t.trust_attributes, 0) & 8) != 0
            ) AS detail
        FROM ad_trust t
        WHERE t.valid_to IS NULL
          AND t.client_id = %(client_id)s
          AND NOT t.sid_filtering_enabled
          AND (COALESCE(t.trust_attributes, 0) & 32) = 0
          -- [v1.1] external trusts only: forest trusts filter by default
          -- (relaxation = TREAT_AS_EXTERNAL, plugin 7002); MIT realms excluded
          AND (COALESCE(t.trust_attributes, 0) & 8) = 0
          AND COALESCE(t.trust_type, 2) IN (1, 2)
          -- [v1.1] outbound or bidirectional: this domain trusts the partner
          AND (COALESCE(t.trust_direction, 0) & 2) != 0
    """,
}
