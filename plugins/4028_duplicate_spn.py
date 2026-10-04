"""
Plugin 4028: Duplicate Service Principal Name Registered on Multiple Accounts

An SPN identifies a service instance to Kerberos, and the KDC uses it to
decide which account's key encrypts the service ticket. That only works if the
SPN resolves to exactly one account.

When two accounts hold the same SPN the KDC cannot choose a key, and returns
KDC_ERR_S_PRINCIPAL_UNKNOWN. The client treats that as "Kerberos is not
available for this service" and **falls back to NTLM**. Access continues to
work, so nothing is reported and nobody investigates. Semperis documented this
as one impact of KerberLoss (CVE-2026-25177): an attacker holding WriteSPN on
any single account in the forest can register a duplicate of any SPN and force
that service off Kerberos and onto NTLM, defeating Kerberos armouring,
constrained delegation controls and any NTLM-reduction programme in one write.

Where NTLM has been disabled outright the same condition is a denial of
service instead, because there is no fallback left.

Duplicates also occur without an attacker. Intra-forest ADMT migrations,
authoritative restores of a deleted account, and cluster or load-balancer
rebuilds all produce them, which is exactly why Microsoft's own guidance
offers dSHeuristics relaxation as a workaround for the resulting
ERROR_DS_SPN_VALUE_NOT_UNIQUE_IN_FOREST failures. A benign origin does not
make the effect benign: the service is off Kerberos either way.

Matching is case-insensitive, because Kerberos SPN comparison is. An SPN
listed twice against the same account is not reported -- that is a duplicate
value, not a duplicate registration, and it has no effect on key selection.

Distinct from plugin 4029, which covers the subtler case where an explicit SPN
shadows a HOST-mapped *alias* rather than duplicating an SPN exactly. Together
they cover both halves of the KerberLoss impact.

[v1.1] Two changes. (1) Finding identity: this finding has no single
object_guid, so its identity is md5(summary + detail). v1.0's detail
carried each holder's distinguishedName, so moving or renaming a holder
"resolved" the finding and opened a new one with nothing changed about
the duplicate. The detail now identifies holders by objectGUID
(whenCreated is kept -- it never changes -- for the migration-debris
triage the remediation describes). (2) Severity: holders of differing
object classes alone no longer raise it to critical, because the most
common benign duplicate is exactly that (HTTP/<host> left on the
computer after the same SPN was set on an app-pool/service user).
Critical is now reserved for a domain controller among the holders, or
a duplicate HOST/ SPN spanning object classes (a user or other
non-computer holding a computer's HOST/ SPN -- the KerberLoss shape that
takes every HOST-mapped service of that machine off Kerberos).
"""

PLUGIN = {
    "plugin_id": 4028,
    "category": "Domain",
    "name": "Duplicate Service Principal Name Registered on Multiple Accounts",
    "version": "1.1",
    "revision_date": "2026-10-04",
    "remediation": (
        "Decide which account legitimately owns the service, then remove the "
        "SPN from every other holder with setspn -D <spn> <account>. "
        "Verify the result with setspn -X, which lists duplicate SPNs "
        "forest-wide and is the quickest way to confirm the cleanup is "
        "complete. Kerberos will resume for that service as soon as only one "
        "holder remains; no restart is required, though clients may cache a "
        "negative result briefly. "
        "Work out which origin applies before assuming the best. If the "
        "evidence shows the holders were created years apart, or one is a "
        "restored or migrated object, this is almost certainly migration "
        "debris -- check whether an ADMT run or an authoritative restore "
        "coincides with the later whenCreated date. If the holders differ in "
        "object class, a user account holding the duplicate of a computer's "
        "SPN in particular, treat it as suspicious: that is the KerberLoss "
        "pattern and it has no legitimate explanation. Security event ID 5136 "
        "on domain controllers identifies who added the value, if SACL "
        "auditing is enabled on servicePrincipalName. "
        "Then remove the conditions that allow it. Confirm SPN uniqueness "
        "verification is enforced (plugin 4030) -- if it is disabled, "
        "duplicates can be created freely by anyone with WriteSPN, and "
        "cleaning up the existing ones will not stop new ones appearing. "
        "Audit who holds write access to servicePrincipalName on the "
        "accounts involved. Finally, check plugin 4027: a duplicate created "
        "via KerberLoss carries invisible Unicode and will look identical to "
        "the legitimate value in dsa.msc, so the pair may not be what it "
        "appears."
    ),
    "control_id": "KERB-205",
    "framework_tags": [
        "NIST-800-53-IA-2",
        "NIST-800-53-IA-4",
        "NIST-800-53-SI-2",
        "NIST-800-53-RA-5",
        "NIST-CSF-2.0-ID.RA-01",
        "PCI-DSS-4.0-8.2.1",
        "PCI-DSS-4.0-6.3.3",
        "CIS-CSC-8-7.3",
        "ISO-27001-2022-A.5.16",
        "ISO-27001-2022-A.8.8",
        "SOC2-CC6.1",
        "SOC2-CC7.1",
        "HIPAA-164.312(a)(2)(i)",
        "MITRE-ATTCK-T1558",
        "MITRE-ATTCK-T1098",
        "MITRE-ATTCK-T1550.002",
        "CVE-2026-25177",
    ],
    "references": [
        {"title": "Semperis: KerberLoss and ResetNightmare -- Kerberos downgrade and full domain takeover",
         "url": "https://www.semperis.com/blog/identity-crisis-novel-vulnerabilities-leading-to-kerberos-downgrade-dos-and-full-domain-takeover/"},
        {"title": "Microsoft: Duplicate SPN check causes restore, domain join and migration failures",
         "url": "https://support.microsoft.com/en-us/topic/duplicate-spn-check-on-windows-server-2012-r2-based-domain-controller-causes-restore-domain-join-and-migration-failures-aa11508f-7dfd-4444-835b-7febc303ed5e"},
    ],
    "description": (
        "Reports a service principal name registered against two or more "
        "accounts. The KDC cannot select an encryption key for an ambiguous "
        "SPN, so it returns KDC_ERR_S_PRINCIPAL_UNKNOWN and clients silently "
        "fall back to NTLM -- or fail outright where NTLM is disabled. "
        "Because access appears to keep working, the condition is rarely "
        "noticed. It arises both from migration and restore debris and, per "
        "KerberLoss (CVE-2026-25177), from deliberate abuse by an attacker "
        "with write access to servicePrincipalName on any one account. "
        "Matching is case-insensitive; an SPN listed twice on the same "
        "account is not reported. Severity is raised to critical when a "
        "domain controller is involved, or when a HOST/ SPN is duplicated "
        "across object classes (e.g. a user holding a computer's HOST/ SPN)."
    ),
    "base_severity": "high",
    "query": """
        WITH holder AS (
            SELECT DISTINCT
                   lower(se.spn) AS spn_key,
                   se.object_guid
            FROM spn_edge se
            WHERE se.client_id = %(client_id)s
              AND se.valid_to IS NULL
              AND se.spn IS NOT NULL
              AND se.spn <> ''
        ),
        dup AS (
            SELECT spn_key, count(*) AS holder_count
            FROM holder
            GROUP BY spn_key
            HAVING count(*) > 1
        ),
        detail_rows AS (
            SELECT d.spn_key,
                   d.holder_count,
                   -- Preserve one original-case spelling for display.
                   min(se.spn) AS spn_display,
                   bool_or(COALESCE(c.is_domain_controller, false)) AS involves_dc,
                   count(DISTINCT do2.object_class) AS distinct_classes,
                   -- [v1.1] stable keys only (no DN): detail is part of the
                   -- identity of this NULL-object_guid finding.
                   jsonb_agg(
                       jsonb_build_object(
                           'object_guid', do2.object_guid,
                           'sam_account_name', do2.sam_account_name,
                           'object_class', do2.object_class,
                           'is_domain_controller',
                               COALESCE(c.is_domain_controller, false),
                           'when_created',
                               COALESCE(c.when_created, u.when_created)
                       ) ORDER BY do2.sam_account_name, do2.object_guid
                   ) AS holders
            FROM dup d
            JOIN holder h ON h.spn_key = d.spn_key
            JOIN spn_edge se
              ON se.object_guid = h.object_guid
             AND se.client_id = %(client_id)s
             AND se.valid_to IS NULL
             AND lower(se.spn) = d.spn_key
            JOIN directory_object do2
              ON do2.object_guid = h.object_guid AND do2.client_id = %(client_id)s
            LEFT JOIN ad_computer c
              ON c.object_guid = h.object_guid
             AND c.client_id = %(client_id)s AND c.valid_to IS NULL
            LEFT JOIN ad_user u
              ON u.object_guid = h.object_guid
             AND u.client_id = %(client_id)s AND u.valid_to IS NULL
            GROUP BY d.spn_key, d.holder_count
        )
        SELECT
            'fail' AS status,
            -- Concerns two or more objects, so no single object_guid applies.
            NULL::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            -- [v1.1] differing classes alone is high, not critical
            CASE
                WHEN r.involves_dc THEN 'critical'
                WHEN r.distinct_classes > 1 AND r.spn_key LIKE 'host/%%' THEN 'critical'
                ELSE 'high'
            END AS fd_severity,
            'Service principal name "' || r.spn_display || '" is registered on '
                || r.holder_count || ' accounts ('
                || (SELECT string_agg(COALESCE(h.value ->> 'sam_account_name', '?'), ', ' ORDER BY h.n)
                    FROM jsonb_array_elements(r.holders) WITH ORDINALITY AS h(value, n))
                || ') -- the KDC cannot select a key, so clients silently fall '
                   'back to NTLM for this service'
                || CASE WHEN r.involves_dc
                        THEN ' and a DOMAIN CONTROLLER is among the holders'
                        WHEN r.distinct_classes > 1
                        THEN ', and the holders are of differing object classes'
                        ELSE '' END AS summary,
            jsonb_build_object(
                'service_principal_name', r.spn_display,
                'holder_count', r.holder_count,
                'holders', r.holders,
                'involves_domain_controller', r.involves_dc,
                'holders_span_object_classes', r.distinct_classes > 1,
                'effect', 'KDC_ERR_S_PRINCIPAL_UNKNOWN then NTLM fallback',
                'related_plugins', jsonb_build_array(4027, 4029, 4030),
                'corroborating_event_id', 5136
            ) AS detail
        FROM detail_rows r
    """,
}
