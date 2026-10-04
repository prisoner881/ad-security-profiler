"""
Plugin 4034: KDS Root Key Readable by Non-Tier-0 Principals (Golden gMSA)

The Key Distribution Service root keys (msKds-ProvRootKey objects under
CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,<config>)
hold msKds-RootKeyData, the secret from which the password of every group
managed service account (gMSA) -- and every dMSA -- in the forest is derived.
Semperis' "Golden gMSA" research (2022) showed that whoever can read that
attribute once can compute every gMSA password offline, for the life of the
key; the root key cannot be rotated, only replaced by a new key plus new
gMSAs. By default only Domain Admins/Enterprise Admins of the forest root,
SYSTEM and the Enterprise Domain Controllers can read it. Any other reader is
a forest-wide credential exposure (MITRE ATT&CK T1555; CISA/Five Eyes 2024 AD
guidance recommends gMSAs on the assumption that this key is protected).

Detection: current allow ACEs (acl_edge) that grant GenericAll (0x10000000 or
full control 0xF01FF), GenericRead (0x80000000), or ReadProperty (0x10) with no
object type or with msKds-RootKeyData's schemaIDGUID
(26627c27-08a2-0a40-a1b1-8dce85b42993):
  * on a current KDS root key object (ad_kds_root_key), ACEs that apply to the
    object itself (inherit_only not TRUE; inherited ACEs included), and
  * on the CN=Master Root Keys container, ACEs that certainly reach the keys:
    inherit-only ACEs scoped to all classes or to msKds-ProvRootKey
    (aa02fd41-17e0-4f18-8687-b2239649736b), or any ACE scoped to that class.
    acl_edge does not record CONTAINER_INHERIT, so an effective (not
    inherit-only) container ACE cannot be told apart from a non-inheritable
    one and is not counted; the keys' own ACLs carry what was inherited.
Trustees excluded: SYSTEM, Domain Admins (-512), Enterprise Admins (-519),
Administrators (S-1-5-32-544), Domain Controllers (-516), Enterprise Domain
Controllers (S-1-5-9), Creator Owner and SELF, and any SID that resolves to a
Tier 0 principal (v_privileged_principal). Unresolvable SIDs are reported by
SID (object_guid NULL). One critical finding per trustee.

Second part: when ad_domain.kds_root_key_count = 0 and no gMSA exists, an
informational 'warn' row on the domain root says no KDS root key exists, so
gMSAs cannot be used (Microsoft recommends gMSAs for service accounts).

Caveat: a low-privileged collection account may not be able to see the key
objects at all (their default ACL does not grant Authenticated Users read).
A count of 0 then means "none visible" -- which is why the info row is
suppressed whenever gMSAs exist -- and the key-level part of this check can
only see what the collection account could read.
"""

PLUGIN = {
    "plugin_id": 4034,
    "category": "Domain",
    "name": "KDS Root Key Readable by Non-Tier-0 Principals (Golden gMSA)",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "CRED-4034",
    "framework_tags": [
        "NIST-800-53-IA-5(1)", "NIST-800-53-SC-28", "NIST-800-53-SC-12",
        "NIST-CSF-2.0-PR.DS-01", "PCI-DSS-4.0-8.3.2", "PCI-DSS-4.0-8.6.2",
        "CIS-CSC-8-3.11", "ISO-27001-2022-A.5.17", "SOC2-CC6.1",
        "HIPAA-164.312(a)(2)(iv)", "NIST-800-53-AC-6", "MITRE-ATTCK-T1555",
    ],
    "references": [
        {"title": "Semperis: GoldenGMSA tool and research",
         "url": "https://github.com/Semperis/GoldenGMSA"},
        {"title": "[MS-ADA2]: Attribute msKds-RootKeyData",
         "url": "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/aa13d9fe-34ec-40db-a6ae-3930f49de815"},
        {"title": "MITRE ATT&CK T1555: Credentials from Password Stores",
         "url": "https://attack.mitre.org/techniques/T1555/"},
        {"title": "CISA et al.: Detecting and Mitigating Active Directory Compromises",
         "url": "https://www.cisa.gov/resources-tools/resources/detecting-and-mitigating-active-directory-compromises"},
    ],
    "description": (
        "A principal outside Tier 0 holds an ACE that lets it read the KDS "
        "root key secret (msKds-RootKeyData) -- GenericAll, GenericRead or "
        "ReadProperty on a root key, or an inheritable grant on the Master "
        "Root Keys container. With that value every gMSA/dMSA password in "
        "the forest can be computed offline, indefinitely (Golden gMSA). "
        "Also reports, informationally, a forest with no KDS root key and no "
        "gMSAs (gMSAs cannot be used)."
    ),
    "remediation": (
        "Remove the ACE: dsacls \"CN=<key guid>,CN=Master Root Keys,CN=Group "
        "Key Distribution Service,CN=Services,CN=Configuration,<forest>\" "
        "/R <trustee> (and the same on the Master Root Keys container), or "
        "edit the security in ADSI Edit (Configuration partition). Only "
        "SYSTEM, Domain/Enterprise Admins of the forest root and Enterprise "
        "Domain Controllers should have read access. Because the key itself "
        "cannot be rotated, treat an exposed key as compromised: create a "
        "new root key (Add-KdsRootKey), recreate every gMSA so it binds to "
        "the new key, and remove the old key (Microsoft: 'Recover from a "
        "Golden gMSA attack'). Audit reads with a SACL on the container "
        "(event 4662). For the informational case, create a root key with "
        "Add-KdsRootKey -EffectiveImmediately (keys are usable after "
        "replication, ~10 hours) and move service accounts to gMSAs."
    ),
    "base_severity": "critical",
    "query": """
        WITH key_aces AS (
            SELECT a.trustee_sid, a.access_mask, a.object_type_guid, a.inherited,
                   ko.dn_current AS on_dn, 'root key' AS on_kind
            FROM acl_edge a
            JOIN ad_kds_root_key k
              ON k.object_guid = a.object_guid AND k.client_id = a.client_id AND k.valid_to IS NULL
            JOIN directory_object ko
              ON ko.object_guid = k.object_guid AND ko.client_id = k.client_id AND NOT ko.is_deleted
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND a.inherit_only IS NOT TRUE
            UNION ALL
            SELECT a.trustee_sid, a.access_mask, a.object_type_guid, a.inherited,
                   c.dn_current, 'Master Root Keys container (inheritable)'
            FROM acl_edge a
            JOIN directory_object c
              ON c.object_guid = a.object_guid AND c.client_id = a.client_id AND NOT c.is_deleted
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND c.object_class = 'container'
              AND c.dn_current ILIKE 'CN=Master Root Keys,%%'
              AND ((a.inherit_only IS TRUE
                    AND (a.inherited_object_type_guid IS NULL
                         OR a.inherited_object_type_guid = 'aa02fd41-17e0-4f18-8687-b2239649736b'))
                   OR a.inherited_object_type_guid = 'aa02fd41-17e0-4f18-8687-b2239649736b')
        ),
        readable AS (
            SELECT ka.*,
                   CASE
                       WHEN (ka.access_mask & 268435456) <> 0 OR (ka.access_mask & 983551) = 983551
                           THEN 'GenericAll'
                       WHEN (ka.access_mask & 2147483648) <> 0 THEN 'GenericRead'
                       WHEN ka.object_type_guid IS NULL THEN 'ReadProperty (all properties)'
                       ELSE 'ReadProperty (msKds-RootKeyData)'
                   END AS right_label
            FROM key_aces ka
            WHERE (ka.access_mask & 268435456) <> 0
               OR (ka.access_mask & 983551) = 983551
               OR (ka.access_mask & 2147483648) <> 0
               OR ((ka.access_mask & 16) <> 0
                   AND (ka.object_type_guid IS NULL
                        OR ka.object_type_guid = '26627c27-08a2-0a40-a1b1-8dce85b42993'))
        ),
        trustee AS (
            SELECT r.trustee_sid,
                   (SELECT t.object_guid FROM directory_object t
                     WHERE t.object_sid = r.trustee_sid AND t.client_id = %(client_id)s
                       AND NOT t.is_deleted
                     ORDER BY t.object_guid LIMIT 1) AS trustee_guid
            FROM (SELECT DISTINCT trustee_sid FROM readable) r
            WHERE r.trustee_sid NOT IN ('S-1-5-18', 'S-1-5-9', 'S-1-5-32-544', 'S-1-3-0', 'S-1-5-10')
              AND r.trustee_sid NOT LIKE 'S-1-5-21-%%-512'
              AND r.trustee_sid NOT LIKE 'S-1-5-21-%%-519'
              AND r.trustee_sid NOT LIKE 'S-1-5-21-%%-516'
        ),
        exposed AS (
            SELECT t.trustee_sid, t.trustee_guid
            FROM trustee t
            WHERE t.trustee_guid IS NULL
               OR NOT EXISTS (
                    SELECT 1 FROM v_privileged_principal pp
                    WHERE pp.client_id = %(client_id)s AND pp.object_guid = t.trustee_guid)
        )
        SELECT
            'fail' AS status,
            e.trustee_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'critical' AS fd_severity,
            'Non-Tier-0 principal ' || COALESCE(o.sam_account_name, o.dn_current, e.trustee_sid)
                || CASE WHEN o.object_guid IS NULL THEN ' (unresolved SID)' ELSE '' END
                || ' can read the KDS root key secret (Golden gMSA) via '
                || string_agg(DISTINCT r.right_label || ' on ' || r.on_kind, '; '
                              ORDER BY r.right_label || ' on ' || r.on_kind)
                || ': every gMSA password in the forest can be computed offline' AS summary,
            jsonb_build_object(
                'trustee_sid', e.trustee_sid,
                'trustee', COALESCE(o.sam_account_name, o.dn_current),
                'trustee_object_class', o.object_class,
                'grants', jsonb_agg(DISTINCT jsonb_build_object(
                    'object_dn', r.on_dn,
                    'object_kind', r.on_kind,
                    'right', r.right_label,
                    'access_mask', r.access_mask,
                    'object_type_guid', r.object_type_guid,
                    'inherited', r.inherited))
            ) AS detail
        FROM exposed e
        JOIN readable r ON r.trustee_sid = e.trustee_sid
        LEFT JOIN directory_object o
          ON o.object_guid = e.trustee_guid AND o.client_id = %(client_id)s
        GROUP BY e.trustee_sid, e.trustee_guid, o.object_guid, o.sam_account_name,
                 o.dn_current, o.object_class

        UNION ALL

        SELECT
            'warn',
            d.object_guid,
            NULL, NULL, NULL, NULL,
            'info',
            'No KDS root key exists in the forest of domain '
                || COALESCE(d.dns_root, o.dn_current)
                || ': gMSAs cannot be used',
            jsonb_build_object(
                'dns_root', d.dns_root,
                'kds_root_key_count', d.kds_root_key_count,
                'gmsa_count', 0,
                'note', 'A low-privileged collection account may not see root keys; '
                        'reported only because no gMSA exists either')
        FROM ad_domain d
        JOIN directory_object o
          ON o.object_guid = d.object_guid AND o.client_id = d.client_id AND NOT o.is_deleted
        WHERE d.client_id = %(client_id)s
          AND d.valid_to IS NULL
          AND d.kds_root_key_count = 0
          AND NOT EXISTS (
                SELECT 1 FROM ad_computer g
                JOIN directory_object go
                  ON go.object_guid = g.object_guid AND go.client_id = g.client_id AND NOT go.is_deleted
                WHERE g.client_id = %(client_id)s AND g.valid_to IS NULL AND g.is_gmsa)
    """,
}
