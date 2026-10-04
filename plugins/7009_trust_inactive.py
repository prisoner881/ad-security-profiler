"""
Plugin 7009: Inactive Trust

Domain controllers change the inter-domain trust password every 30 days
(the trust key is stored on the trusted domain object, TDO), so the TDO's
whenChanged keeps moving while the trust is in use and both sides can reach
each other. A TDO unchanged for more than 60 days means the password has not
rotated twice: the partner domain is gone, unreachable or broken, or the
trust has been forgotten. Stale trusts are unmanaged attack surface -- a
decommissioned partner's name can be re-registered, the old trust key may
survive in backups of a domain nobody watches -- and should be removed
(PingCastle T-Inactive; NIST AC-2/CM-7 review of external connections).

Data: the latest directory_object_version of the trust's TDO,
attributes_full ->> 'whenChanged' (stored by the collector as an ISO-8601
string; LDAP generalized time "YYYYMMDDHHMMSS.0Z" and single-element arrays
are also parsed). It is compared with the start time of the run being
assessed (sync_run.started_at for %(run_id)s; now() if absent), so a
re-assessment of the same run gives the same result. Missing or
unparseable whenChanged -> no finding. One low finding per trust; the exact
age is in detail only.

Excluded: disabled trusts (trust_direction 0, plugin 7004) and MIT Kerberos
realm trusts (trustType 3), whose password is set manually and never
rotates automatically.
"""

PLUGIN = {
    "plugin_id": 7009,
    "category": "Trusts",
    "name": "Inactive Trust",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "TRUST-7009",
    "framework_tags": [
        "NIST-800-53-AC-4", "NIST-800-53-AC-20", "NIST-800-53-SC-7",
        "NIST-800-53-CM-7", "NIST-CSF-2.0-PR.AA-05", "CIS-CSC-8-12.2",
        "ISO-27001-2022-A.8.20", "ISO-27001-2022-A.8.22", "SOC2-CC6.6",
    ],
    "references": [
        {"title": "PingCastle health check rules (T-Inactive)",
         "url": "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
        {"title": "Microsoft AskDS: Machine account password process (trust/secure channel password rotation)",
         "url": "https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396026"},
    ],
    "description": (
        "The trusted domain object has not changed for more than 60 days. "
        "The trust password rotates every 30 days while the trust works, so "
        "the partner is most likely decommissioned or unreachable and the "
        "trust should be removed."
    ),
    "remediation": (
        "Verify the trust: netdom trust <this domain> /domain:<partner> "
        "/verify (or Test-ComputerSecureChannel / Active Directory Domains "
        "and Trusts -> Validate). If the partner no longer exists or is no "
        "longer needed, remove the trust on this side (and on the partner, "
        "if it still exists): netdom trust <this domain> /domain:<partner> "
        "/remove /force. If it is still required, fix name resolution and "
        "connectivity between the PDC emulators, then reset the trust "
        "password (netdom trust ... /resetOneSide on both sides)."
    ),
    "base_severity": "low",
    "query": """
        WITH ref AS (
            SELECT COALESCE(
                (SELECT r.started_at FROM sync_run r
                  WHERE r.run_id = %(run_id)s AND r.client_id = %(client_id)s),
                now()) AS ref_time
        ),
        tdo AS (
            SELECT t.object_guid, t.trust_partner, t.trust_type, t.trust_direction,
                   t.trust_attributes, wc.txt AS when_changed_raw
            FROM ad_trust t
            JOIN directory_object o
              ON o.object_guid = t.object_guid AND o.client_id = t.client_id AND NOT o.is_deleted
            JOIN LATERAL (
                SELECT CASE jsonb_typeof(v.attributes_full -> 'whenChanged')
                           WHEN 'array' THEN v.attributes_full -> 'whenChanged' ->> 0
                           ELSE v.attributes_full ->> 'whenChanged'
                       END AS txt
                FROM directory_object_version v
                WHERE v.object_guid = t.object_guid
                  AND v.client_id = t.client_id
                ORDER BY v.valid_from DESC, v.version_id DESC
                LIMIT 1
            ) wc ON TRUE
            WHERE t.client_id = %(client_id)s
              AND t.valid_to IS NULL
              AND COALESCE(t.trust_direction, -1) <> 0
              AND COALESCE(t.trust_type, 0) <> 3
        ),
        parsed AS (
            SELECT tdo.*,
                   CASE
                       WHEN when_changed_raw ~ '^[0-9]{14}(\\.[0-9]+)?Z$'
                           THEN to_timestamp(substr(when_changed_raw, 1, 14), 'YYYYMMDDHH24MISS')::timestamp
                                AT TIME ZONE 'UTC'
                       WHEN when_changed_raw ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}'
                           THEN when_changed_raw::timestamptz
                   END AS when_changed
            FROM tdo
        )
        SELECT
            'fail' AS status,
            p.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'Trust with "' || COALESCE(p.trust_partner, '(unknown)')
                || '" appears inactive: its trusted domain object has not changed for more than '
                   '60 days (the trust password normally rotates every 30 days)' AS summary,
            jsonb_build_object(
                'trust_partner', p.trust_partner,
                'trust_type', p.trust_type,
                'trust_direction', p.trust_direction,
                'trust_attributes', p.trust_attributes,
                'tdo_when_changed', p.when_changed,
                'assessed_at', r.ref_time,
                'days_since_change', floor(extract(epoch FROM (r.ref_time - p.when_changed)) / 86400)::int,
                'threshold_days', 60
            ) AS detail
        FROM parsed p
        CROSS JOIN ref r
        WHERE p.when_changed IS NOT NULL
          AND p.when_changed < r.ref_time - interval '60 days'
    """,
}
