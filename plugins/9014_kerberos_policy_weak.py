"""
Plugin 9014: Kerberos Policy Weaker Than Recommended

Evaluates the domain Kerberos policy ([Kerberos Policy] in GptTmpl.inf)
that Group Policy actually applies, and reports values weaker than the
Windows defaults that DISA STIG and Microsoft's baselines require:

    MaxTicketAge          max user ticket (TGT) lifetime   <= 10 hours, not 0
    MaxRenewAge           max TGT renewal lifetime         <= 7 days
    MaxServiceAge         max service ticket lifetime      <= 600 minutes, not 0
    MaxClockSkew          max clock skew                   <= 5 minutes
    TicketValidateClient  enforce user logon restrictions  = 1 (enabled)

0 for MaxTicketAge / MaxServiceAge means tickets never expire.

Why: long ticket lifetimes extend how long a stolen or forged ticket can be
used (pass-the-ticket, MITRE ATT&CK T1550.003) and how long a disabled
account keeps working; a large clock skew widens the replay window;
disabling "Enforce user logon restrictions" stops the KDC from checking
that the account is still allowed to log on when it issues service tickets.

How it is resolved: Kerberos policy (like account policy) only takes effect
from GPOs linked at the domain root. For every domain controller the
winning value per key is taken from the GPOs v_gpo_dc_application lists as
linked_at_domain with a non-NULL precedence (precedence 1 wins). A key no
applying GPO sets has the Windows default (10 / 7 / 600 / 5 / 1) and is
compliant. Non-numeric values are ignored. If DCs disagree (security
filtering), every weak value is reported. One row for the domain
(object_guid = the domain root), fail / medium. Detail lists any
domain-linked GPO whose SYSVOL folder could not be read, since its
settings were not evaluated (plugin 9021). Zero rows unless SYSVOL has
been collected (adprofiler.py --sysvol).
"""

PLUGIN = {
    "plugin_id": 9014,
    "category": "Organizational Units",
    "name": "Kerberos Policy Weaker Than Recommended",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "GPO-9014",
    "framework_tags": [
        "NIST-800-53-CM-6", "NIST-800-53-CM-2", "NIST-CSF-2.0-PR.PS-01",
        "PCI-DSS-4.0-2.2.1", "CIS-CSC-8-4.1", "ISO-27001-2022-A.8.9", "SOC2-CC7.1",
        "HIPAA-164.312(c)(1)",
        "NIST-800-53-IA-2(8)", "ISO-27001-2022-A.8.5",
        "DISA-STIG",
        "MITRE-ATTCK-T1550.003",
    ],
    "references": [
        {"title": "Microsoft Learn: Kerberos Policy (security policy settings)",
         "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/kerberos-policy"},
        {"title": "MITRE ATT&CK T1550.003: Use Alternate Authentication Material: Pass the Ticket",
         "url": "https://attack.mitre.org/techniques/T1550/003/"},
    ],
    "description": (
        "Reports a domain Kerberos policy, as applied by GPOs linked at the domain, "
        "that is weaker than the Windows defaults required by DISA STIG: maximum user "
        "ticket lifetime over 10 hours (or 0 = never expires), maximum renewal over 7 "
        "days, maximum service ticket lifetime over 600 minutes (or 0), maximum clock "
        "skew over 5 minutes, or \"Enforce user logon restrictions\" disabled. Keys no "
        "applying GPO sets have the Windows default and are compliant. Long lifetimes "
        "extend how long stolen or forged tickets stay usable. Requires SYSVOL "
        "collection (adprofiler.py --sysvol)."
    ),
    "remediation": (
        "Edit the GPO named in the finding (normally Default Domain Policy): Computer "
        "Configuration > Policies > Windows Settings > Security Settings > Account "
        "Policies > Kerberos Policy. Set Maximum lifetime for user ticket to 10 hours, "
        "Maximum lifetime for user ticket renewal to 7 days, Maximum lifetime for "
        "service ticket to 600 minutes, Maximum tolerance for computer clock "
        "synchronization to 5 minutes and Enforce user logon restrictions to Enabled "
        "(or remove the settings to fall back to these defaults). Kerberos policy "
        "must be defined in a GPO linked at the domain root; values in GPOs linked to "
        "OUs are ignored. Run gpupdate /force on the DCs and verify with "
        "Get-GPResultantSetOfPolicy or secedit /export."
    ),
    "base_severity": "medium",
    "query": """
        WITH sysvol AS (
            SELECT EXISTS (SELECT 1 FROM ad_gpo_sysvol s
                           WHERE s.client_id = %(client_id)s AND s.read_status = 'ok') AS collected
        ),
        rule (key_lower, key_name, unit, recommended) AS (
            VALUES ('maxticketage', 'MaxTicketAge', 'hours', '<= 10 hours, not 0'),
                   ('maxrenewage', 'MaxRenewAge', 'days', '<= 7 days'),
                   ('maxserviceage', 'MaxServiceAge', 'minutes', '<= 600 minutes, not 0'),
                   ('maxclockskew', 'MaxClockSkew', 'minutes', '<= 5 minutes'),
                   ('ticketvalidateclient', 'TicketValidateClient', NULL, '1 (enabled)')
        ),
        app AS (
            SELECT a.dc_guid, a.gpo_guid, a.precedence
            FROM v_gpo_dc_application a
            CROSS JOIN sysvol sv
            WHERE sv.collected
              AND a.client_id = %(client_id)s
              AND a.linked_at_domain
              AND a.precedence IS NOT NULL
        ),
        win AS (
            SELECT DISTINCT ON (a.dc_guid, lower(s.setting_key))
                   a.dc_guid, lower(s.setting_key) AS key_lower, s.setting_value, s.gpo_guid
            FROM app a
            JOIN gpo_setting_edge s
              ON s.client_id = %(client_id)s AND s.gpo_guid = a.gpo_guid AND s.valid_to IS NULL
             AND s.scope = 'machine' AND s.source = 'security_template'
             AND lower(s.section) = 'kerberos policy'
            WHERE lower(s.setting_key) IN (SELECT key_lower FROM rule)
            ORDER BY a.dc_guid, lower(s.setting_key), a.precedence
        ),
        val AS (
            SELECT DISTINCT w.key_lower, w.gpo_guid, btrim(w.setting_value)::bigint AS n
            FROM win w
            WHERE btrim(w.setting_value) ~ '^[0-9]{1,15}$'
        ),
        bad AS (
            SELECT v.*, r.key_name, r.unit, r.recommended
            FROM val v
            JOIN rule r ON r.key_lower = v.key_lower
            WHERE (v.key_lower = 'maxticketage' AND (v.n > 10 OR v.n = 0))
               OR (v.key_lower = 'maxrenewage' AND v.n > 7)
               OR (v.key_lower = 'maxserviceage' AND (v.n > 600 OR v.n = 0))
               OR (v.key_lower = 'maxclockskew' AND v.n > 5)
               OR (v.key_lower = 'ticketvalidateclient' AND v.n = 0)
        ),
        agg AS (
            SELECT string_agg(DISTINCT b.key_name || '=' || b.n
                                  || COALESCE(' ' || b.unit, '')
                                  || ' (recommended ' || b.recommended || ')', '; '
                              ORDER BY b.key_name || '=' || b.n
                                  || COALESCE(' ' || b.unit, '')
                                  || ' (recommended ' || b.recommended || ')') AS weak_list,
                   jsonb_agg(jsonb_build_object(
                       'setting', b.key_name, 'value', b.n, 'unit', b.unit,
                       'recommended', b.recommended,
                       'gpo_guid', g.gpo_guid, 'gpo_object_guid', b.gpo_guid,
                       'gpo_display_name', g.display_name)
                       ORDER BY b.key_name, b.n, b.gpo_guid) AS weak_settings
            FROM bad b
            LEFT JOIN ad_gpo g
              ON g.object_guid = b.gpo_guid AND g.client_id = %(client_id)s AND g.valid_to IS NULL
            HAVING count(*) > 0
        ),
        unreadable AS (
            SELECT jsonb_agg(DISTINCT jsonb_build_object(
                       'gpo_object_guid', a.gpo_guid, 'display_name', g.display_name,
                       'read_status', COALESCE(gs.read_status, 'not collected'))) AS gpos
            FROM app a
            LEFT JOIN ad_gpo_sysvol gs
              ON gs.client_id = %(client_id)s AND gs.gpo_object_guid = a.gpo_guid
            LEFT JOIN ad_gpo g
              ON g.object_guid = a.gpo_guid AND g.client_id = %(client_id)s AND g.valid_to IS NULL
            WHERE gs.read_status IS DISTINCT FROM 'ok'
        )
        SELECT
            'fail' AS status,
            dm.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Domain Kerberos policy applied by Group Policy is weaker than recommended: '
                || ag.weak_list AS summary,
            jsonb_build_object(
                'domain_dn', d.dn_current,
                'weak_settings', ag.weak_settings,
                'windows_defaults', jsonb_build_object(
                    'MaxTicketAge', 10, 'MaxRenewAge', 7, 'MaxServiceAge', 600,
                    'MaxClockSkew', 5, 'TicketValidateClient', 1),
                'unreadable_domain_linked_gpos', u.gpos,
                'note', 'resolved from GPOs linked at the domain root that apply to domain controllers; unset keys use the Windows defaults'
            ) AS detail
        FROM agg ag
        CROSS JOIN unreadable u
        JOIN ad_domain dm
          ON dm.client_id = %(client_id)s AND dm.valid_to IS NULL
        JOIN directory_object d
          ON d.object_guid = dm.object_guid AND d.client_id = dm.client_id AND NOT d.is_deleted
    """,
}
