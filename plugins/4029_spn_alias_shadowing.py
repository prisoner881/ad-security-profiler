"""
Plugin 4029: Explicit Service Principal Name Shadowing a HOST-Mapped Alias

Derived from KerberLoss (CVE-2026-25177), disclosed by Semperis in 2026 and
patched by Microsoft in March 2026.

Every computer account receives a HOST/<name> SPN when it joins the domain.
The sPNMappings attribute in the Configuration partition maps roughly fifty
service classes -- cifs, http, ldap, spooler, wins and so on -- onto that HOST
alias. When a client requests a service ticket for cifs/SERVERB and no explicit
cifs/SERVERB SPN exists, the KDC resolves the alias and encrypts the ticket
with SERVERB's key.

The weakness is precedence: **the SPN lookup algorithm always looks for an
explicit SPN first, and only falls back to the alias if none is found.** So if
an explicit cifs/SERVERB SPN is registered on a *different* account, every
ticket for SERVERB's SMB service is encrypted with that other account's key
instead. SERVERB cannot decrypt them, producing KRB_AP_ERR_MODIFIED and a
denial of service that surfaces to users as misleading errors ("the specified
network name is no longer available", "the target account name is incorrect").

Worse, where Kerberos constrained delegation is in play this becomes an
escalation path rather than an outage. Semperis demonstrated an attacker with
WriteSPN on one host using this to run the full S4U attack and compromise a
third host, without needing WriteSPN on the intermediate service at all.

Why this should not exist in a healthy domain: SPN alias uniqueness
verification, added by CVE-2021-42282 (KB5008382), blocks exactly this
registration. So a finding here means one of four things, all worth an answer:
the check was bypassed via KerberLoss on an unpatched DC; the check is disabled
forest-wide via dSHeuristics character 21 (see plugin 4030); the SPN was
created by a Domain Admin, who bypasses the check; or it predates the 2021
patch and was never cleaned up.

Matching precision: alias uniqueness compares the *entire* remainder of the SPN
after the service class, not just the host. HOST/SERVERB therefore conflicts
with cifs/SERVERB but NOT with http/SERVERB:8080, because the latter maps to
HOST/SERVERB:8080. This plugin compares the full remainder for that reason;
stripping the port would generate false positives on every port-qualified SPN
in the directory.

Note that a conflicting SPN renders identically to a legitimate one in
dsa.msc -- there is nothing for an administrator to notice by eye.

[v1.1] Re-scoped to the service classes the host operating system
implements itself. v1.0 reported every mapped-class SPN on another account,
which flagged the normal, documented Kerberos set-up for a web application
running under a dedicated identity: HTTP/webserver registered on the
application-pool service account (or gMSA) while the computer holds
HOST/webserver. That is not a defect. The KDC resolves an exact SPN match
before it falls back to the HOST alias, so tickets for HTTP/webserver are
correctly encrypted with the service account's key -- the account that is
actually running the web application and can decrypt them. Microsoft's IIS
and SQL Reporting Services Kerberos guidance prescribes exactly this
registration, and v1.0 rated it critical whenever the account was a user.

The shadowing is only harmful where the explicit SPN names a service that
can only ever run under the host's own identity: cifs (the SMB server runs
in the kernel as SYSTEM), rpcss, netlogon, eventlog, spooler, schedule, time,
and the rest of the sPNMappings list apart from the web-hosting classes http,
www and w3svc. No legitimate configuration registers, say, cifs/SERVERB on an
account other than SERVERB (failover-cluster names carry their own HOST/ SPN
on their own computer object, so they never match here). Such an SPN breaks
the service and is the KerberLoss primitive. Those web-hosting classes are
now excluded; everything else is reported as before.

Exact duplicate SPNs, the ambiguity that setspn -X reports, are deliberately
NOT reported here: plugin 4028 covers that case, and duplicating it would
double-count every finding. Severity is now high, or critical only where the
shadowed host is a domain controller (redirecting a DC's cifs or netlogon
service breaks SYSVOL and Group Policy processing, and offers the S4U
escalation path against Tier 0). It no longer depends on whether the
offending account is a user.

Findings are aggregated one-per-offending-account rather than one per
conflicting SPN. A single account can shadow several names at once, and
emitting a row for each would produce multiple findings sharing the same
object_guid, which collides with the evidence table's one-open-version-
per-identity constraint -- the same failure mode that broke plugin 10002
before v0.7.1. The offending account is also the unit of remediation, so
aggregating matches how the finding is actually acted on.

[v1.2] Two refinements. (1) http, www and w3svc are reported again when
the shadowed host is a domain controller: HTTP/<host> is also the SPN of
WinRM / PowerShell remoting, which runs under the host's own identity,
and no application-pool justification applies to a DC, so HTTP/<DC> on
another account shadows WinRM on a Tier-0 host (critical). (2) When
every shadowed host is a disabled computer account, the finding is
rated medium: that is usually a retired server's stale object whose
name a replacement now legitimately serves, i.e. a stale-object cleanup
rather than live shadowing; the detail records each shadowed host's
enabled state and lastLogonTimestamp. Known limitation: sPNMappings is
not collected, so the default alias set (identical to the collector's
HOST_SPN_ALIASES) is assumed; forests that customise sPNMappings are
evaluated against the default list.
"""

PLUGIN = {
    "plugin_id": 4029,
    "category": "Domain",
    "name": "Explicit Service Principal Name Shadowing a HOST-Mapped Alias",
    "version": "1.2",
    "revision_date": "2026-10-04",
    "remediation": (
        "Establish how the conflicting SPN came to exist before removing "
        "it. This finding is limited to service classes the host operating "
        "system implements under its own identity (cifs, rpcss, netlogon, "
        "spooler and the other HOST-mapped classes, excluding the "
        "web-hosting classes http, www and w3svc), so there is no "
        "legitimate configuration that places one of these SPNs on an "
        "account other than the host itself; the shadowed service on that "
        "host is failing Kerberos authentication while it remains. "
        "Note that HTTP/<webserver> registered on an application-pool "
        "service account or gMSA is the correct, documented set-up and is "
        "deliberately not reported -- except on a domain controller, where "
        "HTTP/<DC> belongs to WinRM running as the DC itself. If every "
        "shadowed host is a disabled (retired) computer, remove or clean up "
        "that stale computer object instead. "
        "Unless it is confirmed as debris predating the 2021 uniqueness "
        "checks, treat it as an incident. Remove "
        "it with setspn -D <spn> <account>, then determine how it was created: "
        "check who holds WriteSPN (write access to servicePrincipalName) on "
        "the account that carries it, since that right is what makes this "
        "possible and it is frequently delegated more widely than intended. "
        "Confirm dSHeuristics character 21 is not disabling SPN alias "
        "uniqueness verification (plugin 4030), and confirm domain controllers "
        "carry the March 2026 update that patches CVE-2026-25177. "
        "Because a KerberLoss-created SPN may contain invisible Unicode "
        "characters that make it appear identical to a legitimate value, also "
        "review plugin 4027 output for the accounts involved. Finally, enable "
        "SACL auditing on servicePrincipalName so that Security event ID 5136 "
        "records future changes."
    ),
    "control_id": "KERB-203",
    "framework_tags": ["MITRE-ATTCK-T1558", "MITRE-ATTCK-T1550.003",
                       "MITRE-ATTCK-T1098", "CVE-2026-25177"],
    "references": [
        {"title": "Semperis: KerberLoss and ResetNightmare -- Kerberos downgrade and full domain takeover",
         "url": "https://www.semperis.com/blog/identity-crisis-novel-vulnerabilities-leading-to-kerberos-downgrade-dos-and-full-domain-takeover/"},
        {"title": "Microsoft KB5008382: Verification of uniqueness for UPN, SPN and SPN alias (CVE-2021-42282)",
         "url": "https://support.microsoft.com/en-us/topic/kb5008382-verification-of-uniqueness-for-user-principal-name-service-principal-name-and-the-service-principal-name-alias-cve-2021-42282-4651b175-290c-4e59-8fcb-e4e5cd0cdb29"},
        {"title": "MS-ADTS 3.1.1.5.1.2: Uniqueness Constraints (sPNMappings)",
         "url": "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3c154285-454c-4353-9a99-fb586e806944"},
    ],
    "description": (
        "Reports an explicitly registered service principal name, for a "
        "service the host operating system implements under its own "
        "identity (cifs, rpcss, netlogon, spooler and the other HOST-mapped "
        "classes), that is registered on a different account from the host "
        "holding the matching HOST/ SPN. Because the KDC resolves explicit "
        "SPNs in preference to aliases, service tickets for that service "
        "are encrypted with the wrong account's key: the service on the "
        "host fails Kerberos authentication, and where constrained "
        "delegation is configured it is a documented privilege escalation "
        "path (KerberLoss, CVE-2026-25177). The web-hosting classes http, "
        "www and w3svc are excluded, because registering HTTP/<host> on a "
        "dedicated service account is the documented configuration for a "
        "web application running under that account and is resolved "
        "correctly by the KDC -- except where the shadowed host is a domain "
        "controller (HTTP/<DC> is WinRM under the DC's own identity). "
        "Findings where every shadowed host is a disabled computer account "
        "are rated medium (stale object). Exact duplicate SPNs are reported by plugin "
        "4028. The conflicting SPN is indistinguishable from a legitimate "
        "one in native management tools."
    ),
    "base_severity": "high",
    "query": """
        WITH mapped_class_os (cls) AS (
            -- Default sPNMappings HOST alias set (MS-ADA3 section 2.276),
            -- restricted to services implemented by the host OS itself.
            -- 'host' itself is excluded: HOST/x on two accounts is a plain
            -- duplicate SPN and is reported by plugin 4028, not here.
            VALUES ('alerter'),('appmgmt'),('cisvc'),('clipsrv'),('browser'),
                   ('dhcp'),('dnscache'),('replicator'),('eventlog'),
                   ('eventsystem'),('policyagent'),('oakley'),('dmserver'),
                   ('dns'),('mcsvc'),('fax'),('msiserver'),('ias'),
                   ('messenger'),('netlogon'),('netman'),('netdde'),
                   ('netddedsm'),('nmagent'),('plugplay'),('protectedstorage'),
                   ('rasman'),('rpclocator'),('rpc'),('rpcss'),
                   ('remoteaccess'),('rsvp'),('samss'),('scardsvr'),('scesrv'),
                   ('seclogon'),('scm'),('dcom'),('cifs'),('spooler'),('snmp'),
                   ('schedule'),('tapisrv'),('trksvr'),('trkwks'),('ups'),
                   ('time'),('wins'),('iisadmin'),('msdtc')
            -- [v1.1] The web-hosting classes http, www and w3svc are
            -- deliberately absent. HTTP/<host> on an application-pool
            -- service account (or gMSA) is the documented Kerberos set-up
            -- for IIS, SSRS and similar; the KDC resolves that exact SPN
            -- before the HOST alias, so tickets go to the account that runs
            -- the application. Only classes the OS itself serves under the
            -- host's own identity are a genuine shadowing defect.
        ),
        mapped_class (cls, web_only_for_dc) AS (
            SELECT cls, false FROM mapped_class_os
            UNION ALL
            -- [v1.2] ...except on a domain controller, where HTTP/<DC> is
            -- WinRM / PowerShell remoting running as the DC itself.
            SELECT v.cls, true FROM (VALUES ('http'),('www'),('w3svc')) v(cls)
        ),
        parsed AS (
            -- Alias uniqueness compares the WHOLE remainder after the service
            -- class, so the port and any service-name component are retained.
            -- HOST/srv conflicts with cifs/srv but not with http/srv:8080.
            SELECT se.object_guid,
                   se.spn,
                   lower(split_part(se.spn, '/', 1)) AS cls,
                   lower(substr(se.spn, strpos(se.spn, '/') + 1)) AS remainder
            FROM spn_edge se
            WHERE se.client_id = %(client_id)s
              AND se.valid_to IS NULL
              AND strpos(se.spn, '/') > 1
        ),
        host_spn AS (
            SELECT object_guid, spn, remainder
            FROM parsed
            WHERE cls = 'host'
        ),
        conflict AS (
            SELECT e.object_guid   AS offender_guid,
                   e.spn           AS explicit_spn,
                   e.cls           AS explicit_class,
                   h.object_guid   AS host_guid,
                   h.spn           AS host_spn,
                   h.remainder     AS shadowed_name
            FROM parsed e
            JOIN mapped_class mc ON mc.cls = e.cls
            JOIN host_spn h
              ON h.remainder = e.remainder
             AND h.object_guid <> e.object_guid
            LEFT JOIN ad_computer hdc
              ON hdc.object_guid = h.object_guid
             AND hdc.client_id = %(client_id)s
             AND hdc.valid_to IS NULL
            WHERE NOT mc.web_only_for_dc
               OR COALESCE(hdc.is_domain_controller, false)
        ),
        agg AS (
            -- One row per offending account. An account can shadow several
            -- names at once (cifs/X and http/X, or names on different hosts),
            -- and emitting a row each would produce multiple findings sharing
            -- one object_guid -- which collides on the evidence table's
            -- identity constraint. Aggregating keeps the finding actionable
            -- (it is the offending account you remediate) and collision-free.
            SELECT c.offender_guid,
                   count(*) AS conflict_count,
                   bool_or(COALESCE(hc.is_domain_controller, false)) AS shadows_dc,
                   -- [v1.2] every shadowed host is a disabled computer
                   bool_and(hc.is_enabled IS FALSE) AS all_hosts_disabled,
                   min(c.shadowed_name) AS first_shadowed_name,
                   jsonb_agg(jsonb_build_object(
                       'explicit_spn', c.explicit_spn,
                       'explicit_service_class', c.explicit_class,
                       'shadowed_host_spn', c.host_spn,
                       'shadowed_name', c.shadowed_name,
                       'shadowed_account', hdo.sam_account_name,
                       'shadowed_account_dn', hdo.dn_current,
                       'shadowed_host_is_domain_controller',
                           COALESCE(hc.is_domain_controller, false),
                       'shadowed_host_os', hc.operating_system,
                       'shadowed_host_enabled', hc.is_enabled,
                       'shadowed_host_last_logon', hc.last_logon_timestamp
                   ) ORDER BY c.explicit_spn, c.host_spn) AS conflicts
            FROM conflict c
            JOIN directory_object hdo
              ON hdo.object_guid = c.host_guid AND hdo.client_id = %(client_id)s
            LEFT JOIN ad_computer hc
              ON hc.object_guid = c.host_guid
             AND hc.client_id = %(client_id)s
             AND hc.valid_to IS NULL
            GROUP BY c.offender_guid
        )
        SELECT
            'fail' AS status,
            a.offender_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            -- [v1.1] Critical only where a domain controller's own service
            -- is shadowed; the offending account's object class no longer
            -- escalates severity on its own.
            CASE
                WHEN a.shadows_dc THEN 'critical'
                -- [v1.2] retired (disabled) hosts only: stale object
                WHEN a.all_hosts_disabled THEN 'medium'
                ELSE 'high'
            END AS fd_severity,
            'Account "' || COALESCE(odo.sam_account_name, a.offender_guid::text)
                || '" holds ' || a.conflict_count
                || ' explicit host-service SPN(s) that shadow a HOST alias '
                   'belonging to another account ('
                || (SELECT string_agg(x.value ->> 'explicit_spn', ', '
                                      ORDER BY x.value ->> 'explicit_spn')
                    FROM jsonb_array_elements(a.conflicts) AS x)
                || ') -- these services run under the host''s own identity, so '
                   'Kerberos tickets the KDC issues for them are encrypted with '
                   'a key the host does not hold'
                || CASE WHEN a.shadows_dc
                        THEN ', and a DOMAIN CONTROLLER is among the shadowed hosts'
                        ELSE '' END AS summary,
            jsonb_build_object(
                'offending_account', odo.sam_account_name,
                'offending_account_dn', odo.dn_current,
                'offending_object_class', odo.object_class,
                'conflict_count', a.conflict_count,
                'shadows_domain_controller', a.shadows_dc,
                'conflicts', a.conflicts,
                'scope',
                    'Host-implemented service classes only; http/www/w3svc on '
                    'a service account is the documented configuration and is '
                    'not reported. Exact duplicate SPNs: plugin 4028.',
                'note',
                    'SPN alias uniqueness verification should have blocked '
                    'these registrations; see plugin 4030 and CVE-2026-25177'
            ) AS detail
        FROM agg a
        JOIN directory_object odo
            ON odo.object_guid = a.offender_guid AND odo.client_id = %(client_id)s
    """,
}
