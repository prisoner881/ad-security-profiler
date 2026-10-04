"""
Plugin 2003: Unsupported or Soon-to-be-Unsupported Operating System

A computer running an OS past end of support receives no security
patches at all for newly discovered vulnerabilities -- one of the most
fundamental, well-understood security exposures there is. EOL dates
verified directly against Microsoft's own lifecycle documentation, not
assumed, given how much severity depends on getting them right.

Two severities: confirmed already past end of support (fail), and
approaching end of support within roughly a year (warn) -- specifically
Windows Server 2016, whose extended support ends January 12, 2027.

Notable precision worth keeping in mind when reading results: Windows 10
reached end of support October 14, 2025. Domain-joined machines
specifically do NOT qualify for the free consumer Extended Security
Updates program (confirmed directly from Microsoft's own ESU
documentation) -- only the separate, paid commercial ESU program covers
them, which is a deliberate purchase decision, not something to assume
is already in place.

[v1.1] Also flags whether the machine is likely dormant (no logon in 90+
days, same threshold as plugin 2006) directly in its own output. An
unsupported OS on a machine that's also been dormant for years is very
likely a retired asset whose account was never cleaned up -- the correct
fix there is deleting the account, not upgrading Windows on a box sitting
in a closet, and both findings resolve simultaneously either way. Without
this, a reader has to manually cross-reference against plugin 2006's
separate output to reach the same conclusion.

[v1.5] Matching is done on the OS string with the (R)/(TM) signs removed,
so "Windows Server(R) 2008 Standard" (2008 RTM) is caught; Windows 2000 and
Windows NT are added. Windows 10 LTSC/LTSB editions are judged by build
instead of being flagged wholesale: LTSB 2015 (10240) is past end of
support, LTSB 2016 (14393) and Enterprise LTSC 2021 (19044) are warned until
their end dates (2026-10-13 / 2027-01-12) and failed after, LTSC 2019
(17763) and IoT Enterprise LTSC 2021 are supported and not flagged. The
same date switch turns the Windows Server 2016 warning into a failure after
2027-01-12. The "likely dormant" marker moved from the summary to the
detail only: it is derived from now() and made the summary flip with no
change in AD.
"""

PLUGIN = {
    "plugin_id": 2003,
    "category": "Computer Accounts",
    "name": "Unsupported or Soon-to-be-Unsupported Operating System",
    "version": "1.5",
    "revision_date": "2026-10-04",
    "remediation": (
        "Check whether the machine is also flagged as dormant (no logon "
        "in 90+ days, reflected directly in this finding's own detail) "
        "before deciding how to remediate. If dormant, this is very "
        "likely a retired asset whose account was never cleaned up -- "
        "confirm the machine is genuinely decommissioned, then disable "
        "and remove the account; this resolves the unsupported-OS finding "
        "and the separate dormant-account finding (plugin 2006) at the "
        "same time, and costs far less than an OS upgrade that would be "
        "wasted effort on hardware nobody is using. Only for machines "
        "confirmed still in active use: upgrade to a currently-supported "
        "OS version, or, as an interim measure only, enroll in the paid "
        "commercial Extended Security Updates program if available for "
        "that OS version -- treat ESU as a temporary bridge, not a "
        "long-term solution, since it typically covers critical security "
        "fixes only and has its own hard expiration date. Domain-joined "
        "Windows 10 machines specifically do not qualify for the free "
        "consumer ESU program -- only paid commercial ESU covers them. "
        "For machines approaching end of support (Windows Server 2016, "
        "extended support ending January 12, 2027), begin migration "
        "planning now rather than waiting until the deadline."
    ),
    "control_id": "OS-001",
    "framework_tags": [
        "NIST-800-53-SI-2",
        "NIST-800-53-RA-5",
        "NIST-800-53-SA-22",
        "NIST-CSF-2.0-ID.RA-01",
        "NIST-CSF-2.0-PR.PS-02",
        "PCI-DSS-4.0-6.3.3",
        "PCI-DSS-4.0-12.3.4",
        "CIS-CSC-8-2.2",
        "CIS-CSC-8-7.3",
        "ISO-27001-2022-A.8.8",
        "SOC2-CC7.1",
        "MITRE-ATTCK-T1210",
    ],
    "references": [
        {"title": "Microsoft Lifecycle Policy",
         "url": "https://learn.microsoft.com/en-us/lifecycle/"},
    ],
    "description": (
        "A computer running an operating system past its end-of-support "
        "date receives no security patches at all for newly discovered "
        "vulnerabilities, regardless of how well it is otherwise "
        "configured -- one of the most fundamental security exposures "
        "there is. End-of-support dates verified directly against "
        "Microsoft's own lifecycle documentation as of this plugin's "
        "revision date: Windows 10 (all editions) ended October 14, 2025; "
        "Windows Server 2012/2012 R2 ended October 10, 2023 (paid "
        "Extended Security Updates available only until October 13, "
        "2026); Windows Server 2008/2008 R2, Server 2003, Windows 7/8/8.1/"
        "Vista/XP are all long past end of support. Windows Server 2016 "
        "is flagged separately at lower severity as approaching its "
        "extended-support end date (January 12, 2027) rather than already "
        "unsupported (and failed once that date has passed). Windows Server 2019/2022/2025 and Windows 11 are "
        "not flagged -- confirmed still within their supported lifecycle "
        "as of this writing, though individual Windows 11 feature-update "
        "versions have their own rolling end-of-support dates this check "
        "does not track at that level of granularity. Also flags likely "
        "dormancy (no logon in 90+ days) directly in this finding's own "
        "output, since an unsupported OS on an otherwise-dormant machine "
        "usually means a retired asset rather than an active one still "
        "needing patched -- correlated here rather than requiring the "
        "reader to manually cross-reference plugin 2006's separate output. "
        "NOT downgraded when disabled, and this reasoning is genuinely "
        "different from most other computer-account findings: disabling "
        "the AD computer object blocks that account's ability to "
        "authenticate to the domain, but does not power off or otherwise "
        "disable the underlying physical or virtual machine, which can "
        "remain network-reachable and running its unsupported OS "
        "regardless of the AD object's state."
    ),
    "base_severity": "critical",
    "query": """
        WITH os_norm AS (
            SELECT
                c.object_guid, c.sam_account_name, c.dns_hostname,
                c.operating_system, c.operating_system_version, c.is_domain_controller,
                c.last_logon_timestamp, c.is_enabled,
                regexp_replace(c.operating_system, '[' || chr(174) || chr(8482) || ']', '', 'g') AS os,
                substring(c.operating_system_version FROM '[(]([0-9]+)[)]') AS build
            FROM ad_computer c
            WHERE c.valid_to IS NULL AND c.client_id = %(client_id)s
              AND c.operating_system IS NOT NULL
        ),
        os_check AS (
            SELECT
                n.*,
                (n.last_logon_timestamp IS NULL OR n.last_logon_timestamp < now() - interval '90 days')
                    AS likely_dormant,
                CASE
                    -- Windows 10 LTSC/LTSB: supported per build, not per family
                    WHEN n.os ILIKE '%%windows 10%%' AND (n.os ILIKE '%%LTSC%%' OR n.os ILIKE '%%LTSB%%') THEN
                        CASE
                            WHEN n.build = '10240' THEN 'fail'
                            WHEN n.build = '17763' THEN NULL
                            WHEN n.build = '19044' AND n.os ILIKE '%%IoT%%' THEN NULL
                            WHEN n.build = '14393' AND now() >= timestamptz '2026-10-14' THEN 'fail'
                            WHEN n.build = '19044' AND now() >= timestamptz '2027-01-13' THEN 'fail'
                            WHEN n.build IN ('14393', '19044') THEN 'warn'
                            ELSE 'warn'  -- unknown LTSC build: review
                        END
                    WHEN n.os ILIKE '%%windows 10%%' THEN 'fail'
                    WHEN n.os ILIKE '%%server%%2012%%' THEN 'fail'
                    WHEN n.os ILIKE '%%server%%2008%%' THEN 'fail'
                    WHEN n.os ILIKE '%%server%%2003%%' THEN 'fail'
                    WHEN n.os ILIKE '%%windows 2000%%' THEN 'fail'
                    WHEN n.os ILIKE '%%windows nt%%' THEN 'fail'
                    WHEN n.os ILIKE '%%windows 7%%' THEN 'fail'
                    WHEN n.os ILIKE '%%windows 8%%' THEN 'fail'
                    WHEN n.os ILIKE '%%windows xp%%' THEN 'fail'
                    WHEN n.os ILIKE '%%windows vista%%' THEN 'fail'
                    WHEN n.os ILIKE '%%server%%2016%%' AND now() >= timestamptz '2027-01-13' THEN 'fail'
                    WHEN n.os ILIKE '%%server%%2016%%' THEN 'warn'
                    ELSE NULL
                END AS match_status
            FROM os_norm n
        )
        SELECT
            match_status AS status,
            object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE
                WHEN match_status = 'fail' AND is_domain_controller THEN 'critical'
                WHEN match_status = 'fail' THEN 'high'
                WHEN match_status = 'warn' AND is_domain_controller THEN 'high'
                ELSE 'medium'
            END AS fd_severity,
            (CASE WHEN is_domain_controller THEN 'Domain Controller ' ELSE '' END)
                || 'Computer ' || COALESCE(sam_account_name, object_guid::text)
                || CASE
                     WHEN match_status = 'fail' THEN ' is running an unsupported operating system ('
                     ELSE ' is running an operating system approaching end of support ('
                   END
                || operating_system || COALESCE(' ' || operating_system_version, '') || ')' AS summary,
            jsonb_build_object(
                'sam_account_name', sam_account_name,
                'dns_hostname', dns_hostname,
                'operating_system', operating_system,
                'operating_system_version', operating_system_version,
                'is_domain_controller', is_domain_controller,
                'last_logon_timestamp', last_logon_timestamp,
                'likely_dormant', likely_dormant,
                'is_enabled', is_enabled
            ) AS detail
        FROM os_check
        WHERE match_status IS NOT NULL
    """,
}
