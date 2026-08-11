#!/usr/bin/env python3
"""
================================================================================
 adprofiler.py -- Active Directory Security & Compliance Profiler (Collector)
================================================================================

VERSION: 0.5.7

CHANGELOG:
    0.5.7 - Fixed a long-standing stale error message: the schema-
            incompatibility failure told users to "Apply schema.sql and
            schema_migration_v2.sql" -- filenames that stopped being
            accurate many migrations ago (the actual files are
            schema_init.sql and whatever schema_migration_vNN.sql is
            current). This sent a real client chasing the wrong file
            when their database was actually just missing a later
            incremental migration. New message correctly warns against
            re-running schema_init.sql against a populated database
            (data-loss risk) and points at the incremental migration
            path instead.
    0.5.6 - AD-integrated DNS zone collection (domain-scoped zones only,

CHANGELOG:
    0.5.6 - AD-integrated DNS zone collection (domain-scoped zones only,
            DomainDnsZones partition). Parses dNSProperty per [MS-DNSP]
            2.3.2.1 to extract DSPROPERTY_ZONE_ALLOW_UPDATE. Supports
            plugin 4025 (nonsecure dynamic updates).
    0.5.5 - Domain controller computer-object ownership scanning (targeted
            owner-only SD read, same low-cost profile as domain root/
            AdminSDHolder -- not full ACE scanning). Supports plugin 4023.
    0.5.4 - ADCS ACL collection: certificate template objects, CA
            (pKIEnrollmentService) objects, each CA's own computer
            object (cross-referenced via dNSHostName), and the Public
            Key Services / Certificate Templates / Enrollment Services
            containers, plus NTAuthCertificates (already collected as
            an object, now also ACL-scanned). Enables ESC4 (template
            ACL misconfiguration), ESC5 (PKI infrastructure object ACL
            misconfiguration), and ESC7 (CA object ACL misconfiguration)
            detection -- confirmed LDAP-native for all three before
            building anything; ESC6/ESC16 were investigated and ruled
            out as requiring the CA server's own registry/RPC interface,
            outside this project's LDAP-only model. Required moving the
            acl_edge sync_edges() call from immediately after the OU ACL
            loop to after this new ADCS section -- see the comment left
            in both spots for why a second, separate sync call would
            have been a real bug (already proven once this session),
            not a style choice.
    0.5.3 - NTAuthCertificates collection (ad_ntauth_store). New
            dependency: cryptography, for X.509/DER parsing -- this
            project's first need for it, unlike security descriptor
            parsing (impacket) which already existed for ACL
            collection. Every certificate in the forest-wide
            NTAuthCertificates object (trusted for smart card/
            certificate-based domain logon) is parsed and cross-
            referenced against known Enrollment Service CAs by plugin
            6005, surfacing orphaned or unauthorized entries. Requires
            schema_migration_v24.sql.
    0.5.2 - Added admin_count to computer collection (previously users
            and groups only). Extends plugins 3021 (missing
            AdminSDHolder marker) and 5007 (privileged object owned by
            an unprivileged account) to cover computers -- both had
            explicitly documented this as a known gap since they were
            first written. Requires schema_migration_v23.sql.
    0.5.1 - gMSA password-reader tracking. No new object collection --
            gMSAs are a schema subclass of computer (confirmed against
            Microsoft's own [MS-ADSC] spec), already returned by the
            existing computer collection pass. Added
            msDS-GroupMSAMembership to COMPUTER_ATTRS (a full security
            descriptor, same format as RBCD's own delegation attribute,
            reused here for a different purpose: who can retrieve the
            gMSA's computed password), with the same base64-encoding
            special case in build_attributes_full() that RBCD's
            attribute already needed, since normalize_value()'s generic
            bytes fallback wasn't trusted for this syntax type without
            direct verification against a real DC. Parsed into a new
            dedicated table, gmsa_password_reader_edge -- deliberately
            not reused into acl_edge or delegation_edge; see
            resolve_gmsa_password_readers()'s own docstring for why.
            Requires schema_migration_v22.sql.
    0.5.0 - Organizational Units: full typed-table collection (ad_ou),
            matching every other object class rather than a one-off.
            gPLink (on both OUs and the domain object) resolved into a
            new gpo_link_edge many-to-many table -- closes the
            "orphaned GPO" and "which GPOs actually apply where" gaps
            this project previously had zero visibility into. ACL
            collection extended from domain root + AdminSDHolder only
            to also cover every collected OU -- OU delegation
            (GenericAll/WriteDacl/etc. over everything within it) is
            one of the more common real-world privilege-escalation
            paths, and this project had no visibility into it before.
            Requires schema_migration_v21.sql.
    0.4.2 - Fixed client.domain_fqdn being populated with args.dc_host
            (the specific domain controller hostname typed at
            --dc-host, e.g. 'df-dc-01.forge.local') instead of the
            actual AD domain FQDN ('forge.local') -- close enough to
            look right, wrong enough to break any lookup by the real
            domain name. Found via entra_graph_collector.py's
            --domain-fqdn, which needs the real domain name to find
            the right client row. New base_dn_to_fqdn() derives the
            correct value from base_dn's own DC= components instead,
            which every run already resolves correctly regardless of
            what hostname was passed at the command line. Existing
            production client rows are NOT automatically corrected --
            see the accompanying one-time UPDATE statement.
    0.4.1 - Added --full-rescan: forces every object to get a fresh
            version + typed-columns write this run, even when its raw
            AD attributes are unchanged. Closes a real gap found on the
            first live run against forge.local after v0.4.0's mail/
            proxy_addresses/when_created columns shipped -- every
            existing object's when_created (and, separately, well-
            known-SID resolution for foreign security principals) came
            back NULL/unresolved, because the change-detection path
            that recomputes typed columns only runs when an object's
            raw attributes actually differ from what's already stored.
            None of forge.local's 146 objects had genuinely changed
            since baseline, so none of them ever got the new columns
            backfilled -- not a data-quality bug, but a gap in how
            newly-added derived data reaches already-baselined objects.
            Recorded honestly as change_kind='rescanned' (new enum
            value), not 'modified', since nothing in AD actually
            changed. Requires schema_migration_v19.sql.
    0.4.0 - Added mail/proxyAddresses collection for users, and
            whenCreated promoted to a first-class when_created column
            for users, computers, and groups (previously fetched and
            stored only inside attributes_full's raw JSONB, never
            surfaced as a queryable column). Driven by three new
            "inventory"-type plugins in adaudit.py v0.7.0 (a parallel
            plugin type for snapshot listings, not findings) that
            needed both. Requires schema_migration_v18.sql.
    0.3.2 - Closed a real gap found during a follow-up ACL plugin-
            generation pass: parse_security_descriptor() has computed
            each scanned object's owner SID since v0.3.0, but nothing
            ever persisted it -- silently discarded every run.
            Ownership is a real, distinct security-relevant fact
            (BloodHound's "Owns" edge: an owner implicitly holds
            WRITE_DAC-equivalent rights regardless of what the DACL
            itself says). Added directory_object.owner_sid (generic,
            not scoped to one object type, matching object_sid's own
            precedent) and threaded it through for both objects this
            project currently scans ACLs for (domain root,
            AdminSDHolder). Requires schema_migration_v17.sql.
    0.3.1 - Added Enterprise Domain Controllers (S-1-5-9) to
            WELL_KNOWN_SIDS, found via the first real run of ACL
            collection against forge.local: this well-known SID
            correctly gets collected as a foreignSecurityPrincipal
            object (that part always worked), but had no display name
            mapped, so plugin 5001 showed it as a raw SID string
            instead of a readable name. No new collection needed --
            purely a display fix; will self-correct on the next
            collection run via the same change-detection mechanism
            already used for every other typed-column update.
    0.2.6 - Fixed a real, confirmed display bug found against a real run:
            the per-category log line inside collect_object_class
            ("<label>: N object(s) processed (X new, Y changed this
            pass)") was printing the shared, run-WIDE cumulative
            stats.created/stats.modified counters directly, not a count
            scoped to that category. Invisible in a typical no-op delta
            run (0 either way), but became obviously wrong once any
            earlier category had genuine changes: every subsequent
            category's line kept echoing that same stale cumulative
            number, including categories with zero actual objects (e.g.
            a "trusts" line reporting "2 changed" while also reporting
            "0 trusts object(s) processed"). The shared counters
            themselves were never wrong -- the final Run Summary's true
            whole-run totals were always correct -- only this one
            per-category line was reading the wrong value. Fixed by
            snapshotting the counters at function entry and reporting
            the delta. No schema change, no plugin change.
    0.2.5 - Systematic gap-analysis pass against BloodHound/PingCastle's
            actual finding catalogs. Two new collection additions found
            necessary: (1) foreignSecurityPrincipal objects were never
            collected at all -- well-known SIDs (Everyone, Anonymous
            Logon, Authenticated Users) added to a group's membership
            are represented as real AD objects under
            CN=ForeignSecurityPrincipals, not literal accounts. This
            directly explains the "N unresolved (not a collected
            object)" line present in every single collection run
            throughout this entire project. New minimal typed table
            ad_foreign_security_principal, added to KNOWN_TYPED_TABLES
            so it participates in the existing deletion-detection
            machinery automatically. (2) dSHeuristics 7th character
            (anonymous LDAP access, confirmed against MS-ADTS and DISA
            STIG V-243503) folded into the existing Directory Service
            object query already used for tombstone lifetime -- no new
            LDAP round-trip. Requires schema_migration_v16.sql (includes
            an enum addition that must commit in its own transaction
            before anything reads the new value).
    0.2.4 - Closed three more gaps found during a follow-up ad_domain
            pass. laps_schema_present: whether LAPS is present anywhere
            in the forest at all -- already computed and logged on every
            run ("LAPS schema detected: ..."), but discarded rather than
            stored. pwd_no_clear_change and pwd_allows_admin_lockout:
            pwdProperties bits 0x4/0x8 -- pwdProperties has been
            collected since the base schema, but only bits 0x1 and 0x10
            were ever extracted from it. Requires
            schema_migration_v15.sql.
    0.2.3 - Fixed a real, confirmed bug in tombstone lifetime collection,
            found while investigating a real "could not read
            msDS-DeletedObjectLifetime" warning. Verified directly
            against Microsoft's own protocol spec (MS-ADTS 1887de08):
            msDS-DeletedObjectLifetime being unset is the COMMON case,
            not an edge case, and the spec-correct fallback in that case
            is the older tombstoneLifetime attribute on the same object
            -- which the old code never even requested. The old
            hardcoded last-resort default (180 days, used when nothing
            could be read at all) was ALSO wrong -- per the same spec,
            the correct last-resort default is 60 days. Now requests
            both attributes in one search and applies the correct
            two-tier precedence, with the correct final default. Also
            added tombstone_lifetime_is_default, distinguishing a
            CONFIRMED explicitly-configured value from an ASSUMED
            default -- a real trust distinction for anything downstream
            (e.g. adaudit.py plugin 4011) that evaluates this value.
            Requires schema_migration_v14.sql.
    0.2.2 - Added machine_account_quota (ms-DS-MachineAccountQuota --
            never collected at all; controls how many computers an
            ordinary user can join to the domain, defaults to 10 when
            unset) and pwd_reversible_encryption_domain_wide (pwdProperties
            bit 0x10, DOMAIN_PASSWORD_STORE_CLEARTEXT -- pwdProperties was
            already collected but only bit 0x1 was ever extracted) to
            ad_domain. Requires schema_migration_v13.sql.
    0.2.1 - Added description, notes, and sid_history to ad_group -- the
            same class of gap already closed on ad_user and ad_computer.
            Deliberately did NOT add pwdLastSet or msDS-KeyCredentialLink:
            groups are not authenticatable security principals, so
            neither concept applies to them. Requires
            schema_migration_v12.sql.
    0.2.0 - Full audit of deletion/remediation handling across every data
            point, prompted by a direct request to check whether the
            v0.1.8/v0.1.9 computer-account bug had analogs elsewhere.
            Findings: (1) ad_user was already correctly covered by the
            same generic fix as ad_computer -- confirmed by inspection,
            not just assumption. (2) Edge tables (group membership, SPNs,
            delegation) are architecturally immune to this entire class
            of bug -- sync_edges() compares a complete fresh LDAP read
            against currently-open edges every single run and closes
            anything not reconfirmed, with no dependency on isolated
            deletion detection at all. (3) A real, different gap WAS
            found: ad_fgpp and ad_enrollment_service objects are both
            classified as the generic object_class='other' (shared with
            OUs, containers, and DNS records), so the object_class-keyed
            lookup used by both the v0.1.8 fix and the v0.1.9 repair
            function could never have closed either of their typed
            tables on deletion, regardless of collector version. Fixed
            by replacing the object_class-keyed lookup entirely with
            close_typed_row_if_open(), which checks every table in
            KNOWN_TYPED_TABLES directly rather than trying to infer the
            single right one -- sidesteps the ambiguity rather than
            working around it, and needs no per-class mapping
            maintenance for any future typed table either. Verified
            against a staged FGPP-deletion scenario matching the exact
            gap (object_class='other', typed row still open) -- correctly
            repaired, where the previous object_class-keyed version could
            not have caught it. Re-verified the existing computer-
            deletion scenario and idempotency still hold after the
            redesign. OBJECT_CLASS_TO_TYPED_TABLE removed, superseded.
    0.1.9 - Fixed a real, confirmed follow-on to the v0.1.8 deletion bug.
            v0.1.8 only closes a typed table row at the moment a
            deletion is first detected -- it has no way to revisit an
            object already marked directory_object.is_deleted=TRUE by an
            EARLIER run (in particular, any run using the pre-v0.1.8
            collector) whose typed row was never closed. Once that
            happens, the object becomes permanently invisible to
            collect_deleted_objects()'s own USN-watermark filter: the
            deletion isn't "new" relative to any future run, since an
            earlier run already consumed and advanced past it in the
            watermark. Confirmed against a real case: two computer
            accounts, deleted via ADUC and caught by an earlier
            pre-v0.1.8 run, remained permanently visible to every
            adaudit.py plugin even after upgrading to v0.1.8, because
            nothing in v0.1.8 could ever revisit them again. Added
            repair_orphaned_deleted_typed_rows(), a self-healing
            reconciliation step that runs on EVERY invocation regardless
            of run_type (not gated to delta runs, since it checks
            already-persisted state rather than doing a fresh LDAP
            query): any directory_object row with is_deleted=TRUE whose
            typed table still shows valid_to IS NULL gets repaired,
            regardless of when or by which collector version the
            deletion was originally detected. Verified directly against
            a staged stuck-orphan scenario (repairs correctly, and is
            idempotent -- a second run finds nothing left to fix) and
            confirmed harmless against the existing fresh-deletion
            scenario in test_harness.py (0 repairs needed there, as
            expected, since that deletion is caught within the same run
            that has the v0.1.8 fix). Also fixed a UUID/text type
            mismatch caught during this same testing: psycopg2 needs an
            explicit ::uuid[] cast for a Python list of GUIDs passed to
            = ANY(%s), or Postgres defaults to interpreting it as text[]
            and the comparison fails outright.
    0.1.8 - Fixed a real, confirmed bug: collect_deleted_objects() marked
            directory_object.is_deleted correctly but never closed the
            corresponding TYPED table row (ad_user/ad_computer/etc). Since
            every adaudit.py plugin queries the typed table directly with
            WHERE valid_to IS NULL, a deleted object's typed row stayed
            open forever regardless of the actual AD deletion, and every
            plugin kept flagging it indefinitely. Confirmed against a real
            case: two computer accounts deleted via ADUC continued
            appearing in every finding across a subsequent adaudit.py run
            with no indication anything had changed. Now closes the
            matching typed table row in the same pass. Verified end-to-end
            via a new deletion scenario added to test_harness.py, not just
            code inspection.
    0.1.7 - Closed three more gaps found during a systematic final pass
            over ad_computer: is_enabled was never computed for computer
            accounts at all (present since day one for ad_user), so no
            computer plugin has ever distinguished a disabled machine
            account from an active one. Also added primary_group_id and
            sid_history to ad_computer -- both apply to computer objects
            the same way they do to user accounts. Requires
            schema_migration_v11.sql.
    0.1.6 - Added pwd_last_set, description, notes, and key_credential_count
            to ad_computer -- the same class of gap closed on ad_user
            (password age, description-field password hunting, Shadow
            Credentials) applies equally to computer accounts and was
            never collected for them. Requires schema_migration_v10.sql.
    0.1.5 - Added description/notes (AD's description/info attributes --
            well-documented location for accidentally-left password
            material) and key_credential_count (presence/count of
            msDS-KeyCredentialLink -- Shadow Credentials / Windows Hello
            for Business key material; count only, not per-entry parsing)
            to ad_user, identified during a plugin-coverage gap review.
            Requires schema_migration_v6.sql.
    0.1.4 - Fixed max_pwd_age/min_pwd_age/lockout_duration always NULL on
            ad_domain despite a real, non-default policy: same class of
            bug as the earlier pwdLastSet fix, confirmed against ldap3's
            own source -- minPwdAge/maxPwdAge/lockoutDuration/
            lockOutObservationWindow are mapped to ldap3's
            format_ad_timedelta formatter, which converts the raw value
            into a Python timedelta object that normalize_value() had no
            case for, silently stringifying it into something
            ad_interval_to_seconds() couldn't parse. Fixed via the same
            raw_attributes bypass pattern already used elsewhere. Also
            added explicit handling for AD's INT64_MIN "never expires"
            sentinel on maxPwdAge (confirmed in ldap3's own source),
            which would otherwise have parsed as a ~29,000-year age
            instead of "no maximum".
    0.1.3 - Fixed max/min password age, lockout duration/observation
            window, and password history count never being collected for
            the domain-wide DEFAULT password policy (ad_domain), despite
            the equivalent fields existing for FGPP -- surfaced when
            asked a basic query question ("what's the max password age")
            that had no answer for a domain without FGPP configured
            (the common case, including this project's own test domain).
    0.1.2 - Fixed ESC1-pattern false positives on built-in CA-infrastructure
            templates (SubCA, CrossCA, CA, OfflineRouter -- confirmed
            against real DC data). These structurally match the ESC1
            pattern by default in every ADCS install (confirmed against
            the SpecterOps "Certified Pre-Owned" whitepaper), but are
            commonly never published on any CA, meaning nobody can
            actually request from them regardless of flags. Added
            collection of Enterprise CA (pKIEnrollmentService) objects
            and their certificateTemplates list (new ad_enrollment_service
            + cert_template_enabled_edge tables, schema_migration_v3.sql)
            to add the missing is_enabled signal, the same precondition
            Certipy's own -enabled flag checks -- filter on that before
            treating enrollee_supplies_subject/client_authentication_capable
            as a real finding.
    0.1.1 - Fixed "invalid attribute type ms-Mcs-AdmPwdExpirationTime"
            against a real DC: requesting an attribute name AD's schema
            doesn't define at all fails the WHOLE search, not just that
            field -- confirmed against a forest that never had legacy
            LAPS schema-extended. The two LAPS attributes are no longer
            in the static computer attribute list; now detected at
            runtime via a Schema NC lookup and only requested if the
            forest's schema actually defines them.
    0.1.0 - Closed the "easy" audit-capability gaps identified in the
            capability gap analysis: domain/forest trusts, GPO inventory
            (existence/name/version, not linkage or SYSVOL settings
            content), Fine-Grained Password Policies (new ad_fgpp +
            fgpp_applies_to_edge tables), LAPS deployment status
            (expiration timestamp ONLY, both legacy and modern Windows
            LAPS -- never the password value), AD Certificate Services
            template inventory (properties only, not enrollment ACLs --
            new ad_cert_template table), and effective/nested group
            membership closure (a new SQL view over existing data, not a
            new collection). ACLs and RBCD remain deliberately out of
            scope (same binary security-descriptor parsing constraint).
            Added validate_schema(), run before any collection begins:
            checks every table/column/function this script depends on
            actually exists, with an itemized report on failure, to catch
            a database that's out of sync with what this version expects
            before it causes confusing mid-run errors. Requires
            schema_migration_v2.sql applied on top of the original schema.
    0.0.10 - Fixed member_count_direct always NULL: the code that was
             supposed to fill it in after resolving group membership was
             never actually written, despite a comment claiming it was.
             Now set to the real AD-reported direct member count for
             every group, every run.
    0.0.9 - Fixed is_domain_controller always FALSE: now computed from
            the SERVER_TRUST_ACCOUNT UAC bit (0x2000), the standard AD
            signal for a DC, confirmed against real data. Fixed several
            TEXT fields (user_principal_name, operating_system_version,
            dns_hostname, etc.) storing the literal string "{}" instead
            of NULL: ldap3 represents an absent single-valued attribute
            as an empty list, and psycopg2 silently serializes an empty
            Python list into a TEXT column as "{}" rather than erroring
            or storing NULL. Fixed centrally in normalize_value().
    0.0.8 - Upgraded the v0.0.7 timestamp fix after checking prior art
            (BloodHound.py hit the identical bug in production --
            fox-it/BloodHound.py#24). Now pulls pwdLastSet/
            lastLogonTimestamp/lockoutTime from raw_attributes (bypassing
            ldap3's auto-formatting entirely) instead of defensively
            handling whatever shape the formatted value came back as.
    0.0.7 - Fixed pwd_last_set/last_logon_timestamp/lockout_time always
            NULL: ldap3 pre-converts these AD attributes into datetime
            objects (via schema-aware OID matching, since the collector
            connects with get_info=ALL), but filetime_to_datetime() only
            handled a raw FILETIME integer, so parsing always failed
            silently. Now handles the datetime/ISO-string shape ldap3
            actually produces, with the raw-integer path kept as fallback.
    0.0.6 - Fixed "no partition of relation ... found for row": valid_from
            was backdated to AD's own whenChanged timestamp, which for a
            baseline run can be arbitrarily old and fall outside the
            maintained partition window. Now uses a single collection
            timestamp shared by every row in the run; whenChanged remains
            fully available inside attributes_full.
    0.0.5 - Fixed msDS-ReplAttributeMetaData parsing: was only reading the
            first of its multiple values, and a trailing NUL byte in DC
            responses (seen on Windows Server 2025) broke both XML
            parsing and JSONB storage. NUL bytes are now stripped from
            all string values generically, not just this attribute.
    0.0.4 - Fixed capability probe's security_descriptor_read check: it
            queried nTSecurityDescriptor without the LDAP_SERVER_SD_FLAGS_OID
            control, causing AD to withhold it entirely (implicitly
            requires SACL access a read-only account shouldn't have).
            Now requests Owner+Group+DACL only (SDFlags 0x7), same as
            SharpHound/BloodHound. Was a probe bug, not a permissions gap.
    0.0.3 - Fixed two NOT NULL violations in write_typed_row() (client_id
            and version_id were never included in the INSERT -- would
            fail on the first object of any real run) and a sys.exit()
            vs. exception-handling bug that showed "Result: SUCCESS" on
            failed runs. Verified end-to-end against a mock DC + real DB.
    0.0.2 - Fixed ad_domain.functional_level always NULL, a schema CHECK
            violation on constrained-delegation edges, and progress bars
            always showing 100%.
    0.0.1 - Initial version.

PURPOSE:
    Connects to an on-premise Active Directory Domain Controller via LDAP,
    extracts security-relevant directory data (users, groups, computers, the
    domain object, group membership, SPNs, and delegation configuration),
    and loads it into the "ad_intel" PostgreSQL 17 schema using SCD2
    (slowly-changing-dimension) diff-only versioning.

    This is a proof-of-concept collector. It implements the "Collector MVP"
    phase of the larger project: capability probing, baseline/delta
    collection, and hard-fail behavior on insufficient permissions. ACL
    edges, RBCD delegation, GPOs, and trusts are NOT YET IMPLEMENTED -- see
    the "SCOPE / KNOWN LIMITATIONS" section below.

INPUT FORMAT (command line):
    python3 adprofiler.py --dc-host <fqdn-or-ip> --username <bind-user> [options]

    Required:
        --dc-host       FQDN or IP address of the target Domain Controller.
        --username      Bind account, e.g. user@domain.com or DOMAIN\\user.

    Optional:
        --password      Bind password. If omitted, you will be prompted
                         securely (recommended -- avoids the password
                         appearing in shell history or `ps` output).
        --port           LDAP port. Default: 389 (or 636 if --ssl is set).
        --ssl            Use LDAPS (TLS) instead of plaintext LDAP.
        --base-dn        Override the search base. Default: auto-discovered
                         from the DC's RootDSE (defaultNamingContext).
        --page-size      LDAP paged-search page size. Default: 1000.
        --version        Print version and exit.

    Example:
        python3 adprofiler.py --dc-host dc01.lab.local \\
            --username collector@lab.local --ssl

SETUP (Ubuntu, no pip):
    sudo apt update
    sudo apt install -y python3-ldap3 python3-psycopg2
    (Confirmed available as real apt packages: python3-ldap3 2.9.1-2 and
    python3-psycopg2 2.9.9-1build1 on Ubuntu 24.04's default repos.)

SCOPE / KNOWN LIMITATIONS:
    - ACL edges (acl_edge table) are NOT collected. Requires binary
      nTSecurityDescriptor parsing (MS-DTYP), which needs either the
      `impacket` library (pip-only) or a hand-rolled parser not yet built
      and verified against real AD data. Deferred to a future version.
      This also blocks full risk assessment of certificate templates
      (who can actually enroll) -- template properties ARE collected
      (see below), but enrollment rights are not.
    - RBCD delegation (msDS-AllowedToActOnBehalfOfOtherIdentity) is NOT
      collected for the same reason (binary security-descriptor format).
      Unconstrained and constrained delegation ARE collected (plain UAC
      bits and text/SPN attributes -- no binary parsing required).
    - GPO collection is existence/name/version only. Which OUs a GPO is
      actually linked to (gPLink parsing) and the GPO's actual settings
      content (which lives in SYSVOL, not LDAP) are NOT collected --
      genuinely larger, separate pieces of work.
    - LAPS status is the password EXPIRATION TIMESTAMP only, for both
      legacy (ms-Mcs-AdmPwd) and modern Windows LAPS (msLAPS-*). The
      password value itself is never read, by design -- that's live
      credential material and reading it would be a real departure from
      this project's read-only posture.
    - Certificate template collection covers template properties, plus
      (as of v0.1.2) whether each template is actually published on an
      Enterprise CA (is_enabled) -- but still not the template's
      enrollment ACL (who can actually request from it), which needs the
      same binary parsing noted above. enrollee_supplies_subject +
      client_authentication_capable + is_enabled together are the ESC1
      data pattern per Certipy's own -enabled-gated detection; a full
      risk determination still needs enrollment rights, which this
      version cannot answer. Filter on is_enabled first -- built-in
      CA-infrastructure templates (SubCA, CrossCA, CA, etc.) structurally
      match the flag pattern by default in every ADCS install but are
      commonly never published, which otherwise produces noisy
      false-positive-looking results.
    - Effective (nested) group membership is answered by a SQL view
      (v_effective_group_membership, added in schema_migration_v2.sql)
      computed over the same direct-membership edges already collected --
      not a new collection, a derived query over existing data.
    - Constrained-delegation targets are resolved to an object_guid via
      SPN matching against objects this run has collected. A target SPN
      registered on an object outside this version's collection scope
      (or otherwise unresolvable) is skipped and counted, not guessed at.
    - Trust, GPO, FGPP, and certificate template collection are each
      wrapped independently and treated as non-fatal if their container
      doesn't exist or isn't reachable -- these are all optional AD
      features many domains never configure, and their absence is a
      normal, common finding, not a collection failure.

DESIGN NOTES:
    - Every run is wrapped in a single PostgreSQL transaction. On any
      failure or Ctrl-C, the entire transaction is rolled back -- no
      partial data is ever committed (matches the project's hard-fail,
      no-degraded-pulls design decision). The sync_run log row itself is
      written in a separate, always-committed mini-transaction so that
      failures remain visible even though the data they would have
      written is rolled back. This has been verified: interrupting a run
      mid-collection leaves zero rows in directory_object and correctly
      marks sync_run as 'aborted'.
    - No temporary files are created. All intermediate state (attribute
      normalization, DN-to-GUID resolution cache, diffs) is held in
      memory for the duration of a single run. A cleanup-on-exit hook is
      still registered as a safety net in case a future version needs
      scratch files.
    - Ctrl-C (SIGINT) is caught, the in-progress transaction is rolled
      back, the sync_run row is marked 'aborted', and the script exits
      cleanly.

TESTING STATUS (as of v0.0.5):
    Verified via py_compile, real ldap3/psycopg2 imports, and a mocked
    end-to-end run against a real PostgreSQL instance (baseline + delta
    collection, membership/SPN/delegation edges, Ctrl-C rollback). Also
    now tested against a live Windows Server 2025 DC through capability
    probe and into baseline collection; 0.0.4/0.0.5 fix real issues found
    that way. Not yet run to full completion against a real DC.
================================================================================
"""

import sys
import os
import argparse
import getpass
import signal
import atexit
import struct
import uuid
import json
import base64
import re
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timedelta, timezone
import xml.etree.ElementTree as ET

try:
    import ldap3
    from ldap3.core.exceptions import LDAPException
    from ldap3.protocol.microsoft import security_descriptor_control
except ImportError:
    print("\033[91mERROR: the 'ldap3' package is not installed.\033[0m")
    print("Install it with:  <path-to-venv>/bin/pip install -r requirements.txt")
    sys.exit(1)

try:
    import psycopg2
    from psycopg2 import sql
    from psycopg2.extras import Json
except ImportError:
    print("\033[91mERROR: the 'psycopg2' package is not installed.\033[0m")
    print("Install it with:  <path-to-venv>/bin/pip install -r requirements.txt")
    sys.exit(1)

try:
    # [v0.3.0] Security descriptor (ACL) parsing. Same library BloodHound.py
    # and Certipy use for this exact task -- binary nTSecurityDescriptor
    # parsing is fiddly and easy to get subtly wrong (SID encoding, ACE
    # header alignment, object-specific ACE optional fields), and this is
    # the established, battle-tested implementation rather than a
    # from-scratch one. msada_guids ships 80 extended-right and 1769
    # schema-object GUIDs sourced directly from MS-ADA1/2/3, reused here
    # instead of hand-maintaining a smaller table.
    from impacket.ldap import ldaptypes
    from impacket.uuid import bin_to_string
    import impacket.msada_guids as msada_guids
except ImportError:
    print("\033[91mERROR: the 'impacket' package is not installed.\033[0m")
    print("Install it with:  <path-to-venv>/bin/pip install -r requirements.txt")
    sys.exit(1)

VERSION = "0.5.7"
PG_HOST = "192.168.1.125"
PG_PORT = 5432
PG_DBNAME = "adprofiler"
PG_USER = "postgres"
PG_PASSWORD = "Project2501"

UAC_ACCOUNTDISABLE = 0x0002
UAC_ENCRYPTED_TEXT_PWD_ALLOWED = 0x0080
UAC_DONT_EXPIRE_PASSWORD = 0x10000
UAC_SMARTCARD_REQUIRED = 0x40000
UAC_TRUSTED_FOR_DELEGATION = 0x80000
UAC_SERVER_TRUST_ACCOUNT = 0x2000  # set on domain controller computer accounts

LDAP_CONTROL_SHOW_DELETED = "1.2.840.113556.1.4.417"

USER_ATTRS = [
    "objectGUID", "objectSid", "distinguishedName", "sAMAccountName",
    "userPrincipalName", "userAccountControl", "adminCount", "primaryGroupID",
    "pwdLastSet", "lastLogonTimestamp", "badPwdCount", "lockoutTime",
    "msDS-SupportedEncryptionTypes", "servicePrincipalName", "sIDHistory",
    "msDS-AllowedToDelegateTo", "memberOf", "whenChanged", "whenCreated",
    "uSNChanged", "uSNCreated", "isDeleted", "msDS-ReplAttributeMetaData",
    "description", "info", "msDS-KeyCredentialLink", "mail", "proxyAddresses",
]

COMPUTER_ATTRS = [
    "objectGUID", "objectSid", "distinguishedName", "sAMAccountName",
    "dNSHostName", "operatingSystem", "operatingSystemVersion",
    "userAccountControl", "lastLogonTimestamp", "msDS-SupportedEncryptionTypes",
    "servicePrincipalName", "msDS-AllowedToDelegateTo", "whenChanged",
    "whenCreated", "uSNChanged", "uSNCreated", "isDeleted",
    "msDS-ReplAttributeMetaData", "pwdLastSet", "description", "info",
    "msDS-KeyCredentialLink", "primaryGroupID", "sIDHistory",
    "msDS-AllowedToActOnBehalfOfOtherIdentity", "msDS-GroupMSAMembership",
    "adminCount",
]
# [v0.1.1] The two LAPS expiration attributes are deliberately NOT in this
# static list. Unlike built-in AD attributes (pwdLastSet, userAccountControl,
# etc.), ms-Mcs-AdmPwdExpirationTime and msLAPS-PasswordExpirationTime only
# exist in a forest's schema if that specific LAPS variant's schema
# extension was ever applied (legacy LAPS install, or Update-LapsADSchema
# for modern Windows LAPS). Requesting an attribute name AD's schema
# doesn't recognize at all causes the ENTIRE search to fail with "invalid
# attribute type" -- not an empty value for just that field -- confirmed
# against a real DC that had never had legacy LAPS schema-extended. These
# two attribute names are appended to the computer search's attribute list
# at runtime, only after confirming each is actually defined in the target
# forest's schema (see ldap_attribute_exists()).
LAPS_LEGACY_ATTR = "ms-Mcs-AdmPwdExpirationTime"
LAPS_MODERN_ATTR = "msLAPS-PasswordExpirationTime"

GROUP_ATTRS = [
    "objectGUID", "objectSid", "distinguishedName", "sAMAccountName",
    "groupType", "adminCount", "member", "whenChanged", "whenCreated",
    "uSNChanged", "uSNCreated", "isDeleted", "msDS-ReplAttributeMetaData",
    "description", "info", "sIDHistory",
]

FSP_ATTRS = [
    "objectGUID", "objectSid", "distinguishedName",
    "whenChanged", "whenCreated", "uSNChanged", "uSNCreated",
]

DOMAIN_ATTRS = [
    "objectGUID", "objectSid", "distinguishedName", "minPwdLength",
    "pwdProperties", "lockoutThreshold", "minPwdAge", "maxPwdAge",
    "lockoutDuration", "lockOutObservationWindow", "pwdHistoryLength",
    "whenChanged", "whenCreated", "uSNChanged", "uSNCreated",
    "ms-DS-MachineAccountQuota", "gPLink", "gPOptions", "wellKnownObjects",
]

# [v0.5.0] Organizational Units -- collected with the same typed-table
# treatment as every other object class in this project (ad_user,
# ad_computer, etc.), not as a one-off. gPLink/gPOptions are here so OU
# block-inheritance can be derived the same way domain's is; the GPO
# LINKS themselves (which GPOs, in what order, enabled/enforced) are
# resolved separately into gpo_link_edge, matching how group membership,
# SPNs, and delegation are all resolved as dedicated passes rather than
# folded into typed_columns -- gPLink parsing produces a genuine
# many-to-many edge (one OU can link many GPOs; one GPO can be linked
# from many OUs/the domain), not a single object's own attribute.
OU_ATTRS = [
    "objectGUID", "distinguishedName", "ou", "description",
    "gPLink", "gPOptions", "whenChanged", "whenCreated",
    "uSNChanged", "uSNCreated",
]
OU_FILTER = "(objectClass=organizationalUnit)"

TRUST_ATTRS = [
    "objectGUID", "distinguishedName", "trustPartner", "trustDirection",
    "trustType", "trustAttributes", "whenChanged", "whenCreated",
    "uSNChanged", "uSNCreated", "msDS-ReplAttributeMetaData",
]
TRUST_FILTER = "(objectClass=trustedDomain)"
TRUST_ATTR_FILTER_SIDS = 0x4  # bit in trustAttributes: SID filtering enabled

FGPP_ATTRS = [
    "objectGUID", "distinguishedName", "cn",
    "msDS-PasswordSettingsPrecedence", "msDS-MinimumPasswordLength",
    "msDS-PasswordComplexityEnabled", "msDS-PasswordReversibleEncryptionEnabled",
    "msDS-PasswordHistoryLength", "msDS-MinimumPasswordAge",
    "msDS-MaximumPasswordAge", "msDS-LockoutThreshold",
    "msDS-LockoutDuration", "msDS-LockoutObservationWindow",
    "msDS-PSOAppliesTo", "whenChanged", "whenCreated",
    "uSNChanged", "uSNCreated", "msDS-ReplAttributeMetaData",
]
FGPP_FILTER = "(objectClass=msDS-PasswordSettings)"

GPO_ATTRS = [
    "objectGUID", "distinguishedName", "displayName", "versionNumber",
    "cn", "whenChanged", "whenCreated", "uSNChanged", "uSNCreated",
    "msDS-ReplAttributeMetaData",
]
GPO_FILTER = "(objectClass=groupPolicyContainer)"

CERT_TEMPLATE_ATTRS = [
    "objectGUID", "distinguishedName", "cn", "displayName",
    "msPKI-Enrollment-Flag", "msPKI-Certificate-Name-Flag",
    "pKIExtendedKeyUsage", "whenChanged", "whenCreated",
    "uSNChanged", "uSNCreated", "msDS-ReplAttributeMetaData",
    "msPKI-Certificate-Policy", "msPKI-Template-Schema-Version",
]
CERT_TEMPLATE_FILTER = "(objectClass=pKICertificateTemplate)"

ENROLLMENT_SERVICE_ATTRS = [
    "objectGUID", "distinguishedName", "cn", "dNSHostName",
    "certificateTemplates", "whenChanged", "whenCreated",
    "uSNChanged", "uSNCreated",
]
ENROLLMENT_SERVICE_FILTER = "(objectClass=pKIEnrollmentService)"
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x1  # bit in msPKI-Certificate-Name-Flag
# Well-known EKU OIDs that make a certificate usable for client authentication.
CLIENT_AUTH_EKU_OIDS = {
    "1.3.6.1.5.5.7.3.2",     # Client Authentication
    "1.3.6.1.5.2.3.4",       # PKINIT Client Authentication
    "1.3.6.1.4.1.311.20.2.2",  # Smart Card Logon
    "2.5.29.37.0",           # Any Purpose
}

# [v0.5.3] NTAuthCertificates -- a single, well-known object in the
# Configuration NC (confirmed against Microsoft's own documentation,
# cross-checked against multiple independent sources): despite the
# name suggesting a container with children, it's one object whose
# cACertificate attribute holds every CA certificate trusted
# forest-wide for smart card/certificate-based domain logon (PKINIT).
# A certificate here that doesn't trace back to a currently-known,
# collected CA is either orphaned (a decommissioned CA never cleaned
# up) or a "Golden Certificate"-class forgery planted to be trusted
# for domain authentication without ever having been a real,
# functioning CA. Object name is fixed and identical across every
# forest -- not tenant/domain-specific -- so, like the earlier
# (abandoned) SCP investigation, this needs the Configuration NC as
# the search base, not the domain NC everything else comes from.
NTAUTH_ATTRS = ["objectGUID", "distinguishedName", "cACertificate",
                 "whenChanged", "whenCreated", "uSNChanged", "uSNCreated"]
NTAUTH_FILTER = "(objectClass=*)"

# [v0.5.4] AD Sites and Subnets -- both live in the Configuration NC,
# like NTAuthCertificates/cert templates/enrollment services above.
SITE_ATTRS = ["objectGUID", "distinguishedName", "cn"]
SITE_FILTER = "(objectClass=site)"
SUBNET_ATTRS = ["objectGUID", "distinguishedName", "cn", "siteObject"]
SUBNET_FILTER = "(objectClass=subnet)"

# [v0.5.4] Schema partition objects -- only the ones relevant to the
# Java RFC 2713 extension check (attributeSchema) and the possSuperiors
# abuse check (classSchema) are collected, not the entire schema.
# Filtered at the LDAP level (not "collect everything, filter in SQL")
# specifically to avoid pulling every schema object in the forest for
# two narrow checks.
SCHEMA_JAVA_ATTRS = ["objectGUID", "distinguishedName", "cn", "lDAPDisplayName", "isDefunct"]
SCHEMA_JAVA_FILTER = (
    "(&(objectClass=attributeSchema)(|(lDAPDisplayName=javaClassName)"
    "(lDAPDisplayName=javaCodeBase)(lDAPDisplayName=javaFactory)"
    "(lDAPDisplayName=javaObject)(lDAPDisplayName=javaSerializedObject)))"
)
SCHEMA_POSSSUPERIOR_ATTRS = ["objectGUID", "distinguishedName", "cn", "possSuperiors", "subClassOf"]
# possSuperiors is multi-valued, so filtering server-side for "contains
# computer or user" isn't a single equality match -- collected broadly
# (every classSchema object) and filtered in SQL instead, same
# collect-raw-filter-in-SQL preference as everything else added this
# session.
SCHEMA_POSSSUPERIOR_FILTER = "(objectClass=classSchema)"

# [v0.5.4] DisplaySpecifiers -- Configuration NC, one per locale
# (409 = en-US being the common one, but collected broadly rather than
# hardcoding a specific locale).
#
# [v0.5.5 correction] adminContextMenu's value format is documented by
# Microsoft as always "<order number>,<clsid>" -- a COM registration
# reference, not a script path (confirmed against Microsoft's own
# reference doc: "Registering the Context Menu COM Object in a Display
# Specifier"). The actual "script outside SYSVOL" risk this attribute
# is associated with lives in the LOCAL REGISTRY of whichever machine
# resolves that CLSID (HKCR\CLSID\{...}\InprocServer32's default
# value) -- not in anything this LDAP attribute itself stores, and not
# retrievable by an LDAP-only collector. A plugin (4023, since
# retired) was built against this table before that format was
# verified against Microsoft's own reference, and incorrectly treated
# the CLSID field as if it were a literal command/path to check
# against SYSVOL -- it fired on ordinary built-in COM CLSIDs shipped
# with every AD installation, repeated once per locale. Collection is
# left in place (the raw data is accurate, just not something a valid
# plugin can currently be built from without registry access this
# project doesn't have) -- see this comment if reconsidering a
# DisplaySpecifier-based check in the future.
DISPLAY_SPECIFIER_ATTRS = ["objectGUID", "distinguishedName", "cn", "adminContextMenu"]
DISPLAY_SPECIFIER_FILTER = "(objectClass=displaySpecifier)"

# [v0.5.4] ESC13 -- certificate template OID objects, Configuration NC.
CERT_OID_ATTRS = ["objectGUID", "distinguishedName", "cn", "msDS-OIDToGroupLink"]
CERT_OID_FILTER = "(objectClass=msPKI-Enterprise-Oid)"

# [v0.5.6] AD-integrated DNS zones. Lives in an entirely different
# naming context from everything else this collector queries -- the
# DomainDnsZones application partition, not the domain NC or the
# Configuration NC. Deliberately scoped to domain-scoped zones only
# (DC=DomainDnsZones,<domain>) -- forest-scoped zones
# (DC=ForestDnsZones,<forest root>) would need the forest root's own
# base DN, which can differ from the domain's in a multi-domain forest
# and isn't currently resolved anywhere in this collector. A
# non-AD-integrated (file-based) zone is invisible to LDAP entirely,
# regardless of scope -- not a gap this collector can close.
DNS_ZONE_ATTRS = ["objectGUID", "distinguishedName", "name"]
DNS_ZONE_FILTER = "(objectClass=dnsZone)"
DNSPROPERTY_ID_ALLOW_UPDATE = 2  # DSPROPERTY_ZONE_ALLOW_UPDATE, [MS-DNSP] 2.3.2.1.1

class CollectorAbort(Exception):
    """
    [v0.0.3] Raised for expected, already-logged failure conditions (LDAP
    bind failure, capability probe failure) instead of calling sys.exit()

    directly inside main()'s try block. sys.exit() raises SystemExit, which
    does NOT inherit from Exception, so it was skipping past the
    exit_code = 1 assignment in the surrounding except clauses -- the
    process's actual exit code was still correct (1), but the printed
    Run Summary incorrectly showed "Result: SUCCESS". This exception is
    caught explicitly in main() so the summary reports FAILED correctly.
    """
    pass


PROTECTED_USERS_DN_FRAGMENT = "cn=protected users,"
KNOWN_TYPED_TABLES = {"ad_user", "ad_group", "ad_computer", "ad_domain",
                       "ad_trust", "ad_gpo", "ad_fgpp", "ad_cert_template",
                       "ad_enrollment_service", "ad_foreign_security_principal",
                       "ad_ou", "ad_ntauth_store", "ad_site", "ad_subnet",
                       "ad_schema_object", "ad_display_specifier", "ad_cert_oid",
                       "ad_dns_zone"}
KNOWN_EDGE_TABLES = {"group_member_edge", "spn_edge", "delegation_edge",
                      "fgpp_applies_to_edge", "cert_template_enabled_edge",
                      "acl_edge", "gpo_link_edge", "gmsa_password_reader_edge",
                      "unresolved_delegation_target_edge"}

_USE_COLOR = sys.stdout.isatty()

class _C:
    RESET = "\033[0m" if _USE_COLOR else ""
    RED = "\033[91m" if _USE_COLOR else ""
    GREEN = "\033[92m" if _USE_COLOR else ""
    YELLOW = "\033[93m" if _USE_COLOR else ""
    BLUE = "\033[94m" if _USE_COLOR else ""
    MAGENTA = "\033[95m" if _USE_COLOR else ""
    CYAN = "\033[96m" if _USE_COLOR else ""
    WHITE = "\033[97m" if _USE_COLOR else ""
    BOLD = "\033[1m" if _USE_COLOR else ""
    DIM = "\033[2m" if _USE_COLOR else ""


def _ts():
    return datetime.now().strftime("%H:%M:%S")


def log_info(msg):
    print(f"{_C.DIM}[{_ts()}]{_C.RESET} {_C.WHITE}[INFO]{_C.RESET}    {msg}")


def log_success(msg):
    print(f"{_C.DIM}[{_ts()}]{_C.RESET} {_C.GREEN}[ OK ]{_C.RESET}    {msg}")


def log_warn(msg):
    print(f"{_C.DIM}[{_ts()}]{_C.RESET} {_C.YELLOW}[WARN]{_C.RESET}    {msg}")


def log_error(msg):
    print(f"{_C.DIM}[{_ts()}]{_C.RESET} {_C.RED}[FAIL]{_C.RESET}    {msg}")


def log_header(msg):
    bar = "=" * max(60, len(msg) + 4)
    print(f"\n{_C.BOLD}{_C.CYAN}{bar}\n  {msg}\n{bar}{_C.RESET}")


def print_progress(current, total, label, bar_width=30):
    if total <= 0:
        pct = 1.0
    else:
        pct = min(1.0, current / total)
    filled = int(bar_width * pct)
    bar = "#" * filled + "-" * (bar_width - filled)
    sys.stdout.write(
        f"\r{_C.BLUE}[{label}]{_C.RESET} |{_C.CYAN}{bar}{_C.RESET}| "
        f"{current}/{total} ({pct * 100:5.1f}%)"
    )
    sys.stdout.flush()
    if current >= total:
        sys.stdout.write("\n")


_TEMP_FILES = []


def cleanup_temp_files():
    for path in _TEMP_FILES:
        try:
            if os.path.exists(path):
                os.remove(path)
                log_info(f"Cleaned up temporary file: {path}")
        except OSError as exc:
            log_warn(f"Could not remove temporary file {path}: {exc}")


atexit.register(cleanup_temp_files)


def handle_sigint(signum, frame):
    sys.stdout.write("\n")
    log_warn("Interrupt received (Ctrl-C). Rolling back and aborting cleanly...")
    raise KeyboardInterrupt


signal.signal(signal.SIGINT, handle_sigint)


def sid_bytes_to_str(data):
    if not data:
        return None
    revision = data[0]
    sub_auth_count = data[1]
    identifier_authority = int.from_bytes(data[2:8], byteorder="big")
    sub_authorities = struct.unpack(
        "<%dI" % sub_auth_count, data[8:8 + 4 * sub_auth_count]
    )
    sid = "S-{}-{}".format(revision, identifier_authority)
    for sa in sub_authorities:
        sid += "-{}".format(sa)
    return sid


def guid_bytes_to_str(data):
    if not data:
        return None
    return str(uuid.UUID(bytes_le=data))


# [v0.3.0] AceType byte values, from the ACE header (2.4.4.1 in MS-DTYP).
# Only these four matter for DACL analysis -- audit ACEs (SYSTEM_AUDIT_*)
# are SACL-only, and this collector deliberately never requests SACL (see
# the capability probe's own comment on security_descriptor_control(0x07)
# -- SACL needs SeSecurityPrivilege a read-only account correctly doesn't
# have). Callback/resource-attribute/scoped-policy ACE types exist in
# newer Windows versions for claims-based conditional access and are
# rare in practice; explicitly out of scope for this pass rather than
# silently mishandled -- skipped, not misparsed.
ACE_TYPE_ALLOWED = 0x00
ACE_TYPE_DENIED = 0x01
ACE_TYPE_ALLOWED_OBJECT = 0x05
ACE_TYPE_DENIED_OBJECT = 0x06
ACE_INHERITED_FLAG = 0x10  # from ACE.INHERITED_ACE in impacket's ldaptypes


def parse_dns_zone_allow_update(raw_dns_property_values):
    """[v0.5.6] Extracts DSPROPERTY_ZONE_ALLOW_UPDATE from a zone's raw,
    multi-valued dNSProperty attribute. Format confirmed directly
    against Microsoft's own [MS-DNSP] 2.3.2.1 spec, not guessed at or
    inferred from a third party's tool: each dNSProperty value is one
    complete, self-contained property structure -- a fixed 20-byte
    header (5 little-endian DWORDs: DataLength, NameLength, Flag,
    Version, Id) followed by DataLength bytes of Data, then a 1-byte
    trailing Name field (unused, always ignored per spec). No existing
    library (impacket's dns.py only covers dnsRecord, a different
    attribute entirely) was found to already parse this, so this is a
    from-scratch parser -- verified via a full construct-serialize-
    parse round trip against synthetic property values before being
    trusted against real collection data, the same discipline already
    applied to security descriptor parsing elsewhere in this file.

    Iterates every value looking for Id == DNSPROPERTY_ID_ALLOW_UPDATE
    (0x2) specifically -- a zone's dNSProperty holds many unrelated
    properties (zone type, refresh intervals, aging state, etc.) in
    the same multi-valued attribute, not just this one.

    Returns the raw ZONE_UPDATE_* integer (0=off, 1=unsecure+secure,
    2=secure only) if found, else None (property not present in this
    zone's values at all -- treated by the caller as "could not
    determine", not assumed to be any particular default)."""
    if not raw_dns_property_values:
        return None
    for raw in raw_dns_property_values:
        if len(raw) < 20:
            continue
        try:
            data_length, _name_length, _flag, _version, prop_id = struct.unpack_from("<5I", raw, 0)
        except struct.error:
            continue
        if prop_id != DNSPROPERTY_ID_ALLOW_UPDATE:
            continue
        data = raw[20:20 + data_length]
        if len(data) < 4:
            return None
        return struct.unpack_from("<I", data, 0)[0]
    return None


def parse_security_descriptor(raw_sd_bytes):
    """[v0.3.0] Parses a raw nTSecurityDescriptor (or any attribute using
    the same binary format, e.g. msDS-AllowedToActOnBehalfOfOtherIdentity
    for RBCD -- Microsoft deliberately reuses the SD format there so the
    same ACE semantics apply) into (owner_sid, [ace_dict, ...]).

    Uses impacket's ldap.ldaptypes module rather than a from-scratch
    parser -- the same library BloodHound.py and Certipy use for this
    exact task. Verified via a full construct-serialize-parse round trip
    (synthetic SD with a simple ACCESS_ALLOWED_ACE, an
    ACCESS_ALLOWED_OBJECT_ACE carrying a real extended-right GUID, and an
    ACCESS_DENIED_ACE) before this function was written against real
    collection data, confirming owner SID, trustee SID, access mask, and
    object-type GUID resolution all round-trip correctly.

    Returns (None, []) if raw_sd_bytes is empty/None, or if parsing
    itself fails -- callers should treat a parse failure as "could not
    determine ACLs for this object" (logged, not silently swallowed),
    never as "this object has no ACEs" (a materially different and
    dangerous conclusion to draw from a parse error).
    """
    if not raw_sd_bytes:
        return None, []
    try:
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw_sd_bytes)
    except Exception as exc:
        log_warn(f"Could not parse security descriptor ({len(raw_sd_bytes)} bytes): {exc}")
        return None, []

    owner_sid = None
    if sd["OwnerSid"] != b"":
        owner_sid = sd["OwnerSid"].formatCanonical()

    aces = []
    dacl = sd["Dacl"]
    if dacl == b"":
        return owner_sid, aces

    for ace in dacl.aces:
        ace_type_byte = ace["AceType"]
        if ace_type_byte not in (ACE_TYPE_ALLOWED, ACE_TYPE_DENIED,
                                  ACE_TYPE_ALLOWED_OBJECT, ACE_TYPE_DENIED_OBJECT):
            continue

        body = ace["Ace"]
        ace_type = "allow" if ace_type_byte in (ACE_TYPE_ALLOWED, ACE_TYPE_ALLOWED_OBJECT) else "deny"
        is_inherited = bool(ace["AceFlags"] & ACE_INHERITED_FLAG)
        trustee_sid = body["Sid"].formatCanonical()
        access_mask = body["Mask"]["Mask"]

        object_type_guid = None
        if ace_type_byte in (ACE_TYPE_ALLOWED_OBJECT, ACE_TYPE_DENIED_OBJECT):
            object_type_bytes = body["ObjectType"]
            if object_type_bytes:
                object_type_guid = bin_to_string(object_type_bytes).lower()

        aces.append({
            "trustee_sid": trustee_sid,
            "ace_type": ace_type,
            "access_mask": access_mask,
            "object_type_guid": object_type_guid,
            "is_inherited": is_inherited,
        })

    return owner_sid, aces


def resolve_object_type_name(object_type_guid):
    """Best-effort, human-readable name for an ACE's object_type_guid,
    using impacket's own msada_guids reference tables (extended rights
    first, since those are what security-relevant plugins care about
    most; falls back to schema object/attribute names; returns None,
    not a placeholder string, if genuinely unrecognized -- callers
    should treat None as 'unknown', not silently render it as a name."""
    if not object_type_guid:
        return None
    return (msada_guids.EXTENDED_RIGHTS.get(object_type_guid)
            or msada_guids.SCHEMA_OBJECTS.get(object_type_guid))


def get_object_security_descriptor(conn, dn):
    """[v0.3.0] Directly reads nTSecurityDescriptor for a single,
    well-known object (domain root, AdminSDHolder) -- not part of the
    bulk paged-collection machinery, since there's only ever one or two
    of these per run. Uses the exact same SD Flags control technique
    (Owner+Group+DACL only, 0x07, no SACL) already proven working by the
    capability probe against a real DC -- this is not new/unverified
    ground, just reusing an already-validated read path for a new
    purpose."""
    try:
        sd_flags_control = security_descriptor_control(sdflags=0x07)
        conn.search(dn, "(objectClass=*)", search_scope=ldap3.BASE,
                    attributes=["nTSecurityDescriptor"], controls=sd_flags_control)
        if not conn.response:
            return None
        raw = conn.response[0]["raw_attributes"].get("nTSecurityDescriptor")
        return raw[0] if raw else None
    except LDAPException as exc:
        log_warn(f"Could not read security descriptor for {dn}: {exc}")
        return None


def build_acl_desired_edges(object_guid, raw_sd, label, desired_out):
    """[v0.3.0, fixed same version] Parses one object's security
    descriptor and MERGES its desired ACE keys into desired_out --
    does NOT call sync_edges itself.

    This split exists because of a real bug found via the mock harness
    before this was ever run against real data: get_open_edges() (used
    by every edge table in this project) compares against every
    currently-open row for the ENTIRE CLIENT, not just rows for one
    object -- exactly matching how group_member_edge/spn_edge/
    delegation_edge are each synced with ONE comprehensive dict covering
    every object in a single call per run. Calling sync_edges separately
    per-object (the original version of this function) meant each
    narrow call saw every OTHER already-scanned object's ACEs as
    "no longer present" and incorrectly closed them -- confirmed via a
    direct reproduction showing a fresh domain-root ACL scan reporting
    3 opened AND 3 closed in the same call, with nothing else in the
    database to have caused any closure at all. Fixed by accumulating
    every scanned object's desired keys into one dict and syncing once,
    matching the established pattern exactly rather than inventing a
    new one.

    Returns (True, owner_sid) if the SD was read and parsed successfully
    (even if it had zero ACEs), (False, None) if it could not be read or
    parsed at all -- callers should log those two cases differently.

    [v0.3.2] Now also returns owner_sid, previously computed by
    parse_security_descriptor() and silently discarded here -- ownership
    is itself a real, distinct security-relevant fact (BloodHound's
    "Owns" edge: an owner implicitly holds WRITE_DAC-equivalent rights
    over an object regardless of what the DACL itself says, since an
    owner can always rewrite the DACL)."""
    if raw_sd is None:
        log_warn(f"No security descriptor available for {label} -- "
                 f"ACL data for this object will not be collected this run.")
        return False, None

    owner_sid, aces = parse_security_descriptor(raw_sd)
    if owner_sid is None and not aces:
        log_warn(f"Security descriptor for {label} could not be parsed -- "
                 f"ACL data for this object will not be collected this run.")
        return False, None

    for ace in aces:
        key = (object_guid, ace["trustee_sid"], ace["ace_type"],
               ace["access_mask"], ace["object_type_guid"])
        desired_out[key] = {"inherited": ace["is_inherited"]}
    return True, owner_sid


def collect_well_known_container_acl(conn, pg_cur, client_id, run_id, dn, label,
                                      run_timestamp, desired_out):
    """[v0.3.0, fixed same version] Registers a well-known container object
    (currently just AdminSDHolder) as a minimal directory_object row --
    necessary because acl_edge.object_guid has a hard foreign key
    against directory_object, and containers like AdminSDHolder are not
    part of any normal bulk collection pass (this collector doesn't
    collect OUs/containers as objects generally). object_class='container'
    matches the existing ad_object_class enum value used for exactly
    this kind of object.

    Merges its ACEs into desired_out rather than syncing independently
    -- see build_acl_desired_edges() for why calling sync_edges
    separately per object is a real, confirmed bug, not just a style
    preference.

    Returns object_guid, or None if the container couldn't be read at
    all (e.g. genuinely absent, though AdminSDHolder is a standard
    object present in every AD domain since it's foundational to the
    SDProp process)."""
    try:
        sd_flags_control = security_descriptor_control(sdflags=0x07)
        conn.search(dn, "(objectClass=*)", search_scope=ldap3.BASE,
                    attributes=["objectGUID", "objectSid", "nTSecurityDescriptor"],
                    controls=sd_flags_control)
        if not conn.response:
            log_warn(f"{label} not found at {dn} -- ACL data for it will not be collected this run.")
            return None
        raw_attrs = conn.response[0]["raw_attributes"]
        raw_guid = raw_attrs.get("objectGUID")
        object_guid = guid_bytes_to_str(raw_guid[0]) if raw_guid else None
        if not object_guid:
            log_warn(f"{label} at {dn} has no readable objectGUID -- skipping.")
            return None
        raw_sid = raw_attrs.get("objectSid")
        object_sid = sid_bytes_to_str(raw_sid[0]) if raw_sid else None
        raw_sd = raw_attrs.get("nTSecurityDescriptor")
        raw_sd = raw_sd[0] if raw_sd else None
    except LDAPException as exc:
        log_warn(f"Could not read {label}: {exc}")
        return None

    pg_cur.execute(
        "SELECT * FROM upsert_directory_object(%s, %s, %s, %s, %s, %s, %s);",
        (object_guid, client_id, object_sid, dn, "container", None, run_id),
    )
    pg_cur.fetchone()

    _, owner_sid = build_acl_desired_edges(object_guid, raw_sd, label, desired_out)
    if owner_sid:
        pg_cur.execute(
            "UPDATE directory_object SET owner_sid = %s WHERE object_guid = %s AND client_id = %s",
            (owner_sid, object_guid, client_id),
        )
    return object_guid


def filetime_to_datetime(value):
    """
    [v0.0.7 fix] ldap3, connected with get_info=ALL (always true for this
    collector), recognizes AD timestamp attributes (pwdLastSet,
    lastLogonTimestamp, lockoutTime, accountExpires, lastLogon,
    badPasswordTime, among others) by their LDAP syntax OID and
    pre-converts them into Python datetime objects automatically -- this
    function never actually receives the raw FILETIME integer it was
    originally written to expect. Since attributes_full stores everything
    through normalize_value() (which turns a datetime into an ISO
    string), what reaches here by the time a typed-column builder calls
    it is normally an ISO string, occasionally a raw datetime. The
    original version only handled a raw integer, so int(iso_string)
    always raised and every one of these fields came back None
    regardless of the real value -- confirmed against real DC data where
    pwd_last_set/last_logon_timestamp were NULL for every account
    including active, normal users. parse_generalized_time() already had
    the correct isinstance(value, datetime) guard for this same ldap3
    behavior; this just applies the same pattern here.
    """
    if value in (None, "", 0, "0"):
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            pass  # not an ISO string -- fall through to raw-FILETIME parsing
    try:
        ft = int(value)
    except (TypeError, ValueError):
        return None
    if ft <= 0:
        return None
    epoch_start = datetime(1601, 1, 1, tzinfo=timezone.utc)
    try:
        return epoch_start + timedelta(microseconds=ft // 10)
    except OverflowError:
        return None


def ad_interval_to_seconds(raw_value):
    """
    [v0.1.0] Converts an AD "Interval" attribute -- msDS-MinimumPasswordAge,
    msDS-MaximumPasswordAge, msDS-LockoutDuration,
    msDS-LockoutObservationWindow, minPwdAge, maxPwdAge, lockoutDuration,
    lockOutObservationWindow, and similar -- into whole seconds.

    These are stored as NEGATIVE 100-nanosecond-tick integers representing
    a RELATIVE duration, not an absolute FILETIME timestamp like
    pwdLastSet (confirmed against real Get-ADFineGrainedPasswordPolicy
    output: msDS-LockoutDuration of -18000000000 corresponds to a
    30-minute lockout duration). Do not confuse with filetime_to_datetime()
    -- that function is for absolute timestamps and would produce a
    nonsensical pre-1601 date if given one of these values directly.

    [v0.1.4] INT64_MIN (-9223372036854775808) is a specific AD sentinel
    meaning "never" on attributes like maxPwdAge (confirmed directly in
    ldap3's own format_ad_timedelta source) -- e.g. a domain-wide policy
    of "passwords never expire". Without this check the raw ticks value
    would be interpreted literally as roughly 29,000 years, not "no
    maximum" -- returning None here instead, matching what an absent
    attribute would mean, since both represent "no maximum applies".
    """
    if raw_value in (None, "", 0, "0", -9223372036854775808, "-9223372036854775808"):
        return None
    try:
        ticks = int(raw_value)
    except (TypeError, ValueError):
        return None
    if ticks == -9223372036854775808:
        return None
    return abs(ticks) // 10_000_000


def parse_generalized_time(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, (list, tuple)) and value:
        value = value[0]
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str):
        return None
    fmt_candidates = ["%Y%m%d%H%M%S.%fZ", "%Y%m%d%H%M%SZ"]
    for fmt in fmt_candidates:
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def parse_repl_attr_meta_data(xml_value):
    """
    [v0.0.5 fixes, both found against a live Windows Server 2025 DC]

    1. msDS-ReplAttributeMetaData is MULTI-VALUED (one XML fragment per
       tracked attribute on the object). The prior version took only
       xml_value[0] and silently discarded every other value -- now every
       value in the list is parsed and combined.

    2. Individual fragments were observed with a trailing embedded NUL
       byte (\\x00) after the closing tag, which both breaks strict XML
       parsing (ElementTree treats it as trailing junk) and -- more
       importantly -- can never be stored in PostgreSQL's JSON/JSONB type
       regardless of parsing, since Postgres's internal text
       representation cannot contain U+0000 at all. Stripped here before
       parsing (so parsing now succeeds instead of falling back), and
       independently in normalize_value() as a general-purpose defense
       for any other attribute that might carry one.
    """
    if not xml_value:
        return None
    values = xml_value if isinstance(xml_value, (list, tuple)) else [xml_value]

    entries = []
    for v in values:
        if not v:
            continue
        cleaned = v.replace("\x00", "") if isinstance(v, str) else v
        try:
            root = ET.fromstring(cleaned)
        except ET.ParseError:
            continue
        for attr_elem in root.iter("DS_REPL_ATTR_META_DATA"):
            def _text(tag):
                el = attr_elem.find(tag)
                return el.text if el is not None else None

            entries.append({
                "attributeName": _text("pszAttributeName"),
                "version": _text("dwVersion"),
                "lastOriginatingDcInvocationId": _text("uuidLastOriginatingDsaInvocationID"),
                "lastOriginatingChangeTime": _text("ftimeLastOriginatingChange"),
            })
    return entries if entries else None


def normalize_value(value):
    """[v0.0.5 fix] Strip embedded NUL (U+0000) from every string value.
    PostgreSQL's JSON/JSONB type cannot represent it under any
    circumstances (its internal text representation is itself
    NUL-terminated) -- this isn't a JSON-escaping quirk to work around,
    it's a hard backend limitation. Observed on values returned by a
    Windows Server 2025 DC; stripped generically here rather than only
    for the one attribute it was first seen on, since any attribute could
    carry one and silently fail an otherwise-successful run."""
    if value is None:
        return None
    if isinstance(value, str):
        return value.replace("\x00", "")
    if isinstance(value, (int, float, bool)):
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, bytes):
        try:
            decoded = value.decode("utf-8")
        except UnicodeDecodeError:
            return base64.b64encode(value).decode("ascii")
        return decoded.replace("\x00", "")
    if isinstance(value, (list, tuple)):
        if not value:
            # [v0.0.9 fix] ldap3 represents a requested-but-absent
            # single-valued attribute as an empty list, not None. LDAP has
            # no concept of "attribute present but empty" -- an attribute
            # with zero values IS an absent attribute -- so an empty list
            # is semantically equivalent to None and should be treated as
            # such. Without this, TEXT-typed fields sourced directly from
            # attributes_full (user_principal_name, operating_system,
            # operating_system_version, dns_hostname, etc.) received a raw
            # Python [] whenever the account/computer genuinely lacked
            # that attribute, and psycopg2 silently serializes an empty
            # list into a TEXT column as the literal string "{}" instead
            # of NULL -- confirmed directly against psycopg2's actual
            # behavior, and against real DC data (built-in service
            # accounts with no UPN, Linux/Samba-joined machines with no
            # operatingSystemVersion, both showed "{}" instead of blank).
            return None
        return [normalize_value(v) for v in value]
    if isinstance(value, dict):
        return {k: normalize_value(v) for k, v in value.items()}
    return str(value)


def diff_attributes(old_full, new_full):
    if old_full is None:
        return dict(new_full)
    changed = {}
    all_keys = set(old_full.keys()) | set(new_full.keys())
    for key in all_keys:
        old_v = old_full.get(key)
        new_v = new_full.get(key)
        if old_v != new_v:
            changed[key] = new_v
    return changed


def connect_ldap(host, port, use_ssl, username, password):
    log_info(f"Connecting to {host}:{port} ({'LDAPS' if use_ssl else 'LDAP'})...")
    try:
        server = ldap3.Server(host, port=port, use_ssl=use_ssl, get_info=ldap3.ALL)
        conn = ldap3.Connection(
            server,
            user=username,
            password=password,
            authentication=ldap3.SIMPLE,
            auto_bind=True,
            receive_timeout=30,
        )
    except LDAPException as exc:
        log_error(f"LDAP bind failed: {exc}")
        return None
    log_success(f"Bound to {host} as {username}")
    return conn


def get_rootdse_info(conn, base_dn_override=None):
    info = conn.server.info
    if info is None:
        raise RuntimeError("Could not read RootDSE from the target server.")

    other = info.other or {}
    default_nc = (other.get("defaultNamingContext") or [None])[0]
    config_nc = (other.get("configurationNamingContext") or [None])[0]
    highest_usn = (other.get("highestCommittedUSN") or [None])[0]
    domain_functionality_raw = (other.get("domainFunctionality") or [None])[0]

    base_dn = base_dn_override or default_nc
    if not base_dn:
        raise RuntimeError(
            "Could not determine a search base (defaultNamingContext not "
            "returned by RootDSE and --base-dn not supplied)."
        )

    try:
        highest_usn = int(highest_usn) if highest_usn is not None else None
    except (TypeError, ValueError):
        highest_usn = None

    try:
        domain_functionality = (
            int(domain_functionality_raw) if domain_functionality_raw is not None else None
        )
    except (TypeError, ValueError):
        domain_functionality = None

    return {
        "base_dn": base_dn,
        "config_nc": config_nc,
        "highest_committed_usn": highest_usn,
        "domain_functionality": domain_functionality,
        "naming_contexts": info.naming_contexts or [],
    }


def get_domain_sid_and_tombstone_lifetime(conn, base_dn, config_nc):
    """[v0.2.3 fix] Previously only requested msDS-DeletedObjectLifetime
    and fell back to a hardcoded 180 days if it wasn't set -- but per
    Microsoft's own protocol spec (MS-ADTS 1887de08), an unset
    msDS-DeletedObjectLifetime is the COMMON case (confirmed across
    multiple sources: "by default, msDS-deletedObjectLifetime is also
    set to null"), and the spec-correct fallback in that case is the
    OLDER tombstoneLifetime attribute on the same object -- which the
    old code never even requested. Also, the old hardcoded last-resort
    default (180) was itself wrong: per the same spec, if tombstoneLifetime
    is ALSO unset, the correct default is 60 days, not 180. Now requests
    both attributes in a single search and applies the correct two-tier
    precedence. Also returns whether the value is a confirmed,
    explicitly-configured value or an assumed default, so downstream
    consumers (e.g. adaudit.py plugin 4011) can distinguish "we know
    this is actually true" from "we're assuming this because nothing
    was explicitly set" -- a real trust distinction, not just an
    implementation detail."""
    domain_sid = None
    try:
        conn.search(base_dn, "(objectClass=domain)",
                    search_scope=ldap3.BASE, attributes=["objectSid"])
        if conn.response:
            raw = conn.response[0]["raw_attributes"].get("objectSid")
            if raw:
                domain_sid = sid_bytes_to_str(raw[0])
    except LDAPException as exc:
        log_warn(f"Could not read domain SID: {exc}")

    tombstone_lifetime = None
    tombstone_lifetime_is_default = True
    dsheuristics_anonymous_access = False
    if config_nc:
        ds_dn = f"CN=Directory Service,CN=Windows NT,CN=Services,{config_nc}"
        try:
            conn.search(ds_dn, "(objectClass=*)", search_scope=ldap3.BASE,
                        attributes=["msDS-DeletedObjectLifetime", "tombstoneLifetime",
                                    "dSHeuristics"])
            if conn.response:
                attrs = conn.response[0]["attributes"]
                dol_val = attrs.get("msDS-DeletedObjectLifetime")
                tsl_val = attrs.get("tombstoneLifetime")
                dsh_val = attrs.get("dSHeuristics")
                if dol_val:
                    tombstone_lifetime = int(dol_val[0] if isinstance(dol_val, list) else dol_val)
                    tombstone_lifetime_is_default = False
                elif tsl_val:
                    tombstone_lifetime = int(tsl_val[0] if isinstance(tsl_val, list) else tsl_val)
                    tombstone_lifetime_is_default = False
                    log_info("msDS-DeletedObjectLifetime not explicitly set; using the "
                             "effective fallback value from tombstoneLifetime instead, "
                             "per MS-ADTS -- this is a confirmed, explicitly-configured "
                             "value, not an assumed default.")
                # [v0.2.5] dSHeuristics 7th character = "2" enables anonymous
                # LDAP access forest-wide, confirmed against MS-ADTS and DISA
                # STIG V-243503. Same Directory Service object already being
                # queried here -- no new LDAP round-trip needed.
                if dsh_val:
                    dsh_str = dsh_val[0] if isinstance(dsh_val, list) else dsh_val
                    if len(dsh_str) >= 7 and dsh_str[6] == "2":
                        dsheuristics_anonymous_access = True
        except LDAPException as exc:
            log_warn(f"Could not read tombstone lifetime: {exc}")
    if tombstone_lifetime is None:
        log_warn("Neither msDS-DeletedObjectLifetime nor tombstoneLifetime is explicitly "
                 "set; using the MS-ADTS-specified default of 60 days for this case "
                 "(NOT 180 -- that default only applies once tombstoneLifetime has been "
                 "explicitly set, which is common but not universal). This is an ASSUMED "
                 "value, not a confirmed one.")
        tombstone_lifetime = 60

    return domain_sid, tombstone_lifetime, tombstone_lifetime_is_default, dsheuristics_anonymous_access


def ldap_attribute_exists(conn, config_nc, attribute_ldap_name):
    """
    [v0.1.1] Checks whether a given attribute is actually defined in this
    forest's schema, by querying the Schema NC for a matching
    attributeSchema object. Needed for optional schema-extension
    attributes (LAPS being the concrete example that surfaced this) that
    are NOT present in every AD forest, unlike built-in attributes like
    pwdLastSet or userAccountControl which always exist. Requesting an
    attribute name AD's schema doesn't recognize at all fails the ENTIRE
    LDAP search with "invalid attribute type" -- not an empty/missing
    value for just that one field -- so this must be checked before ever
    including such an attribute name in a search's attribute list.
    Failure here (e.g. can't read the Schema NC at all) is treated as
    "not present" rather than raised, since this is only ever used to
    decide whether to *add* an optional field, never something the run
    should hard-fail over.
    """
    if not config_nc:
        return False
    schema_nc = f"CN=Schema,{config_nc}"
    try:
        conn.search(
            schema_nc, f"(lDAPDisplayName={attribute_ldap_name})",
            search_scope=ldap3.SUBTREE, attributes=["cn"],
        )
        return bool(conn.response)
    except LDAPException:
        return False


def run_capability_probe(conn, base_dn):
    results = {}
    try:
        conn.search(base_dn, "(objectClass=*)", search_scope=ldap3.BASE,
                    attributes=["distinguishedName"])
        ok = bool(conn.response)
        results["base_read"] = {
            "passed": ok,
            "detail": "OK" if ok else "Search returned no results for the base DN.",
        }
    except LDAPException as exc:
        results["base_read"] = {"passed": False, "detail": str(exc)}

    try:
        # [v0.0.4 fix] Without the SD Flags control, AD attempts to return
        # ALL FOUR parts of the security descriptor, including the SACL --
        # which requires audit-related privileges (SeSecurityPrivilege)
        # that a read-only collector account correctly does not have and
        # should not need. Because that portion can't be authorized, AD
        # returns nothing at all, even when the account genuinely has
        # READ_CONTROL and could read Owner+Group+DACL just fine. This is
        # the same technique SharpHound/BloodHound/SOAPHound use (SDFlags
        # 0x7 = OWNER + GROUP + DACL, deliberately excluding SACL's 0x8).
        sd_flags_control = security_descriptor_control(sdflags=0x07)
        conn.search(base_dn, "(objectClass=*)", search_scope=ldap3.BASE,
                    attributes=["nTSecurityDescriptor"], controls=sd_flags_control)
        raw = conn.response[0]["raw_attributes"].get("nTSecurityDescriptor") if conn.response else None
        ok = bool(raw)
        results["security_descriptor_read"] = {
            "passed": ok,
            "detail": "OK" if ok else (
                "nTSecurityDescriptor not returned even with SD Flags control "
                "(Owner+Group+DACL only). Grant READ_CONTROL on the "
                "domain root (see PERMISSIONS.md)."
            ),
        }
    except LDAPException as exc:
        results["security_descriptor_read"] = {"passed": False, "detail": str(exc)}

    try:
        deleted_container = f"CN=Deleted Objects,{base_dn}"
        conn.search(
            deleted_container, "(isDeleted=TRUE)",
            search_scope=ldap3.LEVEL,
            attributes=["distinguishedName"],
            controls=[(LDAP_CONTROL_SHOW_DELETED, True, None)],
        )
        results["view_deleted_objects"] = {
            "passed": True,
            "detail": f"OK ({len(conn.response)} deleted object(s) currently visible)",
        }
    except LDAPException as exc:
        results["view_deleted_objects"] = {
            "passed": False,
            "detail": (
                f"{exc} -- grant the 'View Deleted Objects' (Deleted Object "
                "CONTROL_ACCESS) extended right (see PERMISSIONS.md)."
            ),
        }

    return results


def connect_postgres():
    log_info(f"Connecting to PostgreSQL at {PG_HOST}:{PG_PORT}/{PG_DBNAME}...")
    conn = psycopg2.connect(
        host=PG_HOST, port=PG_PORT, dbname=PG_DBNAME,
        user=PG_USER, password=PG_PASSWORD,
    )
    conn.autocommit = False
    with conn.cursor() as cur:
        cur.execute("SET search_path TO ad_intel, public;")
    conn.commit()
    log_success("Connected to PostgreSQL.")
    return conn


# Every table and column this script writes to, and the two functions it
# calls. Kept as an explicit whitelist (not introspected from write calls)
# so it's an honest, independently-checkable statement of what this
# version of the script actually requires -- deliberately verbose rather
# than clever, so it stays easy to audit and extend alongside new features.
REQUIRED_SCHEMA_COLUMNS = {
    "client": {"client_id", "client_name", "domain_fqdn", "domain_sid",
               "tombstone_lifetime_days"},
    "sync_run": {"run_id", "client_id", "status", "run_type",
                 "high_watermark_usn", "prior_watermark_usn",
                 "capability_probe_result", "failure_reason", "failure_detail"},
    "directory_object": {"object_guid", "client_id", "object_sid", "dn_current",
                          "object_class", "sam_account_name", "first_seen_run_id",
                          "last_confirmed_run_id", "is_deleted", "deleted_run_id",
                          "deleted_detected_at", "owner_sid"},
    "directory_object_current": {"object_guid", "client_id", "version_id", "valid_from"},
    "directory_object_version": {"version_id", "object_guid", "client_id",
                                  "run_id_valid_from", "run_id_valid_to", "valid_from",
                                  "valid_to", "dc_source", "change_kind",
                                  "attributes_changed", "attributes_full"},
    "ad_user": {"object_guid", "client_id", "version_id", "valid_from", "valid_to",
                "user_principal_name", "sam_account_name", "user_account_control",
                "is_enabled", "admin_count", "primary_group_id", "pwd_last_set",
                "pwd_never_expires", "last_logon_timestamp", "bad_pwd_count",
                "lockout_time", "supported_encryption_types", "smartcard_required",
                "reversible_encryption", "service_principal_names", "sid_history",
                "protected_users_member", "description", "notes", "key_credential_count",
                "mail", "proxy_addresses", "when_created"},
    "ad_group": {"object_guid", "client_id", "version_id", "valid_from", "valid_to",
                 "sam_account_name", "group_type", "admin_count",
                 "is_protected_group", "member_count_direct",
                 "description", "notes", "sid_history", "when_created"},
    "ad_computer": {"object_guid", "client_id", "version_id", "valid_from", "valid_to",
                     "sam_account_name", "dns_hostname", "operating_system",
                     "operating_system_version", "user_account_control",
                     "is_domain_controller", "last_logon_timestamp",
                     "supported_encryption_types", "unconstrained_delegation",
                     "laps_expiration_legacy", "laps_expiration_modern",
                     "pwd_last_set", "description", "notes", "key_credential_count",
                     "is_enabled", "primary_group_id", "sid_history", "when_created",
                     "admin_count"},
    "ad_domain": {"object_guid", "client_id", "version_id", "valid_from", "valid_to",
                  "dns_root", "functional_level", "tombstone_lifetime_days",
                  "tombstone_lifetime_is_default",
                  "pwd_policy_min_length", "pwd_policy_complexity", "lockout_threshold",
                  "min_pwd_age_seconds", "max_pwd_age_seconds",
                  "lockout_duration_seconds", "lockout_observation_window_seconds",
                  "pwd_history_count", "machine_account_quota",
                  "pwd_reversible_encryption_domain_wide",
                  "laps_schema_present", "pwd_no_clear_change", "pwd_allows_admin_lockout",
                  "dsheuristics_anonymous_access", "block_inheritance",
                  "well_known_objects", "dfsr_migration_flags"},
    "ad_ou": {"object_guid", "client_id", "version_id", "valid_from", "valid_to",
              "ou_name", "description", "block_inheritance", "when_created"},
    "ad_ntauth_store": {"object_guid", "client_id", "version_id", "valid_from",
                         "valid_to", "certificates", "certificate_count"},
    "ad_site": {"object_guid", "client_id", "version_id", "valid_from",
                "valid_to", "site_name"},
    "ad_subnet": {"object_guid", "client_id", "version_id", "valid_from",
                  "valid_to", "subnet_name", "site_dn"},
    "ad_schema_object": {"object_guid", "client_id", "version_id", "valid_from",
                          "valid_to", "schema_cn", "schema_object_type",
                          "poss_superiors", "sub_class_of"},
    "ad_display_specifier": {"object_guid", "client_id", "version_id", "valid_from",
                              "valid_to", "schema_cn", "admin_context_menu"},
    "ad_cert_oid": {"object_guid", "client_id", "version_id", "valid_from",
                     "valid_to", "schema_cn", "oid_to_group_link"},
    "ad_dns_zone": {"object_guid", "client_id", "version_id", "valid_from",
                     "valid_to", "zone_name", "allow_update"},
    "ad_trust": {"object_guid", "client_id", "version_id", "valid_from", "valid_to",
                 "trust_partner", "trust_direction", "trust_type",
                 "trust_attributes", "sid_filtering_enabled"},
    "ad_foreign_security_principal": {"object_guid", "client_id", "version_id",
                                       "valid_from", "valid_to", "well_known_name"},
    "ad_gpo": {"object_guid", "client_id", "version_id", "valid_from", "valid_to",
               "display_name", "gpo_guid", "version_number"},
    "ad_fgpp": {"object_guid", "client_id", "version_id", "valid_from", "valid_to",
                "policy_name", "precedence", "min_pwd_length",
                "pwd_complexity_enabled", "reversible_encryption_enabled",
                "pwd_history_count", "min_pwd_age_seconds", "max_pwd_age_seconds",
                "lockout_threshold", "lockout_duration_seconds",
                "lockout_observation_window_seconds"},
    "ad_cert_template": {"object_guid", "client_id", "version_id", "valid_from",
                          "valid_to", "template_name", "display_name",
                          "enrollment_flags", "certificate_name_flags",
                          "enrollee_supplies_subject", "extended_key_usage",
                          "client_authentication_capable", "is_enabled",
                          "certificate_policy_oids", "schema_version"},
    "ad_enrollment_service": {"object_guid", "client_id", "version_id", "valid_from",
                               "valid_to", "ca_name", "dns_hostname"},
    "group_member_edge": {"edge_id", "client_id", "group_guid", "member_guid",
                           "is_direct", "valid_from", "valid_to",
                           "run_id_valid_from", "run_id_valid_to"},
    "spn_edge": {"edge_id", "client_id", "object_guid", "spn", "valid_from",
                 "valid_to", "run_id_valid_from", "run_id_valid_to"},
    "delegation_edge": {"edge_id", "client_id", "source_guid", "target_guid",
                         "delegation_type", "valid_from", "valid_to",
                         "run_id_valid_from", "run_id_valid_to"},
    "unresolved_delegation_target_edge": {"edge_id", "client_id", "source_guid",
                                           "target_spn", "valid_from", "valid_to",
                                           "run_id_valid_from", "run_id_valid_to"},
    "fgpp_applies_to_edge": {"edge_id", "client_id", "pso_guid", "target_guid",
                              "valid_from", "valid_to", "run_id_valid_from",
                              "run_id_valid_to"},
    "cert_template_enabled_edge": {"edge_id", "client_id", "ca_guid", "template_guid",
                                    "valid_from", "valid_to", "run_id_valid_from",
                                    "run_id_valid_to"},
}
REQUIRED_SCHEMA_FUNCTIONS = {"upsert_directory_object", "set_current_version"}


def validate_schema(pg_conn):
    """
    [v0.1.0] Checks that every table/column/function this script writes to
    or calls actually exists before any collection begins -- requested
    explicitly to guard against a database that's been altered outside
    this project's migration files, or a schema/script version mismatch
    (e.g. running this version against a database that's missing a more
    recent incremental migration -- as actually happened, prompting this
    fix: the accompanying error message itself used to hardcode
    "schema.sql" and "schema_migration_v2.sql" as the fix, filenames that
    stopped being accurate many migrations ago and sent at least one real
    client chasing the wrong file). Comprehensive: collects every
    problem found rather than stopping at the first, same philosophy as
    the LDAP capability probe. Returns a list of problem strings; empty
    list means the schema is fully compatible.
    """
    problems = []

    with pg_conn.cursor() as cur:
        cur.execute(
            "SELECT table_name, column_name FROM information_schema.columns "
            "WHERE table_schema = 'ad_intel';"
        )
        actual_columns = {}
        for table_name, column_name in cur.fetchall():
            actual_columns.setdefault(table_name, set()).add(column_name)

        cur.execute(
            "SELECT proname FROM pg_proc WHERE pronamespace = 'ad_intel'::regnamespace;"
        )
        actual_functions = {row[0] for row in cur.fetchall()}

    for table, required_cols in REQUIRED_SCHEMA_COLUMNS.items():
        if table not in actual_columns:
            problems.append(f"table '{table}' does not exist")
            continue
        missing_cols = required_cols - actual_columns[table]
        if missing_cols:
            problems.append(
                f"table '{table}' is missing column(s): {', '.join(sorted(missing_cols))}"
            )

    for fn in sorted(REQUIRED_SCHEMA_FUNCTIONS - actual_functions):
        problems.append(f"required function '{fn}' does not exist")

    return problems


def base_dn_to_fqdn(base_dn):
    """Converts an LDAP distinguished name of DC components (e.g.
    'DC=forge,DC=local') into its dotted DNS domain form ('forge.local').
    Case-insensitive on the 'DC=' prefix, matching LDAP's own case-
    insensitivity for attribute type names. [v0.4.3 fix] Previously,
    upsert_client() was called with args.dc_host (the specific domain
    controller hostname the user happened to type at --dc-host, e.g.
    'df-dc-01.forge.local') rather than the actual AD domain FQDN --
    close enough to look right at a glance, wrong enough to break any
    later lookup by the real domain name, as entra_graph_collector.py's
    --domain-fqdn discovered."""
    parts = [p.split("=", 1)[1] for p in base_dn.split(",") if p.strip().upper().startswith("DC=")]
    return ".".join(parts)


def upsert_client(pg_conn, domain_fqdn, domain_sid, tombstone_lifetime_days):
    with pg_conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO client (client_name, domain_fqdn, domain_sid, tombstone_lifetime_days)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (domain_fqdn) DO UPDATE
                SET domain_sid = EXCLUDED.domain_sid,
                    tombstone_lifetime_days = EXCLUDED.tombstone_lifetime_days
            RETURNING client_id;
            """,
            (domain_fqdn, domain_fqdn, domain_sid, tombstone_lifetime_days),
        )
        client_id = cur.fetchone()[0]
    pg_conn.commit()
    return client_id


def create_sync_run(pg_conn, client_id, dc_host, naming_context, run_type,
                     prior_watermark_usn, capability_probe_result):
    with pg_conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO sync_run
                (client_id, dc_queried, naming_context, run_type, status,
                 prior_watermark_usn, last_good_watermark_usn,
                 collector_version, capability_probe_result)
            VALUES (%s, %s, %s, %s, 'running', %s, %s, %s, %s)
            RETURNING run_id;
            """,
            (client_id, dc_host, naming_context, run_type,
             prior_watermark_usn, prior_watermark_usn, VERSION,
             Json(capability_probe_result)),
        )
        run_id = cur.fetchone()[0]
    pg_conn.commit()
    return run_id


def finalize_sync_run(pg_conn, run_id, status, high_watermark_usn=None,
                       objects_seen=None, objects_changed=None,
                       objects_deleted=None, failure_reason=None,
                       failure_detail=None):
    with pg_conn.cursor() as cur:
        cur.execute(
            """
            UPDATE sync_run
               SET status = %s,
                   completed_at = now(),
                   high_watermark_usn = %s,
                   objects_seen = %s,
                   objects_changed = %s,
                   objects_deleted = %s,
                   failure_reason = %s,
                   failure_detail = %s
             WHERE run_id = %s;
            """,
            (status, high_watermark_usn, objects_seen, objects_changed,
             objects_deleted, failure_reason,
             Json(failure_detail) if failure_detail else None, run_id),
        )
    pg_conn.commit()


def get_current_object_state(pg_cur, object_guid):
    pg_cur.execute(
        """
        SELECT v.version_id, v.attributes_full
          FROM directory_object_current c
          JOIN directory_object_version v
            ON v.version_id = c.version_id AND v.valid_from = c.valid_from
         WHERE c.object_guid = %s;
        """,
        (object_guid,),
    )
    row = pg_cur.fetchone()
    if row is None:
        return None, None
    return row[0], row[1]


def close_open_version(pg_cur, object_guid, run_id, valid_to):
    pg_cur.execute(
        """
        UPDATE directory_object_version
           SET valid_to = %s, run_id_valid_to = %s
         WHERE object_guid = %s AND valid_to IS NULL;
        """,
        (valid_to, run_id, object_guid),
    )


def write_object_version(pg_cur, object_guid, client_id, run_id, dc_source,
                          change_kind, attributes_changed, attributes_full,
                          valid_from):
    close_open_version(pg_cur, object_guid, run_id, valid_from)
    pg_cur.execute(
        """
        INSERT INTO directory_object_version
            (object_guid, client_id, run_id_valid_from, valid_from,
             dc_source, change_kind, attributes_changed, attributes_full)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING version_id;
        """,
        (object_guid, client_id, run_id, valid_from, dc_source, change_kind,
         Json(attributes_changed), Json(attributes_full)),
    )
    version_id = pg_cur.fetchone()[0]
    pg_cur.execute(
        "SELECT set_current_version(%s, %s, %s, %s);",
        (object_guid, client_id, version_id, valid_from),
    )
    return version_id


def write_typed_row(pg_cur, table, object_guid, client_id, version_id, valid_from, columns):
    """[v0.0.3 fix] Both client_id and version_id were previously omitted
    from the INSERT. client_id fails a NOT NULL constraint immediately;
    version_id also fails NOT NULL (it's the informational pointer back to
    the directory_object_version row that produced these values -- see the
    schema comment on ad_user for why it's not a hard FK, but it's still
    required, non-null data)."""
    if table not in KNOWN_TYPED_TABLES:
        raise ValueError(f"Refusing to write to unrecognized table: {table}")

    pg_cur.execute(
        sql.SQL("UPDATE {} SET valid_to = %s WHERE object_guid = %s AND valid_to IS NULL")
           .format(sql.Identifier(table)),
        (valid_from, object_guid),
    )

    all_cols = ["object_guid", "client_id", "version_id", "valid_from"] + list(columns.keys())
    all_vals = [object_guid, client_id, version_id, valid_from] + list(columns.values())
    query = sql.SQL("INSERT INTO {} ({}) VALUES ({})").format(
        sql.Identifier(table),
        sql.SQL(", ").join(map(sql.Identifier, all_cols)),
        sql.SQL(", ").join(sql.Placeholder() * len(all_cols)),
    )
    pg_cur.execute(query, all_vals)


def get_open_edges(pg_cur, table, client_id, key_cols):
    if table not in KNOWN_EDGE_TABLES:
        raise ValueError(f"Refusing to read from unrecognized table: {table}")
    query = sql.SQL("SELECT edge_id, {} FROM {} WHERE client_id = %s AND valid_to IS NULL").format(
        sql.SQL(", ").join(map(sql.Identifier, key_cols)),
        sql.Identifier(table),
    )
    pg_cur.execute(query, (client_id,))
    return {tuple(row[1:]): row[0] for row in pg_cur.fetchall()}


def close_edge_by_id(pg_cur, table, edge_id, run_id, valid_to):
    if table not in KNOWN_EDGE_TABLES:
        raise ValueError(f"Refusing to write to unrecognized table: {table}")
    pg_cur.execute(
        sql.SQL("UPDATE {} SET valid_to = %s, run_id_valid_to = %s "
                "WHERE edge_id = %s AND valid_to IS NULL")
           .format(sql.Identifier(table)),
        (valid_to, run_id, edge_id),
    )


def open_edge(pg_cur, table, columns):
    if table not in KNOWN_EDGE_TABLES:
        raise ValueError(f"Refusing to write to unrecognized table: {table}")
    cols = list(columns.keys())
    vals = list(columns.values())
    query = sql.SQL("INSERT INTO {} ({}) VALUES ({})").format(
        sql.Identifier(table),
        sql.SQL(", ").join(map(sql.Identifier, cols)),
        sql.SQL(", ").join(sql.Placeholder() * len(cols)),
    )
    pg_cur.execute(query, vals)


def sync_edges(pg_cur, table, client_id, run_id, valid_from, key_cols,
               desired_edges):
    existing = get_open_edges(pg_cur, table, client_id, key_cols)
    desired_keys = set(desired_edges.keys())
    existing_keys = set(existing.keys())

    opened = 0
    for key in desired_keys - existing_keys:
        row = dict(zip(key_cols, key))
        row.update(desired_edges[key])
        row["client_id"] = client_id
        row["valid_from"] = valid_from
        row["run_id_valid_from"] = run_id
        open_edge(pg_cur, table, row)
        opened += 1

    closed = 0
    for key in existing_keys - desired_keys:
        close_edge_by_id(pg_cur, table, existing[key], run_id, valid_from)
        closed += 1

    return opened, closed


def ldap_paged_search(conn, base_dn, search_filter, attributes, page_size,
                       controls=None):
    entry_generator = conn.extend.standard.paged_search(
        search_base=base_dn,
        search_filter=search_filter,
        search_scope=ldap3.SUBTREE,
        attributes=attributes,
        paged_size=page_size,
        generator=True,
        controls=controls,
    )
    for entry in entry_generator:
        if entry.get("type") != "searchResEntry":
            continue
        yield entry["dn"], entry.get("attributes", {}), entry.get("raw_attributes", {})


def count_ldap_entries(conn, base_dn, search_filter):
    total = 0
    for _ in ldap_paged_search(conn, base_dn, search_filter, [ldap3.NO_ATTRIBUTES], 1000):
        total += 1
    return total


def resolve_ranged_attribute(conn, dn, attr_name, first_batch_raw_keys, first_values):
    ranged_key = None
    for k in first_batch_raw_keys:
        if k.startswith(attr_name + ";range="):
            ranged_key = k
            break
    if ranged_key is None:
        return first_values

    all_values = list(first_values)
    range_part = ranged_key.split("range=")[1]
    _, end = range_part.split("-")
    if end == "*":
        return all_values
    next_start = int(end) + 1

    while True:
        next_attr = f"{attr_name};range={next_start}-*"
        conn.search(dn, "(objectClass=*)", search_scope=ldap3.BASE,
                    attributes=[next_attr])
        if not conn.response:
            break
        raw = conn.response[0]["raw_attributes"]
        matched_key = next(
            (k for k in raw if k.startswith(attr_name + ";range=")), None
        )
        if matched_key is None:
            break
        batch = raw[matched_key]
        all_values.extend(batch)
        if matched_key.endswith("-*"):
            break
        range_end = matched_key.split("-")[-1]
        if range_end == "*":
            break
        next_start = int(range_end) + 1
        if not batch:
            break
    return all_values


def build_attributes_full(dn, attributes, raw_attributes):
    full = {}
    for key, value in attributes.items():
        if key == "objectGUID":
            continue
        if key == "objectSid":
            raw = raw_attributes.get("objectSid")
            full["objectSid"] = sid_bytes_to_str(raw[0]) if raw else None
            continue
        if key == "msDS-AllowedToActOnBehalfOfOtherIdentity":
            # [v0.3.0, fixed same version] RBCD trustee list is itself a
            # full security descriptor (Microsoft deliberately reuses the
            # SD format here so the same ACE semantics apply). Storing
            # RAW bytes here (as originally written) broke JSONB
            # serialization in write_object_version -- "Object of type
            # bytes is not JSON serializable" -- found via the mock
            # harness, not assumed safe. Fixed to match the SAME
            # established convention normalize_value() already uses for
            # binary data elsewhere in this file: base64-encoded string,
            # JSON-safe, decoded back to raw bytes right before
            # parse_security_descriptor() needs it in
            # collect_delegation_edges().
            raw = raw_attributes.get(key)
            full[key] = base64.b64encode(raw[0]).decode("ascii") if raw else None
            continue
        if key == "msDS-GroupMSAMembership":
            # [v0.5.1] Same reasoning and same fix as
            # msDS-AllowedToActOnBehalfOfOtherIdentity immediately above --
            # also String(NT-Sec-Desc) syntax, also a full security
            # descriptor reused for a different purpose (here: who can
            # retrieve a gMSA's computed password, not RBCD). Given the
            # sibling attribute needed this explicit special case despite
            # normalize_value()'s own generic bytes fallback (suggesting
            # ldap3's schema-aware formatting doesn't reliably hand back
            # plain bytes for this syntax type), applying the same fix
            # here rather than assuming the generic path is safe for an
            # attribute this project has not yet collected against a real
            # DC.
            raw = raw_attributes.get(key)
            full[key] = base64.b64encode(raw[0]).decode("ascii") if raw else None
            continue
        if key == "cACertificate":
            # [v0.5.3] Genuinely multi-valued (NTAuthCertificates can and
            # normally does hold more than one CA certificate), unlike
            # the single-valued RBCD/gMSA security descriptors above --
            # every entry needs its own base64 encoding, not just the
            # first. Same underlying caution as those two: Octet String
            # binary syntax, not trusted to normalize_value()'s generic
            # bytes fallback without verification against a real DC,
            # given the sibling binary-syntax attributes above needed
            # this explicit path.
            raw = raw_attributes.get(key) or []
            full[key] = [base64.b64encode(v).decode("ascii") for v in raw] or None
            continue
        if key in ("pwdLastSet", "lastLogonTimestamp", "lockoutTime",
                    "ms-Mcs-AdmPwdExpirationTime", "msLAPS-PasswordExpirationTime"):
            # [v0.0.8, extended in v0.1.0] Pull the RAW, untouched value
            # instead of the formatted one, to bypass ldap3's schema-aware
            # AD-timestamp auto-formatting entirely rather than defensively
            # work around its result -- the same pattern BloodHound.py uses
            # (ADUtils.get_entry_property(..., raw=True)) for the identical
            # reason; this is a known ldap3+AD gotcha that has bitten that
            # project in production too (fox-it/BloodHound.py#24). The two
            # LAPS expiration attributes are schema-extension attributes,
            # not in ldap3's built-in formatter table, so they likely
            # wouldn't hit this specific gotcha -- handled the same way
            # anyway for consistency and because it's proven safe.
            raw = raw_attributes.get(key)
            raw_val = raw[0] if raw else None
            if isinstance(raw_val, bytes):
                raw_val = raw_val.decode("utf-8", errors="replace")
            dt = filetime_to_datetime(raw_val)
            full[key] = dt.isoformat() if dt else None
            continue
        if key in ("minPwdAge", "maxPwdAge", "lockoutDuration", "lockOutObservationWindow"):
            # [v0.1.4] Same class of bug as the FILETIME timestamp
            # attributes above, confirmed against ldap3's own source: these
            # four are mapped to ldap3's format_ad_timedelta formatter
            # (distinct from format_ad_timestamp), which converts the raw
            # negative-tick integer into a Python timedelta object.
            # normalize_value() doesn't have a case for timedelta, so it
            # fell through to str(value) -- "42 days, 0:00:00" -- which
            # ad_interval_to_seconds() then failed to parse as an int and
            # silently returned None. Confirmed against real DC data
            # (forge.local's max_pwd_age/min_pwd_age/lockout_duration were
            # all NULL despite a real, non-default password policy).
            # Pulling the raw ticks value directly, same bypass strategy
            # as above, sidesteps the auto-formatting entirely; the value
            # is stored here as the raw ticks (a string/int), NOT
            # pre-converted to seconds, since ad_interval_to_seconds()
            # already correctly parses a raw ticks value and downstream
            # typed-column builders call it unchanged.
            raw = raw_attributes.get(key)
            raw_val = raw[0] if raw else None
            if isinstance(raw_val, bytes):
                raw_val = raw_val.decode("utf-8", errors="replace")
            full[key] = raw_val
            continue
        if key == "msDS-ReplAttributeMetaData":
            parsed = parse_repl_attr_meta_data(value)
            if parsed is None and value:
                log_warn(f"Could not parse msDS-ReplAttributeMetaData for {dn}; "
                         "storing raw value instead.")
                full[key] = normalize_value(value)
            else:
                full[key] = parsed
            continue
        if key in ("whenChanged", "whenCreated"):
            parsed_dt = parse_generalized_time(value)
            full[key] = parsed_dt.isoformat() if parsed_dt else normalize_value(value)
            continue
        full[key] = normalize_value(value)

    raw_guid = raw_attributes.get("objectGUID")
    object_guid = guid_bytes_to_str(raw_guid[0]) if raw_guid else None
    full["objectGUID"] = object_guid
    full["distinguishedName"] = dn
    return object_guid, full


class CollectionStats:
    def __init__(self, full_rescan=False):
        self.seen = 0
        self.created = 0
        self.modified = 0
        self.unchanged = 0
        self.deleted = 0
        self.edges_opened = 0
        self.edges_closed = 0
        self.skipped_unresolved_members = 0
        self.skipped_unresolved_delegation_targets = 0
        # [v0.4.1] full_rescan and rescanned live on the stats object
        # rather than as a proper parameter on every collect_object_class()
        # call, purely to avoid threading a new argument through all 11
        # call sites individually -- stats is already passed to every one
        # of them. It's read, not accumulated, so it's a mild abuse of
        # "stats" as a run-context carrier, but the alternative (11 call
        # sites, each updated) is worse for a single run-wide flag.
        self.full_rescan = full_rescan
        self.rescanned = 0


def collect_object_class(conn, pg_cur, client_id, run_id, dc_host, base_dn,
                          object_filter, attrs, page_size, label,
                          typed_table, typed_column_fn, dn_to_guid, stats,
                          run_timestamp):
    """
    [v0.0.6 fix] valid_from is now run_timestamp (one fixed value shared by
    every row this run writes), not the AD object's own whenChanged
    attribute. Using whenChanged meant a baseline run against an object
    last modified in AD long before this deployment existed (e.g. months
    or years ago) tried to write into a monthly partition that predates
    the schema itself and doesn't exist -- "no partition of relation
    directory_object_version found for row" against a real DC. valid_from
    is meant to answer "when did WE observe this state", which is always
    now; AD's own last-modified time remains fully available inside
    attributes_full (and per-attribute via msDS-ReplAttributeMetaData) for
    anyone who needs it -- nothing is lost, this only fixes what the
    partition key represents.
    """
    total = count_ldap_entries(conn, base_dn, object_filter)
    log_info(f"Found {total} {label} object(s) to process.")

    # [v0.2.6 fix] stats.created/stats.modified are cumulative counters
    # shared across the ENTIRE run, correctly so -- the final Run Summary
    # depends on that to report true whole-run totals. But this
    # function's own per-category log line at the bottom was printing
    # those same raw cumulative values directly, which is wrong for a
    # line that's supposed to describe only THIS category's processing.
    # Confirmed against a real run: once any earlier category had
    # genuine changes, every SUBSEQUENT category's line kept echoing
    # that same stale cumulative number, including categories with zero
    # actual objects (e.g. "trusts: 0 object(s) processed (0 new, 2
    # changed this pass)" when zero trust objects exist at all). Fixed
    # by snapshotting the counters at entry and reporting the delta.
    created_before = stats.created
    modified_before = stats.modified
    rescanned_before = stats.rescanned

    collected = []
    count = 0
    for dn, attributes, raw_attributes in ldap_paged_search(
        conn, base_dn, object_filter, attrs, page_size
    ):
        object_guid, attributes_full = build_attributes_full(dn, attributes, raw_attributes)
        if not object_guid:
            log_warn(f"Skipping entry with unreadable objectGUID: {dn}")
            continue

        dn_to_guid[dn.lower()] = object_guid
        stats.seen += 1
        count += 1
        print_progress(count, total, label)

        object_sid = attributes_full.get("objectSid")
        sam = attributes_full.get("sAMAccountName")
        object_class = label_to_object_class(label)

        prior_version_id, prior_full = get_current_object_state(pg_cur, object_guid)
        changed_attrs = diff_attributes(prior_full, attributes_full)

        pg_cur.execute(
            "SELECT * FROM upsert_directory_object(%s, %s, %s, %s, %s, %s, %s);",
            (object_guid, client_id, object_sid, dn, object_class, sam, run_id),
        )
        action, _ = pg_cur.fetchone()

        if prior_full is not None and not changed_attrs:
            if not stats.full_rescan:
                stats.unchanged += 1
                collected.append((object_guid, attributes_full))
                continue
            # [v0.4.1] --full-rescan: this object's raw AD attributes
            # genuinely haven't changed, but the collector or schema may
            # have gained new derived columns (e.g. mail/proxy_addresses/
            # when_created, added in v0.4.0) since this object's current
            # version was last written, and those never backfill onto
            # objects that never re-trigger the change-detection path
            # above. Force a fresh version + typed row anyway, but label
            # it honestly as "rescanned", not "modified" -- nothing in
            # AD actually changed, so recording it as a modification
            # would misrepresent the object's real change history.
            change_kind = "rescanned"
            stats.rescanned += 1
        else:
            change_kind = "created" if prior_full is None else "modified"
            if change_kind == "created":
                stats.created += 1
            else:
                stats.modified += 1

        version_id = write_object_version(
            pg_cur, object_guid, client_id, run_id, dc_host,
            change_kind, changed_attrs, attributes_full, run_timestamp,
        )

        typed_columns = typed_column_fn(attributes_full)
        write_typed_row(pg_cur, typed_table, object_guid, client_id, version_id,
                         run_timestamp, typed_columns)

        collected.append((object_guid, attributes_full))

    rescanned_this_pass = stats.rescanned - rescanned_before
    log_success(f"{label}: {count} object(s) processed "
                f"({stats.created - created_before} new, "
                f"{stats.modified - modified_before} changed this pass)"
                + (f", {rescanned_this_pass} rescanned (--full-rescan)" if rescanned_this_pass else ""))
    return collected


# [v0.2.5] Well-known SIDs commonly found as foreignSecurityPrincipal
# objects. Deliberately a short, high-confidence list rather than
# exhaustive -- these are the ones that matter for security findings
# (Pre-Windows 2000 Compatible Access group membership specifically);
# anything not in this list simply gets well_known_name = NULL, which
# is the correct, honest representation for e.g. a genuine cross-
# domain/cross-forest trusted principal.
WELL_KNOWN_SIDS = {
    "S-1-1-0": "Everyone",
    "S-1-5-7": "Anonymous Logon",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-18": "Local System",
    "S-1-5-32-544": "Administrators (BUILTIN)",
}


def foreign_security_principal_typed_columns(full):
    object_sid = full.get("objectSid")
    return {
        "well_known_name": WELL_KNOWN_SIDS.get(object_sid),
    }


def label_to_object_class(label):
    return {
        "users": "user", "groups": "group", "computers": "computer",
        "domain": "domain", "trusts": "trust", "GPOs": "gpo",
        "FGPPs": "other", "certificate templates": "certificate_template",
        "enrollment services": "other",
        "foreign security principals": "foreign_security_principal",
        "OUs": "ou", "NTAuth store": "other",
        "AD sites": "other", "AD subnets": "other",
        "schema (Java extension check)": "other",
        "schema (possSuperiors check)": "other",
        "DisplaySpecifiers": "other", "certificate OIDs": "other",
        "DNS zones": "other",
    }[label]


def user_typed_columns(full):
    uac = int(full.get("userAccountControl") or 0)
    memberof = full.get("memberOf") or []
    if isinstance(memberof, str):
        memberof = [memberof]
    protected_users = any(
        PROTECTED_USERS_DN_FRAGMENT in (m or "").lower() for m in memberof
    )
    spns = full.get("servicePrincipalName") or []
    if isinstance(spns, str):
        spns = [spns]
    sid_history = full.get("sIDHistory") or []
    if isinstance(sid_history, str):
        sid_history = [sid_history]
    key_credentials = full.get("msDS-KeyCredentialLink") or []
    if isinstance(key_credentials, str):
        key_credentials = [key_credentials]
    proxy_addresses = full.get("proxyAddresses") or []
    if isinstance(proxy_addresses, str):
        proxy_addresses = [proxy_addresses]

    return {
        "user_principal_name": full.get("userPrincipalName"),
        "sam_account_name": full.get("sAMAccountName"),
        "user_account_control": uac,
        "is_enabled": not bool(uac & UAC_ACCOUNTDISABLE),
        "admin_count": _as_int(full.get("adminCount")),
        "primary_group_id": _as_int(full.get("primaryGroupID")),
        "pwd_last_set": filetime_to_datetime(full.get("pwdLastSet")),
        "pwd_never_expires": bool(uac & UAC_DONT_EXPIRE_PASSWORD),
        "last_logon_timestamp": filetime_to_datetime(full.get("lastLogonTimestamp")),
        "bad_pwd_count": _as_int(full.get("badPwdCount")),
        "lockout_time": filetime_to_datetime(full.get("lockoutTime")),
        "supported_encryption_types": _as_int(full.get("msDS-SupportedEncryptionTypes")),
        "smartcard_required": bool(uac & UAC_SMARTCARD_REQUIRED),
        "reversible_encryption": bool(uac & UAC_ENCRYPTED_TEXT_PWD_ALLOWED),
        "service_principal_names": spns or None,
        "sid_history": sid_history or None,
        "protected_users_member": protected_users,
        "description": full.get("description"),
        "notes": full.get("info"),
        "key_credential_count": len(key_credentials),
        "mail": full.get("mail"),
        "proxy_addresses": proxy_addresses or None,
        "when_created": full.get("whenCreated"),
    }


def computer_typed_columns(full):
    """[v0.0.9 fix] is_domain_controller was previously hardcoded False
    always. Now computed from the SERVER_TRUST_ACCOUNT UAC bit (0x2000),
    the standard signal Microsoft's own documentation and DCDIAG use to
    identify domain controller computer accounts -- confirmed against
    real DC data (DF-DC-01/DF-DC-02 both showed userAccountControl=532480
    = SERVER_TRUST_ACCOUNT | TRUSTED_FOR_DELEGATION, the well-known
    typical value for a DC).

    [v0.1.0] Added laps_expiration_legacy/modern. Deliberately the
    expiration timestamp only -- never ms-Mcs-AdmPwd / msLAPS-Password /
    msLAPS-EncryptedPassword, which contain the actual (or encrypted)
    credential material. The expiration timestamp alone fully answers the
    audit question (is this machine's local admin password centrally
    [v0.5.2] Added admin_count. Computers can carry the same
    AdminSDHolder/SDProp protection marker as users and groups -- a
    computer that's an effective member of a Tier-0 group (rare, but
    not impossible: a DC's own computer object is a clear example) is
    marked exactly the same way. Previously excluded here, which meant
    plugins 3021 and 5007 had to explicitly scope themselves to users
    and groups only -- both now cover computers too.
    """
    uac = int(full.get("userAccountControl") or 0)
    sid_history = full.get("sIDHistory") or []
    if isinstance(sid_history, str):
        sid_history = [sid_history]
    return {
        "sam_account_name": full.get("sAMAccountName"),
        "dns_hostname": full.get("dNSHostName"),
        "operating_system": full.get("operatingSystem"),
        "operating_system_version": full.get("operatingSystemVersion"),
        "user_account_control": uac,
        "is_domain_controller": bool(uac & UAC_SERVER_TRUST_ACCOUNT),
        "is_enabled": not bool(uac & UAC_ACCOUNTDISABLE),
        "last_logon_timestamp": filetime_to_datetime(full.get("lastLogonTimestamp")),
        "supported_encryption_types": _as_int(full.get("msDS-SupportedEncryptionTypes")),
        "unconstrained_delegation": bool(uac & UAC_TRUSTED_FOR_DELEGATION),
        "laps_expiration_legacy": filetime_to_datetime(full.get("ms-Mcs-AdmPwdExpirationTime")),
        "laps_expiration_modern": filetime_to_datetime(full.get("msLAPS-PasswordExpirationTime")),
        "pwd_last_set": filetime_to_datetime(full.get("pwdLastSet")),
        "description": full.get("description"),
        "notes": full.get("info"),
        "key_credential_count": len(full.get("msDS-KeyCredentialLink") or []),
        "primary_group_id": _as_int(full.get("primaryGroupID")),
        "sid_history": sid_history or None,
        "when_created": full.get("whenCreated"),
        "admin_count": _as_int(full.get("adminCount")),
    }


def group_typed_columns(full):
    group_type = _as_int(full.get("groupType"))
    admin_count = _as_int(full.get("adminCount"))
    is_protected = admin_count == 1
    sid_history = full.get("sIDHistory") or []
    if isinstance(sid_history, str):
        sid_history = [sid_history]
    return {
        "sam_account_name": full.get("sAMAccountName"),
        "group_type": group_type,
        "admin_count": admin_count,
        "is_protected_group": is_protected,
        "member_count_direct": None,  # populated by collect_group_membership() afterward
        "description": full.get("description"),
        "notes": full.get("info"),
        "sid_history": sid_history or None,
        "when_created": full.get("whenCreated"),
    }


def gpoptions_block_inheritance(full):
    """[v0.5.0] gPOptions bit 0x1 -- confirmed against multiple independent
    sources including a Microsoft Scripting Blog example using this exact
    bit test (gpOptions == 1 means Block Inheritance is enabled; this
    project treats it as a bitmask check rather than an exact-equality
    check, matching Microsoft's own PowerShell tooling's -band 1 usage,
    though in practice only the single bit is ever actually set on this
    attribute). Applies to both domain and OU objects -- both carry
    gPOptions, hence this being a shared helper rather than duplicated."""
    return bool((_as_int(full.get("gPOptions")) or 0) & 0x1)


def ou_typed_columns(full):
    """[v0.5.0] Deliberately thin: name, description, block_inheritance,
    when_created. GPO links are NOT here -- see OU_ATTRS's own comment
    for why that's resolved as a separate edge pass instead. The OU's
    own ACL (who can create/modify/delete objects within it) is
    likewise not here -- that's collected into acl_edge, the same table
    domain root/AdminSDHolder already use, not a typed column on the OU
    object itself, matching how every other object's ACL exposure in
    this project works."""
    return {
        "ou_name": full.get("ou"),
        "description": full.get("description"),
        "block_inheritance": gpoptions_block_inheritance(full),
        "when_created": full.get("whenCreated"),
    }


def domain_typed_columns(full, functional_level, tombstone_lifetime_days, tombstone_lifetime_is_default,
                          laps_schema_present, dsheuristics_anonymous_access, dfsr_migration_flags):
    """[v0.1.3 fix] minPwdAge/maxPwdAge/lockoutDuration/lockOutObservationWindow
    were never collected for the domain-wide DEFAULT password policy, even
    though the equivalent fields were built for Fine-Grained Password
    Policies (ad_fgpp) -- an inconsistency that meant a basic question like
    "what's the max password age" had no answer for the common case (a
    domain with no FGPP at all, which is the majority of domains, and was
    in fact this project's own test domain's state). Same AD "Interval"
    negative-duration convention as the FGPP fields; reuses
    ad_interval_to_seconds() rather than duplicating that logic.

    [v0.5.4] well_known_objects is parsed here (wellKnownObjects is now
    part of DOMAIN_ATTRS); dfsr_migration_flags is NOT derived from
    `full` at all -- it comes from a completely separate targeted read
    of a different object (see this function's own call site) and is
    passed straight through.
    """
    pwd_props = _as_int(full.get("pwdProperties")) or 0
    raw_wko = full.get("wellKnownObjects") or []
    if isinstance(raw_wko, str):
        raw_wko = [raw_wko]
    return {
        "dns_root": full.get("distinguishedName"),
        "functional_level": functional_level,
        "tombstone_lifetime_days": tombstone_lifetime_days,
        "tombstone_lifetime_is_default": tombstone_lifetime_is_default,
        "pwd_policy_min_length": _as_int(full.get("minPwdLength")),
        "pwd_policy_complexity": bool(pwd_props & 0x1),
        "pwd_reversible_encryption_domain_wide": bool(pwd_props & 0x10),
        "pwd_no_clear_change": bool(pwd_props & 0x4),
        "pwd_allows_admin_lockout": bool(pwd_props & 0x8),
        "laps_schema_present": laps_schema_present,
        "dsheuristics_anonymous_access": dsheuristics_anonymous_access,
        "lockout_threshold": _as_int(full.get("lockoutThreshold")),
        "min_pwd_age_seconds": ad_interval_to_seconds(full.get("minPwdAge")),
        "max_pwd_age_seconds": ad_interval_to_seconds(full.get("maxPwdAge")),
        "lockout_duration_seconds": ad_interval_to_seconds(full.get("lockoutDuration")),
        "lockout_observation_window_seconds": ad_interval_to_seconds(full.get("lockOutObservationWindow")),
        "pwd_history_count": _as_int(full.get("pwdHistoryLength")),
        "machine_account_quota": _as_int(full.get("ms-DS-MachineAccountQuota")),
        "block_inheritance": gpoptions_block_inheritance(full),
        "well_known_objects": json.dumps(list(raw_wko)) if raw_wko else None,
        "dfsr_migration_flags": dfsr_migration_flags,
    }


def trust_typed_columns(full):
    """[v0.1.0] trustAttributes bit 0x4 (TRUST_ATTRIBUTE_FILTER_SIDS) means
    SID filtering is enabled on this trust -- disabled SID filtering is a
    classic cross-domain/cross-forest escalation risk."""
    trust_attrs = _as_int(full.get("trustAttributes")) or 0
    return {
        "trust_partner": full.get("trustPartner"),
        "trust_direction": _as_int(full.get("trustDirection")),
        "trust_type": _as_int(full.get("trustType")),
        "trust_attributes": trust_attrs,
        "sid_filtering_enabled": bool(trust_attrs & TRUST_ATTR_FILTER_SIDS),
    }


def gpo_typed_columns(full):
    """[v0.1.0] GPO existence/name/version only -- no linkage (which OUs
    apply this GPO) and no settings content (which lives in SYSVOL, not
    LDAP). Both are real, larger follow-on pieces of work, deliberately
    out of scope here; see project notes."""
    gpo_guid = None
    cn = full.get("cn")
    if cn:
        try:
            gpo_guid = str(uuid.UUID(cn.strip("{}")))
        except (ValueError, AttributeError):
            gpo_guid = None
    return {
        "display_name": full.get("displayName"),
        "gpo_guid": gpo_guid,
        "version_number": _as_int(full.get("versionNumber")),
    }


def fgpp_typed_columns(full):
    return {
        "policy_name": full.get("cn"),
        "precedence": _as_int(full.get("msDS-PasswordSettingsPrecedence")),
        "min_pwd_length": _as_int(full.get("msDS-MinimumPasswordLength")),
        "pwd_complexity_enabled": str(full.get("msDS-PasswordComplexityEnabled")).upper() == "TRUE",
        "reversible_encryption_enabled": str(full.get("msDS-PasswordReversibleEncryptionEnabled")).upper() == "TRUE",
        "pwd_history_count": _as_int(full.get("msDS-PasswordHistoryLength")),
        "min_pwd_age_seconds": ad_interval_to_seconds(full.get("msDS-MinimumPasswordAge")),
        "max_pwd_age_seconds": ad_interval_to_seconds(full.get("msDS-MaximumPasswordAge")),
        "lockout_threshold": _as_int(full.get("msDS-LockoutThreshold")),
        "lockout_duration_seconds": ad_interval_to_seconds(full.get("msDS-LockoutDuration")),
        "lockout_observation_window_seconds": ad_interval_to_seconds(full.get("msDS-LockoutObservationWindow")),
    }


def cert_template_typed_columns(full):
    """[v0.1.0] enrollee_supplies_subject + client_authentication_capable
    together are the classic ESC1 data pattern -- flagged here as a data
    point for the auditor's own judgement. Full risk assessment also
    requires the template's enrollment ACL (who can actually request a
    certificate from it), which needs the same binary security-descriptor
    parsing already deferred for acl_edge -- not attempted here.

    [v0.1.2] Confirmed against real DC data and the original SpecterOps
    "Certified Pre-Owned" whitepaper: built-in CA-infrastructure templates
    (SubCA, CrossCA, CA, OfflineRouter) commonly match this exact flag
    pattern by default in every ADCS installation, but are frequently NOT
    published on any CA -- and an unpublished template cannot actually be
    requested by anyone regardless of its flags. is_enabled defaults to
    False here and is corrected by update_cert_template_enabled() after
    cross-referencing every Enterprise CA's certificateTemplates list,
    same non-SCD2-transition refresh pattern as member_count_direct."""
    name_flags = _as_int(full.get("msPKI-Certificate-Name-Flag")) or 0
    eku = full.get("pKIExtendedKeyUsage") or []
    if isinstance(eku, str):
        eku = [eku]
    client_auth = bool(set(eku) & CLIENT_AUTH_EKU_OIDS) or not eku
    cert_policy = full.get("msPKI-Certificate-Policy") or []
    if isinstance(cert_policy, str):
        cert_policy = [cert_policy]
    return {
        "template_name": full.get("cn"),
        "display_name": full.get("displayName"),
        "enrollment_flags": _as_int(full.get("msPKI-Enrollment-Flag")),
        "certificate_name_flags": name_flags,
        "enrollee_supplies_subject": bool(name_flags & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT),
        "extended_key_usage": eku or None,
        "client_authentication_capable": client_auth,
        "is_enabled": False,
        # [v0.5.4] certificate_policy_oids feeds ESC13 (cross-referenced
        # against ad_cert_oid.schema_cn); schema_version feeds ESC15/
        # "EKUwu" (the 2024-disclosed V1-template EKU-substitution
        # technique -- V1 templates are schema_version = 1).
        "certificate_policy_oids": json.dumps(list(cert_policy)) if cert_policy else None,
        "schema_version": _as_int(full.get("msPKI-Template-Schema-Version")),
    }


def enrollment_service_typed_columns(full):
    return {
        "ca_name": full.get("cn"),
        "dns_hostname": full.get("dNSHostName"),
    }


def ntauth_typed_columns(full):
    """[v0.5.3] Parses every certificate in cACertificate via the
    `cryptography` library -- the first genuine X.509 parsing this
    project does; every prior binary attribute (security descriptors)
    used hand-rolled parsing matching a Microsoft-documented binary
    layout this project already had reason to implement for ACL
    collection. X.509/DER is a different, more general format with no
    equivalent existing code to extend, and `cryptography` is the
    standard, well-maintained library for it -- writing a hand-rolled
    ASN.1/DER walker here would be reinventing something this library
    already does correctly, unlike the security descriptor parsing
    where no suitable library existed for that specific, narrower
    Microsoft-specific format.

    Deliberately tolerant of individual unparseable entries: a
    malformed or corrupt certificate value should surface as a finding
    (something is wrong with what's trusted for domain logon), not
    crash collection entirely. Each entry that fails to parse is kept
    with parse_error set and every other field None, rather than
    silently dropped -- its mere presence and inability to parse is
    itself informative.
    """
    certs_b64 = full.get("cACertificate") or []
    if isinstance(certs_b64, str):
        certs_b64 = [certs_b64]
    parsed_certs = []
    for cert_b64 in certs_b64:
        entry = {"parse_error": None, "subject_cn": None, "issuer_cn": None,
                  "not_valid_after": None, "serial_number": None, "thumbprint_sha1": None}
        try:
            der = base64.b64decode(cert_b64)
            cert = x509.load_der_x509_certificate(der)
            subj_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
            entry["subject_cn"] = subj_cn[0].value if subj_cn else None
            entry["issuer_cn"] = issuer_cn[0].value if issuer_cn else None
            entry["not_valid_after"] = cert.not_valid_after_utc.isoformat()
            entry["serial_number"] = format(cert.serial_number, "x")
            entry["thumbprint_sha1"] = cert.fingerprint(hashes.SHA1()).hex()
        except Exception as exc:
            entry["parse_error"] = str(exc)
        parsed_certs.append(entry)
    return {
        # [v0.5.3 fix] write_typed_row() is generic and passes values
        # through to psycopg2 unmodified -- it has no special handling
        # for JSONB columns, since every other typed column in this
        # project is a plain scalar. A raw Python list here fails with
        # "can't adapt type 'dict'" (psycopg2 has no default adapter
        # for arbitrary Python containers); json.dumps() first gives
        # psycopg2 a plain string, which PostgreSQL then assignment-
        # casts to jsonb automatically on INSERT -- confirmed via the
        # mock harness, not assumed.
        "certificates": json.dumps(parsed_certs),
        "certificate_count": len(parsed_certs),
    }


def site_typed_columns(full):
    return {"site_name": full.get("cn")}


def subnet_typed_columns(full):
    return {
        "subnet_name": full.get("cn"),
        "site_dn": full.get("siteObject"),
    }


def schema_java_typed_columns(full):
    """[v0.5.4] Java RFC 2713 extension check -- SCHEMA_JAVA_FILTER
    already narrows collection to just the Java-related attributeSchema
    objects, so every row this produces is, by construction, relevant.
    isDefunct is collected but not filtered on at the LDAP level (a
    defunct-but-still-present attribute is itself worth surfacing, not
    silently excluded)."""
    return {
        "schema_cn": full.get("cn"),
        "schema_object_type": "attributeSchema",
        "poss_superiors": None,
        "sub_class_of": None,
    }


def schema_posssuperior_typed_columns(full):
    """[v0.5.4] possSuperiors abuse check (the CVE-2021-34470 mechanism)
    -- collected broadly (every classSchema object) since possSuperiors
    is multi-valued and "contains computer or user" isn't a single
    server-side equality filter; the actual "is this dangerous"
    judgement (possSuperiors includes computer/user AND subClassOf is
    container) is left to the plugin querying this, matching this
    project's general collect-raw-filter-in-SQL preference."""
    poss_superiors = full.get("possSuperiors") or []
    if isinstance(poss_superiors, str):
        poss_superiors = [poss_superiors]
    return {
        "schema_cn": full.get("cn"),
        "schema_object_type": "classSchema",
        "poss_superiors": json.dumps(list(poss_superiors)) if poss_superiors else None,
        "sub_class_of": full.get("subClassOf"),
    }


def display_specifier_typed_columns(full):
    admin_context_menu = full.get("adminContextMenu") or []
    if isinstance(admin_context_menu, str):
        admin_context_menu = [admin_context_menu]
    return {
        "schema_cn": full.get("cn"),
        "admin_context_menu": json.dumps(list(admin_context_menu)) if admin_context_menu else None,
    }


def cert_oid_typed_columns(full):
    return {
        "schema_cn": full.get("cn"),
        "oid_to_group_link": full.get("msDS-OIDToGroupLink"),
    }


def dns_zone_typed_columns(full):
    """[v0.5.6, corrected] dNSProperty is deliberately NOT read through
    this function -- see the targeted raw_attributes read in main()
    for why. Discovered directly via testing, not assumed: the
    bulk-collection path's generic bytes-handling
    (normalize_value()) tries UTF-8 decoding first and only
    base64-encodes on a decode FAILURE, but dNSProperty's packed
    little-endian DWORDs are frequently small integers (0, 1, 2 for
    ZONE_UPDATE_*, for example) whose byte representation happens to be
    valid, if unprintable, UTF-8 -- meaning normalize_value's embedded-
    NUL-stripping (`.replace("\\x00", "")`, needed elsewhere for a
    genuine PostgreSQL limitation) silently corrupts the packed
    struct's byte alignment before this function would ever see it. A
    real construct-parse round-trip test caught this before it shipped
    -- allow_update ended up None for every zone until the read moved
    to raw_attributes."""
    return {
        "zone_name": full.get("name") or full.get("cn"),
    }


def _as_int(value):
    if value is None:
        return None
    if isinstance(value, list):
        value = value[0] if value else None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def update_group_member_count(pg_cur, object_guid, count):
    """[v0.0.10 fix] member_count_direct was hardcoded None -- the schema
    and an old code comment promised it would be "filled in during
    membership pass" but that step was never actually implemented, so
    every group showed NULL regardless of real membership size. This
    writes the true AD-reported direct member count (the length of the
    resolved `member` attribute, not just the count of members we
    successfully turned into edges) back onto the group's current row.
    Treated as a plain refresh of derived/denormalized data, not an SCD2
    version transition -- the authoritative membership history already
    lives in group_member_edge; this is just a fast-lookup summary kept
    fresh every run regardless of whether anything else about the group
    changed."""
    pg_cur.execute(
        "UPDATE ad_group SET member_count_direct = %s "
        "WHERE object_guid = %s AND valid_to IS NULL",
        (count, object_guid),
    )


def collect_group_membership(conn, pg_cur, client_id, run_id, base_dn,
                              page_size, dn_to_guid, group_entries, stats,
                              run_timestamp):
    log_info("Resolving group membership...")
    desired = {}
    valid_from = run_timestamp
    total_members_seen = 0

    for object_guid, full in group_entries:
        dn = full.get("distinguishedName")
        conn.search(dn, "(objectClass=*)", search_scope=ldap3.BASE,
                    attributes=["member"])
        if not conn.response:
            update_group_member_count(pg_cur, object_guid, 0)
            continue
        raw = conn.response[0]["raw_attributes"]
        first_values = raw.get("member", [])
        member_dns = resolve_ranged_attribute(conn, dn, "member", raw.keys(), first_values)
        update_group_member_count(pg_cur, object_guid, len(member_dns))

        for member_raw in member_dns:
            member_dn = member_raw.decode("utf-8") if isinstance(member_raw, bytes) else member_raw
            member_guid = dn_to_guid.get(member_dn.lower())
            total_members_seen += 1
            if member_guid is None:
                stats.skipped_unresolved_members += 1
                continue
            if member_guid == object_guid:
                continue
            desired[(object_guid, member_guid)] = {"is_direct": True}

    opened, closed = sync_edges(
        pg_cur, "group_member_edge", client_id, run_id, valid_from,
        ["group_guid", "member_guid"], desired,
    )
    stats.edges_opened += opened
    stats.edges_closed += closed
    log_success(f"Group membership: {total_members_seen} member reference(s) seen, "
                f"{opened} edge(s) opened, {closed} closed, "
                f"{stats.skipped_unresolved_members} unresolved (not a collected object)")


def collect_fgpp_applies_to(conn, pg_cur, client_id, run_id, dn_to_guid,
                             fgpp_entries, stats, run_timestamp):
    """
    [v0.1.0] Resolves each FGPP's msDS-PSOAppliesTo (a multi-valued DN
    list of users/groups the policy applies to) into fgpp_applies_to_edge
    rows. Same reconciliation pattern as collect_group_membership, minus
    the nested/is_direct distinction FGPP application doesn't have.
    """
    log_info("Resolving Fine-Grained Password Policy assignments...")
    desired = {}
    unresolved = 0

    for object_guid, full in fgpp_entries:
        applies_to = full.get("msDS-PSOAppliesTo") or []
        if isinstance(applies_to, str):
            applies_to = [applies_to]
        for target_dn in applies_to:
            target_guid = dn_to_guid.get(target_dn.lower())
            if target_guid is None:
                unresolved += 1
                continue
            desired[(object_guid, target_guid)] = {}

    opened, closed = sync_edges(
        pg_cur, "fgpp_applies_to_edge", client_id, run_id, run_timestamp,
        ["pso_guid", "target_guid"], desired,
    )
    stats.edges_opened += opened
    stats.edges_closed += closed
    log_success(f"FGPP assignments: {opened} edge(s) opened, {closed} closed, "
                f"{unresolved} unresolved (target outside this version's collection scope)")


GPLINK_ENTRY_RE = re.compile(r"\[LDAP://([^;\]]+);(\d+)\]")


def parse_gplink(gplink_value):
    """[v0.5.0] gPLink format confirmed against Microsoft's own
    documentation (Group Policy scope in Windows) plus multiple
    independent cross-checks: a concatenated string of
    '[LDAP://<GPO container DN>;<link options>]' entries, IN ORDER --
    order is significant (Microsoft's own docs call it 'a sorted list',
    and it directly determines precedence when GPOs conflict). The
    trailing link-options integer is a 2-bit mask: bit 0 (value 1) =
    LINK_DISABLED, bit 1 (value 2) = LINK_ENFORCED -- confirmed against
    a DEF CON 33 presentation's own table AND an independently-written
    replication-monitoring article describing the same 0-3 range,
    cross-checked against each other rather than trusted from one
    source alone.

    Returns a list of (gpo_container_dn, link_enabled, link_enforced)
    tuples in gPLink's own order -- 1-based position in this list IS
    the precedence order, so no separate 'link_order' needs deriving;
    the caller just enumerates this list.
    """
    if not gplink_value:
        return []
    entries = []
    for dn, options_str in GPLINK_ENTRY_RE.findall(gplink_value):
        options = int(options_str)
        link_enabled = not bool(options & 0x1)
        link_enforced = bool(options & 0x2)
        entries.append((dn, link_enabled, link_enforced))
    return entries


def resolve_gpo_links(pg_cur, client_id, run_id, dn_to_guid, linkable_entries, stats, run_timestamp):
    """[v0.5.0] Resolves gPLink on every linkable container (the domain
    object plus every OU -- both carry gPLink; sites also can, but this
    project doesn't collect site objects) into gpo_link_edge rows. Same
    reconciliation pattern as collect_group_membership/
    collect_fgpp_applies_to: build the full desired-state dict, then one
    sync_edges call. link_order is the GPO's 1-based position within
    ITS OWN container's gPLink list (precedence within that container),
    not a global ordering across containers -- there's no such thing as
    global GPO link order in AD, precedence is evaluated per container
    during Group Policy processing.

    linkable_entries: list of (container_guid, full) tuples -- the
    domain's own entry plus every OU's, exactly as already collected by
    their respective collect_object_class() calls (attributes_full
    already has gPLink in it from OU_ATTRS/DOMAIN_ATTRS; no extra LDAP
    round-trip needed here).
    """
    log_info("Resolving GPO links (gPLink) across the domain and every OU...")
    desired = {}
    unresolved = 0

    for container_guid, full in linkable_entries:
        for order, (gpo_dn, link_enabled, link_enforced) in enumerate(
            parse_gplink(full.get("gPLink")), start=1
        ):
            gpo_guid = dn_to_guid.get(gpo_dn.lower())
            if gpo_guid is None:
                unresolved += 1
                continue
            desired[(container_guid, gpo_guid)] = {
                "link_order": order,
                "link_enabled": link_enabled,
                "link_enforced": link_enforced,
            }

    opened, closed = sync_edges(
        pg_cur, "gpo_link_edge", client_id, run_id, run_timestamp,
        ["container_guid", "gpo_guid"], desired,
    )
    stats.edges_opened += opened
    stats.edges_closed += closed
    log_success(f"GPO links: {opened} edge(s) opened, {closed} closed, "
                f"{unresolved} unresolved (linked GPO not found in this run's collection)")


def update_cert_template_enabled(pg_cur, object_guid, is_enabled):
    """[v0.1.2] Refreshes ad_cert_template.is_enabled on the template's
    current row -- same non-SCD2-transition pattern as
    update_group_member_count()."""
    pg_cur.execute(
        "UPDATE ad_cert_template SET is_enabled = %s "
        "WHERE object_guid = %s AND valid_to IS NULL",
        (is_enabled, object_guid),
    )


def collect_cert_template_publication(pg_cur, client_id, run_id, ca_entries,
                                       cert_template_entries, stats, run_timestamp):
    """
    [v0.1.2] Cross-references each Enterprise CA's certificateTemplates
    attribute (a plain list of template NAMES, not DNs or GUIDs) against
    the templates this run collected, to determine which templates are
    actually published/requestable -- confirmed via the original
    SpecterOps "Certified Pre-Owned" whitepaper and Certipy's own
    -enabled flag as a documented precondition for ESC1-class
    exploitability, separate from (and in addition to) the template's own
    flags. Writes cert_template_enabled_edge rows and refreshes each
    template's is_enabled convenience flag.
    """
    log_info("Resolving certificate template publication (which CAs enable which templates)...")
    name_to_guid = {}
    for object_guid, full in cert_template_entries:
        name = full.get("cn")
        if name:
            name_to_guid[name.lower()] = object_guid

    desired = {}
    enabled_guids = set()
    unresolved = 0
    for ca_guid, full in ca_entries:
        templates = full.get("certificateTemplates") or []
        if isinstance(templates, str):
            templates = [templates]
        for template_name in templates:
            template_guid = name_to_guid.get(template_name.lower())
            if template_guid is None:
                unresolved += 1
                continue
            desired[(ca_guid, template_guid)] = {}
            enabled_guids.add(template_guid)

    opened, closed = sync_edges(
        pg_cur, "cert_template_enabled_edge", client_id, run_id, run_timestamp,
        ["ca_guid", "template_guid"], desired,
    )
    stats.edges_opened += opened
    stats.edges_closed += closed

    for object_guid, _full in cert_template_entries:
        update_cert_template_enabled(pg_cur, object_guid, object_guid in enabled_guids)

    log_success(f"Certificate template publication: {opened} edge(s) opened, {closed} closed, "
                f"{len(enabled_guids)} of {len(cert_template_entries)} template(s) enabled on a CA, "
                f"{unresolved} unresolved (template name not found in this run's collection)")


def build_spn_to_guid(entries):
    mapping = {}
    for object_guid, full in entries:
        spns = full.get("servicePrincipalName") or []
        if isinstance(spns, str):
            spns = [spns]
        for spn in spns:
            mapping.setdefault(spn.lower(), object_guid)
    return mapping


def collect_spn_edges(pg_cur, client_id, run_id, entries, stats, run_timestamp):
    valid_from = run_timestamp
    desired = {}
    for object_guid, full in entries:
        spns = full.get("servicePrincipalName") or []
        if isinstance(spns, str):
            spns = [spns]
        for spn in spns:
            desired[(object_guid, spn)] = {}
    opened, closed = sync_edges(
        pg_cur, "spn_edge", client_id, run_id, valid_from,
        ["object_guid", "spn"], desired,
    )
    stats.edges_opened += opened
    stats.edges_closed += closed
    log_success(f"SPNs: {len(desired)} active, {opened} edge(s) opened, {closed} closed")


def collect_delegation_edges(pg_cur, client_id, run_id, entries, spn_to_guid, stats, run_timestamp):
    valid_from = run_timestamp
    desired = {}
    unresolved = 0
    rbcd_unresolved_trustees = 0
    # [v0.5.4] "Ghost SPN" tracking (Purple Knight-inspired): every
    # msDS-AllowedToDelegateTo entry that doesn't resolve to a known
    # object gets recorded here instead of just incrementing the
    # `unresolved` counter and being discarded -- a pre-staged or
    # decommissioned delegation target an attacker could exploit by
    # registering a matching SPN themselves. Keyed by (source_guid,
    # target_spn) -- unlike delegation_edge's own key, this can safely
    # include the raw SPN text since there's no FK/check-constraint
    # concern for this dedicated table (see this migration's own
    # header comment on why delegation_edge itself couldn't represent
    # this).
    ghost_spn_desired = {}

    # [v0.3.0] SID->GUID lookup for resolving RBCD trustees. Built once
    # per call rather than per-entry -- RBCD trustees are arbitrary
    # principals (typically another computer, sometimes a user), and
    # there's no existing DN-based lookup (like spn_to_guid) that already
    # covers this the way it does for constrained-delegation targets.
    pg_cur.execute(
        "SELECT object_sid, object_guid FROM directory_object "
        "WHERE client_id = %s AND object_sid IS NOT NULL",
        (client_id,),
    )
    sid_to_guid = dict(pg_cur.fetchall())

    for object_guid, full in entries:
        uac = int(full.get("userAccountControl") or 0)
        if uac & UAC_TRUSTED_FOR_DELEGATION:
            desired[(object_guid, None, "unconstrained")] = {}

        allowed_to = full.get("msDS-AllowedToDelegateTo") or []
        if isinstance(allowed_to, str):
            allowed_to = [allowed_to]
        for target_spn in allowed_to:
            target_guid = spn_to_guid.get(target_spn.lower())
            if target_guid is None:
                unresolved += 1
                ghost_spn_desired[(object_guid, target_spn)] = {}
                continue
            desired[(object_guid, target_guid, "constrained")] = {}

        # RBCD: msDS-AllowedToActOnBehalfOfOtherIdentity is itself a full
        # security descriptor (same format as nTSecurityDescriptor) whose
        # DACL lists every principal permitted to act on behalf of this
        # computer. Each trustee SID in that DACL becomes its own
        # delegation_edge row; source_guid=trustee (matches "source CAN
        # delegate" reading already used for the other two types),
        # target_guid=this computer (the resource whose attribute grants
        # it). access_mask/ace_type are not meaningful for this
        # attribute's conventional usage -- what matters is trustee
        # presence in the DACL, not a specific rights value.
        raw_rbcd_b64 = full.get("msDS-AllowedToActOnBehalfOfOtherIdentity")
        if raw_rbcd_b64:
            raw_rbcd_sd = base64.b64decode(raw_rbcd_b64)
            _, rbcd_aces = parse_security_descriptor(raw_rbcd_sd)
            for ace in rbcd_aces:
                trustee_guid = sid_to_guid.get(ace["trustee_sid"])
                if trustee_guid is None:
                    rbcd_unresolved_trustees += 1
                    continue
                desired[(trustee_guid, object_guid, "rbcd")] = {}

    opened, closed = sync_edges(
        pg_cur, "delegation_edge", client_id, run_id, valid_from,
        ["source_guid", "target_guid", "delegation_type"], desired,
    )
    stats.edges_opened += opened
    stats.edges_closed += closed
    stats.skipped_unresolved_delegation_targets += unresolved

    ghost_opened, ghost_closed = sync_edges(
        pg_cur, "unresolved_delegation_target_edge", client_id, run_id, valid_from,
        ["source_guid", "target_spn"], ghost_spn_desired,
    )

    log_success(f"Delegation: {opened} edge(s) opened, {closed} closed, "
                f"{unresolved} constrained target(s) unresolved "
                f"({ghost_opened} ghost-SPN edge(s) opened, {ghost_closed} closed), "
                f"{rbcd_unresolved_trustees} RBCD trustee(s) unresolved "
                "(not a collected object)")


def resolve_gmsa_password_readers(pg_cur, client_id, run_id, computer_entries, stats, run_timestamp):
    """[v0.5.1] gMSA (Group Managed Service Account) objects are a schema
    subclass of computer (confirmed against Microsoft's own [MS-ADSC]
    specification: msDS-GroupManagedServiceAccount's subClassOf is
    computer) -- meaning they already come through the existing
    "(objectClass=computer)" collection pass via LDAP's hierarchical
    objectClass matching, with no separate object-class collection
    needed. Only the msDS-GroupMSAMembership attribute itself needed
    adding.

    That attribute is, like RBCD's msDS-AllowedToActOnBehalfOfOtherIdentity,
    a full security descriptor reused for a different purpose here: its
    DACL lists every principal permitted to retrieve this gMSA's
    computed password (confirmed against multiple independent sources
    describing the same mechanism, cross-checked against each other).
    Same parsing approach as RBCD -- decode the base64 stored by
    build_attributes_full's special case, parse via the same
    parse_security_descriptor() already proven against real ACL data --
    but written to its own dedicated table (gmsa_password_reader_edge)
    rather than reused into acl_edge or delegation_edge: a gMSA's
    password-reader list is a different KIND of relationship than
    either "who can modify this object" (acl_edge) or "who can
    authenticate as this identity via delegation" (delegation_edge),
    even though the underlying binary format happens to be identical --
    conflating them into an existing table would make plugins written
    against that table silently, incorrectly pick up gMSA password
    readers as if they were something else entirely.
    """
    valid_from = run_timestamp
    desired = {}
    unresolved_trustees = 0
    gmsa_count = 0

    sids = [full.get("objectSid") for _, full in computer_entries if full.get("objectSid")]
    pg_cur.execute(
        "SELECT object_sid, object_guid FROM directory_object WHERE client_id = %s AND object_sid = ANY(%s);",
        (client_id, sids),
    )
    sid_to_guid = dict(pg_cur.fetchall())

    for object_guid, full in computer_entries:
        raw_membership_b64 = full.get("msDS-GroupMSAMembership")
        if not raw_membership_b64:
            continue
        gmsa_count += 1
        raw_membership_sd = base64.b64decode(raw_membership_b64)
        _, membership_aces = parse_security_descriptor(raw_membership_sd)
        for ace in membership_aces:
            trustee_guid = sid_to_guid.get(ace["trustee_sid"])
            desired[(object_guid, ace["trustee_sid"])] = {
                "access_mask": ace["access_mask"],
                "ace_type": ace["ace_type"],
            }
            if trustee_guid is None:
                unresolved_trustees += 1

    opened, closed = sync_edges(
        pg_cur, "gmsa_password_reader_edge", client_id, run_id, valid_from,
        ["gmsa_guid", "trustee_sid"], desired,
    )
    stats.edges_opened += opened
    stats.edges_closed += closed
    log_success(f"gMSA password readers: {gmsa_count} gMSA(s) found, {opened} edge(s) opened, "
                f"{closed} closed, {unresolved_trustees} trustee(s) not a collected object "
                "(still recorded by SID)")


def close_typed_row_if_open(pg_cur, object_guid, valid_to):
    """[v0.2.0] Closes whichever typed table (if any) has an open row for
    this object_guid, checked directly across every table in
    KNOWN_TYPED_TABLES rather than inferred from object_class.

    Deliberately NOT keyed by object_class: label_to_object_class() maps
    both FGPPs and enrollment services to the generic 'other' value,
    which is also shared by OUs, containers, and DNS records --
    genuinely ambiguous, and unsafe to use as a lookup key. An object can
    only ever have an open row in at most one typed table regardless of
    how its object_class was recorded, so checking every table directly
    is both simpler and correct for every case, including the two that
    object_class-based lookup could never have covered.
    """
    for typed_table in KNOWN_TYPED_TABLES:
        pg_cur.execute(
            sql.SQL("UPDATE {} SET valid_to = %s WHERE object_guid = %s AND valid_to IS NULL")
               .format(sql.Identifier(typed_table)),
            (valid_to, object_guid),
        )
        if pg_cur.rowcount > 0:
            return typed_table
    return None


def collect_deleted_objects(conn, pg_cur, client_id, run_id, dc_host, base_dn,
                             prior_watermark_usn, stats, run_timestamp):
    """[v0.1.8 fix] Previously only marked directory_object.is_deleted and
    wrote a synthetic 'deleted' row to the generic directory_object_version
    history table -- the TYPED table (ad_user, ad_computer, etc.) was never
    closed. Since every plugin queries the typed table directly with
    WHERE valid_to IS NULL to determine current state, a deleted object's
    typed row stayed open forever regardless of the actual AD deletion,
    meaning every plugin kept flagging it indefinitely. Confirmed against
    a real case: two computer accounts (WANDERER, RANGER) deleted via
    ADUC continued showing up in every finding across a subsequent
    adaudit.py run, with zero indication anything had changed, because
    ad_computer's row for both was never closed. Now closes the matching
    typed table row (looked up via the object's own object_class) in the
    same pass, immediately after marking it deleted."""
    if prior_watermark_usn is None:
        return

    log_info("Checking for deleted objects since last successful run...")
    deleted_container = f"CN=Deleted Objects,{base_dn}"
    search_filter = f"(&(isDeleted=TRUE)(uSNChanged>={prior_watermark_usn}))"
    count = 0
    try:
        for dn, attributes, raw_attributes in ldap_paged_search(
            conn, deleted_container, search_filter,
            ["objectGUID", "lastKnownParent", "uSNChanged"], 1000,
            controls=[(LDAP_CONTROL_SHOW_DELETED, True, None)],
        ):
            raw_guid = raw_attributes.get("objectGUID")
            object_guid = guid_bytes_to_str(raw_guid[0]) if raw_guid else None
            if not object_guid:
                continue
            pg_cur.execute(
                """
                UPDATE directory_object
                   SET is_deleted = TRUE,
                       deleted_run_id = %s,
                       deleted_detected_at = %s
                 WHERE object_guid = %s AND client_id = %s AND NOT is_deleted
                RETURNING object_guid;
                """,
                (run_id, run_timestamp, object_guid, client_id),
            )
            row = pg_cur.fetchone()
            if row is not None:
                write_object_version(
                    pg_cur, object_guid, client_id, run_id, dc_host,
                    "deleted", {"isDeleted": True}, {"isDeleted": True}, run_timestamp,
                )
                close_typed_row_if_open(pg_cur, object_guid, run_timestamp)
                count += 1
                stats.deleted += 1
    except LDAPException as exc:
        log_warn(f"Deleted-object search failed unexpectedly: {exc}")

    log_success(f"Deleted objects: {count} newly marked deleted")


def repair_orphaned_deleted_typed_rows(pg_cur, client_id, run_timestamp):
    """[v0.2.0] Self-healing reconciliation, run on EVERY invocation
    regardless of run_type -- not just a one-time fix for the v0.1.8 bug.

    Checks every typed table directly for any row belonging to an object
    already marked directory_object.is_deleted = TRUE, rather than
    inferring which single table to check from object_class. This
    matters for a second, independent reason beyond the original v0.1.8
    gap: label_to_object_class() maps both FGPPs and enrollment services
    to the generic 'other' class, which is also shared by OUs,
    containers, and DNS records -- an object_class-keyed lookup could
    never have correctly closed ad_fgpp or ad_enrollment_service rows,
    regardless of which collector version detected the deletion. Checking
    every table directly sidesteps that ambiguity entirely.

    The v0.1.8 gap itself: an object already marked is_deleted=TRUE by an
    earlier run (in particular, any run using the pre-v0.1.8 collector)
    without its typed row ever being closed becomes permanently invisible
    to collect_deleted_objects()'s own USN-watermark filter -- the
    deletion isn't "new" relative to any future run, since an earlier run
    already consumed and advanced past it. Nothing else would ever
    revisit it again without this separate, independent check.

    Confirmed against a real case: two computer accounts deleted via
    ADUC were correctly marked is_deleted=TRUE by an earlier run, but
    remained permanently visible to every adaudit.py plugin because
    ad_computer's row for both was never closed.
    """
    repaired = 0
    for typed_table in KNOWN_TYPED_TABLES:
        pg_cur.execute(
            sql.SQL("""
                UPDATE {} t SET valid_to = %s
                FROM directory_object do2
                WHERE do2.object_guid = t.object_guid AND do2.client_id = %s
                  AND do2.is_deleted AND t.valid_to IS NULL;
            """).format(sql.Identifier(typed_table)),
            (run_timestamp, client_id),
        )
        repaired += pg_cur.rowcount

    if repaired:
        log_warn(f"Repaired {repaired} object(s) marked deleted upstream whose typed table row "
                 f"was never closed (orphaned by the pre-v0.1.8 deletion bug, or any future "
                 f"equivalent gap this check exists to catch).")
    return repaired


def parse_args():
    """
    [v0.0.3 fix] --dc-host and --username were previously argparse
    required=True, which meant `adprofiler.py --version` failed with a
    usage error before main() ever got a chance to check args.version --
    argparse validates required arguments before returning. They are no
    longer marked required at the argparse level; main() checks for
    --version first, then validates their presence manually.
    """
    parser = argparse.ArgumentParser(
        description="adprofiler.py -- Active Directory Security & Compliance "
                    "Profiler (Collector), v" + VERSION,
    )
    parser.add_argument("--dc-host", default=None,
                         help="FQDN or IP of the target Domain Controller. "
                              "Required unless --version is given.")
    parser.add_argument("--username", default=None,
                         help="Bind account (UPN or DOMAIN\\user). "
                              "Required unless --version is given.")
    parser.add_argument("--password", default=None,
                         help="Bind password. If omitted, you will be prompted "
                              "securely (recommended).")
    parser.add_argument("--port", type=int, default=None,
                         help="LDAP port. Default: 389, or 636 if --ssl is set.")
    parser.add_argument("--ssl", action="store_true",
                         help="Use LDAPS (TLS) instead of plaintext LDAP.")
    parser.add_argument("--base-dn", default=None,
                         help="Override search base. Default: auto-discovered.")
    parser.add_argument("--page-size", type=int, default=1000,
                         help="LDAP paged-search page size. Default: 1000.")
    parser.add_argument("--full-rescan", action="store_true",
                         help="Force every object to get a fresh version + typed-columns "
                              "write this run, even if its raw AD attributes haven't "
                              "changed since the last run. Normally, an object whose "
                              "attributes are unchanged is left untouched -- which means "
                              "newly-added or newly-fixed derived columns (e.g. a schema/"
                              "collector upgrade that adds a new field) never backfill "
                              "onto existing, unchanged objects. Run this once after such "
                              "an upgrade to backfill; not needed for routine runs. "
                              "Recorded honestly as change_kind='rescanned', distinct from "
                              "'modified', since nothing in AD actually changed.")
    parser.add_argument("--version", action="store_true",
                         help="Print version and exit.")
    args = parser.parse_args()

    if not args.version and (not args.dc_host or not args.username):
        parser.error("the following arguments are required: --dc-host, --username")

    return args


def main():
    args = parse_args()

    if args.version:
        print(f"adprofiler.py version {VERSION}")
        sys.exit(0)

    log_header(f"adprofiler.py v{VERSION} -- AD Security & Compliance Collector")

    if args.password:
        log_warn("Password supplied via --password is visible in shell history "
                  "and process listings. Prefer omitting it and entering it "
                  "at the secure prompt.")
        password = args.password
    else:
        password = getpass.getpass(f"LDAP password for {args.username}: ")

    port = args.port or (636 if args.ssl else 389)

    start_time = datetime.now(timezone.utc)
    stats = CollectionStats(full_rescan=args.full_rescan)
    if args.full_rescan:
        log_warn("--full-rescan: every object will get a fresh version + typed-columns "
                  "write this run, regardless of whether its AD attributes changed. "
                  "This is expected to be slower and to write far more rows than a "
                  "normal run -- only intended for backfilling after a schema/collector "
                  "upgrade, not for routine use.")
    pg_conn = None
    run_id = None
    ldap_conn = None
    exit_code = 0

    try:
        ldap_conn = connect_ldap(args.dc_host, port, args.ssl, args.username, password)
        if ldap_conn is None:
            log_error("Cannot proceed without a successful LDAP bind. Exiting.")
            raise CollectorAbort("LDAP bind failed")

        rootdse = get_rootdse_info(ldap_conn, args.base_dn)
        base_dn = rootdse["base_dn"]
        log_info(f"Search base: {base_dn}")
        log_info(f"Current DC highestCommittedUSN: {rootdse['highest_committed_usn']}")

        domain_sid, tombstone_lifetime, tombstone_lifetime_is_default, dsheuristics_anonymous_access = get_domain_sid_and_tombstone_lifetime(
            ldap_conn, base_dn, rootdse["config_nc"]
        )

        log_header("Capability Probe")
        probe_results = run_capability_probe(ldap_conn, base_dn)
        all_passed = True
        for check, result in probe_results.items():
            if result["passed"]:
                log_success(f"{check}: {result['detail']}")
            else:
                log_error(f"{check}: {result['detail']}")
                all_passed = False

        pg_conn = connect_postgres()

        schema_problems = validate_schema(pg_conn)
        if schema_problems:
            log_error(f"Database schema is not compatible with this version "
                      f"({len(schema_problems)} problem(s)):")
            for problem in schema_problems:
                log_error(f"  - {problem}")
            log_error(
                "This is very likely just a missing incremental schema "
                "migration, not a fresh-install situation -- do NOT run "
                "schema_init.sql against a database that already has data "
                "in it (it does plain CREATE TABLE with no IF NOT EXISTS "
                "guards, and can fail or, worse, leave things in a mixed "
                "state). Apply the schema_migration_vNN.sql file(s) that "
                "add whatever's listed as missing above -- check the "
                "migration files' own descriptions/comments to find the "
                "right one(s) for what's actually absent, and apply them "
                "in order if you're behind by more than one. "
                "schema_init.sql is only for a genuinely brand-new, empty "
                "database. Aborting."
            )
            raise CollectorAbort("Schema validation failed")
        log_success("Database schema validated.")

        client_id = upsert_client(pg_conn, base_dn_to_fqdn(base_dn), domain_sid, tombstone_lifetime)

        with pg_conn.cursor() as cur:
            cur.execute(
                "SELECT high_watermark_usn FROM sync_run "
                "WHERE client_id = %s AND status = 'succeeded' "
                "ORDER BY completed_at DESC LIMIT 1;",
                (client_id,),
            )
            row = cur.fetchone()
        prior_watermark = row[0] if row else None
        run_type = "delta" if prior_watermark is not None else "baseline"
        log_info(f"Run type: {run_type}"
                 + (f" (prior watermark USN: {prior_watermark})" if prior_watermark else ""))

        run_id = create_sync_run(
            pg_conn, client_id, args.dc_host, base_dn, run_type,
            prior_watermark, probe_results,
        )
        log_info(f"sync_run row created: run_id={run_id}")

        if not all_passed:
            reason = "Capability probe failed: " + "; ".join(
                f"{k}: {v['detail']}" for k, v in probe_results.items() if not v["passed"]
            )
            log_error("One or more required capabilities are missing. "
                      "Aborting -- no data will be collected. See PERMISSIONS.md.")
            finalize_sync_run(pg_conn, run_id, "failed", failure_reason=reason,
                               failure_detail=probe_results)
            raise CollectorAbort("Capability probe failed")

        log_header("Collecting Directory Data")
        dn_to_guid = {}
        # [v0.0.6] Single timestamp shared by every row this run writes.
        # See collect_object_class()'s docstring for why this replaced
        # per-object AD whenChanged timestamps as valid_from.
        run_timestamp = datetime.now(timezone.utc)

        # [v0.1.1] Detect which LAPS variant(s), if any, this forest's
        # schema actually defines, before ever including either attribute
        # name in a search. See ldap_attribute_exists()'s docstring for why
        # this can't just be a static attribute list like everything else.
        laps_legacy_present = ldap_attribute_exists(ldap_conn, rootdse["config_nc"], LAPS_LEGACY_ATTR)
        laps_modern_present = ldap_attribute_exists(ldap_conn, rootdse["config_nc"], LAPS_MODERN_ATTR)
        computer_attrs = list(COMPUTER_ATTRS)
        if laps_legacy_present:
            computer_attrs.append(LAPS_LEGACY_ATTR)
        if laps_modern_present:
            computer_attrs.append(LAPS_MODERN_ATTR)
        laps_detected = ", ".join(filter(None, [
            "legacy" if laps_legacy_present else None,
            "modern" if laps_modern_present else None,
        ]))
        log_info(f"LAPS schema detected: {laps_detected or 'none (LAPS schema extension not present on this forest)'}")

        with pg_conn.cursor() as cur:
            user_filter = "(&(objectClass=user)(objectCategory=person))"
            users = collect_object_class(
                ldap_conn, cur, client_id, run_id, args.dc_host, base_dn,
                user_filter, USER_ATTRS, args.page_size, "users",
                "ad_user", user_typed_columns, dn_to_guid, stats, run_timestamp,
            )

            computers = collect_object_class(
                ldap_conn, cur, client_id, run_id, args.dc_host, base_dn,
                "(objectClass=computer)", computer_attrs, args.page_size,
                "computers", "ad_computer", computer_typed_columns,
                dn_to_guid, stats, run_timestamp,
            )

            groups = collect_object_class(
                ldap_conn, cur, client_id, run_id, args.dc_host, base_dn,
                "(objectClass=group)", GROUP_ATTRS, args.page_size,
                "groups", "ad_group", group_typed_columns, dn_to_guid, stats,
                run_timestamp,
            )

            # [v0.2.5] Must run before collect_group_membership(), not just
            # "somewhere in collection" -- well-known SIDs (Everyone,
            # Anonymous Logon) referenced as group members only resolve
            # correctly if their foreignSecurityPrincipal GUID is already
            # in dn_to_guid by the time membership resolution runs. An
            # earlier version of this placed FSP collection after trusts,
            # which is AFTER collect_group_membership() -- caught before
            # shipping by checking the actual call sequence, not assumed.
            try:
                fsp_container = f"CN=ForeignSecurityPrincipals,{base_dn}"
                collect_object_class(
                    ldap_conn, cur, client_id, run_id, args.dc_host, fsp_container,
                    "(objectClass=foreignSecurityPrincipal)", FSP_ATTRS, args.page_size,
                    "foreign security principals", "ad_foreign_security_principal",
                    foreign_security_principal_typed_columns, dn_to_guid, stats, run_timestamp,
                )
            except LDAPException as exc:
                log_warn(f"Foreign security principal collection failed (non-fatal): {exc}")

            # [v0.5.4] FRS-vs-DFSR SYSVOL migration state -- a single,
            # well-known object, read the same targeted way
            # NTAuthCertificates already is (BASE-scope search for one
            # specific DN, not part of the bulk domain-object collection
            # since msDFSR-Flags lives on a completely different object).
            # Confirmed via multiple independent sources before building:
            # value 48 means fully migrated to DFSR (FRS retired);
            # NULL/0/16/32 means still on FRS or mid-migration.
            dfsr_globalsettings_dn = f"CN=DFSR-GlobalSettings,CN=System,{base_dn}"
            dfsr_migration_flags = None
            try:
                ldap_conn.search(
                    dfsr_globalsettings_dn, "(objectClass=*)", search_scope=ldap3.BASE,
                    attributes=["msDFSR-Flags"],
                )
                if ldap_conn.response:
                    raw_flags = ldap_conn.response[0]["raw_attributes"].get("msDFSR-Flags")
                    if raw_flags:
                        dfsr_migration_flags = int(raw_flags[0])
            except LDAPException as exc:
                log_warn(f"Could not read DFSR-GlobalSettings (non-fatal): {exc}")

            domain_entries = collect_object_class(
                ldap_conn, cur, client_id, run_id, args.dc_host, base_dn,
                "(objectClass=domain)", DOMAIN_ATTRS, args.page_size,
                "domain", "ad_domain",
                lambda full: domain_typed_columns(
                    full, rootdse.get("domain_functionality"), tombstone_lifetime,
                    tombstone_lifetime_is_default, laps_legacy_present or laps_modern_present,
                    dsheuristics_anonymous_access, dfsr_migration_flags,
                ),
                dn_to_guid, stats, run_timestamp,
            )

            # [v0.5.0] Organizational Units -- same full typed-table
            # treatment as every other object class, not a one-off
            # stand-in the way AdminSDHolder's is (see
            # collect_well_known_container_acl's own docstring for why
            # THAT function exists: it was written specifically for
            # objects this collector otherwise never touches. OUs are
            # no longer in that category once this call exists.)
            try:
                ou_entries = collect_object_class(
                    ldap_conn, cur, client_id, run_id, args.dc_host, base_dn,
                    OU_FILTER, OU_ATTRS, args.page_size, "OUs",
                    "ad_ou", ou_typed_columns, dn_to_guid, stats, run_timestamp,
                )
            except LDAPException as exc:
                log_warn(f"OU collection failed (non-fatal): {exc}")
                ou_entries = []

            # [v0.3.0] ACL collection. Domain root first (DCSync rights --
            # who besides Domain Admins/Enterprise Admins/DCs can
            # replicate secrets), then AdminSDHolder (its ACL is the
            # template SDProp pushes onto every protected object, so a
            # bad grant here propagates broadly). Both use the same
            # SD Flags control technique (0x07, Owner+Group+DACL, no
            # SACL) already proven working by the capability probe.
            # [v0.5.0] Extended to every OU -- OU delegation (who can
            # create/modify/delete objects within it) is one of the
            # more common real-world privilege-escalation paths this
            # project had no visibility into before. Still NOT extended
            # to per-user/computer/group ACLs, GPO ACLs, or cert
            # template ACLs -- see CHANGELOG.
            #
            # Every object's ACEs are merged into ONE combined dict and
            # synced in a SINGLE sync_edges call at the end -- not one
            # call per object. get_open_edges() compares against every
            # currently-open acl_edge row for the entire client, not
            # just one object, matching how every other edge table in
            # this project is synced (one comprehensive call per run).
            # An earlier version of this called sync_edges once per
            # object; confirmed via direct reproduction that this
            # incorrectly closed every other already-scanned object's
            # ACEs on each subsequent call.
            acl_desired = {}
            domain_root_guid = dn_to_guid.get(base_dn.lower())
            if domain_root_guid:
                raw_domain_sd = get_object_security_descriptor(ldap_conn, base_dn)
                _, domain_owner_sid = build_acl_desired_edges(
                    domain_root_guid, raw_domain_sd, "domain root", acl_desired,
                )
                if domain_owner_sid:
                    cur.execute(
                        "UPDATE directory_object SET owner_sid = %s WHERE object_guid = %s AND client_id = %s",
                        (domain_owner_sid, domain_root_guid, client_id),
                    )
            else:
                log_warn("Domain root object_guid not resolved -- skipping its ACL collection.")

            adminsdholder_dn = f"CN=AdminSDHolder,CN=System,{base_dn}"
            collect_well_known_container_acl(
                ldap_conn, cur, client_id, run_id, adminsdholder_dn,
                "AdminSDHolder", run_timestamp, acl_desired,
            )

            ou_acl_read_failures = 0
            for ou_guid, ou_full in ou_entries:
                ou_dn = ou_full.get("distinguishedName")
                if not ou_dn:
                    continue
                raw_ou_sd = get_object_security_descriptor(ldap_conn, ou_dn)
                ok, ou_owner_sid = build_acl_desired_edges(
                    ou_guid, raw_ou_sd, ou_dn, acl_desired,
                )
                if not ok:
                    ou_acl_read_failures += 1
                    continue
                if ou_owner_sid:
                    cur.execute(
                        "UPDATE directory_object SET owner_sid = %s WHERE object_guid = %s AND client_id = %s",
                        (ou_owner_sid, ou_guid, client_id),
                    )

            # [v0.5.5] Domain controller computer-object ownership. Not
            # part of the bulk computer collection (COMPUTER_ATTRS
            # deliberately excludes nTSecurityDescriptor, matching the
            # established "SD reads are targeted, not bulk" pattern),
            # so scanned here separately -- there are only ever a
            # handful of DCs, the same low-cost profile as domain
            # root/AdminSDHolder above. Owner-only: reuses
            # build_acl_desired_edges() for its already-proven SD
            # parsing, but its ACE output is deliberately discarded
            # into a scratch dict rather than merged into acl_desired --
            # this is specifically about "who owns this DC's account,"
            # not a request to also start scanning DC computer-object
            # ACEs generally, which wasn't asked for and would add
            # LDAP read cost with no plugin currently using it.
            dc_owner_read_failures = 0
            for comp_guid, comp_full in computers:
                if not (int(comp_full.get("userAccountControl") or 0) & UAC_SERVER_TRUST_ACCOUNT):
                    continue
                comp_dn = comp_full.get("distinguishedName")
                if not comp_dn:
                    continue
                raw_dc_sd = get_object_security_descriptor(ldap_conn, comp_dn)
                _scratch_edges = {}
                ok, dc_owner_sid = build_acl_desired_edges(
                    comp_guid, raw_dc_sd, comp_dn, _scratch_edges,
                )
                if not ok:
                    dc_owner_read_failures += 1
                    continue
                if dc_owner_sid:
                    cur.execute(
                        "UPDATE directory_object SET owner_sid = %s WHERE object_guid = %s AND client_id = %s",
                        (dc_owner_sid, comp_guid, client_id),
                    )
            log_success(f"DC computer object ownership: scanned, "
                        f"{dc_owner_read_failures} read failure(s)")


            # [v0.5.4] The sync_edges("acl_edge", ...) call that used to sit
            # here was moved to AFTER the ADCS ACL collection section below --
            # cert templates, CA objects, and the PKI containers all need
            # their ACEs merged into this SAME acl_desired dict before the
            # single sync call, for exactly the reason documented on
            # build_acl_desired_edges() above: sync_edges/get_open_edges
            # compares against every currently-open acl_edge row for the
            # whole client, not a scoped subset, so a second, separate
            # sync_edges call here would have looked at the ADCS-object
            # ACEs (not yet accumulated at this point) as "no longer
            # present" and incorrectly closed the ADCS ones added later --
            # or the reverse, if ADCS ran first. One accumulation, one
            # sync, same discipline already proven necessary once this
            # session.

            collect_group_membership(
                ldap_conn, cur, client_id, run_id, base_dn, args.page_size,
                dn_to_guid, groups, stats, run_timestamp,
            )

            all_principals = users + computers
            spn_to_guid = build_spn_to_guid(all_principals)
            collect_spn_edges(cur, client_id, run_id, all_principals, stats, run_timestamp)
            collect_delegation_edges(cur, client_id, run_id, all_principals,
                                      spn_to_guid, stats, run_timestamp)
            resolve_gmsa_password_readers(cur, client_id, run_id, computers, stats, run_timestamp)

            # --- v0.1.0: trusts, GPOs, FGPP, ADCS templates -----------------
            # Each wrapped independently: none of these containers is
            # guaranteed to exist on every domain (FGPP and ADCS especially
            # are commonly never configured at all), and one missing/
            # inaccessible container shouldn't abort collection of
            # everything else. A failure here is logged as a warning, not
            # a hard-fail -- distinct from the LDAP capability probe, which
            # gates on rights we know we need; these are optional data
            # categories whose absence is itself a normal, common finding.
            try:
                collect_object_class(
                    ldap_conn, cur, client_id, run_id, args.dc_host, base_dn,
                    TRUST_FILTER, TRUST_ATTRS, args.page_size, "trusts",
                    "ad_trust", trust_typed_columns, dn_to_guid, stats, run_timestamp,
                )
            except LDAPException as exc:
                log_warn(f"Trust collection failed (non-fatal): {exc}")

            try:
                collect_object_class(
                    ldap_conn, cur, client_id, run_id, args.dc_host, base_dn,
                    GPO_FILTER, GPO_ATTRS, args.page_size, "GPOs",
                    "ad_gpo", gpo_typed_columns, dn_to_guid, stats, run_timestamp,
                )
            except LDAPException as exc:
                log_warn(f"GPO collection failed (non-fatal): {exc}")

            # [v0.5.0] Must run after GPO collection, not before -- gPLink
            # entries reference GPO container DNs, and dn_to_guid only
            # has an entry for a GPO once collect_object_class() has
            # actually processed it. An earlier version of this called
            # resolve_gpo_links() right after the OU ACL loop (logically
            # adjacent, since both are OU-related), which meant every
            # GPO reference came back unresolved -- caught by the mock
            # harness reporting "1 unresolved" against a scenario that
            # should have resolved cleanly, not by inspection.
            resolve_gpo_links(
                cur, client_id, run_id, dn_to_guid,
                domain_entries + ou_entries, stats, run_timestamp,
            )

            try:
                pso_container = f"CN=Password Settings Container,CN=System,{base_dn}"
                fgpp_entries = collect_object_class(
                    ldap_conn, cur, client_id, run_id, args.dc_host, pso_container,
                    FGPP_FILTER, FGPP_ATTRS, args.page_size, "FGPPs",
                    "ad_fgpp", fgpp_typed_columns, dn_to_guid, stats, run_timestamp,
                )
                collect_fgpp_applies_to(ldap_conn, cur, client_id, run_id,
                                         dn_to_guid, fgpp_entries, stats, run_timestamp)
            except LDAPException as exc:
                log_warn(f"Fine-Grained Password Policy collection failed (non-fatal): {exc}")

            try:
                cert_template_container = (
                    f"CN=Certificate Templates,CN=Public Key Services,"
                    f"CN=Services,{rootdse['config_nc']}"
                )
                cert_template_entries = collect_object_class(
                    ldap_conn, cur, client_id, run_id, args.dc_host, cert_template_container,
                    CERT_TEMPLATE_FILTER, CERT_TEMPLATE_ATTRS, args.page_size,
                    "certificate templates", "ad_cert_template",
                    cert_template_typed_columns, dn_to_guid, stats, run_timestamp,
                )

                enrollment_service_container = (
                    f"CN=Enrollment Services,CN=Public Key Services,"
                    f"CN=Services,{rootdse['config_nc']}"
                )
                ca_entries = collect_object_class(
                    ldap_conn, cur, client_id, run_id, args.dc_host, enrollment_service_container,
                    ENROLLMENT_SERVICE_FILTER, ENROLLMENT_SERVICE_ATTRS, args.page_size,
                    "enrollment services", "ad_enrollment_service",
                    enrollment_service_typed_columns, dn_to_guid, stats, run_timestamp,
                )

                collect_cert_template_publication(
                    cur, client_id, run_id, ca_entries, cert_template_entries,
                    stats, run_timestamp,
                )

                # [v0.5.3] NTAuthCertificates -- a single, well-known object,
                # not a class of many. base_dn is the object's own EXACT DN
                # (not the broader "Public Key Services" container), with a
                # broad "(objectClass=*)" filter -- LDAP subtree scope
                # includes the base object itself, so this returns exactly
                # the one object, matching the same targeted pattern already
                # used for AdminSDHolder rather than searching the entire
                # Public Key Services subtree (which also holds Certificate
                # Templates, Enrollment Services, AIA, CDP, KRA, OID) just
                # to find one specifically-named child.
                ntauth_dn = (
                    f"CN=NTAuthCertificates,CN=Public Key Services,"
                    f"CN=Services,{rootdse['config_nc']}"
                )
                collect_object_class(
                    ldap_conn, cur, client_id, run_id, args.dc_host, ntauth_dn,
                    NTAUTH_FILTER, NTAUTH_ATTRS, args.page_size,
                    "NTAuth store", "ad_ntauth_store",
                    ntauth_typed_columns, dn_to_guid, stats, run_timestamp,
                )

                # [v0.5.4] ADCS ACL collection -- ESC4 (a non-admin can
                # rewrite a certificate template into an ESC1-shaped one),
                # ESC5 (the same idea applied to the PKI infrastructure
                # objects the whole certificate ecosystem depends on: the
                # containers below, NTAuthCertificates, and each CA's own
                # computer object), and ESC7 (a non-admin holds ManageCA/
                # ManageCertificates on the CA's own AD object). All three
                # confirmed LDAP-native (not a CA-server registry/RPC
                # query, unlike ESC6/ESC16, which were checked and ruled
                # out as out of scope for this project's LDAP-only model)
                # before writing any of this.
                #
                # Merges into the SAME acl_desired dict already accumulating
                # domain root/AdminSDHolder/OU ACEs from earlier in this
                # function -- see the comment left at that dict's sync call
                # (now placed at the end of this block) for why a second,
                # separate sync_edges call here would be a real bug, not a
                # style choice.
                pki_container_base = f"CN=Public Key Services,CN=Services,{rootdse['config_nc']}"
                collect_well_known_container_acl(
                    ldap_conn, cur, client_id, run_id, pki_container_base,
                    "Public Key Services container", run_timestamp, acl_desired,
                )
                collect_well_known_container_acl(
                    ldap_conn, cur, client_id, run_id, cert_template_container,
                    "Certificate Templates container", run_timestamp, acl_desired,
                )
                collect_well_known_container_acl(
                    ldap_conn, cur, client_id, run_id, enrollment_service_container,
                    "Enrollment Services container", run_timestamp, acl_desired,
                )

                # NTAuthCertificates was already collected as a real object
                # a few lines up (unlike the three containers above, which
                # this collector never gathers as objects in their own
                # right) -- its object_guid is already in dn_to_guid, so
                # this reads and merges its ACL the same way the OU loop
                # already does for already-collected objects, not the
                # collect_well_known_container_acl path those containers
                # needed.
                ntauth_guid = dn_to_guid.get(ntauth_dn.lower())
                if ntauth_guid:
                    raw_ntauth_sd = get_object_security_descriptor(ldap_conn, ntauth_dn)
                    build_acl_desired_edges(
                        ntauth_guid, raw_ntauth_sd, "NTAuthCertificates", acl_desired,
                    )

                # ESC4: each individual certificate template's own ACL.
                cert_template_acl_failures = 0
                for template_guid, template_full in cert_template_entries:
                    template_dn = template_full.get("distinguishedName")
                    if not template_dn:
                        continue
                    raw_template_sd = get_object_security_descriptor(ldap_conn, template_dn)
                    ok, _ = build_acl_desired_edges(
                        template_guid, raw_template_sd, template_dn, acl_desired,
                    )
                    if not ok:
                        cert_template_acl_failures += 1

                # ESC7 (CA object ACL) and the CA-computer-object half of
                # ESC5, together, since both are per-CA and this project
                # already has the computers list in scope to cross-reference
                # dNSHostName against without a second LDAP round-trip.
                computers_by_dns_hostname = {
                    c_full.get("dNSHostName", "").lower(): c_guid
                    for c_guid, c_full in computers if c_full.get("dNSHostName")
                }
                ca_acl_failures = 0
                ca_computer_matches = 0
                for ca_guid, ca_full in ca_entries:
                    ca_dn = ca_full.get("distinguishedName")
                    if ca_dn:
                        raw_ca_sd = get_object_security_descriptor(ldap_conn, ca_dn)
                        ok, _ = build_acl_desired_edges(ca_guid, raw_ca_sd, ca_dn, acl_desired)
                        if not ok:
                            ca_acl_failures += 1

                    ca_hostname = (ca_full.get("dNSHostName") or "").lower()
                    ca_computer_guid = computers_by_dns_hostname.get(ca_hostname)
                    if ca_computer_guid:
                        ca_computer_matches += 1
                        computer_dn = next(
                            (c_full.get("distinguishedName") for c_guid, c_full in computers
                             if c_guid == ca_computer_guid), None,
                        )
                        if computer_dn:
                            raw_ca_computer_sd = get_object_security_descriptor(ldap_conn, computer_dn)
                            build_acl_desired_edges(
                                ca_computer_guid, raw_ca_computer_sd,
                                f"CA computer object ({ca_hostname})", acl_desired,
                            )

                log_success(
                    f"ADCS ACLs: {len(cert_template_entries)} template(s) scanned "
                    f"({cert_template_acl_failures} read failure(s)), {len(ca_entries)} CA "
                    f"object(s) scanned ({ca_acl_failures} read failure(s), "
                    f"{ca_computer_matches} matched to a computer object), Public Key "
                    f"Services/Certificate Templates/Enrollment Services containers and "
                    f"NTAuthCertificates included."
                )
            except LDAPException as exc:
                log_warn(f"Certificate template/enrollment service collection failed (non-fatal): {exc}")

            # [v0.5.4] Moved here from right after the OU ACL loop -- see
            # the comment left in that spot for why. acl_desired now holds
            # domain root + AdminSDHolder + every OU + (if ADCS collection
            # above succeeded) every cert template + every CA object +
            # every matched CA computer object + the three PKI containers +
            # NTAuthCertificates, all accumulated into one dict, synced
            # here exactly once.
            acl_opened, acl_closed = sync_edges(
                cur, "acl_edge", client_id, run_id, run_timestamp,
                ["object_guid", "trustee_sid", "ace_type", "access_mask", "object_type_guid"],
                acl_desired,
            )
            log_success(f"ACLs: {acl_opened} edge(s) opened, {acl_closed} closed "
                        f"(domain root + AdminSDHolder + {len(ou_entries)} OU(s) + "
                        f"ADCS objects, {ou_acl_read_failures} OU ACL read failure(s))")

            # --- v0.5.4: Sites/Subnets, schema objects, DisplaySpecifiers,
            # cert OIDs -- new gaps identified via this project's own
            # PingCastle/Purple Knight/Locksmith comparison. Each wrapped
            # independently, same reasoning as the trusts/GPO/FGPP/ADCS
            # block above: none of these are guaranteed to exist or be
            # reachable in every environment, and one failure shouldn't
            # abort collection of everything else.
            try:
                sites_container = f"CN=Sites,{rootdse['config_nc']}"
                collect_object_class(
                    ldap_conn, cur, client_id, run_id, args.dc_host, sites_container,
                    SITE_FILTER, SITE_ATTRS, args.page_size, "AD sites",
                    "ad_site", site_typed_columns, dn_to_guid, stats, run_timestamp,
                )
            except LDAPException as exc:
                log_warn(f"AD Sites collection failed (non-fatal): {exc}")

            try:
                subnets_container = f"CN=Subnets,CN=Sites,{rootdse['config_nc']}"
                collect_object_class(
                    ldap_conn, cur, client_id, run_id, args.dc_host, subnets_container,
                    SUBNET_FILTER, SUBNET_ATTRS, args.page_size, "AD subnets",
                    "ad_subnet", subnet_typed_columns, dn_to_guid, stats, run_timestamp,
                )
            except LDAPException as exc:
                log_warn(f"AD Subnets collection failed (non-fatal): {exc}")

            try:
                # Schema NC is always CN=Schema,<config_nc> -- a fixed AD
                # convention (confirmed against [MS-ADTS]), not a separate
                # RootDSE field this collector needs to look up.
                schema_nc = f"CN=Schema,{rootdse['config_nc']}"
                collect_object_class(
                    ldap_conn, cur, client_id, run_id, args.dc_host, schema_nc,
                    SCHEMA_JAVA_FILTER, SCHEMA_JAVA_ATTRS, args.page_size,
                    "schema (Java extension check)", "ad_schema_object",
                    schema_java_typed_columns, dn_to_guid, stats, run_timestamp,
                )
                collect_object_class(
                    ldap_conn, cur, client_id, run_id, args.dc_host, schema_nc,
                    SCHEMA_POSSSUPERIOR_FILTER, SCHEMA_POSSSUPERIOR_ATTRS, args.page_size,
                    "schema (possSuperiors check)", "ad_schema_object",
                    schema_posssuperior_typed_columns, dn_to_guid, stats, run_timestamp,
                )
            except LDAPException as exc:
                log_warn(f"Schema object collection failed (non-fatal): {exc}")

            try:
                display_specifiers_container = f"CN=DisplaySpecifiers,{rootdse['config_nc']}"
                collect_object_class(
                    ldap_conn, cur, client_id, run_id, args.dc_host, display_specifiers_container,
                    DISPLAY_SPECIFIER_FILTER, DISPLAY_SPECIFIER_ATTRS, args.page_size,
                    "DisplaySpecifiers", "ad_display_specifier",
                    display_specifier_typed_columns, dn_to_guid, stats, run_timestamp,
                )
            except LDAPException as exc:
                log_warn(f"DisplaySpecifier collection failed (non-fatal): {exc}")

            try:
                cert_oid_container = f"CN=OID,CN=Public Key Services,CN=Services,{rootdse['config_nc']}"
                collect_object_class(
                    ldap_conn, cur, client_id, run_id, args.dc_host, cert_oid_container,
                    CERT_OID_FILTER, CERT_OID_ATTRS, args.page_size,
                    "certificate OIDs", "ad_cert_oid",
                    cert_oid_typed_columns, dn_to_guid, stats, run_timestamp,
                )
            except LDAPException as exc:
                log_warn(f"Certificate OID collection failed (non-fatal): {exc}")

            try:
                # [v0.5.6] Domain-scoped AD-integrated DNS zones live in
                # their own application partition, not the domain NC or
                # Configuration NC anything else here queries -- see
                # DNS_ZONE_ATTRS's own comment for why this is
                # deliberately scoped to domain-scoped zones only, not
                # forest-scoped ones too.
                dns_zones_container = f"CN=MicrosoftDNS,DC=DomainDnsZones,{base_dn}"
                dns_zone_entries = collect_object_class(
                    ldap_conn, cur, client_id, run_id, args.dc_host, dns_zones_container,
                    DNS_ZONE_FILTER, DNS_ZONE_ATTRS, args.page_size,
                    "DNS zones", "ad_dns_zone",
                    dns_zone_typed_columns, dn_to_guid, stats, run_timestamp,
                )
                # [v0.5.6] dNSProperty is read separately, per zone, via
                # a targeted raw_attributes search -- NOT through the
                # bulk collect_object_class() path above, which routes
                # everything through normalize_value()'s generic
                # bytes-handling. That path silently corrupts this
                # specific attribute's packed binary structure (see
                # dns_zone_typed_columns's own docstring for the
                # mechanism, found via real testing, not assumed). Same
                # small-object-count, targeted-read pattern already
                # used for domain root/AdminSDHolder/DC ownership above.
                dns_property_read_failures = 0
                for zone_guid, zone_full in dns_zone_entries:
                    zone_dn = zone_full.get("distinguishedName")
                    if not zone_dn:
                        continue
                    try:
                        ldap_conn.search(zone_dn, "(objectClass=*)", search_scope=ldap3.BASE,
                                          attributes=["dNSProperty"])
                        if not ldap_conn.response:
                            dns_property_read_failures += 1
                            continue
                        raw_props = ldap_conn.response[0]["raw_attributes"].get("dNSProperty") or []
                        allow_update = parse_dns_zone_allow_update(raw_props)
                    except LDAPException as exc:
                        log_warn(f"Could not read dNSProperty for {zone_dn}: {exc}")
                        dns_property_read_failures += 1
                        continue
                    cur.execute(
                        "UPDATE ad_dns_zone SET allow_update = %s "
                        "WHERE object_guid = %s AND client_id = %s AND valid_to IS NULL",
                        (allow_update, zone_guid, client_id),
                    )
                log_success(f"DNS zone dynamic-update settings: {len(dns_zone_entries)} zone(s), "
                            f"{dns_property_read_failures} read failure(s)")
            except LDAPException as exc:
                log_warn(f"DNS zone collection failed (non-fatal, possibly no "
                          f"AD-integrated DNS zones or no DomainDnsZones partition): {exc}")

            if run_type == "delta":
                collect_deleted_objects(
                    ldap_conn, cur, client_id, run_id, args.dc_host, base_dn,
                    prior_watermark, stats, run_timestamp,
                )

            repair_orphaned_deleted_typed_rows(cur, client_id, run_timestamp)

        pg_conn.commit()
        finalize_sync_run(
            pg_conn, run_id, "succeeded",
            high_watermark_usn=rootdse["highest_committed_usn"],
            objects_seen=stats.seen,
            objects_changed=stats.created + stats.modified,
            objects_deleted=stats.deleted,
        )
        log_success("Transaction committed. Run completed successfully.")

    except KeyboardInterrupt:
        exit_code = 130
        log_warn("Aborting due to Ctrl-C...")
        if pg_conn is not None:
            try:
                pg_conn.rollback()
                log_info("Data transaction rolled back (no partial data committed).")
            except Exception as exc:
                log_error(f"Rollback failed: {exc}")
            if run_id is not None:
                try:
                    finalize_sync_run(pg_conn, run_id, "aborted",
                                       failure_reason="Interrupted by user (Ctrl-C).")
                except Exception as exc:
                    log_error(f"Could not finalize sync_run as aborted: {exc}")

    except CollectorAbort:
        # Already logged in detail at the point of failure (LDAP bind
        # message or capability-probe itemized report); sync_run has
        # already been finalized as 'failed' where applicable. Only need
        # to make sure the Run Summary reflects FAILED, not SUCCESS.
        exit_code = 1

    except Exception as exc:
        exit_code = 1
        log_error(f"Unexpected error: {exc}")
        if pg_conn is not None:
            try:
                pg_conn.rollback()
                log_info("Data transaction rolled back (no partial data committed).")
            except Exception as rb_exc:
                log_error(f"Rollback failed: {rb_exc}")
            if run_id is not None:
                try:
                    finalize_sync_run(pg_conn, run_id, "failed", failure_reason=str(exc))
                except Exception as fin_exc:
                    log_error(f"Could not finalize sync_run as failed: {fin_exc}")

    finally:
        if ldap_conn is not None:
            try:
                ldap_conn.unbind()
            except Exception:
                pass
        if pg_conn is not None:
            try:
                pg_conn.close()
            except Exception:
                pass

        duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        log_header("Run Summary")
        print(f"  {_C.WHITE}Run ID:{_C.RESET}              {run_id}")
        print(f"  {_C.WHITE}Duration:{_C.RESET}            {duration:.1f}s")
        print(f"  {_C.WHITE}Objects seen:{_C.RESET}        {stats.seen}")
        print(f"  {_C.GREEN}Objects created:{_C.RESET}     {stats.created}")
        print(f"  {_C.YELLOW}Objects modified:{_C.RESET}    {stats.modified}")
        print(f"  {_C.WHITE}Objects unchanged:{_C.RESET}   {stats.unchanged}")
        if stats.rescanned:
            print(f"  {_C.CYAN}Objects rescanned:{_C.RESET}   {stats.rescanned} "
                  "(--full-rescan; AD-unchanged, backfilled anyway)")
        print(f"  {_C.RED}Objects deleted:{_C.RESET}     {stats.deleted}")
        print(f"  {_C.WHITE}Edges opened:{_C.RESET}        {stats.edges_opened}")
        print(f"  {_C.WHITE}Edges closed:{_C.RESET}        {stats.edges_closed}")
        if stats.skipped_unresolved_members:
            print(f"  {_C.YELLOW}Unresolved members:{_C.RESET}  "
                  f"{stats.skipped_unresolved_members} (referenced objects "
                  "outside this version's collection scope)")
        if stats.skipped_unresolved_delegation_targets:
            print(f"  {_C.YELLOW}Unresolved deleg. targets:{_C.RESET} "
                  f"{stats.skipped_unresolved_delegation_targets}")
        status_color = _C.GREEN if exit_code == 0 else _C.RED
        status_text = "SUCCESS" if exit_code == 0 else (
            "ABORTED" if exit_code == 130 else "FAILED"
        )
        print(f"  {_C.WHITE}Result:{_C.RESET}              {status_color}{status_text}{_C.RESET}\n")

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
