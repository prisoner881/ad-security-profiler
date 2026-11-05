"""
platform_client.py -- collector_daemon.py's side of the FortifyData platform
==============================================================================
VERSION: 2.0

collector_daemon.py needs four things from "the platform":

    1. a lease on the license (activate, renew every 2 minutes, release),
       so that one license runs one collector at a time;
    2. the client's run configuration: AD and Entra connection settings,
       their secrets, and the daily schedule;
    3. somewhere to send a health report every 5 minutes;
    4. the activation key adaudit.py pushes the evaluation results with.

Two implementations give the daemon the same interface (PlatformClient):

LocalPlatform ([platform] mode = "local")
    Everything is local: the configuration comes from the [schedule], [ad]
    and [entra] sections of the daemon's TOML configuration file (re-read
    before every run, so an edit needs no restart), secrets from files or
    environment variables, the lease calls do nothing and the health report
    goes only to the daemon log and its status file. Pushing still works
    when an activation key is configured.

FortifyDataPlatform ([platform] mode = "fortifydata")
    [2.0] The platform's collector API as the platform developer specified
    it (documents 04 and 05), deployed on their test environment. All calls
    go to the environment's API server and carry "Authorization: LicenseKey
    <license key>":

    POST   /api/v1/integration/collector/activations/{instanceId}
           take the lease (no body). 201 {"instanceId", "leaseExpiryDate",
           "serverDate"}; a restart with the instance id that holds the
           lease gets 201 too. 409 another instance holds it.
    PUT    .../activations/{instanceId}    renew: 202 (same body); 404 no
           activation for this id, 409 another instance holds it -> POST.
    DELETE .../activations/{instanceId}    release: 202 always.
    POST   /api/v1/integration/collector/health
           the health report, every 5 minutes. The response is the
           collector's record and its configuration, flat (document 05):
           identity and lifecycle (status, targetVersion, autoUpgrade,
           imageName, ...), the AD settings (host, username, password,
           useLdaps, ldapPort, caCertificate, domainFqdn, readSysvol,
           sysvolKerberos), Entra (entraTenantId -- null: no Entra --
           entraClientId, entraClientSecret, readPtaAgents), the schedule
           (scheduleTime, scheduleTimeZone) and configVersion.

    401: the key is not recognised or the integration is switched off --
    the client must fetch a new activation key from the portal; 403: the key
    is valid but may not call these endpoints. Both are retried every 5
    minutes. A 404 from the health check: no collector for this key, or it
    was deleted -- decommissioned: no scans, keep polling. Status EXPIRED:
    no scans, keep reporting; FAILED (set by the platform from our own error
    report) is ignored. The lease length comes from leaseExpiryDate - serverDate, and
    serverDate (or the Date header) gives the clock skew, which the daemon
    warns about. The secrets arrive as plain strings over TLS (the platform's
    decision, Q4.3): there is no key pair and no encryption. host, username
    or password null: not configured yet (no run, keep polling); Entra fields
    null: no Entra step. ldapPort is always used as given.

RUN CONFIGURATION, as the daemon uses it (the TOML file's tables; the
platform's flat fields map onto it in config_from_health()):

    version                   logged, never the content (configVersion)
    schedule.time             "HH:MM", 24-hour, local to schedule.timezone
    schedule.timezone         IANA name, e.g. "America/Chicago" (default UTC)
    ad.dc_host                required
    ad.username               required (UPN or DOMAIN\\user)
    ad.password               SECRET, required
    ad.ssl                    default true
    ad.port                   default 636 with ssl, 389 without
    ad.ca_cert_pem            PEM text; with ssl, verifies the DC certificate
    ad.sysvol                 default true (Group Policy files over SMB)
    ad.sysvol_kerberos        default false
    ad.smb_host               default dc_host
    ad.domain_fqdn            links the Entra data to the AD data; optional
                              when the database holds a single domain
    entra.tenant_id           the [entra] section / object is optional:
    entra.app_id              without it the Entra step is skipped
    entra.client_secret       SECRET, required when entra is present
    entra.include_pta_agents  default false

Nothing in this module logs or returns a secret except as the value of the
secret field itself; RunConfig's repr hides them, and the cacheable copy of
a platform response (PlatformResponse.cacheable) leaves them out.

CHANGELOG:
    2.0  The platform's real collector API (documents 04 and 05): new paths,
         no request body, 202 renewals, the lease from leaseExpiryDate, the
         clock skew, the configuration in the health response (flat fields,
         configVersion, status, targetVersion / autoUpgrade / imageName), no
         key pair or secret encryption (TLS only, Q4.3). The environment
         names prod / eu / test (adaudit_push.py).
    1.0  First version (collector_daemon.py 1.0.0), against a proposed API.
"""

import json
import os
import re
import stat
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from datetime import time as dtime
from email.utils import parsedate_to_datetime
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import adaudit_push
import secret_input

VERSION = "2.0"

USER_AGENT_PRODUCT = "fortifydata-ad-collector"

# The platform's collector API (documents 04 and 05).
ACTIVATION_PATH = "/api/v1/integration/collector/activations/{instance_id}"
HEALTH_PATH = "/api/v1/integration/collector/health"
ACTIVATE_OK = {200, 201}
RENEW_OK = {200, 202, 204}
RENEW_LEASE_LOST = {404, 409}
RELEASE_OK = {200, 202, 204, 404}
DEFAULT_LEASE_SECONDS = 300
# The fields of a health response that hold secrets: never cached on disk.
SECRET_FIELDS = ("password", "entraClientSecret")
# Collector statuses in which no scan runs; the health checks continue
# (platform developer, answer to Q3 of the follow-up). EXPIRED: the record is
# returned unchanged and no update is taken. DELETED is never returned (the
# health check answers 404 instead, CollectorRemoved); DECOMMISSIONED is the
# daemon's own name for that. FAILED is a display state the platform sets
# from our own error report, and is ignored.
STOPPED_STATUSES = ("EXPIRED", "DELETED", "DECOMMISSIONED")

REQUEST_TIMEOUT_SECONDS = 30
TRANSIENT_STATUSES = {408, 429, 500, 502, 503, 504}


# ============================================================================
# Errors
# ============================================================================

class PlatformError(Exception):
    """The platform could not be reached or answered something unexpected;
    worth retrying later. retry_after is the server's Retry-After in seconds,
    when it sent one."""

    def __init__(self, message, retry_after=None):
        super().__init__(message)
        self.retry_after = retry_after


class LicenseInUse(PlatformError):
    """Another instance holds the lease on this license."""


class LicenseRefused(PlatformError):
    """The platform refused the license key (401/403): revoked, expired,
    integration switched off. Retried, much less often."""


class LeaseLost(PlatformError):
    """A renewal found that this instance no longer holds the lease."""


class ConfigError(Exception):
    """The run configuration is missing, incomplete or invalid. The message
    says what to fix and never contains a secret."""


class CollectorRemoved(PlatformError):
    """[2.0] The health check answered 404: the platform has no collector for
    this key, or it was deleted (decommissioned). No scans; keep polling."""


class NotConfigured(ConfigError):
    """[2.0] The platform has no AD settings for this collector yet (host,
    username or password null): no run, keep polling."""


# ============================================================================
# Run configuration
# ============================================================================

@dataclass
class Schedule:
    time: str = "02:00"
    timezone: str = "UTC"

    @property
    def at(self):
        hour, minute = self.time.split(":")
        return dtime(int(hour), int(minute))

    @property
    def zone(self):
        return ZoneInfo(self.timezone)

    def __str__(self):
        return f"{self.time} {self.timezone}"


@dataclass
class AdConfig:
    dc_host: str
    username: str
    password: str = field(repr=False)
    ssl: bool = True
    port: int = None
    ca_cert_pem: str = field(default=None, repr=False)
    sysvol: bool = True
    sysvol_kerberos: bool = False
    smb_host: str = None
    domain_fqdn: str = None


@dataclass
class EntraConfig:
    tenant_id: str
    app_id: str
    client_secret: str = field(repr=False)
    include_pta_agents: bool = False


@dataclass
class RunConfig:
    version: str
    schedule: Schedule
    ad: AdConfig
    entra: EntraConfig = None
    warnings: list = field(default_factory=list, repr=False)

    def summary(self):
        """One loggable line (no secrets)."""
        parts = [f"configuration version {self.version}", f"schedule {self.schedule}",
                 f"AD {self.ad.username} @ {self.ad.dc_host}"
                 f"{' (LDAPS' + (', CA verified)' if self.ad.ca_cert_pem else ', CA NOT verified)') if self.ad.ssl else ' (plain LDAP)'}"
                 f"{', SYSVOL' if self.ad.sysvol else ''}"]
        parts.append(f"Entra tenant {self.entra.tenant_id}" if self.entra else "no Entra")
        return "; ".join(parts)


_TIME_RE = re.compile(r"^([01]?[0-9]|2[0-3]):([0-5][0-9])$")
_HOST_RE = re.compile(r"^[A-Za-z0-9._:\[\]-]{1,253}$")


def _str(section, data, name, required, what=None):
    value = data.get(name)
    if value is None or (isinstance(value, str) and not value.strip()):
        if required:
            raise ConfigError(f"{section}.{name} is missing{(' (' + what + ')') if what else ''}")
        return None
    if not isinstance(value, (str, int)) or isinstance(value, bool):
        raise ConfigError(f"{section}.{name} must be text")
    return str(value).strip()


def _bool(section, data, name, default):
    value = data.get(name, default)
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ConfigError(f"{section}.{name} must be true or false")
    return value


def parse_schedule(data):
    data = data or {}
    if not isinstance(data, dict):
        raise ConfigError("schedule must be a table/object")
    when = _str("schedule", data, "time", False) or "02:00"
    match = _TIME_RE.match(when)
    if not match:
        raise ConfigError(f"schedule.time {when[:20]!r} is not HH:MM (24-hour)")
    when = f"{int(match.group(1)):02d}:{match.group(2)}"
    zone = _str("schedule", data, "timezone", False) or "UTC"
    try:
        ZoneInfo(zone)
    except (ZoneInfoNotFoundError, ValueError):
        raise ConfigError(f"schedule.timezone {zone[:60]!r} is not a known IANA time zone "
                          f"(e.g. America/Chicago; the system may lack time zone data: tzdata)")
    return Schedule(when, zone)


def parse_run_config(data, secret_value):
    """Builds RunConfig from a dict (TOML tables or the platform's JSON).
    secret_value(path, raw) turns a secret field's raw value into the secret
    string; it returns None when the field is absent and raises ConfigError
    when it cannot be used."""
    if not isinstance(data, dict):
        raise ConfigError("the run configuration is not an object")
    version = data.get("version")
    version = "unversioned" if version is None else str(version)[:64]
    schedule = parse_schedule(data.get("schedule"))

    ad_data = data.get("ad")
    if not isinstance(ad_data, dict) or not ad_data:
        raise ConfigError("there are no AD settings (ad): nothing can be collected")
    dc_host = _str("ad", ad_data, "dc_host", True, "the domain controller's FQDN or IP")
    if not _HOST_RE.match(dc_host):
        raise ConfigError("ad.dc_host is not a host name or IP address")
    username = _str("ad", ad_data, "username", True, "the bind account")
    password = secret_value("ad.password", ad_data.get("password"))
    if not password:
        raise ConfigError("ad.password is missing (the bind account's password)")
    ssl = _bool("ad", ad_data, "ssl", True)
    port = ad_data.get("port")
    if port is not None:
        if isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536:
            raise ConfigError("ad.port must be a port number")
    ca_cert_pem = ad_data.get("ca_cert_pem")
    if ca_cert_pem is not None:
        if not isinstance(ca_cert_pem, str) or "-----BEGIN CERTIFICATE-----" not in ca_cert_pem:
            raise ConfigError("ad.ca_cert_pem is not a PEM certificate")
    smb_host = _str("ad", ad_data, "smb_host", False)
    if smb_host and not _HOST_RE.match(smb_host):
        raise ConfigError("ad.smb_host is not a host name or IP address")
    domain_fqdn = _str("ad", ad_data, "domain_fqdn", False)
    warnings = []
    if ca_cert_pem and not ssl:
        warnings.append("ad.ca_cert_pem is set but ad.ssl is false: the certificate is not used "
                        "(plain LDAP is not encrypted)")
    ad = AdConfig(dc_host=dc_host, username=username, password=password, ssl=ssl, port=port,
                  ca_cert_pem=ca_cert_pem or None, sysvol=_bool("ad", ad_data, "sysvol", True),
                  sysvol_kerberos=_bool("ad", ad_data, "sysvol_kerberos", False),
                  smb_host=smb_host, domain_fqdn=domain_fqdn)

    entra = None
    entra_data = data.get("entra")
    if entra_data is not None and not isinstance(entra_data, dict):
        raise ConfigError("entra must be a table/object")
    if entra_data and any(entra_data.get(k) for k in ("tenant_id", "app_id")):
        tenant_id = _str("entra", entra_data, "tenant_id", True, "GUID or verified domain")
        app_id = _str("entra", entra_data, "app_id", True, "the App Registration's client id")
        client_secret = secret_value("entra.client_secret", entra_data.get("client_secret"))
        if not client_secret:
            raise ConfigError("entra.client_secret is missing (the App Registration's secret)")
        entra = EntraConfig(tenant_id=tenant_id, app_id=app_id, client_secret=client_secret,
                            include_pta_agents=_bool("entra", entra_data,
                                                     "include_pta_agents", False))
    return RunConfig(version=version, schedule=schedule, ad=ad, entra=entra, warnings=warnings)


def config_from_health(data):
    """[2.0] RunConfig from a health response's flat fields (document 05).
    Raises NotConfigured when host, username or password is null, and
    ConfigError when a field is unusable."""
    missing = [name for name in ("host", "username", "password")
               if data.get(name) in (None, "")]
    if missing:
        raise NotConfigured("the collector is not configured in the FortifyData portal yet ("
                            + ", ".join(missing) + " not set)")
    use_ldaps = data.get("useLdaps")
    use_ldaps = True if use_ldaps is None else use_ldaps
    port = data.get("ldapPort")
    if port is None:  # document 05 says it is always present; be safe
        port = 636 if use_ldaps is True else 389
    ad = {"dc_host": data.get("host"), "username": data.get("username"),
          "password": data.get("password"), "ssl": use_ldaps, "port": port,
          "ca_cert_pem": data.get("caCertificate") or None,
          "domain_fqdn": data.get("domainFqdn"),
          "sysvol": data.get("readSysvol"), "sysvol_kerberos": data.get("sysvolKerberos")}
    warnings = []
    entra = None
    if data.get("entraTenantId"):
        if data.get("entraClientId") and data.get("entraClientSecret"):
            entra = {"tenant_id": data.get("entraTenantId"),
                     "app_id": data.get("entraClientId"),
                     "client_secret": data.get("entraClientSecret"),
                     "include_pta_agents": data.get("readPtaAgents")}
        else:
            warnings.append("Entra: entraTenantId is set but the client id or secret is not; "
                            "the Entra step is skipped")
    schedule = {"time": data.get("scheduleTime"), "timezone": data.get("scheduleTimeZone")}
    if not data.get("scheduleTime"):
        warnings.append("scheduleTime is not set: 02:00 is used")
    version = data.get("configVersion")
    cfg = parse_run_config({"version": "unversioned" if version is None else version,
                            "schedule": schedule, "ad": ad, "entra": entra},
                           lambda path, raw: raw if isinstance(raw, str) and raw else None)
    cfg.warnings = warnings + cfg.warnings
    return cfg


@dataclass
class PlatformResponse:
    """[2.0] What a health exchange brought back."""
    config: object = None          # RunConfig, or None
    config_error: str = None       # why there is no usable configuration
    not_configured: bool = False
    config_version: object = None
    status: str = None             # the collector's status on the platform
    target_version: str = None
    auto_upgrade: bool = None
    image_name: str = None
    cacheable: dict = None         # the response without its secrets

    @property
    def scans_stopped(self):
        return (self.status or "").upper() in STOPPED_STATUSES


def response_from_health(data):
    """PlatformResponse from a health response body (a dict)."""
    resp = PlatformResponse(
        config_version=data.get("configVersion"), status=data.get("status"),
        target_version=data.get("targetVersion"), auto_upgrade=data.get("autoUpgrade"),
        image_name=data.get("imageName"),
        cacheable={k: v for k, v in data.items() if k not in SECRET_FIELDS})
    try:
        resp.config = config_from_health(data)
    except NotConfigured as exc:
        resp.config_error, resp.not_configured = str(exc), True
    except ConfigError as exc:
        resp.config_error = f"the configuration in the portal is not usable: {exc}"
    return resp


@dataclass
class LeaseInfo:
    """[2.0] A lease answer: its length, and the platform's clock against
    ours (seconds; positive: our clock is ahead)."""
    seconds: int = DEFAULT_LEASE_SECONDS
    clock_skew: float = None


# ============================================================================
# The interface
# ============================================================================

class PlatformClient:
    """What collector_daemon.py calls. Subclasses implement all of it."""

    mode = None
    #: the license key adaudit.py pushes with (activation key text), or None
    activation_key = None
    #: an API URL override passed to adaudit.py --api-url, or None
    api_url_override = None
    #: [2.0] True when the configuration arrives with the health exchange
    config_via_health = False

    def describe(self):
        raise NotImplementedError

    def activate(self):
        """Takes the lease. Returns LeaseInfo (None: no lease needed)."""
        raise NotImplementedError

    def renew(self):
        """Renews the lease. Returns LeaseInfo or None."""
        raise NotImplementedError

    def release(self):
        raise NotImplementedError

    def fetch_config(self):
        """Local mode: returns RunConfig; raises ConfigError."""
        raise NotImplementedError

    def exchange_health(self, report):
        """Sends the health report. Returns PlatformResponse, or None when
        the health report goes nowhere (local mode). Raises PlatformError."""
        raise NotImplementedError

    @property
    def needs_lease(self):
        return False


def load_activation_key(path, allow_env=True):
    """(License, key text, source description) from a file path, or the
    FD_ACTIVATION_KEY / FD_ACTIVATION_KEY_FILE environment. Returns
    (None, None, None) when none is configured. Raises ConfigError."""
    try:
        if path:
            text = secret_input.read_secret_file(path, "[platform] activation_key_file")
            source = f"file {path}"
        elif allow_env:
            text, how = secret_input.resolve_secret(
                "FortifyData activation key", None, None, "FD_ACTIVATION_KEY", "",
                required=False, allow_prompt=False)
            if text is None:
                return None, None, None
            source = secret_input.describe_source(how, None, "FD_ACTIVATION_KEY")
        else:
            return None, None, None
        lic = adaudit_push.parse_activation_key(text)
    except secret_input.SecretUnavailable as exc:
        raise ConfigError(f"activation key: {exc}")
    except adaudit_push.LicenseKeyError as exc:
        raise ConfigError(f"the activation key is not usable: {exc}. Copy it again from the "
                          f"FortifyData portal")
    return lic, text.strip(), source


def check_api_url(url):
    if not (url.startswith("https://")
            or re.match(r"http://(localhost|127\.0\.0\.1)(:\d+)?(/|$)", url)):
        raise ConfigError("[platform] api_url must be https:// (or prod / eu / test); plain "
                          "http is only accepted for localhost, for testing against a mock")
    return url.rstrip("/")


# ============================================================================
# Local mode
# ============================================================================

class LocalPlatform(PlatformClient):
    """Configuration from the daemon's own TOML file. config_loader() returns
    the parsed TOML document (re-read on every call)."""

    mode = "local"

    def __init__(self, config_loader, activation_key=None, api_url_override=None, log=None):
        self._load = config_loader
        # Secrets read from a pipe (VAR_FILE=/dev/fd/N) can be read only
        # once; they are kept for the later configuration reads.
        self._pipe_cache = {}
        self.activation_key = activation_key
        self.api_url_override = api_url_override
        self.log = log

    def describe(self):
        return ("local mode: configuration from the [schedule], [ad] and [entra] sections; "
                + ("results are pushed with the activation key" if self.activation_key
                   else "no activation key, results are not pushed"))

    def activate(self):
        return None

    def renew(self):
        pass

    def release(self):
        pass

    def exchange_health(self, report):
        return None

    # Environment variables for the secret fields, when no <name>_file is set.
    SECRET_ENV = {"ad.password": "AD_BIND_PASSWORD", "entra.client_secret": "ENTRA_APP_SECRET"}

    def fetch_config(self):
        """In the TOML file a secret is never written inline: it is
        <name>_file = "/path" in the same table (password_file in [ad],
        client_secret_file in [entra]), or the environment variable
        (AD_BIND_PASSWORD / ENTRA_APP_SECRET, or their _FILE variants). The
        configuration file is not a secret store and gets copied around. The
        CA certificate is ca_cert_file in [ad]."""
        try:
            doc = self._load()
        except ConfigError:
            raise
        except Exception as exc:  # a TOML syntax error, an unreadable file
            raise ConfigError(f"cannot read the configuration file: {exc}")
        for name in ("schedule", "ad", "entra"):
            if doc.get(name) is not None and not isinstance(doc.get(name), dict):
                raise ConfigError(f"[{name}] must be a table")
        tables = {name: dict(doc.get(name) or {}) for name in ("ad", "entra")}
        data = {"version": "local",
                "schedule": doc.get("schedule"), "ad": tables["ad"],
                "entra": tables["entra"] or None}
        ca_file = tables["ad"].pop("ca_cert_file", None)
        if ca_file:
            try:
                tables["ad"]["ca_cert_pem"] = Path(ca_file).read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                raise ConfigError(f"[ad] ca_cert_file ({ca_file}) cannot be read: {exc}")
        files = {"ad.password": tables["ad"].pop("password_file", None),
                 "entra.client_secret": tables["entra"].pop("client_secret_file", None)}

        def secret_value(path, raw):
            section, name = path.split(".")
            env_var = self.SECRET_ENV[path]
            if raw is not None:
                raise ConfigError(f"{path} must not be written in the configuration file; set "
                                  f"{name}_file = \"/path/to/file\" in [{section}], or "
                                  f"{env_var} / {env_var}_FILE")
            try:
                if files[path]:
                    if os.environ.get(env_var) or os.environ.get(env_var + "_FILE"):
                        raise ConfigError(f"[{section}] {name}_file and {env_var}(_FILE) are "
                                          f"both set; set only one of them")
                    return secret_input.read_secret_file(str(files[path]),
                                                         f"[{section}] {name}_file")
                file_var = os.environ.get(env_var + "_FILE")
                is_pipe = False
                if file_var and not os.environ.get(env_var):
                    try:
                        is_pipe = not stat.S_ISREG(os.stat(file_var).st_mode)
                    except OSError:
                        is_pipe = file_var in self._pipe_cache
                    if is_pipe and file_var in self._pipe_cache:
                        return self._pipe_cache[file_var]
                value, _how = secret_input.resolve_secret(
                    path, None, None, env_var, "", required=False, allow_prompt=False)
                if is_pipe and value is not None:
                    self._pipe_cache[file_var] = value
                return value
            except secret_input.SecretUnavailable as exc:
                raise ConfigError(str(exc))

        return parse_run_config(data, secret_value)


# ============================================================================
# FortifyData mode
# ============================================================================

def _parse_time(text):
    if not isinstance(text, str) or not text:
        return None
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


class FortifyDataPlatform(PlatformClient):

    mode = "fortifydata"
    config_via_health = True

    def __init__(self, lic, activation_key, instance_id, collector_version,
                 api_url=None, ca_bundle=None, timeout=REQUEST_TIMEOUT_SECONDS, log=None):
        import requests
        self._requests = requests
        self.license = lic
        self.activation_key = activation_key
        self.instance_id = str(uuid.UUID(str(instance_id)))
        self.collector_version = collector_version
        self.api_url_override = check_api_url(api_url) if api_url else None
        try:
            self.base_url = check_api_url(lic.api_url(self.api_url_override))
        except adaudit_push.LicenseKeyError as exc:
            raise ConfigError(f"{exc} ([platform] api_url)")
        self.timeout = timeout
        self.log = log
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"LicenseKey {lic.license_key}",
            "User-Agent": f"{USER_AGENT_PRODUCT}/{collector_version}",
            "Accept": "application/json",
        })
        # Passed on every request: a session-level verify is overridden by
        # REQUESTS_CA_BUNDLE / CURL_CA_BUNDLE in the environment.
        self.verify = ca_bundle or True

    @property
    def needs_lease(self):
        return True

    def describe(self):
        return (f"FortifyData mode: company {self.license.company_id}, environment "
                f"{self.license.environment or 'none'}, API {self.base_url}, instance "
                f"{self.instance_id}")

    # --- HTTP ---------------------------------------------------------------

    def _call(self, method, path, what, payload=None):
        url = self.base_url + path
        try:
            resp = self.session.request(method, url, json=payload, timeout=self.timeout,
                                        verify=self.verify)
        except self._requests.exceptions.SSLError as exc:
            raise PlatformError(f"{what}: TLS error talking to {self.base_url} ({exc}). Behind a "
                                f"TLS-inspecting proxy, set [platform] ca_bundle")
        except self._requests.exceptions.RequestException as exc:
            raise PlatformError(f"{what}: cannot reach {self.base_url}: "
                                f"{exc.__class__.__name__}: {str(exc)[:300]}")
        return resp

    @staticmethod
    def _body(resp):
        try:
            return resp.json()
        except ValueError:
            return None

    def _unexpected(self, resp, what):
        body = self._body(resp)
        reason = adaudit_push.reason_of(body) if isinstance(body, dict) else None
        retry_after = None
        try:
            retry_after = max(0, int(resp.headers.get("Retry-After", "")))
        except ValueError:
            pass
        detail = f" ({reason})" if reason else ""
        if resp.status_code == 401:
            return LicenseRefused(
                f"{what}: the platform does not accept the activation key (HTTP 401){detail}: "
                f"it is not recognised, or the AD audit integration is switched off. Fetch a "
                f"new activation key from the FortifyData portal", retry_after)
        if resp.status_code == 403:
            return LicenseRefused(
                f"{what}: the activation key is valid but not allowed to call this endpoint "
                f"(HTTP 403){detail}. Check the collector's licence in the FortifyData portal",
                retry_after)
        if resp.status_code in TRANSIENT_STATUSES:
            return PlatformError(f"{what}: HTTP {resp.status_code}{detail}; will retry",
                                 retry_after)
        return PlatformError(f"{what}: unexpected HTTP {resp.status_code}{detail}", retry_after)

    def _lease_info(self, resp):
        """LeaseInfo from a 201/202 answer: the length from leaseExpiryDate -
        serverDate, the skew from serverDate (or the Date header)."""
        body = self._body(resp)
        body = body if isinstance(body, dict) else {}
        server = _parse_time(body.get("serverDate"))
        if server is None and resp.headers.get("Date"):
            try:
                server = parsedate_to_datetime(resp.headers["Date"])
            except (TypeError, ValueError):
                server = None
        expiry = _parse_time(body.get("leaseExpiryDate"))
        seconds = DEFAULT_LEASE_SECONDS
        if expiry is not None and server is not None:
            seconds = int((expiry - server).total_seconds())
            if seconds <= 0:
                seconds = DEFAULT_LEASE_SECONDS
        skew = None
        if server is not None:
            skew = (datetime.now(timezone.utc) - server).total_seconds()
        return LeaseInfo(seconds, skew)

    # --- lease --------------------------------------------------------------

    def activate(self):
        what = "activation"
        resp = self._call("POST", ACTIVATION_PATH.format(instance_id=self.instance_id), what)
        if resp.status_code in ACTIVATE_OK:
            return self._lease_info(resp)
        if resp.status_code == 409:
            raise LicenseInUse("activation: license in use by another instance (HTTP 409). Stop "
                               "the other collector, or wait for its lease to expire if it is "
                               "gone")
        raise self._unexpected(resp, what)

    def renew(self):
        what = "lease renewal"
        resp = self._call("PUT", ACTIVATION_PATH.format(instance_id=self.instance_id), what)
        if resp.status_code in RENEW_OK:
            return self._lease_info(resp)
        if resp.status_code in RENEW_LEASE_LOST:
            raise LeaseLost(f"lease renewal: the lease is no longer held (HTTP "
                            f"{resp.status_code}"
                            + (", another instance holds it" if resp.status_code == 409 else "")
                            + "); re-activating")
        raise self._unexpected(resp, what)

    def release(self):
        what = "lease release"
        resp = self._call("DELETE", ACTIVATION_PATH.format(instance_id=self.instance_id), what)
        if resp.status_code not in RELEASE_OK:
            raise self._unexpected(resp, what)

    # --- health and configuration -------------------------------------------

    def exchange_health(self, report):
        what = "health check"
        resp = self._call("POST", HEALTH_PATH, what, json.loads(json.dumps(report, default=str)))
        if resp.status_code == 404:
            raise CollectorRemoved("health check: the platform has no collector for this "
                                   "activation key, or it was deleted (HTTP 404): no scans run "
                                   "until it is set up again in the portal")
        if resp.status_code >= 300:
            raise self._unexpected(resp, what)
        data = self._body(resp)
        if not isinstance(data, dict):
            raise PlatformError("health check: the response is not a JSON object")
        return response_from_health(data)
