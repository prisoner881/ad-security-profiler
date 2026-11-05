"""
platform_client.py -- collector_daemon.py's side of the FortifyData platform
==============================================================================
VERSION: 1.0

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
    when an activation key is configured: the ingest API (adaudit_push.py,
    contract 1.0) does not depend on the activation endpoints below. This
    is the mode to run in until the platform endpoints exist.

FortifyDataPlatform ([platform] mode = "fortifydata")
    The activation, configuration and health endpoints, as PROPOSED to the
    platform developer (questions-for-developer, sections 3 to 5). NONE OF
    THEM IS CONFIRMED YET. Every path, field name, status code and the
    secret encryption scheme are marked PROVISIONAL below and kept in one
    place each, so that adapting this module to the developer's answers
    touches only this file. Tested against a local mock only.

PROVISIONAL API (all relative to the environment's API server, the same one
adaudit_push.py pushes to; authenticated with "Authorization: LicenseKey
<license key from the activation key>"):

    POST   /collector/activations/{instance_id}   take the lease
           body {"collector_version", "hostname", "public_key_pem"}
           201/200 ok (body may give "lease_seconds"); 409 another instance
           holds it; 401/403 key refused
    PUT    /collector/activations/{instance_id}   renew the lease
           200/204 ok; 404/409/410 the lease is lost (expired or taken)
    DELETE /collector/activations/{instance_id}   release (404/410 are fine)
    GET    /collector/configuration               the run configuration
           200 JSON (RUN CONFIGURATION below); 404 not configured yet
    POST   /collector/health/{instance_id}        the health report (JSON)

instance_id is a random UUID the daemon creates on first start and keeps in
its state directory. The daemon key pair (RSA-3072, private key in
state_dir/daemon_key.pem, mode 0600) is created at the same time; its public
key goes with every activation so that the platform can encrypt secrets to
this installation only.

RUN CONFIGURATION (the same field names in the TOML file and in the JSON):

    version                   any string or number; logged, never the content
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

A SECRET field from the platform is either a plain string (accepted with a
warning: a TLS-inspecting proxy can read it) or the PROVISIONAL envelope

    {"alg": "RSA-OAEP-256+A256GCM", "ek": <b64>, "iv": <b64>, "ct": <b64>}

ek is a fresh AES-256 key encrypted with RSA-OAEP (SHA-256, MGF1-SHA-256) to
the daemon's public key; iv is the 12-byte GCM nonce; ct is the AES-GCM
ciphertext of the UTF-8 secret followed by the 16-byte tag; the additional
authenticated data is the field's path ("ad.password",
"entra.client_secret"), so an encrypted value cannot be moved to another
field. In the TOML file a secret is never written inline: see
LocalPlatform.

Nothing in this module logs or returns a secret except as the value of the
secret field itself; RunConfig's repr hides them.

CHANGELOG:
    1.0  First version (collector_daemon.py 1.0.0).
"""

import base64
import json
import os
import re
import socket
import stat
import uuid
from dataclasses import dataclass, field
from datetime import time as dtime
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import adaudit_push
import secret_input

VERSION = "1.0"

USER_AGENT_PRODUCT = "fortifydata-ad-collector"

# --- PROVISIONAL: pending the platform developer's answers -----------------
ACTIVATION_PATH = "/collector/activations/{instance_id}"
CONFIGURATION_PATH = "/collector/configuration"
HEALTH_PATH = "/collector/health/{instance_id}"
ACTIVATE_OK = {200, 201}
RENEW_OK = {200, 204}
RENEW_LEASE_LOST = {404, 409, 410}
RELEASE_OK = {200, 202, 204, 404, 410}
SECRET_ALG = "RSA-OAEP-256+A256GCM"
DEFAULT_LEASE_SECONDS = 300
# ---------------------------------------------------------------------------

DAEMON_KEY_FILE = "daemon_key.pem"
DAEMON_KEY_BITS = 3072
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


# ============================================================================
# The daemon key pair and secret envelopes (PROVISIONAL scheme)
# ============================================================================

class DaemonKey:
    """RSA private key kept in the state directory, created on first use."""

    def __init__(self, state_dir):
        self.path = Path(state_dir) / DAEMON_KEY_FILE
        self._key = None

    def load_or_create(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        if self._key is not None:
            return self._key
        if self.path.exists():
            mode = self.path.stat().st_mode & 0o077
            if mode:
                os.chmod(self.path, 0o600)
            self._key = serialization.load_pem_private_key(self.path.read_bytes(), password=None)
            return self._key
        key = rsa.generate_private_key(public_exponent=65537, key_size=DAEMON_KEY_BITS)
        pem = key.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(pem)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.path)
        self._key = key
        return key

    def public_key_pem(self):
        from cryptography.hazmat.primitives import serialization
        return self.load_or_create().public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")

    def fingerprint(self):
        """SHA-256 of the DER public key, hex (loggable)."""
        import hashlib
        from cryptography.hazmat.primitives import serialization
        der = self.load_or_create().public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        return hashlib.sha256(der).hexdigest()

    def decrypt(self, envelope, field_path):
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        if envelope.get("alg") != SECRET_ALG:
            raise ConfigError(f"{field_path} is encrypted with {str(envelope.get('alg'))[:40]!r}, "
                              f"not {SECRET_ALG}")
        try:
            ek = base64.b64decode(envelope["ek"], validate=True)
            iv = base64.b64decode(envelope["iv"], validate=True)
            ct = base64.b64decode(envelope["ct"], validate=True)
        except (KeyError, TypeError, ValueError):
            raise ConfigError(f"{field_path}: the encrypted value is malformed (ek, iv, ct)")
        try:
            cek = self.load_or_create().decrypt(ek, padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                label=None))
            plain = AESGCM(cek).decrypt(iv, ct, field_path.encode("utf-8"))
        except (ValueError, InvalidTag):
            raise ConfigError(f"{field_path} cannot be decrypted with this installation's key "
                              f"(encrypted to another installation, or to a key from before "
                              f"the state directory was reset); enter it again in the portal")
        try:
            return plain.decode("utf-8")
        except UnicodeDecodeError:
            raise ConfigError(f"{field_path} does not decrypt to text")


def encrypt_secret(public_key_pem, plaintext, field_path):
    """The platform side of the envelope; used by tests and the mock."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    pub = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    cek = AESGCM.generate_key(bit_length=256)
    iv = os.urandom(12)
    ct = AESGCM(cek).encrypt(iv, plaintext.encode("utf-8"), field_path.encode("utf-8"))
    ek = pub.encrypt(cek, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                       algorithm=hashes.SHA256(), label=None))
    b64 = lambda b: base64.b64encode(b).decode("ascii")  # noqa: E731
    return {"alg": SECRET_ALG, "ek": b64(ek), "iv": b64(iv), "ct": b64(ct)}


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

    def describe(self):
        raise NotImplementedError

    def activate(self):
        """Takes the lease. Returns the lease length in seconds."""
        raise NotImplementedError

    def renew(self):
        raise NotImplementedError

    def release(self):
        raise NotImplementedError

    def fetch_config(self):
        """Returns RunConfig; raises ConfigError or PlatformError."""
        raise NotImplementedError

    def report_health(self, report):
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
        raise ConfigError("[platform] api_url must be https:// (or test / us / eu); plain "
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

    def report_health(self, report):
        pass

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
# FortifyData mode (PROVISIONAL)
# ============================================================================

class FortifyDataPlatform(PlatformClient):

    mode = "fortifydata"

    def __init__(self, lic, activation_key, instance_id, daemon_key, collector_version,
                 api_url=None, ca_bundle=None, timeout=REQUEST_TIMEOUT_SECONDS, log=None):
        import requests
        self._requests = requests
        self.license = lic
        self.activation_key = activation_key
        self.instance_id = str(uuid.UUID(str(instance_id)))
        self.key = daemon_key
        self.collector_version = collector_version
        self.api_url_override = check_api_url(api_url) if api_url else None
        self.base_url = self.api_url_override or adaudit_push.API_SERVERS[
            lic.environment_or_default]
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
                f"{self.license.environment_or_default}, API {self.base_url}, instance "
                f"{self.instance_id} (PROVISIONAL activation/configuration/health endpoints)")

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
        if resp.status_code in (401, 403):
            return LicenseRefused(
                f"{what}: the platform refused the license key (HTTP {resp.status_code})"
                f"{detail}. Check that the AD audit integration is enabled for this client and "
                f"that the activation key is current", retry_after)
        if resp.status_code in TRANSIENT_STATUSES:
            return PlatformError(f"{what}: HTTP {resp.status_code}{detail}; will retry",
                                 retry_after)
        return PlatformError(f"{what}: unexpected HTTP {resp.status_code}{detail}", retry_after)

    # --- lease --------------------------------------------------------------

    def activate(self):
        what = "activation"
        payload = {"collector_version": self.collector_version,
                   "hostname": socket.gethostname(),
                   "public_key_pem": self.key.public_key_pem()}
        resp = self._call("POST", ACTIVATION_PATH.format(instance_id=self.instance_id),
                          what, payload)
        if resp.status_code in ACTIVATE_OK:
            body = self._body(resp) or {}
            lease = body.get("lease_seconds") if isinstance(body, dict) else None
            return lease if isinstance(lease, int) and lease > 0 else DEFAULT_LEASE_SECONDS
        if resp.status_code == 409:
            raise LicenseInUse("activation: another collector instance holds this license "
                               "(HTTP 409). Stop the other instance, or wait for its lease to "
                               "expire if it is gone")
        raise self._unexpected(resp, what)

    def renew(self):
        what = "lease renewal"
        resp = self._call("PUT", ACTIVATION_PATH.format(instance_id=self.instance_id), what)
        if resp.status_code in RENEW_OK:
            return
        if resp.status_code in RENEW_LEASE_LOST:
            raise LeaseLost(f"lease renewal: the lease is no longer held (HTTP "
                            f"{resp.status_code}); re-activating")
        raise self._unexpected(resp, what)

    def release(self):
        what = "lease release"
        resp = self._call("DELETE", ACTIVATION_PATH.format(instance_id=self.instance_id), what)
        if resp.status_code not in RELEASE_OK:
            raise self._unexpected(resp, what)

    # --- configuration and health -------------------------------------------

    def fetch_config(self):
        what = "configuration fetch"
        resp = self._call("GET", CONFIGURATION_PATH, what)
        if resp.status_code == 404:
            raise ConfigError("the platform has no run configuration for this client yet "
                              "(HTTP 404): enter the AD settings in the portal")
        if resp.status_code != 200:
            raise self._unexpected(resp, what)
        data = self._body(resp)
        if not isinstance(data, dict):
            raise PlatformError("configuration fetch: the response is not a JSON object")
        warnings = []

        def secret_value(path, raw):
            if raw is None or raw == "":
                return None
            if isinstance(raw, str):
                warnings.append(f"{path} arrived unencrypted (protected by TLS only)")
                return raw
            if isinstance(raw, dict):
                return self.key.decrypt(raw, path)
            raise ConfigError(f"{path} is neither text nor an encrypted value")

        cfg = parse_run_config(data, secret_value)
        cfg.warnings = warnings + cfg.warnings
        return cfg

    def report_health(self, report):
        what = "health report"
        resp = self._call("POST", HEALTH_PATH.format(instance_id=self.instance_id), what,
                          json.loads(json.dumps(report, default=str)))
        if resp.status_code >= 300:
            raise self._unexpected(resp, what)
