"""
sysvol_collector.py -- SYSVOL / NETLOGON reader for adprofiler.py
=================================================================
VERSION: 1.0 (ships with adprofiler.py 0.7.0, schema v39)

Group Policy settings are not in LDAP: a GPO's LDAP object (the GPC) only
points at its folder on the SYSVOL share (the GPT), where the settings
themselves live. adprofiler.py calls collect_sysvol() when run with
--sysvol, inside the same database transaction and sync_run as the LDAP
collection.

WHAT IS READ (read-only, over SMB2/3, with the same account as the LDAP
bind -- Authenticated Users can read SYSVOL by default, because every
computer and user applies Group Policy from it):

    <GPO folder>\\gpt.ini                                          version
    <GPO folder>\\Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf   security template
    <GPO folder>\\Machine|User\\Registry.pol                        admin templates
    <GPO folder>\\Machine\\Microsoft\\Windows NT\\Audit\\audit.csv      advanced audit policy
    <GPO folder>\\Machine|User\\Preferences\\<Type>\\<Type>.xml        GPP items
    <GPO folder>\\Machine|User\\Scripts\\...                          scripts (scanned)
    \\\\<DC>\\NETLOGON\\...                                             logon scripts (scanned)

SECRETS ARE NEVER STORED:
    - Group Policy Preferences cpassword values (MS14-025) are detected,
      never stored or decrypted: only has_cpassword and the account name.
    - String registry values whose name suggests a credential
      (DefaultPassword for AutoAdminLogon, ...) are stored as '<redacted>'.
    - Scripts: only the names of the credential patterns found and their
      line numbers -- never the matched text.

FAILURE HANDLING: SYSVOL collection never fails the run. If the share
cannot be reached at all, nothing changes in the database except
sysvol_collection_status ('failed'). If a single GPO folder (or NETLOGON)
cannot be read, that GPO's previously collected settings are carried
forward unchanged, so an access-denied folder never looks like "all its
settings were removed". Files that simply don't exist are normal (most
GPOs only use one or two of them).

TESTABILITY: everything goes through a small reader interface
(list_dir / read_file), implemented over SMB by SmbSysvolReader; tests
substitute a reader backed by a local directory tree.
"""

import csv
import hashlib
import io
import json
import re
import struct
import xml.etree.ElementTree as ET

# Size and count limits: SYSVOL is small by design, but a share used as a
# file dump shouldn't stall a run or fill the database.
MAX_POLICY_FILE_BYTES = 8 * 1024 * 1024
MAX_SCRIPT_FILE_BYTES = 1024 * 1024
DEFAULT_MAX_SCRIPT_FILES = 500
MAX_SCRIPT_DEPTH = 4

SCRIPT_EXTENSIONS = {".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".kix", ".wsf",
                     ".txt", ".ini", ".cfg", ".config", ".xml", ".sh", ".py"}

# GPP types that can carry a cpassword, plus Groups (local group changes).
PREFERENCE_TYPES = ("Groups", "ScheduledTasks", "Services", "DataSources", "Drives", "Printers")

REDACTED = "<redacted>"
SECRET_NAME_RE = re.compile(r"password|passwd|passphrase|pwd|secret|apikey|api_key",
                            re.IGNORECASE)
# Only non-empty string values are redacted: an empty one is not a secret
# (keeping it empty lets plugins tell it apart), a DWORD can't hold a
# password, and numeric settings such as LAPS PasswordLength /
# PasswordAgeDays must stay readable.
STRING_REG_TYPES = {"REG_SZ", "REG_EXPAND_SZ", "REG_MULTI_SZ", None}

# Credential patterns for script scanning: (indicator name, compiled regex).
# Deliberately specific -- a script that merely mentions "password" in a
# comment is not flagged.
SCRIPT_PATTERNS = [
    ("net_use_password", re.compile(r"\bnet\s+use\b[^\r\n]*\s/u(ser)?:\S+\s+(?!\*)\S+", re.IGNORECASE)),
    ("plaintext_securestring", re.compile(r"ConvertTo-SecureString\b[^\r\n]*-AsPlainText", re.IGNORECASE)),
    ("pscredential_literal", re.compile(r"New-Object\s+(System\.Management\.Automation\.)?PSCredential\s*\(?[^\r\n]*[\"']",
                                        re.IGNORECASE)),
    ("password_assignment", re.compile(r"(?<![\w.$-])(\$?(password|passwd|pwd|pass)\w*)\s*=\s*[\"'][^\"'\s]{3,}[\"']",
                                       re.IGNORECASE)),
    ("connection_string_password", re.compile(r"(password|pwd)\s*=\s*[^;\"'\s]{3,}\s*;", re.IGNORECASE)),
    ("cpassword", re.compile(r"cpassword\s*=\s*\"[^\"]+\"", re.IGNORECASE)),
    ("runas_savecred", re.compile(r"\brunas\b[^\r\n]*/savecred", re.IGNORECASE)),
    ("autologon_default_password", re.compile(r"DefaultPassword", re.IGNORECASE)),
]

REG_TYPES = {0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY", 4: "REG_DWORD",
             5: "REG_DWORD_BIG_ENDIAN", 7: "REG_MULTI_SZ", 11: "REG_QWORD"}

# GptTmpl.inf [Registry Values] hive prefixes -> section names used in
# gpo_setting_edge (Registry.pol paths have no hive; scope decides it).
INF_HIVES = {"machine": "HKLM", "user": "HKCU", "users": "HKU", "classes_root": "HKCR"}


class SysvolError(Exception):
    """Base class for reader failures."""


class SysvolNotFound(SysvolError):
    pass


class SysvolAccessDenied(SysvolError):
    pass


# ============================================================================
# Readers
# ============================================================================

class SmbSysvolReader:
    """Reads files over SMB with impacket. Paths are share-relative and use
    backslashes. Errors are mapped onto SysvolNotFound / SysvolAccessDenied
    / SysvolError so callers never need impacket's error codes."""

    def __init__(self, host, username, password, domain="", use_kerberos=False, kdc_host=None,
                 timeout=60, port=445):
        from impacket.smbconnection import SMBConnection, SessionError
        self._session_error = SessionError
        self.host = host
        try:
            self.conn = SMBConnection(remoteName=host, remoteHost=host, sess_port=port, timeout=timeout)
            user, dom = split_account(username, domain)
            if use_kerberos:
                self.conn.kerberosLogin(user, password, dom, kdcHost=kdc_host or host)
            else:
                self.conn.login(user, password, dom)
        except SessionError as exc:
            raise self._map(exc) from None
        except Exception as exc:  # socket errors, Kerberos errors, ...
            raise SysvolError(f"could not connect to \\\\{host} over SMB: {exc}") from None

    def _map(self, exc):
        from impacket import nt_errors
        code = exc.getErrorCode() if hasattr(exc, "getErrorCode") else None
        text = exc.getErrorString()[0] if hasattr(exc, "getErrorString") else str(exc)
        if code in (nt_errors.STATUS_OBJECT_NAME_NOT_FOUND, nt_errors.STATUS_OBJECT_PATH_NOT_FOUND,
                    nt_errors.STATUS_NO_SUCH_FILE, getattr(nt_errors, "STATUS_NOT_FOUND", -1)):
            return SysvolNotFound(text)
        if code in (nt_errors.STATUS_ACCESS_DENIED, getattr(nt_errors, "STATUS_LOGON_FAILURE", -2)):
            return SysvolAccessDenied(text)
        return SysvolError(text)

    def list_dir(self, share, path):
        pattern = (path.rstrip("\\") + "\\*") if path else "*"
        try:
            entries = self.conn.listPath(share, pattern)
        except self._session_error as exc:
            raise self._map(exc) from None
        except Exception as exc:
            raise SysvolError(str(exc)) from None
        out = []
        for e in entries:
            name = e.get_longname()
            if name in (".", ".."):
                continue
            out.append((name, bool(e.is_directory()), int(e.get_filesize())))
        return out

    def read_file(self, share, path, max_bytes):
        buf = io.BytesIO()

        def _cb(data):
            if buf.tell() + len(data) > max_bytes:
                raise SysvolError(f"{path} is larger than {max_bytes} bytes")
            buf.write(data)
        try:
            self.conn.getFile(share, path, _cb)
        except self._session_error as exc:
            raise self._map(exc) from None
        except SysvolError:
            raise
        except Exception as exc:
            raise SysvolError(str(exc)) from None
        return buf.getvalue()

    def close(self):
        try:
            self.conn.logoff()
        except Exception:
            pass


def split_account(username, domain=""):
    """'user@corp.local' -> ('user', 'corp.local'); 'CORP\\user' -> ('user', 'CORP')."""
    if "\\" in username:
        dom, user = username.split("\\", 1)
        return user, dom
    if "@" in username:
        user, dom = username.rsplit("@", 1)
        return user, dom
    return username, domain


# ============================================================================
# Parsers (pure functions; unit-tested)
# ============================================================================

def decode_text(data):
    """GPO files are UTF-16LE with a BOM (GptTmpl.inf), UTF-8 (XML, CSV)
    or ANSI (scripts). Never raises."""
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        return data.decode("utf-16", errors="replace")
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", errors="replace")
    if len(data) >= 4 and data[1:2] == b"\x00" and data[3:4] == b"\x00":
        return data.decode("utf-16-le", errors="replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def parse_inf(data):
    """INI parser tolerant of what secedit writes (duplicate-free sections,
    keys with spaces, values with '=' or commas, [Unicode]/[Version]).
    Returns {section: [(key, value)]} preserving order; keys keep case."""
    sections = {}
    current = None
    for raw in decode_text(data).splitlines():
        line = raw.strip()
        if not line or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].strip()
            sections.setdefault(current, [])
            continue
        if current is None:
            continue
        if "=" in line:
            key, value = line.split("=", 1)
            sections[current].append((key.strip(), value.strip()))
        else:
            sections[current].append((line, ""))
    return sections


def parse_gpt_ini_version(data):
    for section, items in parse_inf(data).items():
        if section.lower() == "general":
            for key, value in items:
                if key.lower() == "version":
                    try:
                        return int(value)
                    except ValueError:
                        return None
    return None


def parse_registry_pol(data):
    """PReg format ([MS-GPREG] 2.2.1): 'PReg' + uint32 version 1, then
    entries '[' key ';' valuename ';' type ';' size ';' data ']' where the
    brackets/semicolons and strings are UTF-16LE and type/size are uint32.
    Returns [(key, value_name, type_int, data_bytes)]."""
    if len(data) < 8 or data[:4] != b"PReg":
        raise ValueError("not a Registry.pol file (missing PReg signature)")
    pos = 8
    out = []
    n = len(data)

    def read_wstr(p):
        end = p
        while end + 1 < n and data[end:end + 2] != b"\x00\x00":
            end += 2
        return data[p:end].decode("utf-16-le", errors="replace"), end + 2

    def expect(p, ch):
        if data[p:p + 2] != ch.encode("utf-16-le"):
            raise ValueError(f"malformed Registry.pol at offset {p}")
        return p + 2

    while pos < n:
        if data[pos:pos + 2] != "[".encode("utf-16-le"):
            break
        pos += 2
        key, pos = read_wstr(pos)
        pos = expect(pos, ";")
        value_name, pos = read_wstr(pos)
        pos = expect(pos, ";")
        (vtype,) = struct.unpack_from("<I", data, pos); pos += 4
        pos = expect(pos, ";")
        (size,) = struct.unpack_from("<I", data, pos); pos += 4
        pos = expect(pos, ";")
        value = data[pos:pos + size]; pos += size
        pos = expect(pos, "]")
        out.append((key, value_name, vtype, value))
    return out


def format_reg_value(vtype, raw):
    """(value_type, setting_value) as stored in gpo_setting_edge."""
    tname = REG_TYPES.get(vtype, f"REG_TYPE_{vtype}")
    try:
        if vtype == 4 and len(raw) >= 4:
            return tname, str(struct.unpack_from("<I", raw)[0])
        if vtype == 5 and len(raw) >= 4:
            return tname, str(struct.unpack_from(">I", raw)[0])
        if vtype == 11 and len(raw) >= 8:
            return tname, str(struct.unpack_from("<Q", raw)[0])
        if vtype in (1, 2):
            return tname, raw.decode("utf-16-le", errors="replace").rstrip("\x00")
        if vtype == 7:
            parts = raw.decode("utf-16-le", errors="replace").split("\x00")
            return tname, "\n".join(p for p in parts if p)
    except struct.error:
        pass
    return tname, raw.hex()


def inf_registry_value(raw_value):
    """GptTmpl [Registry Values] value 'type,data' -> (value_type, value).
    Type numbers are REG_* constants; multi-strings are comma-separated."""
    if "," not in raw_value:
        return None, raw_value
    t, v = raw_value.split(",", 1)
    try:
        vtype = int(t)
    except ValueError:
        return None, raw_value
    v = v.strip()
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        v = v[1:-1]
    if vtype == 7:
        v = "\n".join(p for p in v.split(",") if p)
    return REG_TYPES.get(vtype, f"REG_TYPE_{vtype}"), v


def parse_audit_csv(data):
    """audit.csv columns: Machine Name, Policy Target, Subcategory,
    Subcategory GUID, Inclusion Setting, Exclusion Setting, Setting Value.
    Returns [(guid_lower_no_braces, subcategory_name, setting_value)].
    Global object access (Policy Target File/Registry) and option rows
    (no GUID) are kept with their name as the key."""
    rows = []
    reader = csv.reader(io.StringIO(decode_text(data)))
    header = None
    for rec in reader:
        if not rec or all(not c.strip() for c in rec):
            continue
        if header is None:
            header = [h.strip().lower() for h in rec]
            continue
        row = dict(zip(header, (c.strip() for c in rec)))
        guid = (row.get("subcategory guid") or "").strip("{}").lower()
        name = row.get("subcategory") or ""
        value = row.get("setting value") or ""
        key = guid or name.lower()
        if key:
            rows.append((key, name, value))
    return rows


def _local(tag):
    return tag.rsplit("}", 1)[-1]


def parse_gpp_xml(data, preference_type):
    """Group Policy Preferences XML -> list of item dicts:
    {item_uid, item_name, action, has_cpassword, account_name, details}.
    cpassword is only tested for presence -- the value is discarded here."""
    if len(data) > MAX_POLICY_FILE_BYTES:
        raise ValueError("preference file too large")
    text = decode_text(data)
    if "<!DOCTYPE" in text or "<!ENTITY" in text:
        raise ValueError("preference file contains a DTD (refused)")
    root = ET.fromstring(text)
    items = []
    for el in root.iter():
        props = next((c for c in el if _local(c.tag) == "Properties"), None)
        if props is None:
            continue
        a = props.attrib
        cpassword = a.get("cpassword") or ""
        account = a.get("userName") or a.get("runAs") or a.get("accountName") or a.get("username") or None
        name = el.attrib.get("name") or a.get("groupName") or a.get("name") or ""
        uid = el.attrib.get("uid")
        if not uid:
            uid = "h:" + hashlib.sha1(f"{preference_type}|{_local(el.tag)}|{name}".encode()).hexdigest()
        details = {"element": _local(el.tag)}
        if _local(el.tag) == "Group":
            details.update({
                "group_name": a.get("groupName"), "group_sid": a.get("groupSid") or None,
                "delete_all_users": a.get("deleteAllUsers") == "1",
                "delete_all_groups": a.get("deleteAllGroups") == "1",
                "members": sorted(
                    ({"name": m.attrib.get("name"), "sid": m.attrib.get("sid") or None,
                      "action": m.attrib.get("action")}
                     for m in props.iter() if _local(m.tag) == "Member"),
                    key=lambda m: ((m["name"] or "").lower(), m["sid"] or "", m["action"] or "")),
            })
        elif _local(el.tag) in ("Task", "TaskV2", "ImmediateTask", "ImmediateTaskV2"):
            principal = next((p for p in props.iter() if _local(p.tag) == "Principal"), None)
            if principal is not None:
                logon_type = next((c.text for c in principal if _local(c.tag) == "LogonType"), None)
                run_level = next((c.text for c in principal if _local(c.tag) == "RunLevel"), None)
                details.update({"logon_type": logon_type, "run_level": run_level})
                if account is None:
                    account = next((c.text for c in principal if _local(c.tag) == "UserId"), None)
            if not cpassword:
                cpassword = next((p.attrib.get("cpassword", "") for p in props.iter()
                                  if p.attrib.get("cpassword")), "")
        items.append({
            "item_uid": uid, "item_name": name or None, "action": a.get("action"),
            "has_cpassword": bool(cpassword.strip()), "account_name": account,
            "details": details,
        })
    return items


def scan_script(data):
    """Sorted unique "<pattern>:<line>" indicators; never the text itself."""
    text = decode_text(data)
    found = set()
    for lineno, line in enumerate(text.splitlines(), start=1):
        if len(line) > 4000:
            line = line[:4000]
        for name, rx in SCRIPT_PATTERNS:
            if rx.search(line):
                found.add(f"{name}:{lineno}")
    return sorted(found, key=lambda s: (s.split(":")[0], int(s.split(":")[1])))


def is_secret_value_name(name):
    return bool(SECRET_NAME_RE.search(name or ""))


def gpt_settings(gpttmpl_sections):
    """GptTmpl.inf sections -> (source, section, key, value_type, value) rows.
    [Registry Values] become 'registry' rows under their hive; [Unicode]
    and [Version] are format headers, not settings."""
    rows = []
    for section, items in gpttmpl_sections.items():
        sl = section.lower()
        if sl in ("unicode", "version"):
            continue
        for key, value in items:
            if sl == "registry values":
                hive_part, _, path = key.partition("\\")
                hive = INF_HIVES.get(hive_part.lower())
                if hive is None:
                    hive, path = "HKLM", key
                vtype, v = inf_registry_value(value)
                if vtype in STRING_REG_TYPES and v and is_secret_value_name(path.rsplit("\\", 1)[-1]):
                    v = REDACTED
                rows.append(("registry", hive, path, vtype, v))
            elif sl == "service general setting" and not value:
                # '"Spooler",4,"<SDDL>"': service name -> start mode
                # (2 automatic, 3 manual, 4 disabled). The service SDDL is
                # not kept.
                parts = next(csv.reader([key]), [])
                if len(parts) >= 2:
                    rows.append(("security_template", section, parts[0].strip(), "start_mode",
                                 parts[1].strip()))
                else:
                    rows.append(("security_template", section, key, None, value))
            else:
                rows.append(("security_template", section, key, None, value))
    return rows


def registry_pol_settings(entries, scope):
    hive = "HKLM" if scope == "machine" else "HKCU"
    rows = []
    for key, value_name, vtype, raw in entries:
        if value_name.lower().startswith("**del.") or value_name.lower().startswith("**delvals"):
            rows.append(("registry", hive, f"{key}\\{value_name}", "DELETE", ""))
            continue
        t, v = format_reg_value(vtype, raw)
        if t in STRING_REG_TYPES and v and is_secret_value_name(value_name):
            v = REDACTED
        rows.append(("registry", hive, f"{key}\\{value_name}", t, v))
    return rows


def sysvol_relative_path(gpc_file_sys_path, domain_fqdn, gpo_cn):
    """'\\\\corp.local\\SysVol\\corp.local\\Policies\\{GUID}' ->
    'corp.local\\Policies\\{GUID}' (share-relative on SYSVOL). Falls back
    to the standard layout when gPCFileSysPath is missing or unusual."""
    if gpc_file_sys_path:
        parts = [p for p in gpc_file_sys_path.replace("/", "\\").split("\\") if p]
        lowered = [p.lower() for p in parts]
        if "sysvol" in lowered:
            rest = parts[lowered.index("sysvol") + 1:]
            if rest:
                return "\\".join(rest)
    return f"{domain_fqdn}\\Policies\\{gpo_cn}"


# ============================================================================
# Collection
# ============================================================================

class _GpoReadFailed(Exception):
    def __init__(self, status, detail):
        super().__init__(detail)
        self.status = status
        self.detail = detail


def _read_optional(reader, share, path, max_bytes):
    """File contents, or None if it doesn't exist. Any other failure is a
    reason to treat the whole GPO as unreadable."""
    try:
        return reader.read_file(share, path, max_bytes)
    except SysvolNotFound:
        return None
    except SysvolAccessDenied as exc:
        raise _GpoReadFailed("access_denied", f"{path}: {exc}")
    except SysvolError as exc:
        raise _GpoReadFailed("error", f"{path}: {exc}")


def _list_optional(reader, share, path):
    try:
        return reader.list_dir(share, path)
    except SysvolNotFound:
        return []
    except SysvolAccessDenied as exc:
        raise _GpoReadFailed("access_denied", f"{path}: {exc}")
    except SysvolError as exc:
        raise _GpoReadFailed("error", f"{path}: {exc}")


def _walk_scripts(reader, share, base, depth, budget, out):
    """Collects (path, size) of candidate script files below base."""
    if depth > MAX_SCRIPT_DEPTH or budget[0] <= 0:
        return
    for name, is_dir, size in sorted(_list_optional(reader, share, base)):
        path = f"{base}\\{name}" if base else name
        if is_dir:
            _walk_scripts(reader, share, path, depth + 1, budget, out)
        else:
            ext = ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else ""
            if ext in SCRIPT_EXTENSIONS and size <= MAX_SCRIPT_FILE_BYTES:
                if budget[0] <= 0:
                    return
                budget[0] -= 1
                out.append((path, size))


def read_gpo_folder(reader, gpo_path, max_script_files):
    """Reads one GPO folder. Returns dict with gpt_ini_version, settings
    rows (scope, source, section, key, value_type, value), preference
    items, scripts and files_read. Raises _GpoReadFailed."""
    share = "SYSVOL"
    # The folder itself must be listable; a missing folder is reported
    # distinctly from an unreadable one.
    try:
        reader.list_dir(share, gpo_path)
    except SysvolNotFound:
        raise _GpoReadFailed("not_found", f"{gpo_path} does not exist")
    except SysvolAccessDenied as exc:
        raise _GpoReadFailed("access_denied", f"{gpo_path}: {exc}")
    except SysvolError as exc:
        raise _GpoReadFailed("error", f"{gpo_path}: {exc}")

    result = {"gpt_ini_version": None, "settings": [], "preferences": [], "scripts": [],
              "files_read": []}

    data = _read_optional(reader, share, f"{gpo_path}\\gpt.ini", MAX_POLICY_FILE_BYTES)
    if data is not None:
        result["files_read"].append("gpt.ini")
        result["gpt_ini_version"] = parse_gpt_ini_version(data)

    rel = "Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf"
    data = _read_optional(reader, share, f"{gpo_path}\\{rel}", MAX_POLICY_FILE_BYTES)
    if data is not None:
        result["files_read"].append(rel)
        for row in gpt_settings(parse_inf(data)):
            result["settings"].append(("machine",) + row)

    for scope, folder in (("machine", "Machine"), ("user", "User")):
        rel = f"{folder}\\Registry.pol"
        data = _read_optional(reader, share, f"{gpo_path}\\{rel}", MAX_POLICY_FILE_BYTES)
        if data is not None:
            result["files_read"].append(rel)
            try:
                entries = parse_registry_pol(data)
            except (ValueError, struct.error) as exc:
                raise _GpoReadFailed("error", f"{rel}: unparseable ({exc})")
            for row in registry_pol_settings(entries, scope):
                result["settings"].append((scope,) + row)

    rel = "Machine\\Microsoft\\Windows NT\\Audit\\audit.csv"
    data = _read_optional(reader, share, f"{gpo_path}\\{rel}", MAX_POLICY_FILE_BYTES)
    if data is not None:
        result["files_read"].append(rel)
        for key, name, value in parse_audit_csv(data):
            result["settings"].append(("machine", "audit", "advanced_audit", key, name or None, value))

    for scope, folder in (("machine", "Machine"), ("user", "User")):
        for ptype in PREFERENCE_TYPES:
            rel = f"{folder}\\Preferences\\{ptype}\\{ptype}.xml"
            data = _read_optional(reader, share, f"{gpo_path}\\{rel}", MAX_POLICY_FILE_BYTES)
            if data is None:
                continue
            result["files_read"].append(rel)
            try:
                items = parse_gpp_xml(data, ptype)
            except (ET.ParseError, ValueError) as exc:
                raise _GpoReadFailed("error", f"{rel}: unparseable ({exc})")
            for item in items:
                result["preferences"].append((scope, ptype, item))

        scripts = []
        _walk_scripts(reader, share, f"{gpo_path}\\{folder}\\Scripts", 0, [max_script_files], scripts)
        for path, size in scripts:
            data = _read_optional(reader, share, path, MAX_SCRIPT_FILE_BYTES)
            if data is None:
                continue
            indicators = scan_script(data)
            if indicators:
                result["scripts"].append((path, size, indicators))

    # Same key twice (e.g. a value in both GptTmpl [Registry Values] and
    # Registry.pol): the security template wins, matching the order the
    # rows were added.
    dedup = {}
    for scope, source, section, key, vtype, value in result["settings"]:
        k = (scope, source, section, key.lower())
        if k not in dedup:
            dedup[k] = (scope, source, section, key, vtype, value)
    result["settings"] = list(dedup.values())
    return result


def _carry_forward(pg_cur, table, client_id, key_cols, payload_cols, where_sql, params, desired):
    """Re-adds currently open rows matching where_sql to desired so the
    following sync_edges call leaves them untouched (data we could not
    re-read this run is not data that disappeared)."""
    cols = key_cols + payload_cols
    pg_cur.execute(
        f"SELECT {', '.join(cols)} FROM {table} WHERE client_id = %s AND valid_to IS NULL AND ({where_sql})",
        (client_id,) + tuple(params),
    )
    n = len(key_cols)
    carried = 0
    for row in pg_cur.fetchall():
        key = tuple(row[:n])
        if key not in desired:
            desired[key] = dict(zip(payload_cols, row[n:]))
            carried += 1
    return carried


def collect_sysvol(pg_cur, client_id, run_id, run_timestamp, reader, smb_host, domain_fqdn,
                   gpo_entries, sync_edges, log, max_script_files=DEFAULT_MAX_SCRIPT_FILES):
    """Reads every GPO folder and NETLOGON through reader and syncs
    gpo_setting_edge / gpo_preference_item_edge / sysvol_script_edge,
    ad_gpo_sysvol and sysvol_collection_status.

    gpo_entries: [(gpo_object_guid, attributes_full)] from the LDAP GPO
    collection. sync_edges / log: adprofiler.py's functions (passed in to
    avoid a circular import). Returns (edges_opened, edges_closed)."""
    settings_desired, prefs_desired, scripts_desired = {}, {}, {}
    unreadable_gpos = []
    gpos_read = 0
    status_rows = []

    for gpo_guid, full in gpo_entries:
        gpo_cn = full.get("cn") or ""
        path = sysvol_relative_path(full.get("gPCFileSysPath"), domain_fqdn, gpo_cn)
        try:
            res = read_gpo_folder(reader, path, max_script_files)
        except _GpoReadFailed as exc:
            unreadable_gpos.append(gpo_guid)
            status_rows.append((gpo_guid, path, exc.status, None, None, exc.detail))
            continue
        except Exception as exc:  # parser bug or unexpected data: never fatal
            unreadable_gpos.append(gpo_guid)
            status_rows.append((gpo_guid, path, "error", None, None, f"unexpected: {exc}"))
            continue
        gpos_read += 1
        status_rows.append((gpo_guid, path, "ok", res["gpt_ini_version"], sorted(res["files_read"]), None))
        for scope, source, section, key, vtype, value in res["settings"]:
            settings_desired[(gpo_guid, scope, source, section, key)] = {
                "value_type": vtype, "setting_value": value}
        for scope, ptype, item in res["preferences"]:
            prefs_desired[(gpo_guid, scope, ptype, item["item_uid"])] = {
                "item_name": item["item_name"], "action": item["action"],
                "has_cpassword": item["has_cpassword"], "account_name": item["account_name"],
                "details_json": json.dumps(item["details"], sort_keys=True),
            }
        for spath, size, indicators in res["scripts"]:
            scripts_desired[("SYSVOL", spath)] = {"gpo_guid": gpo_guid, "size_bytes": size,
                                                  "credential_indicators": indicators}

    netlogon_ok = True
    netlogon_detail = None
    try:
        files = []
        _walk_scripts(reader, "NETLOGON", "", 0, [max_script_files], files)
        for spath, size in files:
            data = _read_optional(reader, "NETLOGON", spath, MAX_SCRIPT_FILE_BYTES)
            if data is None:
                continue
            indicators = scan_script(data)
            if indicators:
                scripts_desired[("NETLOGON", spath)] = {"gpo_guid": None, "size_bytes": size,
                                                        "credential_indicators": indicators}
    except _GpoReadFailed as exc:
        netlogon_ok = False
        netlogon_detail = exc.detail

    # Carry forward what couldn't be re-read.
    for gpo_guid in unreadable_gpos:
        _carry_forward(pg_cur, "gpo_setting_edge", client_id,
                       ["gpo_guid", "scope", "source", "section", "setting_key"],
                       ["value_type", "setting_value"], "gpo_guid = %s", [gpo_guid], settings_desired)
        _carry_forward(pg_cur, "gpo_preference_item_edge", client_id,
                       ["gpo_guid", "scope", "preference_type", "item_uid"],
                       ["item_name", "action", "has_cpassword", "account_name", "details_json"],
                       "gpo_guid = %s", [gpo_guid], prefs_desired)
        _carry_forward(pg_cur, "sysvol_script_edge", client_id, ["share", "file_path"],
                       ["gpo_guid", "size_bytes", "credential_indicators"],
                       "gpo_guid = %s", [gpo_guid], scripts_desired)
    if not netlogon_ok:
        _carry_forward(pg_cur, "sysvol_script_edge", client_id, ["share", "file_path"],
                       ["gpo_guid", "size_bytes", "credential_indicators"],
                       "share = 'NETLOGON'", [], scripts_desired)

    # size_bytes is informational: only a change in what was FOUND versions a
    # script row, not an edit that leaves the same indicators.
    opened = closed = 0
    for table, keys, desired, payload in (
        ("gpo_setting_edge", ["gpo_guid", "scope", "source", "section", "setting_key"],
         settings_desired, ["value_type", "setting_value"]),
        ("gpo_preference_item_edge", ["gpo_guid", "scope", "preference_type", "item_uid"],
         prefs_desired, ["item_name", "action", "has_cpassword", "account_name", "details_json"]),
        ("sysvol_script_edge", ["share", "file_path"], scripts_desired,
         ["gpo_guid", "credential_indicators"]),
    ):
        o, c = sync_edges(pg_cur, table, client_id, run_id, run_timestamp, keys, desired,
                          payload_cols=payload)
        opened += o
        closed += c

    pg_cur.execute("DELETE FROM ad_gpo_sysvol WHERE client_id = %s", (client_id,))
    for gpo_guid, path, status, version, files, detail in status_rows:
        pg_cur.execute(
            "INSERT INTO ad_gpo_sysvol (client_id, gpo_object_guid, sysvol_path, read_status, "
            "gpt_ini_version, files_read, error_detail, run_id, collected_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (client_id, gpo_guid, path, status, version, files, detail, run_id, run_timestamp),
        )

    overall = "ok" if not unreadable_gpos and netlogon_ok else "partial"
    detail_bits = []
    if unreadable_gpos:
        detail_bits.append(f"{len(unreadable_gpos)} GPO folder(s) unreadable (previous data kept)")
    if not netlogon_ok:
        detail_bits.append(f"NETLOGON unreadable: {netlogon_detail}")
    write_collection_status(pg_cur, client_id, run_id, run_timestamp, smb_host, overall,
                            gpos_read, len(unreadable_gpos), netlogon_ok,
                            "; ".join(detail_bits) or None)
    log(f"SYSVOL: {gpos_read} GPO folder(s) read, {len(unreadable_gpos)} unreadable, "
        f"NETLOGON {'read' if netlogon_ok else 'unreadable'}; {opened} edge(s) opened, {closed} closed")
    return opened, closed


def write_collection_status(pg_cur, client_id, run_id, run_timestamp, smb_host, status,
                            gpos_read, gpos_unreadable, netlogon_read, detail):
    pg_cur.execute(
        "INSERT INTO sysvol_collection_status (client_id, run_id, collected_at, smb_host, status, "
        "gpos_read, gpos_unreadable, netlogon_read, detail) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) "
        "ON CONFLICT (client_id) DO UPDATE SET run_id = EXCLUDED.run_id, "
        "collected_at = EXCLUDED.collected_at, smb_host = EXCLUDED.smb_host, "
        "status = EXCLUDED.status, gpos_read = EXCLUDED.gpos_read, "
        "gpos_unreadable = EXCLUDED.gpos_unreadable, netlogon_read = EXCLUDED.netlogon_read, "
        "detail = EXCLUDED.detail",
        (client_id, run_id, run_timestamp, smb_host, status, gpos_read, gpos_unreadable,
         netlogon_read, detail),
    )
