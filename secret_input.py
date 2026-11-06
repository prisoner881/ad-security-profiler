"""
secret_input.py -- where adprofiler.py, entra_graph_collector.py and
adaudit.py get their secrets
==============================================================================
VERSION: 1.1

The three scripts need up to three secrets: the AD bind password
(adprofiler.py), the Entra ID App Registration client secret
(entra_graph_collector.py) and the PostgreSQL password (all three). They used
to come from a command-line option or an interactive getpass prompt only.
An option is visible in shell history and in `ps` output, and a prompt is no
use to a scheduled run (getpass raises EOFError when standard input is not a
terminal and has nothing to read).

resolve_secret() looks in this order and uses the first one found:

    1. The command-line option (--password, --app-secret, --pg-password).
       Still accepted for interactive use, with a warning, because it is
       visible to other users of the machine.
    2. The environment variable: AD_BIND_PASSWORD, ENTRA_APP_SECRET or
       PGPASSWORD (the variable libpq and psql already use). An empty value
       counts as not set.
    3. The file named by <variable>_FILE (AD_BIND_PASSWORD_FILE,
       ENTRA_APP_SECRET_FILE, PGPASSWORD_FILE): its first line, without the
       line ending. Keep such a file readable only by the account that
       runs the scripts.
    4. An interactive prompt with hidden input, only when standard input is
       a terminal.

Setting both <variable> and <variable>_FILE is an error: one of them would
be silently ignored. With none of the four, a required secret raises
SecretUnavailable (the scripts log it and exit 1) instead of a traceback.
The PostgreSQL password is not required: without one, None is passed to
psycopg2, and libpq then uses ~/.pgpass (or the file named by PGPASSFILE --
libpq's own variable for a .pgpass-format file, unrelated to
PGPASSWORD_FILE) or a password-less authentication method, or the
connection fails with libpq's own message.

The value is never logged or printed. describe_source() gives a loggable
description of where it came from ("environment variable PGPASSWORD",
"file named by AD_BIND_PASSWORD_FILE").

CHANGELOG:
    1.0  First version (adprofiler.py 1.0.7, entra_graph_collector.py 1.0.5,
         adaudit.py 1.0.6).
    1.1  resolve_secret(allow_prompt=False) never prompts, and
         read_secret_file() reads a secret from a named file, with the same
         rules as <variable>_FILE.
"""

import getpass
import os
import sys

VERSION = "1.1"

# A secret file larger than this is refused: a secret is a short string, and
# a mistaken path (a log, a disk image) should not be read into memory.
MAX_SECRET_FILE_BYTES = 64 * 1024

FROM_OPTION = "option"
FROM_ENV = "env"
FROM_FILE = "file"
FROM_PROMPT = "prompt"
NOT_GIVEN = "none"


class SecretUnavailable(Exception):
    """A secret could not be obtained. The message says what to set; it never
    contains the secret."""


def read_secret_file(path, described_as):
    """[1.1] First line of the file (or pipe) at path, without its line
    ending. described_as names where the path came from, for messages
    ("the file named by [database] password_file"). Raises
    SecretUnavailable."""
    return _read_secret_file(described_as, path, prefix="")


def _read_secret_file(env_file_var, path, prefix="the file named by "):
    """First line of the file (or pipe) at path, without its line ending."""
    try:
        # newline="" keeps "\r" so that a CRLF file can be handled below,
        # and no other character of the secret is changed.
        with open(path, "r", encoding="utf-8", newline="") as fh:
            content = fh.read(MAX_SECRET_FILE_BYTES + 1)
    except OSError as exc:
        raise SecretUnavailable(
            f"cannot read {prefix}{env_file_var} ({path}): {exc.strerror or exc}")
    except UnicodeDecodeError:
        raise SecretUnavailable(f"{prefix}{env_file_var} ({path}) is not UTF-8 text")
    if len(content) > MAX_SECRET_FILE_BYTES:
        raise SecretUnavailable(
            f"{prefix}{env_file_var} ({path}) is larger than "
            f"{MAX_SECRET_FILE_BYTES // 1024} KiB; it should hold only the secret")
    first_line = content.split("\n", 1)[0]
    if first_line.endswith("\r"):
        first_line = first_line[:-1]
    if not first_line:
        raise SecretUnavailable(f"{prefix}{env_file_var} ({path}) is empty")
    return first_line


def resolve_secret(what, option_value, option_name, env_var, prompt, required=True,
                   allow_prompt=True):
    """Returns (secret, source) where source is one of FROM_OPTION, FROM_ENV,
    FROM_FILE, FROM_PROMPT or NOT_GIVEN (secret None; only when required is
    False). `what` names the secret in messages ("LDAP bind password"),
    option_name is its command-line option ("--password"), env_var its
    environment variable ("AD_BIND_PASSWORD"; the file variant is env_var +
    "_FILE"), prompt the text of the interactive prompt. Raises
    SecretUnavailable when a required secret cannot be obtained, or when the
    environment is contradictory or unreadable. [1.1] allow_prompt=False
    skips the prompt even on a terminal; option_name may then be None (no
    command-line option exists)."""
    if option_value:
        return option_value, FROM_OPTION

    env_file_var = env_var + "_FILE"
    env_value = os.environ.get(env_var) or None
    env_file = os.environ.get(env_file_var) or None
    if env_value is not None and env_file is not None:
        raise SecretUnavailable(
            f"both {env_var} and {env_file_var} are set; set only one of them")
    if env_value is not None:
        return env_value, FROM_ENV
    if env_file is not None:
        return _read_secret_file(env_file_var, env_file), FROM_FILE

    stdin = sys.stdin
    if allow_prompt and stdin is not None and stdin.isatty():
        try:
            return getpass.getpass(prompt), FROM_PROMPT
        except EOFError:
            pass  # the terminal closed: treat as not given
    if not required:
        return None, NOT_GIVEN
    if not allow_prompt:
        raise SecretUnavailable(
            f"no {what} was given. Set {env_var}, or {env_file_var} to a file holding it "
            f"(first line)"
            + (f", or pass {option_name} (visible in process listings)" if option_name else ""))
    raise SecretUnavailable(
        f"no {what} was given and there is no terminal to prompt on. Set {env_var}, or "
        f"{env_file_var} to a file holding it (first line), or pass "
        f"{option_name} (visible in process listings)")


def describe_source(source, option_name, env_var):
    """Loggable description of where a secret came from (never the secret)."""
    return {
        FROM_OPTION: f"command-line option {option_name}",
        FROM_ENV: f"environment variable {env_var}",
        FROM_FILE: f"file named by {env_var}_FILE",
        FROM_PROMPT: "interactive prompt",
        NOT_GIVEN: "not given",
    }.get(source, source)


def option_warning(what, option_name, env_var):
    """The warning logged when a secret came from a command-line option."""
    return (f"{what} supplied via {option_name} is visible in shell history and process "
            f"listings. Prefer {env_var} or {env_var}_FILE, or omit it to be prompted.")
