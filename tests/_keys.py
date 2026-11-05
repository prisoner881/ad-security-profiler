"""Builds activation keys and license keys for the tests (document 04's format:
base64 of {"k": <license key>, "e": <environment>}; the license key is
<8-digit company>.<b64 integration>.<b64 collector type>.<b64 agent UUID>)."""
import base64
import json

AGENT = "3f6c1d2e-8a4b-4c5d-9e6f-7a8b9c0d1e2f"


def b64(text, urlsafe=False, pad=True):
    raw = text.encode() if isinstance(text, str) else text
    out = (base64.urlsafe_b64encode if urlsafe else base64.b64encode)(raw).decode()
    return out if pad else out.rstrip("=")


def license_key(company="00000012", integ="AD_AUDIT_COLLECTOR", ctype="AD_AUDIT", agent=AGENT,
                **kw):
    return ".".join([company, b64(integ, **kw), b64(ctype, **kw), b64(agent, **kw)])


def activation(k=None, e=None, urlsafe=False, pad=True, extra=None):
    data = {"k": k if k is not None else license_key()}
    if e is not None:
        data["e"] = e
    if extra:
        data.update(extra)
    return b64(json.dumps(data), urlsafe=urlsafe, pad=pad)
