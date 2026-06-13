import re

_CONTROL_CHARS = re.compile(r"[\r\n\t\x00-\x1f\x7f]")

SENSITIVE_KEYS = {
    "password", "passwd", "pwd", "secret", "token", "authorization", "cookie", "session", "csrf", "ssn", "card", "cvv",
}

def sanitize(value) -> str:

    text = str(value)
    text = _CONTROL_CHARS.sub("\u2424", text)
    if len (text) > 256:
        text = text[:256] + "...[truncated]"

    return text

def redact(mapping: dict) -> dict:

    out = {}

    for key, val in mapping.items():
        if key.lower() in SENSITIVE_KEYS:
            out[key] = "***REDACTED***"
        else:
            out[key] = sanitize(val)

    return out

    
