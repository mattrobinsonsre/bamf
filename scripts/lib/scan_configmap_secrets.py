"""Fail if a rendered ConfigMap carries a secret-looking value.

Reads a `helm template` stream on stdin. Secrets must flow via secretKeyRef /
existingSecret (Secret resources / env), never inline in a ConfigMap. Exit 1 on
the first offending line.

A line is flagged only when BOTH hold: the key looks secret-ish (contains
password/secret/token/private_key/api_key, allowing prefixes like `db_password`)
AND the value is a real literal (not a bool, number, empty, or a k8s reference).
So config flags like `password_reset_enabled: true` and non-secret keys like
`redis_url:` don't false-positive.
"""

import re
import sys

import yaml

_SECRET_KEY = re.compile(r"(?i)(password|passwd|secret|token|private_key|api_?key)")
_KV = re.compile(r"\s*([A-Za-z0-9_-]+)\s*[:=]\s*(.*)")


def _is_secret_value(v: str) -> bool:
    v = v.strip().strip("\"'")
    if not v:
        return False
    if v.lower() in ("true", "false", "null", "none", "~"):
        return False
    if re.fullmatch(r"-?\d+(\.\d+)?[a-z%]*", v):  # numbers, durations, sizes
        return False
    return True


found = False
for doc in yaml.safe_load_all(sys.stdin):
    if not doc or doc.get("kind") != "ConfigMap":
        continue
    name = doc.get("metadata", {}).get("name", "?")
    for value in (doc.get("data") or {}).values():
        for line in str(value).splitlines():
            if "secretKeyRef" in line or "existingSecret" in line:
                continue
            m = _KV.match(line)
            if m and _SECRET_KEY.search(m.group(1)) and _is_secret_value(m.group(2)):
                print(f"SECRET IN CONFIGMAP {name}: {line.strip()[:100]}")
                found = True

sys.exit(1 if found else 0)
