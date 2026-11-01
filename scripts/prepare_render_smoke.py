"""Generate secrets for the disposable container smoke job. No values reach stdout."""

import base64
import os
import secrets
from pathlib import Path

directory = Path(".secrets")
directory.mkdir(mode=0o700, exist_ok=True)
fd = os.open(directory / "render-smoke.env", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as stream:
    stream.write("DATABASE_URL=postgresql://aegisvault:disposable-smoke-only@db/aegisvault\n")
    stream.write("AEGIS_ALLOW_SYNTHETIC_DEPLOY=yes\n")
    for name in ["AEGIS_WRAPPING_KEY", "AEGIS_SEARCH_KEY", "AEGIS_AUDIT_KEY", "AEGIS_API_TOKEN"]:
        stream.write(name + "=" + base64.b64encode(secrets.token_bytes(32)).decode() + "\n")
print("Disposable container secrets prepared.")
