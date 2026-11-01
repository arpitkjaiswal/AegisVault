"""Create private local-demo Compose credentials; refuse overwrite and never print them."""

import os
import secrets
from pathlib import Path

path = Path(__file__).resolve().parents[1] / ".env"
password = secrets.token_hex(32)
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as stream:
    stream.write(f"AEGIS_POSTGRES_PASSWORD={password}\n")
    stream.write(f"AEGIS_DATABASE_URL=postgresql+psycopg://aegisvault:{password}@db/aegisvault\n")
    stream.flush()
    os.fsync(stream.fileno())
print("Created private .env for synthetic local Compose use. Never commit this file.")
