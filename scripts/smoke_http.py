"""Run against the authorized local synthetic demo; never echo token or document bodies."""

import argparse
import json
import uuid
from pathlib import Path
from urllib.request import Request, urlopen

from aegisvault.cli import private_json

parser = argparse.ArgumentParser()
parser.add_argument("--url", default="http://127.0.0.1:8000")
parser.add_argument("--state", type=Path, default=Path(".aegisvault"))
args = parser.parse_args()
if not args.url.startswith("http://127.0.0.1:"):
    raise SystemExit("This smoke command only targets a loopback demo.")
token = private_json(args.state / "demo-token.json")["token"]


def request(path, method="GET", body=None):
    req = Request(
        args.url + path,
        method=method,
        data=None if body is None else json.dumps(body).encode(),
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
    )
    with urlopen(req, timeout=5) as response:
        assert response.headers["Cache-Control"] == "no-store"
        return json.load(response)


rid = "smoke-" + uuid.uuid4().hex
path = "/api/records/customers/" + rid
doc = {"name": "Synthetic Smoke", "email": rid + "@example.test", "profile": {"nested": [1, True]}}
assert request(path, "PUT", {"document": doc})["revision"] == 1
assert request(path)["document"] == doc
assert (
    request("/api/search/customers", "POST", {"field": "email", "values": [doc["email"].upper()]})[
        "records"
    ][0]["id"]
    == rid
)
assert request("/api/audit/checkpoint")["seq"] >= 3
assert request(path, "DELETE", {"expected_revision": 1})["deleted"] is True
print("PASS: live HTTP create/read/normalized search/audit/delete; no-store headers")
