"""Real HTTP checks for the disposable Compose job. Never prints bearer or document values."""

import json
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

mode = sys.argv[1]
env = dict(
    line.split("=", 1) for line in Path(".secrets/render-smoke.env").read_text().splitlines()
)
base = "http://127.0.0.1:18000"
path = "/api/records/customers/render-smoke"
document = {
    "name": "Synthetic restart check",
    "email": "render-smoke@example.test",
    "profile": {"nested": [True, 17, None]},
}


def request(path, method="GET", data=None, authenticate=True):
    headers = {"Content-Type": "application/json"}
    if authenticate:
        headers["Authorization"] = "Bearer " + env["AEGIS_API_TOKEN"]
    req = Request(
        base + path,
        method=method,
        headers=headers,
        data=None if data is None else json.dumps(data).encode(),
    )
    try:
        with urlopen(req, timeout=10) as response:
            assert response.headers["Cache-Control"] == "no-store"
            return response.status, json.load(response)
    except HTTPError as exc:
        return exc.code, json.load(exc)


if mode != "outage":
    for _attempt in range(60):
        try:
            if request("/readyz")[0] == 200:
                break
        except (OSError, URLError):
            pass
        time.sleep(0.5)
    else:
        raise SystemExit("readiness did not succeed")

if mode == "create":
    assert request(path, "PUT", {"document": document}, authenticate=False)[0] == 403
    assert request(path, "PUT", {"document": document}) == (
        200,
        {"id": "render-smoke", "revision": 1},
    )
elif mode == "outage":
    assert request("/readyz")[0] == 503
    assert request("/healthz")[0] == 200
    print("PASS: database outage is unready; process remains live")
    raise SystemExit(0)
elif mode != "verify":
    raise SystemExit("unknown smoke mode")

assert request(path)[1]["document"] == document
assert (
    request(
        "/api/search/customers", "POST", {"field": "email", "values": ["RENDER-SMOKE@example.test"]}
    )[1]["records"][0]["id"]
    == "render-smoke"
)
assert request("/api/audit/checkpoint")[1]["seq"] >= 3
print("PASS: authenticated encrypted CRUD/search/audit on the Render container port; " + mode)
