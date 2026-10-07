#!/usr/bin/env python3
"""Provision the localhost lab monitor's retained private configuration."""
import json
import os
from pathlib import Path
import runpy
import sys
import urllib.parse
import urllib.request

helpers = runpy.run_path(str(Path(__file__).with_name("initialize-audit.py")))
private_directory = helpers["private_directory"]
read_private = helpers["read_private"]
create_private = helpers["create_private"]


def retained_file(path, value):
    if path.exists() or path.is_symlink():
        if json.loads(read_private(path)) != value:
            raise ValueError("retained monitor material does not match deployment")
    else:
        create_private(path, json.dumps(value) + "\n")


def main():
    os.umask(0o077)
    root = private_directory(sys.argv[1])
    dsn_file, keys_file, registry, genesis = sys.argv[2:6]
    with urllib.request.urlopen("http://127.0.0.1:8090/v1/health", timeout=5) as response:
        health = json.load(response)
    if health.get("registryId") != registry or health.get("genesisHash") != genesis or health.get("cluster") != "solana:local":
        raise ValueError("monitor deployment identity mismatch")
    # The dedicated role has no signing credentials and is checked for write
    # privileges by the monitor itself. This lab cluster uses loopback trust;
    # production credential provisioning remains a separate deployment gate.
    dsn = urllib.parse.urlsplit(read_private(dsn_file).strip())
    if dsn.scheme != "postgresql" or dsn.hostname != "127.0.0.1" or dsn.password:
        raise ValueError("monitor provisioning requires the explicit local lab database")
    source_dsn = urllib.parse.urlunsplit((dsn.scheme, "onelayer_monitor@127.0.0.1:" + str(dsn.port), dsn.path, "", ""))
    keys = json.loads(read_private(keys_file))
    if set(keys) != {"idKey", "fieldKeyMaster"}:
        raise ValueError("monitor verification key schema mismatch")
    for value in keys.values():
        if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise ValueError("invalid monitor verification material")
    retained_file(root / "keys.json", keys)
    private_directory(root / "evidence")
    retained_file(root / "monitor.json", {
        "registryId": registry, "programId": health["programId"], "configPda": health["configPda"],
        "rpcUrl": "http://127.0.0.1:18899", "sourceDsn": source_dsn,
        "keysFile": str(root / "keys.json"), "evidenceDir": str(root / "evidence"),
        "evidenceFloorFile": str(root / "evidence.floor.json"), "pollIntervalMs": 5000,
    })


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("monitor provisioning refused: " + type(error).__name__, file=sys.stderr)
        sys.exit(1)
