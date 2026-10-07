#!/usr/bin/env python3
"""Provision retained, private lab audit state; never expose capabilities."""
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys
import tempfile
import urllib.request


def private_directory(path):
    path = Path(path)
    if not path.is_absolute():
        raise ValueError("audit state must be absolute")
    for parent in [*reversed(path.parents), path]:
        if not parent.exists():
            parent.mkdir(mode=0o700)
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError("audit state ancestor is not a real directory")
    info = path.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("audit state must be owner-private")
    return path


def read_private(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_size > 65536:
            raise ValueError("audit provisioning input is not owner-private")
        return os.read(fd, 65537).decode()
    finally:
        os.close(fd)


def create_private(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as output:
        output.write(value)
        output.flush()
        os.fsync(output.fileno())


def main():
    os.umask(0o077)
    if sys.argv[1] == "check":
        root = Path(sys.argv[2])
        request = urllib.request.Request("http://127.0.0.1:18991/v1/status", headers={"Authorization": "Bearer " + read_private(root / "status.cap").strip()})
        with urllib.request.urlopen(request, timeout=2) as response:
            if response.status != 200:
                raise ValueError("audit status unavailable")
            # Readiness means the protected process responds, not that its
            # independently reported projection is CURRENT.
            json.load(response)
        return
    root = private_directory(sys.argv[1])
    binary, dsn_file, registry = sys.argv[2:5]
    private_directory(root / "sink")
    key = root / "cap.key"
    if key.exists() or key.is_symlink():
        value = read_private(key).strip()
        if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise ValueError("invalid retained audit key")
    else:
        # A missing key with retained evidence is a loss of trust, never a
        # reason to silently provision a new signing authority.
        if any((root / "sink").iterdir()):
            raise ValueError("retained audit evidence has no capability key")
        create_private(key, secrets.token_hex(32) + "\n")
    config = {"listen": "127.0.0.1:18991", "stateDir": str(root / "sink"), "capabilityKeyFile": str(key), "projectionDsn": read_private(dsn_file).strip(), "sources": ["demo-api"], "registries": [registry]}
    config_file = root / "audit.json"
    if config_file.exists() or config_file.is_symlink():
        if json.loads(read_private(config_file)) != config:
            raise ValueError("retained audit configuration does not match deployment")
    else:
        create_private(config_file, json.dumps(config) + "\n")
    for operation in ["append", "read", "export", "rebuild", "status"]:
        destination = root / (operation + ".cap")
        if destination.exists() or destination.is_symlink():
            read_private(destination)
        fd, temporary = tempfile.mkstemp(prefix=".cap-", dir=root)
        os.close(fd)
        try:
            subprocess.run([binary, "issue-capability", "--config", str(config_file), "--op", operation, "--source", "demo-api", "--registry", registry, "--subject", "demo-api", "--expires-ms", "86400000", "--out", temporary], check=True, stdout=subprocess.DEVNULL)
            read_private(temporary)
            os.replace(temporary, destination)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Config and capabilities must never be included in diagnostics.
        print("audit provisioning refused: " + type(error).__name__, file=sys.stderr)
        sys.exit(1)
