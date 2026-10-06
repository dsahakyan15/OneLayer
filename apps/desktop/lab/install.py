#!/usr/bin/python3
"""Install the runtime harness into a NEW disposable prefix, without host mutation.

The prefix carries only the Python modules and one generated
``live_demo_source_root.py`` binding: a single bounded, non-secret absolute
path to the trusted source tree whose Node helpers (A1 signer, operator
address, A4 QR decoder) the installed launcher runs. No key material and no
repository content is copied into the prefix.
"""
import argparse
from pathlib import Path
import shlex
import shutil

MODULES = ("native.py", "launcher_view.py", "launcher_state.py", "broker.py", "callback.py", "session.py",
     "live_demo_api.py", "live_demo_session.py", "live_demo_runtime.py", "live_demo_signer.py",
     "live_demo_qr.py", "live_demo_controller.py", "live_demo_view.py")

MAX_SOURCE_ROOT_CHARS = 1024
HELPER_PATHS = (
    "apps/demo-api/scripts/live-demo-sign.ts",
    "apps/desktop/lab/live-demo-operator-address.ts",
    "apps/mvp-web/scripts/live-demo-qr-decode.mjs",
)

parser = argparse.ArgumentParser()
parser.add_argument("prefix", type=Path)
parser.add_argument("--source-root", type=Path, default=None,
                    help="Trusted source tree holding the Node helpers "
                         "(default: the checkout this installer runs from)")
args = parser.parse_args()
prefix = args.prefix.absolute()
source_root = (args.source_root or Path(__file__).resolve().parents[3]).absolute()
if not source_root.is_absolute() or len(str(source_root)) > MAX_SOURCE_ROOT_CHARS:
    raise SystemExit("source root is invalid")
if not source_root.is_dir():
    raise SystemExit("source root is not a directory")
missing = [name for name in HELPER_PATHS if not (source_root / name).is_file()]
if missing:
    raise SystemExit("source root is missing helpers: " + ", ".join(missing))
prefix.mkdir(parents=False, exist_ok=False)
(prefix / "bin").mkdir()
destination = prefix / "lib" / "onelayer-desktop-lab"
destination.mkdir(parents=True)
for name in MODULES:
    source = Path(__file__).parent / name
    if not source.is_file():
        raise SystemExit(f"missing lab module: {name}")
    shutil.copyfile(source, destination / name)
# Bounded non-secret binding so the installed prefix can find the Node
# helpers. One absolute path, validated below and again before every use.
(destination / "live_demo_source_root.py").write_text(
    '"""Installer-written binding to the trusted source tree (one path, no secrets)."""\n'
    f"SOURCE_REPO_ROOT = {str(source_root)!r}\n"
)
launcher = prefix / "bin" / "onelayer-desktop-lab"
launcher.write_text("#!/bin/sh\nexec /usr/bin/python3 " + shlex.quote(str(destination / "native.py")) + ' "$@"\n')
launcher.chmod(0o755)
print(launcher)
