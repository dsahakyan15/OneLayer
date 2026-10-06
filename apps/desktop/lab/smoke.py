#!/usr/bin/python3
"""Reproducible disposable installation + native window smoke, no account login.

Beyond the mapped-window smoke this now exercises REAL actions through the
*installed* prefix, bound to a separate source root that contains spaces:

* the A1 operator-address helper (``--ensure`` then read-only) under an
  isolated throwaway ``HOME`` — the same address back, key file 0600 there and
  **nothing** created in the real home directory;
* the A1 signer contract against the real ``live-demo-sign.ts`` (a refusable
  request returns a code-only refusal) and a happy-path fixture signature for
  the ensured address;
* a real A4 QR decode of a generated PNG through the real helper.

Nothing here writes to a chain, and no persistent key is generated or copied.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile

LAB_MODULES = ("native.py", "launcher_view.py", "launcher_state.py", "broker.py", "callback.py", "session.py",
     "live_demo_api.py", "live_demo_session.py", "live_demo_runtime.py", "live_demo_signer.py",
     "live_demo_qr.py", "live_demo_controller.py", "live_demo_view.py")

HELPER_PATHS = (
    "apps/demo-api/scripts/live-demo-sign.ts",
    "apps/desktop/lab/live-demo-operator-address.ts",
    "apps/mvp-web/scripts/live-demo-qr-decode.mjs",
)

parser = argparse.ArgumentParser()
parser.add_argument("--screenshot", type=Path, required=True)
args = parser.parse_args()
source = Path(__file__).resolve().parent
repo_root = source.parents[2]
screenshot = args.screenshot.absolute()
node = shutil.which("node")
if node is None:
    raise SystemExit("node is required for the real-action checks")

REAL_KEY_PATH = (Path(os.environ.get("HOME") or Path.home()) / ".local" / "state"
                 / "onelayer-devnet-demo" / "keys" / "demo-operator.json")


def run_python(installed: Path, body: str, *, home: Path, timeout: int = 60):
    """Run one snippet against the installed prefix with an isolated HOME."""
    script = "import json, os, sys\nsys.path.insert(0, %r)\n" % str(installed) + body
    return subprocess.run(["/usr/bin/python3", "-c", script],
                          env=dict(os.environ, HOME=str(home)), capture_output=True, text=True,
                          timeout=timeout)


def check(result, what: str) -> dict:
    if result.returncode != 0:
        raise RuntimeError(f"{what} failed: {result.stderr or result.stdout}")
    if result.stderr:
        raise RuntimeError(f"{what} wrote to stderr: {result.stderr}")
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    return json.loads(lines[-1])


# The Node helpers only run their main() when the invoked entry path is their
# own module URL, so the entry scripts are copied into the stand-in tree (never
# symlinked); their dependencies are reached through symlinked subtrees.
ENTRY_COPIES = (
    ("apps", "demo-api", "scripts", "live-demo-sign.ts"),
    ("apps", "demo-api", "scripts", "live-demo-key-store.ts"),
    ("apps", "mvp-web", "scripts", "live-demo-qr-decode.mjs"),
    ("apps", "desktop", "lab", "live-demo-operator-address.ts"),
    ("apps", "desktop", "lab", "live-demo-smoke-request.ts"),
)
ENTRY_LINKS = (
    ("apps", "demo-api", "src"),
    ("apps", "demo-api", "node_modules"),
    ("apps", "mvp-web", "node_modules"),
    ("packages",),
)


def build_spaced_source(repo_root: Path, spaced: Path) -> None:
    """Build a separate source-root stand-in whose path contains spaces."""
    spaced.mkdir()
    for parts in ENTRY_LINKS:
        link = spaced.joinpath(*parts)
        link.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(repo_root.joinpath(*parts), link)
    for parts in ENTRY_COPIES:
        original = repo_root.joinpath(*parts)
        if not original.is_file():
            raise RuntimeError("source checkout is missing helper: " + original.name)
        target = spaced.joinpath(*parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, target)
    for name in HELPER_PATHS:
        if not (spaced / name).is_file():
            raise RuntimeError("spaced source root is missing helper: " + name)


with tempfile.TemporaryDirectory(prefix="onelayer-desktop-") as temporary:
    temporary = Path(temporary)
    prefix = temporary / "prefix with spaces"
    subprocess.run(["/usr/bin/python3", str(source / "install.py"), str(prefix)], check=True)
    installed = prefix / "lib" / "onelayer-desktop-lab"
    missing = [name for name in LAB_MODULES if not (installed / name).is_file()]
    if missing:
        raise RuntimeError("Installed prefix is missing modules: " + ", ".join(missing))
    binding = installed / "live_demo_source_root.py"
    if not binding.is_file():
        raise RuntimeError("Installed prefix is missing the source-root binding")
    launcher = prefix / "bin" / "onelayer-desktop-lab"
    native = subprocess.run([str(launcher), "--smoke", "--screenshot", str(screenshot)],
                            capture_output=True, text=True, timeout=15)
    if native.returncode != 0:
        raise RuntimeError("Native smoke failed: " + native.stderr)
    if native.stderr:
        raise RuntimeError("Native smoke wrote to stderr: " + native.stderr)
    if '"native_window": "mapped"' not in native.stdout:
        raise RuntimeError("Native smoke did not confirm a mapped window: " + native.stdout)
    print("PASS: native window rendered without stderr output")
    if not screenshot.is_file() or screenshot.stat().st_size == 0:
        raise RuntimeError("Native capture missing")
    for name in ("native.py", "launcher_view.py", "launcher_state.py"):
        print(name, "sha256", hashlib.sha256((installed / name).read_bytes()).hexdigest())
    refusal = subprocess.run(["/usr/bin/python3", str(source / "install.py"), str(prefix)], capture_output=True)
    if refusal.returncode == 0:
        raise RuntimeError("Installer overwrote existing prefix")
    print("PASS: existing-prefix install refused")

    # -- real actions through an installed prefix bound to a spaced source root
    spaced = temporary / "source root with spaces"
    build_spaced_source(repo_root, spaced)
    actions_prefix = temporary / "prefix real actions"
    subprocess.run(["/usr/bin/python3", str(source / "install.py"), str(actions_prefix),
                    "--source-root", str(spaced)], check=True)
    actions = actions_prefix / "lib" / "onelayer-desktop-lab"
    bound = (actions / "live_demo_source_root.py").read_text()
    if str(spaced) not in bound or len(bound) > 4096:
        raise RuntimeError("source-root binding is not the bounded spaced path")
    print("PASS: install bound to a separate source root with spaces")

    isolated_home = temporary / "isolated home"
    # 0700: the A1 key store refuses group-writable ancestors on purpose.
    isolated_home.mkdir(mode=0o700)
    key_before = REAL_KEY_PATH.is_file()
    before_bytes = REAL_KEY_PATH.read_bytes() if key_before else None

    # 1. public operator address: ensure, then read-only, same address.
    ensure = run_python(actions, """
from live_demo_signer import OperatorSigner
signer = OperatorSigner()
created = signer.operator_address(ensure=True)
looked = signer.operator_address()
print(json.dumps({"created": vars(created), "looked": vars(looked)}))
""", home=isolated_home)
    identity = check(ensure, "installed operator-address ensure/read")
    created, looked = identity["created"], identity["looked"]
    if not created["created"] or looked["created"]:
        raise RuntimeError("ensure/read created flags are wrong: " + json.dumps(identity))
    if created["address"] != looked["address"] or not created["address"]:
        raise RuntimeError("ensure/read disagree on the address")
    if set(created) != {"address", "path", "created"} or set(looked) != {"address", "path", "created"}:
        raise RuntimeError("address helper leaked extra fields: " + json.dumps(identity))
    key_path = Path(created["path"])
    if not str(key_path).startswith(str(isolated_home)):
        raise RuntimeError("key was not created under the isolated home: " + created["path"])
    mode = stat.S_IMODE(key_path.stat().st_mode)
    if mode & 0o077:
        raise RuntimeError("isolated key file is not private: " + oct(mode))
    print("PASS: installed operator-address ensure/read (isolated HOME, key 0600)")

    # 2. A1 signer contract against the real helper: a refusable request is
    #    code-only, and the happy-path fixture for this address really signs.
    bogus = {
        "approved": True, "intentId": "11111111-2222-3333-4444-555555555555",
        "cluster": "solana:devnet", "intentHash": "dd" * 32,
        "transactionBase64": "AQE=", "instructionData": "AAAA", "intent": {},
    }
    contract = run_python(actions, """
from live_demo_signer import SignerError, OperatorSigner
signer = OperatorSigner()
try:
    signer.sign(json.loads(%r))
except SignerError as error:
    print(json.dumps({"refused": error.code}))
else:
    print(json.dumps({"refused": None}))
""" % json.dumps(bogus), home=isolated_home)
    refused = check(contract, "installed signer contract refusal")
    code = refused["refused"]
    if not isinstance(code, str) or not code.isupper() or code in ("SIGNER_UNAVAILABLE",):
        raise RuntimeError("the real A1 helper was not reached: " + json.dumps(refused))
    print("PASS: installed signer contract (real A1 refusal code: " + code + ")")

    builder = spaced / "apps" / "desktop" / "lab" / "live-demo-smoke-request.ts"
    built = subprocess.run(
        [node, "--experimental-transform-types", "--disable-warning=ExperimentalWarning",
         str(builder), "--operator", created["address"]],
        capture_output=True, text=True, timeout=60)
    if built.returncode != 0 or built.stderr:
        raise RuntimeError("request builder failed: " + (built.stderr or built.stdout))
    request = json.loads(built.stdout)
    sign = run_python(actions, """
from live_demo_signer import OperatorSigner
signed = OperatorSigner().sign(json.loads(%r))
print(json.dumps({"signedLength": len(signed), "signed": signed}))
""" % json.dumps(request), home=isolated_home)
    signed = check(sign, "installed signer happy path")["signed"]
    if not signed or len(signed) < 64 or not all(ch.isalnum() or ch in "+/=" for ch in signed):
        raise RuntimeError("happy-path signature is not a signed wire transaction")
    print("PASS: installed signer happy-path fixture signature (" + str(len(signed)) + " base64 chars)")

    # 3. real QR decode of a generated PNG through the real A4 helper.
    good_url = "http://127.0.0.1:8090/c/" + "ab" * 16 + "?h=" + "A" * 43
    image = temporary / "real-qr.png"
    generator = temporary / "qr-gen.mjs"
    helper = spaced / "apps" / "mvp-web" / "scripts" / "live-demo-qr-decode.mjs"
    generator.write_text(
        "import { createRequire } from 'node:module';\n"
        "import { writeFileSync } from 'node:fs';\n"
        f"const require = createRequire({json.dumps(str(helper))});\n"
        "const QRCode = require('qrcode');\n"
        "const [out, payload] = process.argv.slice(2);\n"
        "const buf = await QRCode.toBuffer(payload, "
        "{ type: 'png', errorCorrectionLevel: 'M', margin: 2, width: 256 });\n"
        "writeFileSync(out, buf);\n"
    )
    made = subprocess.run([node, str(generator), str(image), good_url],
                          capture_output=True, text=True, timeout=60)
    if made.returncode != 0 or not image.read_bytes().startswith(b"\x89PNG"):
        raise RuntimeError("QR generation failed: " + (made.stderr or made.stdout))
    decode = run_python(actions, f"""
from live_demo_qr import QrImageDecoder
from pathlib import Path
decoder = QrImageDecoder()
if not decoder.available:
    raise SystemExit("QR helper unavailable through the binding")
print(json.dumps({{"payload": decoder.decode(Path({str(image)!r}))}}))
""", home=isolated_home)
    payload = check(decode, "installed QR decode")["payload"]
    if payload != good_url:
        raise RuntimeError("QR decode did not round-trip: " + payload)
    print("PASS: installed QR decode round-tripped the generated PNG")

    if key_before:
        if not REAL_KEY_PATH.is_file() or REAL_KEY_PATH.read_bytes() != before_bytes:
            raise RuntimeError("the real home key store was modified by the smoke")
    elif REAL_KEY_PATH.exists():
        raise RuntimeError("the smoke created a persistent key in the real home")
    print("PASS: no persistent key generated or copied; no chain writes")

    environment = dict(os.environ, DBUS_SESSION_BUS_ADDRESS=f"unix:path={temporary}/missing-service")
    unavailable = subprocess.run(["/usr/bin/python3", "-c",
        "from broker import NativeCredentialStore; NativeCredentialStore().save('lab', 'synthetic-only')"],
        cwd=source, env=environment, capture_output=True, timeout=10)
    if unavailable.returncode == 0 or b"No such file or directory" not in unavailable.stderr:
        raise RuntimeError("Missing credential service did not produce expected failure")
    print("PASS: absent credential service refused write; no plaintext fallback")
print("PASS: temporary installation removed")
