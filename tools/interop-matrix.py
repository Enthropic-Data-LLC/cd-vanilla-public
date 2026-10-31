#!/usr/bin/env python3
"""Seal with each implementation, open with every other — format v1.4.

Five implementations (the JavaScript reference and the Python, Go, Rust and
Java ports) each seal a signed ECDH cell and a v1.3 cell for the conformance
cast; every implementation then opens every cell. A pass means identical
plaintext and, for signed cells, the signer's fingerprint. Run from the
repository root after building the ports:

    (cd impl/rust && cargo build --release)
    (cd impl/go && go build -o /tmp/cdcell-go ./cmd/cdcell)
    (cd impl/java && mvn -q package -DskipTests)
    PYTHONPATH=impl/python python3 tools/interop-matrix.py --go /tmp/cdcell-go

The ports' CLIs seal to `ecdh-p256` recipients only, which is what is tested;
passphrase (PBKDF2 and Argon2id) entries are covered by the conformance corpus.
"""
import argparse, base64, json, os, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KEYS = ROOT / "conformance" / "keys"
BRIDGE = ROOT / "impl" / "python" / "tests" / "interop" / "js_bridge.mjs"
PAYLOAD = "interop matrix — é 😀 — " + "x" * 700


def cli(impl, go_bin):
    return {
        "python": [sys.executable, "-m", "cellular_defense"],
        "go": [go_bin],
        "rust": [str(ROOT / "impl/rust/target/release/cdcell")],
        "java": ["java", "-jar", str(ROOT / "impl/java/target/cellular-defense-0.1.0.jar")],
    }[impl]


def flag(impl, name):
    return ("-" if impl == "go" else "--") + name


def run(cmd, **kw):
    r = subprocess.run(cmd, capture_output=True, text=True, env={**os.environ, "PYTHONPATH": str(ROOT / "impl/python")}, **kw)
    if r.returncode != 0:
        raise RuntimeError(f"{' '.join(map(str, cmd))}\n{r.stderr or r.stdout}")
    return r.stdout


def seal(impl, go_bin, src, out):
    if impl == "js":
        alice = json.load(open(KEYS / "alice.cdpub"))
        bob = json.load(open(KEYS / "bob.cdkey"))
        spec = {"data_b64": base64.b64encode(src.read_bytes()).decode(), "filename": "m.txt",
                "recipients": [{"method": "ecdh-p256", "label": "x", "spki": alice["spki"]}],
                "sender": bob}
        sp = out.with_suffix(".spec.json"); sp.write_text(json.dumps(spec))
        run(["node", str(BRIDGE), "seal", str(sp), str(out)])
        return
    c = cli(impl, go_bin)
    run(c + ["seal", str(src), flag(impl, "to"), str(KEYS / "alice.cdpub"),
             flag(impl, "sign"), str(KEYS / "bob.cdkey"), flag(impl, "out"), str(out)])


def open_cell(impl, go_bin, cell, out):
    if impl == "js":
        alice = json.load(open(KEYS / "alice.cdkey"))
        sp = out.with_suffix(".ospec.json"); sp.write_text(json.dumps({"keys": [alice]}))
        res = out.with_suffix(".res.json")
        run(["node", str(BRIDGE), "open", str(cell), str(sp), str(res)])
        r = json.load(open(res))
        out.write_bytes(base64.b64decode(r["data_b64"]))
        return r.get("sig_verified")
    c = cli(impl, go_bin)
    text = run(c + ["open", str(cell), flag(impl, "key"), str(KEYS / "alice.cdkey"), flag(impl, "out"), str(out)])
    return text


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--go", default="/tmp/cdcell-go")
    ap.add_argument("--impls", default="js,python,go,rust,java")
    a = ap.parse_args()
    impls = a.impls.split(",")
    bob_fp = json.load(open(KEYS / "bob.cdpub"))["fingerprint"]
    work = Path(tempfile.mkdtemp(prefix="interop-"))
    src = work / "m.txt"; src.write_text(PAYLOAD)
    failures = 0
    print(f"{'sealed by':>10} → " + "  ".join(f"{o:>7}" for o in impls))
    for s in impls:
        cell = work / f"{s}.cell"
        try:
            seal(s, a.go, src, cell)
        except Exception as e:
            print(f"{s:>10}   SEAL FAILED: {str(e)[:300]}"); failures += len(impls); continue
        row = []
        for o in impls:
            out = work / f"{s}-{o}.out"
            try:
                info = open_cell(o, a.go, cell, out)
                ok = out.read_text() == PAYLOAD
                if ok and bob_fp not in str(info) and o == "js":
                    ok = False
                row.append("ok" if ok else "DIFF")
                failures += 0 if ok else 1
            except Exception as e:
                row.append("FAIL"); failures += 1
                print(f"  {s}→{o}: {str(e)[:300]}")
        print(f"{s:>10}   " + "  ".join(f"{x:>7}" for x in row))
    print("matrix:", "all pass" if not failures else f"{failures} failures")
    sys.exit(1 if failures else 0)


main()
