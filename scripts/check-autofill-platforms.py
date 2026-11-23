#!/usr/bin/env python3
"""Cross-check relay, protocol and real Windows pipe/ACL source; no OS runtime claim.

Requires the corresponding rustup targets. Artifacts stay under native-host/target.
No browser registration, installation, vault access, or complete Tauri build.
"""
import argparse
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
TARGETS = ("x86_64-pc-windows-msvc", "x86_64-unknown-linux-gnu")


def run(*args, env=None):
    print("+ " + " ".join(map(str, args)), flush=True)
    subprocess.run(list(map(str, args)), cwd=ROOT, env=env, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--targets", nargs="+", choices=TARGETS, default=list(TARGETS))
    args = parser.parse_args()
    env = {**os.environ, "CARGO_TARGET_DIR": str(ROOT / "native-host/target/platform-check")}
    for target in args.targets:
        for manifest in ("native-host/Cargo.toml", "autofill-protocol/Cargo.toml"):
            run("cargo", "check", "--locked", "--target", target, "--manifest-path", manifest, env=env)
    if TARGETS[0] in args.targets:
        lock = (ROOT / "tauri-desktop/src-tauri/Cargo.lock").read_text()
        packages = re.findall(r'^name = "(tokio|windows)"\nversion = "([^"]+)"$', lock, re.MULTILINE)
        tokio = next(version for name, version in packages if name == "tokio")
        desktop = (ROOT / "tauri-desktop/src-tauri/Cargo.toml").read_text()
        if ('windows', '0.58.0') not in packages or not re.search(r'windows = \{ version = "0\.58"', desktop):
            raise RuntimeError("Review the Windows probe when updating the desktop windows crate")
        with tempfile.TemporaryDirectory(prefix="fluxlock-windows-compile-") as folder:
            probe = Path(folder)
            # Include the source used in the real app, rather than a copied
            # implementation that could silently diverge.
            source = ROOT / "tauri-desktop/src-tauri/src/autofill/windows_pipe.rs"
            (probe / "Cargo.toml").write_text(f'''[package]
name = "fluxlock-windows-compile-check"
version = "0.0.0"
edition = "2021"
[lib]
path = "lib.rs"
[dependencies]
tokio = {{ version = "={tokio}", features = ["net", "rt", "macros", "io-util"] }}
windows = {{ version = "=0.58.0", features = ["Win32_Foundation", "Win32_Security", "Win32_Security_Authorization"] }}
''')
            (probe / "lib.rs").write_text(f'#[path = {json.dumps(str(source), ensure_ascii=False)}]\nmod windows_pipe;\n', encoding="utf-8")
            run("cargo", "check", "--tests", "--target", TARGETS[0], "--manifest-path", probe / "Cargo.toml", env=env)
    print("Compilation/type checks passed. Native OS execution and full Tauri validation remain separate.", flush=True)


if __name__ == "__main__":
    main()
