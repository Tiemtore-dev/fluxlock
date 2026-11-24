#!/usr/bin/env python3
"""Register only the supplied extension ID. Dry-run unless --install is given."""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import tempfile


DEFAULT_EXTENSION_ID = "oifhfkkohaimodaedcjbnfbamhgocndg"


def prepare(host: Path, extension_id: str, browser: str, test: bool):
    if not re.fullmatch(r"[a-p]{32}", extension_id):
        raise ValueError("L’identifiant Chromium doit contenir exactement 32 lettres de a à p.")
    host = host.resolve(strict=True)
    if not host.is_file() or (os.name != "nt" and not os.access(host, os.X_OK)):
        raise ValueError("Choisissez le binaire exécutable fluxlock-browser-host.")
    name = "com.fluxlock.browser.test" if test else "com.fluxlock.browser"
    system = platform.system()
    if system == "Darwin":
        directories = {"chrome": "Google/Chrome", "brave": "BraveSoftware/Brave-Browser", "edge": "Microsoft Edge"}
        folder = Path.home() / "Library/Application Support" / directories[browser] / "NativeMessagingHosts"
    elif system == "Windows":
        folder = Path(os.environ["LOCALAPPDATA"]) / "FluXlock Browser Host" / browser
    else:
        directories = {"chrome": "google-chrome", "brave": "BraveSoftware/Brave-Browser", "edge": "microsoft-edge"}
        folder = Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))) / directories[browser] / "NativeMessagingHosts"
    manifest = {"name": name, "description": "FluXlock local encrypted browser relay", "path": str(host), "type": "stdio", "allowed_origins": [f"chrome-extension://{extension_id}/"]}
    return folder / f"{name}.json", manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, type=Path)
    parser.add_argument("--extension-id", default=DEFAULT_EXTENSION_ID)
    parser.add_argument("--browser", choices=["chrome", "brave", "edge"], required=True)
    parser.add_argument("--test-profile", action="store_true")
    parser.add_argument("--install", action="store_true")
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args()
    destination, manifest = prepare(args.host, args.extension_id, args.browser, args.test_profile)
    text = json.dumps(manifest, indent=2) + "\n"
    print(f"Manifeste : {destination}")
    print(text, end="")
    if not args.install:
        print("Simulation uniquement. Ajoutez --install pour enregistrer cet hôte.")
        return
    if destination.is_symlink():
        raise ValueError("Le manifeste existant est un lien symbolique.")
    if destination.exists() and destination.read_text() != text and not args.replace:
        raise ValueError("Un autre enregistrement existe. Examinez-le avant d’utiliser --replace.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=destination.parent, delete=False) as staged:
        staged.write(text)
        staged.flush()
        os.fsync(staged.fileno())
        temporary = Path(staged.name)
    try:
        if os.name != "nt":
            temporary.chmod(0o600)
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
    if os.name == "nt":
        import winreg
        vendor = {"chrome": "Google\\Chrome", "brave": "BraveSoftware\\Brave-Browser", "edge": "Microsoft\\Edge"}[args.browser]
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, f"Software\\{vendor}\\NativeMessagingHosts\\{manifest['name']}") as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, str(destination))
    print("Hôte enregistré. Le binaire doit rester à cet emplacement. L’appairage dans FluXlock reste obligatoire.")


if __name__ == "__main__":
    main()
