#!/usr/bin/env python3
"""Configure and verify the provisioning used by the macOS release."""
import argparse
import base64
from datetime import datetime, timezone
from fnmatch import fnmatchcase
import json
import os
from pathlib import Path
import plistlib
import subprocess

APP_ID = "com.fluxlock.app"
APP_IDENTIFIER = "com.apple.application-identifier"
TEAM_IDENTIFIER = "com.apple.developer.team-identifier"
ACCESS_GROUPS = "keychain-access-groups"


def read_profile(path):
    payload = subprocess.check_output(["security", "cms", "-D", "-i", str(path)])
    profile = plistlib.loads(payload)
    team, = profile["TeamIdentifier"]
    entitlements = profile["Entitlements"]
    app_id = entitlements[APP_IDENTIFIER]
    if app_id != f"{team}.{APP_ID}" or entitlements[TEAM_IDENTIFIER] != team:
        raise ValueError(f"Le profil doit autoriser l’identifiant {APP_ID} pour son équipe Apple.")
    if profile["ExpirationDate"].replace(tzinfo=timezone.utc) <= datetime.now(timezone.utc):
        raise ValueError("Le profil d’approvisionnement macOS a expiré.")
    if not any(fnmatchcase(app_id, group) for group in entitlements.get(ACCESS_GROUPS, [])):
        raise ValueError("Le profil macOS doit autoriser le groupe du trousseau de FluXlock.")
    return team, app_id


def prepare(directory):
    if not os.environ.get("APPLE_SIGNING_IDENTITY", "").startswith("Developer ID Application: "):
        raise ValueError("APPLE_SIGNING_IDENTITY doit désigner un certificat Developer ID Application.")
    if not os.environ.get("APPLE_CERTIFICATE"):
        raise ValueError("APPLE_CERTIFICATE doit contenir le certificat Developer ID au format P12 encodé en base64.")
    encoded_profile = os.environ.get("APPLE_PROVISIONING_PROFILE", "")
    if not encoded_profile:
        raise ValueError("APPLE_PROVISIONING_PROFILE doit contenir le profil Developer ID de FluXlock encodé en base64.")

    directory = directory.resolve()
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    profile = directory / "embedded.provisionprofile"
    profile.write_bytes(base64.b64decode("".join(encoded_profile.split()), validate=True))
    team, app_id = read_profile(profile)
    base = Path(__file__).resolve().parents[1] / "tauri-desktop/src-tauri/Entitlements.plist"
    entitlements = plistlib.loads(base.read_bytes())
    entitlements.update({APP_IDENTIFIER: app_id, TEAM_IDENTIFIER: team, ACCESS_GROUPS: [app_id]})
    signed_entitlements = directory / "Entitlements.plist"
    signed_entitlements.write_bytes(plistlib.dumps(entitlements))
    config = {"bundle": {"macOS": {
        "entitlements": str(signed_entitlements),
        "files": {"embedded.provisionprofile": str(profile)},
    }}}
    (directory / "config.json").write_text(json.dumps(config), encoding="utf-8")


def verify(app):
    with (app / "Contents/Info.plist").open("rb") as bundle_info:
        if plistlib.load(bundle_info)["CFBundleIdentifier"] != APP_ID:
            raise ValueError("Identifiant de paquet macOS incorrect.")
    team, app_id = read_profile(app / "Contents/embedded.provisionprofile")
    subprocess.run(["codesign", "--verify", "--deep", "--strict", str(app)], check=True)
    description = subprocess.check_output(
        ["codesign", "--display", "--verbose=4", str(app)], stderr=subprocess.STDOUT, text=True
    ).splitlines()
    if f"TeamIdentifier={team}" not in description or not any(
        line.startswith("Authority=Developer ID Application: ") for line in description
    ):
        raise ValueError("L’application doit être signée par l’équipe Apple du profil.")
    entitlements = plistlib.loads(subprocess.check_output(
        ["codesign", "--display", "--entitlements", "-", "--xml", str(app)]
    ))
    if (entitlements.get(APP_IDENTIFIER) != app_id
        or entitlements.get(TEAM_IDENTIFIER) != team
        or app_id not in entitlements.get(ACCESS_GROUPS, [])):
        raise ValueError("La signature ne contient pas les autorisations Touch ID de FluXlock.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "verify"))
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    try:
        (prepare if args.action == "prepare" else verify)(args.path)
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Signature macOS : {error}\n")
