#!/usr/bin/env python3
"""Validate release versions; only create an absent tag on validated current main.

Without --github this is read-only and does not contact a remote or create tags.
The reusable release workflow is called only after main's application/browser CI.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parent.parent


def metadata(root):
    desktop = root / 'tauri-desktop'
    package = json.loads((desktop / 'package.json').read_text())
    lock = json.loads((desktop / 'package-lock.json').read_text())
    config = json.loads((desktop / 'src-tauri/tauri.conf.json').read_text())
    manifest = (desktop / 'src-tauri/Cargo.toml').read_text()
    cargo_lock = (desktop / 'src-tauri/Cargo.lock').read_text()
    rust = re.search(r'^version = "([^"]+)"$', manifest, re.M)
    locked = re.search(r'^name = "fluxlock"\nversion = "([^"]+)"$', cargo_lock, re.M)
    version = package['version']
    if not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', version):
        raise ValueError('A stable semantic version is required')
    if not rust or not locked or any(v != version for v in (
        lock['version'], lock['packages']['']['version'], config['version'],
        rust.group(1), locked.group(1),
    )):
        raise ValueError('Desktop, npm, Cargo and Tauri versions must match')
    return {'version': version, 'tag': 'v' + version}


def decision(ref, event, tag, head, main, existing):
    if ref == 'refs/heads/main' and event == 'push':
        # Never move a tag or publish a stale main run. Later commits with the
        # same application version must not publish that version again.
        return 'skip' if existing or head != main else 'create'
    if ref == 'refs/tags/' + tag and event == 'push':
        if existing != head:
            raise ValueError('The release tag must point to the tested checkout')
        return 'publish'
    raise ValueError('Publication requires a main push or matching version tag')


def git(*args, check=True):
    return subprocess.run(['git', *args], cwd=ROOT, check=check,
                          text=True, stdout=subprocess.PIPE).stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--github', action='store_true')
    args = parser.parse_args()
    info = metadata(ROOT)
    if not args.github:
        print(json.dumps(info))
        return
    head = git('rev-parse', 'HEAD')
    if head != os.environ['GITHUB_SHA']:
        raise ValueError('Checkout and workflow commit differ')
    remote_main = git('ls-remote', 'origin', 'refs/heads/main').split()
    if not remote_main:
        raise ValueError('Remote main is unavailable')
    existing = git('rev-parse', '-q', '--verify',
                   'refs/tags/' + info['tag'] + '^{commit}', check=False)
    action = decision(os.environ['GITHUB_REF'], os.environ['GITHUB_EVENT_NAME'],
                      info['tag'], head, remote_main[0], existing)
    if action == 'create':
        git('-c', 'user.name=github-actions[bot]', '-c',
            'user.email=41898282+github-actions[bot]@users.noreply.github.com',
            'tag', '-a', info['tag'], '-m', 'FluXlock ' + info['tag'], head)
        # No --force. A concurrent creator causes failure before publishing.
        git('push', 'origin', 'refs/tags/' + info['tag'])
    info.update(commit=head, publish='false' if action == 'skip' else 'true')
    with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
        for key in ('tag', 'commit', 'publish'):
            output.write(key + '=' + info[key] + '\n')
    print(json.dumps(info))


if __name__ == '__main__':
    main()
