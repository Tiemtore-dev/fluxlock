#!/usr/bin/env python3
"""Package an explicitly compiled relay and, optionally, the built MV3 extension."""
import argparse
import json
from pathlib import Path
import re
import zipfile

ROOT = Path(__file__).resolve().parent.parent
TARGETS = ('aarch64-apple-darwin', 'x86_64-apple-darwin',
           'x86_64-pc-windows-msvc', 'x86_64-unknown-linux-gnu')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', choices=TARGETS, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--extension', action='store_true')
    args = parser.parse_args()
    version = re.search(r'^version = "([^"]+)"$',
                        (ROOT / 'native-host/Cargo.toml').read_text(), re.M).group(1)
    binary = 'fluxlock-browser-host' + ('.exe' if 'windows' in args.target else '')
    source = ROOT / 'native-host/target' / args.target / 'release' / binary
    if not source.is_file() or source.stat().st_size == 0:
        raise ValueError('The selected native relay has not been compiled')
    args.output.mkdir(parents=True, exist_ok=True)
    archive = args.output / ('FluXlock-browser-host_' + version + '_' + args.target + '.zip')
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as package:
        package.write(source, binary)
        package.write(ROOT / 'scripts/install-browser-host.py', 'install-browser-host.py')
        package.writestr('INSTALLATION.md', '''# Relais natif FluXlock

Installez la nouvelle application FluXlock et l’extension Chromium 0.4.0.
Décompressez ce relais dans un emplacement durable, accessible en écriture
uniquement à votre compte. Sous Unix, rendez le binaire exécutable si nécessaire.

Chargez l’extension décompressée et copiez son ID exact dans la page des extensions.
Examinez la simulation (Python 3) :

    python3 install-browser-host.py --browser brave --host CHEMIN_ABSOLU_DU_BINAIRE --extension-id ID_REEL

Choisissez chrome, brave ou edge. Ajoutez --install après examen ; --replace est
nécessaire pour remplacer un ancien manifeste différent. Sous Windows, utilisez
python et le binaire .exe. Aucun enregistrement ne se fait en décompressant le zip.

Dans FluXlock : Paramètres → Extension de navigateur → Connecter un navigateur.
Comparez les huit groupes de l’empreinte et confirmez des deux côtés. Les anciens
appairages ne sont pas importés. Chaque remplissage demande ensuite une nouvelle
authentification dans FluXlock. Android AutofillService n’est pas inclus.
''')
    print(archive)
    if args.extension:
        dist = ROOT / 'browser-extension/dist'
        manifest = json.loads((dist / 'manifest.json').read_text())
        archive = args.output / ('FluXlock-extension_' + manifest['version'] + '.zip')
        with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as package:
            for source in sorted(dist.rglob('*')):
                if source.is_file():
                    package.write(source, source.relative_to(dist))
        print(archive)


if __name__ == '__main__':
    main()
