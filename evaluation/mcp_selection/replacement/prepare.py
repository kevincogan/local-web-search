"""Stage the pinned, patched MCP server in an isolated destination, never node_modules."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
MODULES = HERE.parent / 'node_modules'
PACKAGE = MODULES / 'mcp-searxng'
PIN = '2.11.0'
PATCH = HERE / 'reader.patch'
PROJECT_PROFILE = HERE.parents[2] / 'local-search'


def prepare(destination, *, local_routing=False):
    destination = destination.resolve()
    if destination.is_relative_to(MODULES.resolve()) or destination.exists():
        raise ValueError('Use a new isolated output folder outside the installed dependencies')
    public_metadata = json.loads((PACKAGE / 'package.json').read_text())
    if public_metadata['version'] != PIN:
        raise ValueError('Review and requalify the patch for this new version before staging')
    destination.mkdir()
    shutil.copyfile(PACKAGE / 'package.json', destination / 'package.json')
    shutil.copytree(PACKAGE / 'dist', destination / 'dist')
    (destination / 'node_modules').symlink_to(MODULES, target_is_directory=True)
    expected = {'index.js': '3c6d75b8e2e4a22ab61f7bf0a2310beface7ad65d8edfb80cbb708a4fb64aebe', 'types.js': 'ce1196eaf4b0cff1fff945d87086e0ee8f8b336e270ea19f245e36c66271dd3d', 'search.js': '477388008ef972ff10029bb4446c35143939e44ed2d2948f313a6557dd060b4c', 'url-reader.js': 'de0ce58c2358b74f2192a1588fc4671b8281865684bc03b88988b95dc2872b10'}
    for name, digest in expected.items():
        if sha256((destination / 'dist' / name).read_bytes()).hexdigest() != digest:
            raise ValueError(f'Installed {name} does not match the reviewed pin')
    shutil.copyfile(HERE / 'evidence-select.mjs', destination / 'dist/evidence-select.mjs')
    for options in (['--dry-run'], []):
        subprocess.run(['patch', '-s', '-F', '0', '-p1', *options, '-i', str(PATCH)],
                       cwd=destination, check=True, capture_output=True, timeout=8)
    if local_routing:
        if sha256((destination / 'dist' / 'proxy.js').read_bytes()).hexdigest() != '317d2aa1a443bdd06ab072a89b241ec09b41790a6f15ca3c00cab35a84679804':
            raise ValueError('Installed proxy.js does not match the reviewed pin')
        shutil.copyfile(PROJECT_PROFILE / 'huggingface-catalog.mjs', destination / 'dist/huggingface-catalog.mjs')
        for options in (['--dry-run'], []):
            subprocess.run(['patch', '-s', '-F', '0', '-p1', *options, '-i',
                            str(PROJECT_PROFILE / 'specialist-catalog.patch')], cwd=destination,
                           check=True, capture_output=True, timeout=8)
        # Keep historical reader-only experiments unchanged.
        shutil.copyfile(PROJECT_PROFILE / 'engine-routing.mjs', destination / 'dist/engine-routing.mjs')
        shutil.copyfile(PROJECT_PROFILE / 'evidence-bundle.mjs', destination / 'dist/evidence-bundle.mjs')
        for options in (['--dry-run'], []):
            subprocess.run(['patch', '-s', '-F', '0', '-p1', *options, '-i',
                            str(PROJECT_PROFILE / 'engine-routing.patch')], cwd=destination,
                           check=True, capture_output=True, timeout=8)
        subprocess.run(['node', '--check', str(destination / 'dist/search.js')], check=True, timeout=8)
    cli = destination / 'dist/cli.js'
    subprocess.run(['node', '--check', str(destination / 'dist/index.js')], check=True, timeout=8)
    return cli


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('destination', type=Path)
    p.add_argument('--local-routing', action='store_true')
    args = p.parse_args()
    print(prepare(args.destination, local_routing=args.local_routing))
