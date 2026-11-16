"""Build the frozen Move modules and WITS fixture exporter under the local runtime."""

import argparse
import shutil
import subprocess

from replay_support import ADDR, BENCH, CLI, EXPORTER, MOVE_PACKAGES, RUNTIME, SOURCE, check_address, check_cli


def compile_move(scheme):
    framework = RUNTIME / 'tools/aptos-core/aptos-move/framework/aptos-framework'
    if not (framework / 'Move.toml').is_file():
        raise FileNotFoundError(f'{framework}. Run bootstrap_aptos.py first.')
    source = SOURCE / 'move/sources' if scheme == 'wits' else BENCH / 'das-rust/move/sources'
    target = RUNTIME / 'build' / scheme
    shutil.copytree(source, target / 'sources', dirs_exist_ok=True)
    (target / 'Move.toml').write_text(
        f'[package]\nname="{MOVE_PACKAGES[scheme]}"\nversion="0.1.0"\n'
        f'[addresses]\nbench="_"\n[dependencies.AptosFramework]\nlocal="{framework.as_posix()}"\n'
    )
    subprocess.run([str(CLI), 'move', 'compile', '--package-dir', str(target),
                    '--named-addresses', 'bench=' + ADDR], cwd=RUNTIME, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--offline', action='store_true', help='Require a prefilled Rust dependency cache')
    args = parser.parse_args()
    check_cli()
    check_address()
    for scheme in MOVE_PACKAGES:
        compile_move(scheme)
    command = ['cargo', 'build', '--release', '--locked',
               '--target-dir', str(EXPORTER.parents[1]),
               '--manifest-path', str(SOURCE / 'rust/Cargo.toml')]
    if args.offline:
        command.append('--offline')
    subprocess.run(command, check=True)


if __name__ == '__main__':
    main()
