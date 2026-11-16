"""Install the pinned Linux Aptos CLI and framework into the local runtime."""

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import zipfile

from replay_support import CLI, PINS, RUNTIME, check_cli


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def archive(tools, name, url, expected, cache):
    path = tools / name
    if not path.is_file() or digest(path) != expected:
        temporary = path.with_suffix(path.suffix + ".partial")
        if cache is not None:
            shutil.copyfile(cache / name, temporary)
        else:
            subprocess.run(
                ["curl", "--fail", "--location", "--retry", "2", "--output",
                 str(temporary), url],
                check=True,
            )
        if digest(temporary) != expected:
            raise ValueError(f"Unexpected SHA-256 for {name}")
        temporary.replace(path)
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, help="Directory holding both pinned archives")
    args = parser.parse_args()
    tools = RUNTIME / "tools"
    tools.mkdir(parents=True, exist_ok=True)
    cli_archive = archive(
        tools, "aptos-cli-9.6.0-Linux-x86_64.zip", PINS["asset_url"],
        PINS["archive_sha256"], args.cache,
    )
    with zipfile.ZipFile(cli_archive) as source:
        entry = next(member for member in source.infolist() if Path(member.filename).name == "aptos")
        binary = source.read(entry)
    if not CLI.is_file() or digest(CLI) != hashlib.sha256(binary).hexdigest():
        if CLI != (tools / "aptos").resolve():
            raise ValueError("WTAS_APTOS_CLI must point to the pinned executable.")
        CLI.parent.mkdir(parents=True, exist_ok=True)
        temporary = CLI.with_suffix(".partial")
        temporary.write_bytes(binary)
        temporary.chmod(0o755)
        temporary.replace(CLI)
    check_cli()
    framework_archive = archive(
        tools, "framework.tar.gz", PINS["framework_source_url"],
        PINS["framework_archive_sha256"], args.cache,
    )
    prefix = f"aptos-core-{PINS['framework_commit']}/"
    framework = tools / "aptos-core"
    marker = framework / ".source-sha256"
    expected = PINS["framework_archive_sha256"]
    if not marker.exists() or marker.read_text().strip() != expected:
        framework.mkdir(exist_ok=True)
        with tarfile.open(framework_archive, "r:gz") as source:
            for member in source:
                if member.name.startswith(prefix + "aptos-move/framework/"):
                    member.name = member.name.removeprefix(prefix)
                    source.extract(member, framework, filter="data")
        move_manifest = framework / "aptos-move/framework/aptos-framework/Move.toml"
        if not move_manifest.is_file():
            raise FileNotFoundError(move_manifest)
        marker.write_text(expected + "\n")
    print(f"Pinned Aptos CLI and framework are available in {RUNTIME}.")


if __name__ == "__main__":
    if os.name != "posix":
        raise SystemExit("Run the Aptos bootstrap in Linux or WSL Ubuntu.")
    main()
