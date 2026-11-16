"""Run the complete honest Rust host experiments on shared public fixtures."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import shutil
import statistics
import subprocess
import sys
import tempfile


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SIZES = (32, 64, 128, 256, 512)
SCHEMES = ("ours", "garg", "das")
THREAD_ENV = {
    "GOMAXPROCS": "1",
    "RAYON_NUM_THREADS": "1",
    "OMP_NUM_THREADS": "1",
    "OPENBLAS_NUM_THREADS": "1",
    "MKL_NUM_THREADS": "1",
}
METRICS = (
    "setup_ms",
    "keygen_ms",
    "preprocessing_ms",
    "initialization_ms",
    "signing_ms",
    "signer_mean_ms",
    "signer_max_ms",
    "coordination_ms",
    "share_validation_ms",
    "aggregation_core_ms",
    "proving_ms",
    "combine_with_proof_ms",
    "serialization_ms",
    "aggregation_and_proving_ms",
    "verification_ms",
    "signature_verification_ms",
    "proof_verification_ms",
    "online_total_ms",
    "proof_bytes",
    "core_package_bytes",
    "registry_material_bytes",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, indent=2) + "\n", encoding="utf-8", newline="\n"
    )


def fixture(n: int, seed: int) -> dict:
    """Regenerate the deterministic public fixtures used in the paper."""
    fixed = random.Random(20261027 + n)
    weights = [fixed.randrange(1, 1001) for _ in range(n)]
    threshold = (2 * sum(weights) + 4) // 5
    selector = random.Random(202610270000 + n * 1000 + seed)
    while True:
        chosen = sorted(selector.sample(range(n), n // 2))
        selected = sum(weights[i] for i in chosen)
        if selected >= threshold:
            break
    chosen_set = set(chosen)

    def digest(label: str) -> str:
        return hashlib.sha256(f"WTAS/cpu/{n}/{seed}/{label}".encode()).hexdigest()

    message = (
        f"WTAS CPU comparison|chain=cpu-only|app=weighted-authorization|"
        f"registry-version=1|N={n}|threshold={threshold}|operation={seed}"
    )
    return {
        "n": n,
        "k": len(chosen),
        "seed": seed,
        "weights": weights,
        "participation_bits": [int(i in chosen_set) for i in range(n)],
        "selected_weight": selected,
        "threshold": threshold,
        "message_hex": message.encode().hex(),
        "public_benchmark_key_seeds": [digest(f"key/{i}") for i in range(n)],
        "rng_seed_hex": digest("fresh-session-nonces-and-proof-randomness"),
        "fixture_warning": (
            "Public deterministic research seeds. Never use for production keys or nonces."
        ),
    }


def pin_cpu(requested: int | None) -> int | None:
    if not hasattr(os, "sched_getaffinity"):
        if requested is not None:
            raise RuntimeError("--cpu requires Linux or WSL.")
        return None
    available = os.sched_getaffinity(0)
    cpu = min(available) if requested is None else requested
    if cpu not in available:
        raise RuntimeError(f"CPU {cpu} is outside the allowed set {sorted(available)}.")
    os.sched_setaffinity(0, {cpu})
    return cpu


def executable_paths() -> dict[str, Path]:
    suffix = ".exe" if os.name == "nt" else ""
    host_release = HERE / "rust/target/release"
    das_release = ROOT / "das-rust/target/release"
    return {
        "ours": host_release / f"ours-current{suffix}",
        "garg": host_release / f"garg-reference-timed{suffix}",
        "das": das_release / f"das-rust{suffix}",
    }


def independent_ed25519(folder: Path) -> str:
    record = json.loads((folder / "ed25519-check.json").read_text(encoding="utf-8"))
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        Ed25519PublicKey = None
    openssl = shutil.which("openssl") if Ed25519PublicKey is None else None
    if Ed25519PublicKey is None and openssl is None:
        raise RuntimeError("Install Python cryptography or OpenSSL 3 for the Ed25519 check.")
    for prefix in ("", "combiner_"):
        key = bytes.fromhex(record[f"{prefix}public_key"])
        message = bytes.fromhex(record[f"{prefix}message"])
        signature = bytes.fromhex(record[f"{prefix}signature"])
        if Ed25519PublicKey is not None:
            Ed25519PublicKey.from_public_bytes(key).verify(signature, message)
        else:
            with tempfile.TemporaryDirectory() as temporary:
                location = Path(temporary)
                (location / "key.der").write_bytes(
                    bytes.fromhex("302a300506032b6570032100") + key
                )
                (location / "message.bin").write_bytes(message)
                (location / "signature.bin").write_bytes(signature)
                subprocess.run(
                    [
                        openssl,
                        "pkeyutl",
                        "-verify",
                        "-pubin",
                        "-keyform",
                        "DER",
                        "-inkey",
                        "key.der",
                        "-rawin",
                        "-in",
                        "message.bin",
                        "-sigfile",
                        "signature.bin",
                    ],
                    cwd=location,
                    check=True,
                    capture_output=True,
                )
    return "cryptography" if Ed25519PublicKey is not None else "OpenSSL"


def run_case(
    scheme: str,
    n: int,
    seed: int,
    fixture_path: Path,
    work: Path,
    binary: Path,
    environment: dict[str, str],
    timeout: int,
    das_reference: dict,
) -> dict:
    role = "das-rust" if scheme == "das" else "cpu-comparison"
    folder = work / role / "results" / scheme / f"n{n}" / f"seed{seed:02d}"
    folder.mkdir(parents=True)
    print(f"Run {scheme}: N={n}, seed={seed}", flush=True)
    with (folder / "stdout.log").open("w") as stdout, (
        folder / "stderr.log"
    ).open("w") as stderr:
        subprocess.run(
            [str(binary), str(folder)],
            cwd=folder,
            env={
                **environment,
                "WTAS_BENCH_FIXTURE": str(fixture_path),
                "WTAS_BENCH_OUT": str(folder),
            },
            stdout=stdout,
            stderr=stderr,
            timeout=timeout,
            check=True,
        )
    report_path = folder / "result.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if (
        not report.get("honest_pass")
        or report.get("scheme") != scheme
        or report.get("n") != n
        or report.get("k") != n // 2
        or report.get("seed") != seed
    ):
        raise RuntimeError(f"Unexpected verification result in {report_path}.")
    checks = {"honest_pass": True, "fixture_sha256": sha256(fixture_path)}
    if scheme == "ours":
        expected_bytes = 32 * (9 + 2 * (n.bit_length() - 1))
        if (folder / "proof.bin").stat().st_size != expected_bytes:
            raise RuntimeError(f"Unexpected WITS proof length in {folder}.")
        checks["independent_ed25519"] = independent_ed25519(folder)
    if scheme == "das":
        expected = das_reference[f"n{n}/seed{seed:02d}"]
        actual = {name: sha256(folder / name) for name in expected}
        if actual != expected:
            raise RuntimeError(f"Das output differs from the frozen Go reference in {folder}.")
        checks["matches_frozen_go_sha256"] = actual
    write_json(folder / "validated.json", checks)
    report["initialization_ms"] = sum(
        report[key] for key in ("setup_ms", "keygen_ms", "preprocessing_ms")
    )
    report["online_total_ms"] = sum(
        report[key] for key in ("signing_ms", "aggregation_and_proving_ms", "verification_ms")
    )
    return report


def summarize(output: Path, cases: dict) -> None:
    fields = ["n", "k", "scheme", "samples", "honest_successes"]
    fields.extend(
        f"{metric}_{stat}" for metric in METRICS for stat in ("mean", "min", "max")
    )
    with (output / "summary.csv").open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        for (n, scheme), group in sorted(cases.items()):
            row = dict(n=n, k=n // 2, scheme=scheme, samples=len(group),
                       honest_successes=len(group))
            for metric in METRICS:
                values = [
                    case[metric] for case in group
                    if isinstance(case.get(metric), (int, float))
                ]
                if values:
                    row[f"{metric}_mean"] = statistics.mean(values)
                    row[f"{metric}_min"] = min(values)
                    row[f"{metric}_max"] = max(values)
            writer.writerow(row)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="fresh run directory")
    parser.add_argument("--sizes", nargs="+", type=int, choices=SIZES, default=SIZES)
    parser.add_argument("--schemes", nargs="+", choices=SCHEMES, default=SCHEMES)
    parser.add_argument("--samples", type=int, choices=range(1, 6), default=5)
    parser.add_argument("--cpu", type=int, help="Linux CPU to pin, default: first allowed")
    parser.add_argument("--timeout", type=int, default=1800, help="seconds per subprocess")
    args = parser.parse_args()
    schemes = tuple(dict.fromkeys(args.schemes))
    binaries = executable_paths()
    for scheme in schemes:
        if not binaries[scheme].is_file():
            parser.error(f"Build the locked release binaries first. Missing {binaries[scheme]}")
    output = args.output.resolve()
    if output.exists():
        parser.error(f"Choose a fresh --output directory. Already exists: {output}")
    if args.timeout < 1:
        parser.error("--timeout must be positive.")
    reference = json.loads((HERE / "das-reference-sha256.json").read_text(encoding="utf-8"))
    cpu = pin_cpu(args.cpu)
    output.mkdir(parents=True)
    write_json(
        output / "environment.json",
        {
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "cpu_affinity": None if cpu is None else [cpu],
            "thread_environment": THREAD_ENV,
            "binary_sha256": {scheme: sha256(binaries[scheme]) for scheme in schemes},
            "das_reference_manifest_sha256": sha256(HERE / "das-reference-sha256.json"),
            "samples": args.samples,
            "sizes": sorted(set(args.sizes)),
            "schemes": schemes,
        },
    )
    environment = {**os.environ, **THREAD_ENV}
    for option in ("DAS_ORACLE_JSON", "DAS_EXPECTED_GO_PACKAGE"):
        environment.pop(option, None)
    cases = {}
    fields = ["scheme", "protocol_version", "n", "k", "seed", "honest_pass", *METRICS]
    with (output / "samples.csv").open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for n in sorted(set(args.sizes)):
            for seed in range(args.samples):
                path = output / "cpu-comparison/fixtures" / f"n{n}" / f"seed{seed:02d}.json"
                path.parent.mkdir(parents=True, exist_ok=True)
                # The original public fixtures were hashed with CRLF newlines.
                path.write_text(
                    json.dumps(fixture(n, seed), indent=2) + "\n",
                    encoding="utf-8",
                    newline="\r\n",
                )
                shift = seed % len(schemes)
                for scheme in schemes[shift:] + schemes[:shift]:
                    report = run_case(
                        scheme, n, seed, path, output, binaries[scheme],
                        environment, args.timeout, reference,
                    )
                    cases.setdefault((n, scheme), []).append(report)
                    writer.writerow(report)
                    file.flush()
    summarize(output, cases)
    print(f"Completed {sum(map(len, cases.values()))} verified cases in {output}.")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, subprocess.SubprocessError) as error:
        sys.exit(f"{error} See the case logs in the run directory.")
