"""Audit native pairing invocation counts with an unfolded official profile.

Call ``audit()`` while run_move's existing local node is still running. This
helper never starts/stops a node, registers a resource, or submits a transaction.
It reuses a copy of the completed N=32 session state and writes only beneath
chain-results/unfolded-n32. The original result and folded profile are preserved.
"""

from decimal import Decimal
from pathlib import Path
import hashlib
import html
import json
import math
import re
import shutil
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _operations(path):
    """Retain the profiler's actual Hits column, rather than counting rows."""
    text = path.read_text(encoding="utf-8")
    match = re.search(
        r'<table data-name="exec_operations">(.*?)</table>', text, re.S
    )
    if match is None:
        raise ValueError("Official profiler exec_operations table is missing")
    operations = []
    for row in re.findall(r"<tr>(.*?)</tr>", match.group(1), re.S):
        cells = [
            html.unescape(re.sub(r"<[^>]+>", "", cell)).strip()
            for cell in re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)
        ]
        if len(cells) == 4:
            operations.append(
                {
                    "operation": cells[0],
                    "hits": int(cells[1].replace(",", "")),
                    "execution_gas": cells[2].replace(",", ""),
                }
            )
    return operations


def audit():
    """Return the validation record; require the parent's already-running node."""
    # Importing this runner defines helpers only: main() is deliberately not run.
    import run_move as runner

    source = runner.OUT / "n32" / "seed00"
    complete_path = source / "complete.json"
    complete = json.loads(complete_path.read_text())
    assert complete["n"] == 32 and complete["full"]["success"]
    assert complete["normal_budget_success"], "N=32 must use the original gas schedule"
    originals = [
        complete_path,
        source / "session" / "config.json",
        source / "session" / "delta.json",
        source / "gas-profile" / "index.html",
    ]
    provenance = {str(p.relative_to(runner.RUN_ROOT)): _sha(p) for p in originals}
    folder = runner.OUT / "unfolded-n32"
    if (folder / "validation.json").exists():
        prior = json.loads((folder / "validation.json").read_text())
        assert prior["source_sha256"] == provenance
        assert prior["valid"] is True
        return prior
    if folder.exists():
        raise FileExistsError(f"Preserve previous audit evidence; inspect {folder}")

    env_path = runner.OUT / "ENVIRONMENT.json"
    env = json.loads(env_path.read_text())
    # No fallback launch: an unavailable or mismatched node must stop the audit.
    node = runner.get()
    assert node["chain_id"] == 4
    assert node["git_hash"] == env["node"]["git_hash"]
    gas_path = "/accounts/0x1/resource/0x1::gas_schedule::GasScheduleV2"
    feature_path = "/accounts/0x1/resource/0x1::features::Features"
    assert runner.get(gas_path)["data"] == env["gas_schedule"]
    features = runner.get(feature_path)["data"]
    expected_features = json.loads(
        (runner.ROOT / "aptos-benchmark" / "features.json").read_text()
    )["data"]
    assert features == expected_features

    cpu = runner.RUN_ROOT / "das-rust/results/das/n32/seed00"
    package_path = cpu / "core-package.bin"
    assert _sha(package_path) == complete["cpu_package_sha256"]
    public = json.loads((cpu / "move-params.json").read_text())
    arguments = ["hex:" + public["message_hex"], "hex:" + package_path.read_bytes().hex()]

    folder.mkdir()
    session = folder / "session"
    session.mkdir()
    for name in ["config.json", "delta.json"]:
        shutil.copy2(source / "session" / name, session / name)
    (folder / "source.json").write_text(
        json.dumps({"source_sha256": provenance, "environment_sha256": _sha(env_path)}, indent=2)
    )

    try:
        result_dir = runner.profiler.profile(
            folder, session, "das_reference", "verify", arguments, env, complete["full"], fold=False
        )
        _, _, execution, io = runner.costs.tables(result_dir / "index.html")
        assert execution == Decimal(complete["execution_gas"])
        assert io == Decimal(complete["io_gas"])
        assert math.ceil(execution + io) == complete["full"]["total_charge_gas_units"]
        operations = _operations(result_dir / "index.html")
        multi = [row for row in operations if "::multi_pairing_internal<" in row["operation"]]
        single = [row for row in operations if "::pairing_internal<" in row["operation"]]
        multi_hits = sum(row["hits"] for row in multi)
        single_hits = sum(row["hits"] for row in single)
        assert multi_hits == 5, multi
        assert single_hits == 4, single
        old_ops = _operations(source / "gas-profile" / "index.html")
        old_pairing_costs = {
            row["operation"]: Decimal(row["execution_gas"])
            for row in old_ops if "pairing_internal<" in row["operation"]
        }
        assert {
            row["operation"]: Decimal(row["execution_gas"])
            for row in multi + single
        } == old_pairing_costs
        events = json.loads((folder / "profile-overlay-requests.json").read_text())
        assert not any(
            event["method"] == "POST" and "/transactions" in event["path"]
            for event in events
        )
        assert all(_sha(path) == provenance[str(path.relative_to(runner.RUN_ROOT))] for path in originals)
        assert runner.get(gas_path)["data"] == env["gas_schedule"]
        assert runner.get(feature_path)["data"] == features
        record = {
            "valid": True,
            "n": 32,
            "seed": 0,
            "official_profiler": True,
            "fold_unique_stack": False,
            "multi_pairing_native_hits": multi_hits,
            "single_pairing_native_hits": single_hits,
            "total_pairing_native_api_hits": multi_hits + single_hits,
            "pairing_operations": multi + single,
            "pairing_input_pairs_from_source": 15,
            "pairing_input_pairs_scope": "Four two-pair and one three-pair native calls, plus four single-pair calls; API Hits are measured, argument lengths follow source.",
            "execution_gas": str(execution),
            "io_gas": str(io),
            "total_charge_gas": complete["full"]["total_charge_gas_units"],
            "exact_fee_matches_original": True,
            "pairing_operation_costs_match_folded_profile": True,
            "original_files_unchanged": True,
            "source_sha256": provenance,
            "transactions_submitted": False,
            "gas_schedule_unchanged": True,
            "features_unchanged": True,
            "node_lifecycle_managed": False,
            "measurement": "One additional read-only complete-verifier official profiler replay; no benchmark rerun or registration charge included.",
        }
        (folder / "validation.json").write_text(json.dumps(record, indent=2))
        return record
    except Exception as exc:
        (folder / "audit_failure.json").write_text(
            json.dumps({"error": repr(exc), "source_sha256": provenance}, indent=2)
        )
        raise


if __name__ == "__main__":
    print(json.dumps(audit(), indent=2))
