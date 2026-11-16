# Reproduce Aptos verification

Use Linux x86-64 or WSL Ubuntu. The verifier and profiler use Aptos CLI 9.6.0,
framework commit `07490157d3250932a385010878a3c5ae7c1338bb`, and the pinned
[gas schedule](aptos-benchmark/gas-schedule.json) and
[feature flags](aptos-benchmark/features.json). The scripts use the official
VM session interface and read-only profiler replay on the loopback localnet.

## Start an isolated localnet

From the artifact root, download the pinned CLI and framework. The script
checks both archived SHA-256 values before installing the tools. Keep the
localnet running in the first terminal.

```sh
export WTAS_APTOS_RUNTIME="$PWD/.aptos-runtime"
python3 aptos-benchmark/vnext-chain/bootstrap_aptos.py
"$WTAS_APTOS_RUNTIME/tools/aptos" node run-localnet \
  --test-dir "$WTAS_APTOS_RUNTIME/localnet" --no-txn-stream \
  --do-not-delegate --bind-to 127.0.0.1 --assume-yes
```

An existing download cache can be passed with `--cache`. It must contain
`aptos-cli-9.6.0-Linux-x86_64.zip` and `framework.tar.gz`. An existing pinned
local runtime can also be selected with `WTAS_APTOS_RUNTIME`.

Once the localnet readiness endpoint at `http://127.0.0.1:8070/` responds,
initialize and fund a fresh account in a second terminal from the
artifact root. Use the same profile and address for compilation and
measurement. The local faucet funds this account.

```sh
export WTAS_APTOS_RUNTIME="$PWD/.aptos-runtime"
export WTAS_BENCH_RUN_DIR="$PWD/runs/reproduction"
export WTAS_APTOS_PROFILE=bench
(
  cd "$WTAS_APTOS_RUNTIME"
  ./tools/aptos init --network local --profile bench --assume-yes
  ./tools/aptos account fund-with-faucet --profile bench --amount 1000000000
)
# Use the Account address reported by Aptos for the new local profile.
export WTAS_APTOS_ADDRESS='paste-the-funded-local-account-address-here'
```

Run the Rust benchmarks in the [main README](README.md) to prepare the shared
fixtures and proof packages in `runs/reproduction`. For a single-size check,
set `WTAS_BENCH_RUN_DIR="$PWD/work/host-smoke"` after running the host smoke
command instead.

The account needs funds for simulated registration and proof storage. For
the largest Garg case, plan for at least 10 APT of local test funds before
starting the VM sessions.

## Build and measure

```sh
python3 aptos-benchmark/vnext-chain/build.py
python3 aptos-benchmark/vnext-chain/run_honest.py --n 32
python3 aptos-benchmark/vnext-chain/collect_results.py
python3 aptos-benchmark/das-rust/run_move.py --sizes 32
```

For all five sizes, pass `--n 32 64 128 256 512` to `run_honest.py` and use
`--sizes 32 64 128 256 512` for `run_move.py`. Run `collect_results.py` after
the WITS and Garg measurements to produce the input to the Das summary.
The Move modules and registry data are loaded into local session state.
The independent profiler checks the same verification call through a
read-only proxy. Measurements and profiles are written under
`WTAS_BENCH_RUN_DIR`. A changed node, feature set, schedule, or account
requires a fresh result directory.

## Rerun the execution ceilings

After collecting the full-size WITS and Garg data, run:

```sh
python3 aptos-benchmark/vnext-chain/run_extension.py
```

This reuses the saved valid proofs at committee sizes 256 and 512 in copies
of their VM sessions. The 1x, 2x, 4x, and 8x ceilings change only the
execution limit. The resulting summaries and case logs go under
`WTAS_BENCH_RUN_DIR/extension-budget`. These results describe local VM
execution feasibility for the evaluated budgets.
