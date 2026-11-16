# WITS experimental artifact

Code and data for *WITS: Pairing-Free Weighted Threshold Signatures with
Compact Authorization Proofs*. The artifact covers the Rust host benchmarks,
the Aptos Move verification experiments, the execution-budget reruns, and the
data and renderer for the paper's two performance figures.

## Find an implementation

| Scheme | Rust | Aptos Move |
| --- | --- | --- |
| WITS | [ours.rs](aptos-benchmark/cpu-comparison/rust/src/ours.rs) | [wtas_vnext.move](aptos-benchmark/vnext-chain/move/sources/wtas_vnext.move) |
| Garg et al. | [garg.rs](aptos-benchmark/cpu-comparison/rust/src/garg.rs) | [garg_vnext_reference.move](aptos-benchmark/vnext-chain/move/sources/garg_vnext_reference.move) |
| Das et al. | [protocol.rs](aptos-benchmark/das-rust/src/protocol.rs) | [das_reference.move](aptos-benchmark/das-rust/move/sources/das_reference.move) |

The identifiers `ours` and `wtas_vnext` refer to WITS.

## Regenerate the figures

Run from the artifact root with Python 3.12.

```sh
python data/verify.py
python -m pip install -r manuscript/requirements.txt
python manuscript/render_figures.py --output-dir work/figures
python data/verify.py --rendered-dir work/figures
```

The data check reconstructs the paper's plotted values from the preserved
observations. See the [data dictionary](data/README.md) for the original
timings, execution gas, phase breakdowns, transaction sizes, and cap results.

## Run the Rust benchmarks

Use Linux or WSL Ubuntu for comparable timings. Install Rust/Cargo, Python
3.12, a C compiler for the BLS backend, and either OpenSSL 3 or the Python
`cryptography` package for independent Ed25519 verification. Run these commands
from the artifact root.

```sh
cargo build --release --locked --manifest-path aptos-benchmark/cpu-comparison/rust/Cargo.toml
cargo build --release --locked --manifest-path aptos-benchmark/das-rust/Cargo.toml
python3 aptos-benchmark/cpu-comparison/run_host.py --sizes 32 --samples 1 --output work/host-smoke
python3 aptos-benchmark/cpu-comparison/run_host.py --output runs/reproduction
```

The reported CPU experiment contains 75 valid executions across three
schemes and five committee sizes (32, 64, 128, 256, and 512), with five
fixtures per group. Each fixture selects half the committee and supplies common weights,
threshold, message, and participant indices. The Rust release executables
measure initialization, local signing, aggregation with proof generation,
and complete verification. The online total sums all individual signing
times, aggregation, and verification.

Each runner invocation requires a fresh output directory. It regenerates the
shared fixtures and writes per-case proof artifacts, verification records,
`samples.csv`, and `summary.csv`. The Das output hashes are verified against
the archived comparison cases. Use `--cpu 0` when CPU 0 is available to
match the paper's affinity.

## Run Aptos verification

Follow the [pinned Aptos instructions](APTOS.md) to stand up a localnet,
compile the three Move verifiers, and replay the full verification calls.

The Aptos experiment executes a complete valid verifier once per scheme and
size with a common gas schedule. The results include execution gas,
verification I/O, transmitted bytes, and separate registration and proof
upload measurements. The budget reruns use the same valid inputs for WITS
and Garg at committee sizes 256 and 512 under four local execution ceilings.

## Measurement scope

- WITS runs its dual-nonce signing, share checks, Ed25519 signature checks,
  and complete IPA authorization argument. The local benchmark validates
  proof of possession during initialization and reuses the registry during
  signing.
- The Das port runs the full BLS12-381 signing and proof path using locally
  generated CRS, keys, and aggregation hints. Its timed setup models honest
  local preparation with trusted registration material. The retained pairing
  grouping follows the corrected reference implementation.
- The Garg adaptation uses Ristretto255, 96 FRI queries, expansion factor
  16, and direct polynomial arithmetic over an arbitrary domain. It runs
  the Schnorr, hidden opening, FRI, Merkle, and weighted authorization
  checks for that implementation.
- These are serial host measurements and Aptos VM session executions.
  Fixtures use public research seeds. The Aptos budget tiers in the paper
  are local VM execution ceilings.

See [NOTICE.md](NOTICE.md) for source attribution and repository licensing.

Verify the release file hashes with `sha256sum -c SHA256SUMS` from the
artifact root. The source and data checksums refer to the shipped files.
Reproductions write new timings and VM profiles to separate run directories.

## Release verification

The three Rust release executables regenerated valid proofs for the
32-member fixture. The WITS and Garg proof bytes matched the archived
artifacts, and the Das proof and package matched the reference hashes.
All three Move verifiers were then compiled and run on a fresh localnet.
Their execution Gas, I/O Gas, fees, proof sizes, and verification
transaction sizes matched the reported values for that fixture.

The 256-member WITS and Garg fixtures were replayed at all four execution
ceilings. Their observed limits, full Gas profiles, and proof hashes
matched the archived records. The data verifier checks the full frozen
datasets, and both performance figures regenerate the exact numerical
values used in the paper.
