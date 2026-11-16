# Paper data and figures

Run these commands from the artifact root with Python 3.12:

```sh
python data/verify.py
python -m pip install -r manuscript/requirements.txt
python manuscript/render_figures.py --active-only
python data/verify.py --rendered-dir manuscript/figures
```

The renderer reads the preserved results, generates the two performance figures
in PDF, SVG, and PNG, and writes the plotted CSVs and provenance to
`manuscript/figures/`. Use `--output-dir` to select a different destination.
Figure values are checked against `published-figures/`. Rendering uses Times
New Roman when available and falls back to a system serif font otherwise.

| Data | Contents |
| --- | --- |
| `host-samples.csv` | Current CPU experiment, 75 honest executions. WITS and Garg are the frozen Rust samples; Das is the replacement Rust port. |
| `../aptos-benchmark/das-rust/replacement_time_summary.csv` | Source of the CPU figure, with five samples per scheme and size. |
| `../aptos-benchmark/das-rust/chain-results/three_scheme_summary.csv` | Source of the Gas figure, with fifteen complete verifier executions. |
| `../aptos-benchmark/paper-comparison-20261028/chain_summary.csv` | Historical WITS and Garg execution, I/O, registration, proof upload, and byte counts. |
| `../aptos-benchmark/paper-comparison-20261028/chain_step_gas.csv` | WITS and Garg execution Gas by disjoint verification stage. |
| `../aptos-benchmark/das-rust/chain-results/step_gas.csv` | Das execution Gas by disjoint verification stage. |
| `../aptos-benchmark/paper-comparison-20261028/chain_native_operation_gas.csv` | WITS and Garg operation-level Gas breakdown. This and the stage breakdown describe the same execution costs. |
| `cap-attempts.csv`, `cap-summary.csv` | Sixteen local VM attempts at 1x, 2x, 4x, and 8x execution ceilings, plus the four scheme/size summaries. |

Column `online_total_ms` sums the local work of all participating signers,
complete aggregation and proof generation, and full verification. Error bars
show the observed minimum and maximum. The VM tests use Aptos CLI 9.6.0 and the
pinned local gas schedule. The cap experiment changes the execution ceiling
without changing prices. Registering committee material and uploading proofs
are accounted for separately from complete verification.

## Provenance

The exact plot inputs keep their historical paths for compatibility with the
paper renderer. The earlier CPU summary is retained so the renderer can check
the WITS and Garg observations against the pre-replacement data. Its historical
Das rows are Go observations. The current Das rows in the paper use the separate
Rust measurements. The current per-run table selects WITS/Garg observations from
the historical `time_samples.csv` and Das observations from the Rust port's
`samples.csv`, projecting the same timing columns for each scheme.

The replacement provenance document uses repository-relative names. The numeric
measurements and source hashes in that document are preserved. `manifest.json`
records SHA-256 digests of the packaged data and figure sources.
