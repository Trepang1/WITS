# Source and dependency attribution

- **WITS:** this artifact packages the research implementation and experiment
  code for *WITS: Pairing-Free Weighted Threshold Signatures with Compact
  Authorization Proofs*. The authors select the repository license for their
  own material.
- **Das et al.:** *Threshold Signatures from Inner Product Argument: Succinct,
  Weighted, and Multi-threshold*, CCS 2023,
  [paper](https://eprint.iacr.org/2023/598). The Rust and Move baselines were
  developed against [the authors' Go repository](https://github.com/sourav1547/wts)
  at revision 33c487bee852598636288c247e883c439f41add2. The study corrected
  Fiat–Shamir transcript hashing and added the asymmetric commitment
  complement check in a local reference copy. The comparison records retain
  the resulting output hashes.
- **Garg, Goel, and Wang:** *How to Prove Statements Obliviously?*, CRYPTO
  2024, [paper](https://eprint.iacr.org/2023/1609). The benchmark uses this
  project's Ristretto255 arbitrary-domain adaptation of the weighted signature
  construction.
- **ECFFT:** [Andrew Milson's ECFFT library](https://github.com/andrewmilson/ecfft)
  is redistributed under its accompanying
  [MIT license](aptos-benchmark/garg/vendor/ecfft-main/LICENSE).
  [Source provenance](aptos-benchmark/garg/vendor/SOURCE.md) records the
  archived upstream revision by SHA-256.
- **Aptos and Cargo dependencies:** obtain these from their upstream sources.
  Cargo lockfiles identify resolved packages. Aptos tooling and framework
  provenance are recorded in the Aptos reproduction instructions.
