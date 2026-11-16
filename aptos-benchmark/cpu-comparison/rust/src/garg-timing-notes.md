# Garg reference CPU timing boundaries

Source: `aptos-benchmark/v2/honest-provers/garg/src/main.rs`, copied without modifying the old file. The new executable is `garg-reference-timed`; its first argument is the output directory, and `WTAS_BENCH_FIXTURE` names a shared JSON fixture. It performs no chain transactions.

This remains the arbitrary-domain Ristretto/Schnorr research construction, not Garg's original roots-of-unity instantiation or an optimized ECFFT prover. The 96 FRI queries, 16-fold evaluation domain, batched hidden/clear openings, degree shifts, Merkle multiproofs, full FRI fold checks, and three final authorization identities are retained. Domain generation, reference polynomial interpolation/multiplication and group polynomial evaluation are not claimed to have the paper's optimal asymptotic implementation costs. No matched-128-bit certification follows from these fixed research parameters.

## Timers

- `setup_ms`: arbitrary-domain generation and the vanishing polynomial for its first N points. This is public, committee-size-dependent work.
- `keygen_ms`: all N benchmark Schnorr scalars derived by wide SHA-512 reduction of the supplied 32-byte seeds, and their Ristretto public keys. Ed25519 pruning from the old shared-key fixture routine is not applied to these Schnorr keys. Fixture loading, JSON/hex decoding and input-shape checks are outside the timers.
- `preprocessing_ms`: public-only basis polynomials and their normalization factors, weighted clear polynomial, hidden group polynomial constructed **only from public keys**, registry Merkle tree/digest, and binary/JSON registry material encoding. The participation polynomial is not computed here. This timer does not simulate public-key proofs of possession or independently authenticate an untrusted registration authority.
- `signing_ms`: sum of local CPU times for all k selected participants, executed serially. Every participant creates a fresh nonce/commitment, independently decodes every received Ristretto opening, checks canonical encoding and commitment hashes, independently sums the nonce points, derives the signing challenge and computes its response. `signer_mean_ms` is this sum divided by k; `signer_max_ms` is the maximum participant's accumulated round CPU time. These are not parallel wall-clock signing latency or network round-trip times. Three local rounds are modeled without fabricated network latency.
- `coordination_ms`: choosing participants, initializing the fixture RNG, collecting the commitment/opening bulletin, and the coordinator's nonce aggregation/challenge. In-memory pushes between separately timed actor computations and general loop/timer overhead are not assigned to an artificial protocol phase.
- `share_validation_ms`: the coordinator checks every selected signature response against the corresponding public key and nonce point. These checks are not charged to participant signing a second time.
- `aggregation_core_ms`: sum of accepted signature responses and selected public keys. It excludes share validation, proof generation and serialization.
- `proving_ms`: **starts before interpolation of the private participation polynomial**. It includes its interpolation from the public basis, all relation quotient polynomials, initial and folded oracles, hidden/clear opening work, query selection, Merkle trees/multiproofs, and transcript-dependent proof encoding. No signing secret is an argument to `preprocess()` or `prove()`.
- `serialization_ms`: final core-package construction and public-instance JSON encoding. Encoding required for Fiat-Shamir and the proof itself remains in `proving_ms`; it is not double counted or claimed to have been isolated. One-time registry encoding stays in preprocessing.
- `aggregation_and_proving_ms`: coordination + share validation + core aggregation + proving + final serialization. Participant signing, setup, key generation, preprocessing, verification and file I/O are excluded.
- `signature_verification_ms`: the full Ristretto/Schnorr signature equation and its challenge hash.
- `proof_verification_ms`: public threshold/range checks, proof parsing, all authorization identities, all Merkle authentication, hidden/clear batched opening conversions, all FRI folds and exact proof-length consumption.
- `verification_ms`: both preceding verification phases in one surrounding timer, so it can differ slightly from their sum by timer overhead. No verification equation was replaced by a hash or a cached expected answer.

The executable creates no worker threads; the runner is responsible for pinning it to the same single CPU as the comparison executable. Rust `Instant` reports elapsed time; on a pinned, otherwise controlled serial process it is a local latency observation, not a hardware-independent cycle count. Output writes and printing occur after all reported timers.

## Explicit changes from the frozen reference

1. The old `signers()` mixed key derivation, signing, share validation and aggregation. These now have separate timers. Every signer checks all openings and constructs its own R, rather than counting only one coordinator pass.
2. The old registry loop also interpolated the selected b vector. This private, session-specific work is now in `prove()`, timed as proof generation. Public bases and inverses remain reusable preprocessing.
3. Nonces are sequential fresh draws from `StdRng` seeded by the fixture's `rng_seed_hex`, replacing the old repeated hash of sk/message. The fixture is intentionally public and reproducible, so this is a benchmark sampling mechanism, **not production secret randomness or a concurrent nonce state machine**. Changing the fixture changes the signing session and hence the proof transcript.
4. The old verifier's incidental `T <= 100*N` benchmark bound is replaced by `T <= sum(registered weights)`, calculated with checked u64 addition. Shared fixtures contain positive u64 weights exceeding 100; the bit/weight/key polynomial identities are unchanged. A positive threshold and no u64 overflow are required.

## Byte counters and files

- `proof_bytes` is the actual length of `proof.bin`, including its FRI roots/openings and Merkle multiproofs, but not the signature or statement.
- `signature_core_bytes = 64`: compressed R and scalar z. This is Garg's Ristretto/Schnorr output, not the standard Ed25519 challenge convention.
- `core_package_bytes` is the actual `core-package.bin` length: apk(32) || R(32) || z(32) || exact-weight-u64(8) || proof, hence proof bytes + 104. It excludes common message/context, registered parameters, combiner authentication and transport framing.
- `registry_material_bytes` is the actual `registry.bin` length. Its explicit research format contains a version marker, N/query count/threshold/registered weight, root/digest, all public keys and weights, domain layers, map-denominator coefficients used by the verifier, and the vanishing polynomial, with vector lengths. It is **not** the succinct verification-key size claimed by the original paper; this implementation carries explicit arbitrary-domain mapping material.
- `registry.json` is a diagnostic hex/JSON representation of that public registry. Its textual byte length is not used for the registry-material counter. It and `registry.bin` are encoded in preprocessing; disk writes are untimed.
- `public.json` contains the signature, instance and identifiers. `result.json` is written only after the signature and entire authorization proof pass.

This source does not claim production signing security, signer anonymity, exact reproduction of the paper's optimal prover, deployment gas, or a full fairness result against a protocol with different setup/security assumptions. A successful run establishes consistency of the complete reference prover/verifier on the specified fixture.
