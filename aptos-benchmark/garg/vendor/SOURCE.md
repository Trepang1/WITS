# ECFFT dependency provenance

Downloaded 2026-10-12 from https://codeload.github.com/andrewmilson/ecfft/zip/refs/heads/main

Archive SHA-256: `d19d04f2ced3c8a3f3b1b8b4ea48b96868dfe63f2b8b92c97f4e1ec3c1ff7f60`.
The exact archive is retained; this hash, rather than the mutable branch name,
identifies the input. MIT license retained in `ecfft-main/LICENSE`.

This is Andrew Milson's arithmetic library, not an official Garg implementation.
It provides ECFFT and FIND_CURVE; it does not provide a complete arbitrary-field
hidden FRI, LHEncap polynomial-opening verifier, or weighted threshold signature.
The small sibling probe validates arithmetic in the actual Ed25519 scalar field;
passing it does not establish correctness or security of the missing protocol.
