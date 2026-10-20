# XCHAIN fuzz targets

libFuzzer targets for the post-quantum signature code (spec/pq-signature.md). They build like the
upstream targets (see `fuzzing.md`); CI builds them with `fuzzer;address;undefined` sanitizers and runs
each for a fixed time (`fuzz` job in `.github/workflows/xchain-ci.yml`).

| Target | What it checks |
| --- | --- |
| `pqsig_encoding` | Arbitrary bytes into `CheckPQPubKeyEncoding`, `CheckPQSignatureEncoding` and `pqsig::Verify`. The encoding verdicts follow the spec exactly (1,313-byte key with algorithm byte 0x01; 2,421-byte signature whose verdict depends only on the sighash byte and never on the STRICTENC / FORKID flags); malformed keys and signatures are rejected without crashing. |
| `pqsig_verify` | A valid signature, then fuzzed byte flips in the public key, the signature and the digest, or another valid key. Verification succeeds if and only if nothing changed. |
| `pqsig_script` | A fuzzed transaction (1–3 inputs and outputs, any version, locktime, sequence, amounts) spending P2PQH, bare `OP_CHECKPQSIG`, `OP_CHECKPQSIGVERIFY` or a 1-of-2 P2SH32 multisig with any FORKID sighash type. The correct spend passes with exactly one SigCheck; then one fuzzed edit (unlocking-script byte, truncation or extension, spent amount, version, locktime, outpoint, sequence, or a committed output) must make it fail. This is the third-party malleability and amount-commitment property. |
| `script_flags` (upstream) | Now also flips `SCRIPT_ENABLE_PQSIG`: adding or removing it may only change the result through BAD_OPCODE / DISABLED_OPCODE, like the other flags that add opcodes. Its flag filter now also requires MAY2025 whenever MAY2026 is set: the first 15-minute run found an input where MAY2026 without MAY2025 (impossible on chain, since upgrades activate in order) gave UNKNOWN, and adding MAY2025 made it pass. This is a gap in the upstream harness, not in the PQ code (the PQ flag was off in both evaluations). |
| `transaction_deserialize` (upstream) | Run in CI as well: PQ transactions are ordinary transactions with large scripts. |

Seed inputs live in `test/fuzz/xchain-corpus/<target>/`. Build and run locally:

```bash
cmake -S . -B build-fuzz -GNinja -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
  -DENABLE_SANITIZERS="fuzzer;address;undefined" -DBUILD_BITCOIN_WALLET=OFF -DBUILD_BITCOIN_QT=OFF
ninja -C build-fuzz fuzz-pqsig_encoding fuzz-pqsig_verify fuzz-pqsig_script
mkdir -p corpus && build-fuzz/src/test/fuzz/pqsig_script -max_total_time=600 corpus test/fuzz/xchain-corpus/pqsig_script
```

Signing under the sanitizers takes about 30 ms, so `pqsig_script` runs about 30 inputs per second and
`pqsig_verify` mostly reuses precomputed signatures. Long runs are worth doing before a release.
