# RandomX (vendored)

- Upstream: https://github.com/tevador/RandomX, tag `v1.2.3` (commit 12f2c2ffe2108d6cf54c391fee33c8bc3646cdab, 2026-07-17)
- License: BSD-3-Clause (`LICENSE`), compatible with the node's MIT license
- Contents: `CMakeLists.txt`, `LICENSE`, `README.md` and `src/` copied unchanged
- Algorithm: RandomX v1 ("rx/0", the variant Monero uses), standard configuration (`src/configuration.h` unchanged)
- Built with `ARCH=default` (no `-march=native`), so binaries are portable; the JIT is used where available

Used for proof of work on the xChain networks (decision D5): see `src/pow.cpp` and `spec/randomx-pow.md` in the
project repository. Updates: replace this directory with a newer tag and record it here.
