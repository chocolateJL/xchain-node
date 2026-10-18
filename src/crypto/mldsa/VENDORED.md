# Vendored: mldsa-native

- Upstream: https://github.com/pq-code-package/mldsa-native
- Version: v2.0.0 (commit 834a90d5e846ffa1e1611bd24e160bb2e9b86d35)
- Copied: the `mldsa/` directory, unmodified, plus LICENSE (Apache-2.0 OR ISC OR MIT)
- Do not edit files here. To update, replace the whole directory from a new upstream tag and
  rerun the ML-DSA tests in `lab/mldsa-native` and `src/test/pqsig_tests.cpp`.

Build configuration (see src/crypto/CMakeLists.txt): parameter set 44, namespace prefix
`xc_mldsa44`, portable C only (decision D12 pending; no native backend, no assembly).
