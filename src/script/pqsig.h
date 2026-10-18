// Copyright (c) 2026 The XCHAIN developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <script/container_types.h>
#include <support/allocators/secure.h>
#include <uint256.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

/**
 * ML-DSA-44 (FIPS 204) transaction signatures, as used by OP_CHECKPQSIG.
 * See spec/pq-signature.md.
 */
namespace pqsig {

/** Algorithm identifier: first byte of every public key stack element. */
inline constexpr uint8_t ALG_ML_DSA_44 = 0x01;

inline constexpr size_t RAW_PUBKEY_SIZE = 1312;
inline constexpr size_t RAW_SIG_SIZE = 2420;
inline constexpr size_t SECRET_KEY_SIZE = 2560;
inline constexpr size_t SEED_SIZE = 32;

/** Public key stack element: algorithm identifier + raw ML-DSA-44 public key. */
inline constexpr size_t PUBKEY_SIZE = 1 + RAW_PUBKEY_SIZE;
/** Signature stack element: raw ML-DSA-44 signature + sighash type byte. */
inline constexpr size_t SIG_SIZE = RAW_SIG_SIZE + 1;

/** FIPS 204 context string. "XCHAIN" is a placeholder until the chain is named (decision D13). */
inline constexpr char CONTEXT[] = "XCHAIN-tx-v1";
inline constexpr size_t CONTEXT_SIZE = sizeof(CONTEXT) - 1;

using SecretKey = std::vector<uint8_t, secure_allocator<uint8_t>>;

/** True if `pubkey` is exactly PUBKEY_SIZE bytes and starts with a known algorithm identifier. */
bool IsValidPubKeyEncoding(ByteView pubkey);

/**
 * Verify a raw signature (without the sighash byte) over a 32-byte digest.
 * `pubkey` is the full stack element including the algorithm identifier.
 * Returns false for any encoding error.
 */
bool Verify(ByteView pubkey, ByteView rawSig, const uint256 &digest);

/** Derive a key pair from a 32-byte seed (ML-DSA.KeyGen_internal). `pubkey` gets the algorithm identifier. */
bool KeyPairFromSeed(const std::array<uint8_t, SEED_SIZE> &seed, std::vector<uint8_t> &pubkey, SecretKey &secret);

/** Hedged (randomized) signature over a 32-byte digest. Writes RAW_SIG_SIZE bytes, no sighash byte. */
bool Sign(const SecretKey &secret, const uint256 &digest, std::vector<uint8_t> &rawSig);

/**
 * Deterministic variant (FIPS 204 with rnd = 0^32). For reproducible test vectors only;
 * wallets must use Sign(). Verification does not depend on which variant was used.
 */
bool SignDeterministic(const SecretKey &secret, const uint256 &digest, std::vector<uint8_t> &rawSig);

} // namespace pqsig
