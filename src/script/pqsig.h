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
 * Post-quantum transaction signatures, as used by OP_CHECKPQSIG. ML-DSA-44 (FIPS 204) is the only enabled
 * algorithm. See spec/pq-signature.md.
 */
namespace pqsig {

/** Algorithm identifiers: first byte of every public key stack element. */
inline constexpr uint8_t ALG_ML_DSA_44 = 0x01;
/** Reserved identifiers, treated as unknown until a network upgrade enables them (decisions D1, D19). */
inline constexpr uint8_t ALG_SLH_DSA_RESERVED = 0x02;
inline constexpr uint8_t ALG_FN_DSA_512_RESERVED = 0x03;

/** Sizes of one signature algorithm. Raw sizes exclude the identifier byte and the sighash byte. */
struct Algorithm {
    uint8_t id;
    const char *name;
    size_t rawPubKeySize;
    size_t rawSigSize;

    /** Public key stack element: algorithm identifier + raw public key. */
    constexpr size_t PubKeySize() const { return 1 + rawPubKeySize; }
    /** Signature stack element: raw signature + sighash type byte. */
    constexpr size_t SigSize() const { return rawSigSize + 1; }
};

inline constexpr Algorithm ML_DSA_44{ALG_ML_DSA_44, "ML-DSA-44", 1312, 2420};

/**
 * The enabled algorithm a public key element names, or nullptr if the identifier is unknown or the element has the
 * wrong size. Adding an algorithm (FN-DSA-512 under 0x03, D19) means adding it here and in Verify(), gated by the
 * script flag of the upgrade that enables it.
 */
const Algorithm *GetPubKeyAlgorithm(ByteView pubkey);

/**
 * Serialized size of a transaction input spending a P2PQH output with `alg`: outpoint (36), scriptSig length (3),
 * the signature and public key pushes (PUSHDATA2, 3 bytes of overhead each, since both elements are 256-65535 bytes)
 * and sequence (4).
 */
constexpr size_t P2PQHInputSize(const Algorithm &alg) {
    return 36 + 3 + (3 + alg.SigSize()) + (3 + alg.PubKeySize()) + 4;
}

// ML-DSA-44 sizes: the key generation and signing below, and the wallet default.
inline constexpr size_t RAW_PUBKEY_SIZE = ML_DSA_44.rawPubKeySize;
inline constexpr size_t RAW_SIG_SIZE = ML_DSA_44.rawSigSize;
inline constexpr size_t SECRET_KEY_SIZE = 2560;
inline constexpr size_t SEED_SIZE = 32;
inline constexpr size_t PUBKEY_SIZE = ML_DSA_44.PubKeySize();
inline constexpr size_t SIG_SIZE = ML_DSA_44.SigSize();

/** FIPS 204 context string; "XCHAIN" from the chain name xChain (decision D13). */
inline constexpr char CONTEXT[] = "XCHAIN-tx-v1";
inline constexpr size_t CONTEXT_SIZE = sizeof(CONTEXT) - 1;

using SecretKey = std::vector<uint8_t, secure_allocator<uint8_t>>;

/** True if `pubkey` names an enabled algorithm and has that algorithm's public key element size. */
bool IsValidPubKeyEncoding(ByteView pubkey);

/**
 * Verify a raw signature (without the sighash byte) over a 32-byte digest with the algorithm `pubkey` names.
 * `pubkey` is the full stack element including the algorithm identifier.
 * Returns false for any encoding error, including a signature of the wrong size for that algorithm.
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
