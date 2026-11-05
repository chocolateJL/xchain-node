// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-present The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <primitives/txid.h>
#include <script/interpreter.h>
#include <script/scriptcache.h>

#include <functional>
#include <utility>
#include <vector>

// DoS prevention: limit cache size to 32MB (over 1000000 entries on 64-bit
// systems). Due to how we count cache size, actual memory usage is slightly
// more (~32.25 MB)
static constexpr int64_t DEFAULT_MAX_SIG_CACHE_SIZE = 32;
// Maximum sig cache size allowed
static constexpr int64_t MAX_MAX_SIG_CACHE_SIZE = 16384;

class CPubKey;

/**
 * We're hashing a nonce into the entries themselves, so we don't need extra
 * blinding in the set hash computation.
 *
 * This may exhibit platform endian dependent behavior but because these are
 * nonced hashes (random) and this state is only ever used locally it is safe.
 * All that matters is local consistency.
 */
class SignatureCacheHasher {
public:
    template <uint8_t hash_select>
    uint32_t operator()(const uint256 &key) const noexcept {
        static_assert(hash_select < 8, "SignatureCacheHasher only has 8 hashes available.");
        uint32_t u;
        std::memcpy(&u, key.begin() + 4 * hash_select, 4);
        return u;
    }
};

class CachingTransactionSignatureChecker : public TransactionSignatureChecker {
private:
    bool store;

    bool IsCached(const ByteView &vchSig, const CPubKey &vchPubKey, const uint256 &sighash) const;
    bool IsPQCached(const ByteView &rawSig, const ByteView &pubkey, const uint256 &sighash) const;

public:
    CachingTransactionSignatureChecker(const ScriptExecutionContext &contextIn, bool storeIn,
                                       PrecomputedTransactionData &txdataIn)
        : TransactionSignatureChecker(contextIn, txdataIn),
          store(storeIn) {}

    bool VerifySignature(const ByteView &vchSig,
                         const CPubKey &vchPubKey,
                         const uint256 &sighash) const override;

    // XCHAIN: ML-DSA verification costs more than ECDSA; without the cache a transaction's PQ signatures are verified
    // twice on mempool acceptance (standard, then consensus flags).
    bool VerifyPQSignature(const ByteView &rawSig, const ByteView &pubkey, const uint256 &sighash) const override;

    friend class TestCachingTransactionSignatureChecker;
};

/**
 * Initialize the signature cache. Must be called once in
 * AppInitMain/BasicTestingSetup to initialize the signatureCache. Subsequent
 * calls will reset the cache and clear it. (Re)Initialization of the cache
 * should happen in the main thread before other threads are started since
 * this function takes no locks.
 */
void InitSignatureCache();

/** Default for -pqadmitavx2: verify PQ signatures with the AVX2 build on mempool acceptance (see pqsig.h). */
static constexpr bool DEFAULT_PQ_ADMIT_AVX2 = true;

/**
 * While a PQAdmissionScope is alive on a thread (mempool acceptance), CachingTransactionSignatureChecker verifies PQ
 * signatures with pqsig::VerifyForAdmission. When that is the AVX2 build, its results go only into an admission part
 * of the signature cache, and each verified signature is queued for the portable build; only the portable build's
 * results go into the part that block validation reads (decision D12). A signature the AVX2 build rejects is
 * checked again with the portable build, so the AVX2 build never makes us reject a valid transaction.
 */
class PQAdmissionScope {
public:
    PQAdmissionScope();
    ~PQAdmissionScope();
    PQAdmissionScope(const PQAdmissionScope &) = delete;
    PQAdmissionScope &operator=(const PQAdmissionScope &) = delete;

    /** True if a signature check in this scope relied on an AVX2 result not yet confirmed by the portable build. */
    bool UsedAVX2Results() const;

    /**
     * For an accepted transaction: queue the AVX2 results this scope relied on for the portable build. Once it
     * confirms them all, the transaction's script cache entry (`scriptKey`, `nSigChecks`) is added too.
     */
    void QueueConfirmation(const CTransaction &tx, const ScriptCacheKey &scriptKey, int nSigChecks) const;
};

/**
 * Start the thread that verifies the signatures queued by PQAdmissionScope with the portable build. It hands script
 * cache entries for confirmed transactions to `onConfirmed` in batches (which must take cs_main to add them). If the
 * portable build rejects a signature, the AVX2 build is disabled and `onMismatch` is called with the transaction's id.
 */
void StartPQAdmissionChecker(std::function<void(std::vector<std::pair<ScriptCacheKey, int>> &&)> onConfirmed,
                             std::function<void(const TxId &)> onMismatch);
void StopPQAdmissionChecker();
