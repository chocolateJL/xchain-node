// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2022 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/sigcache.h>

#include <cuckoocache.h>
#include <logging.h>
#include <memusage.h>
#include <pubkey.h>
#include <random.h>
#include <script/pqsig.h>
#include <uint256.h>
#include <util/system.h>
#include <util/threadnames.h>

#include <algorithm>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <shared_mutex>
#include <thread>

namespace {

/**
 * Valid signature cache, to avoid doing expensive ECDSA signature checking
 * twice for every transaction (once when accepted into memory pool, and
 * again when accepted into the block chain)
 */
class CSignatureCache {
    //! Entries are SHA256(nonce || signature hash || public key || signature). PQ signature entries are
    //! SHA256(pqNonce || SHA256(signature hash || public key || signature)), or with pqAdmissionNonce for results of
    //! the AVX2 build (see PQAdmissionScope); separate nonces keep the kinds of entry apart.
    uint256 nonce;
    uint256 pqNonce;
    uint256 pqAdmissionNonce;
    using map_type = CuckooCache::cache<CuckooCache::KeyOnly<uint256>, SignatureCacheHasher>;
    map_type setValid;
    std::shared_mutex cs_sigcache;

    bool ready = false;

    void Reset() {
        setValid.~map_type(); // manually destroy the cache
        new (&setValid) map_type(); // replace cache with placement new
        ready = false;
    }

public:
    CSignatureCache() {
        GetRandBytes(nonce.data(), 32);
        GetRandBytes(pqNonce.data(), 32);
        GetRandBytes(pqAdmissionNonce.data(), 32);
    }

    uint256 ComputeEntry(const uint256 &hash, const ByteView &vchSig, const CPubKey &pubkey) const {
        uint256 ret(uint256::Uninitialized);
        CSHA256()
            .Write(nonce.data(), 32)
            .Write(hash.data(), 32)
            .Write(&pubkey[0], pubkey.size())
            .Write(vchSig.data(), vchSig.size())
            .Finalize(ret.data());
        return ret;
    }

    /** What a PQ signature check covers; hashed once per check, then keyed per kind of entry. */
    static uint256 ComputePQMaterial(const uint256 &hash, const ByteView &rawSig, const ByteView &pubkey) {
        uint256 ret(uint256::Uninitialized);
        CSHA256()
            .Write(hash.data(), 32)
            .Write(pubkey.data(), pubkey.size())
            .Write(rawSig.data(), rawSig.size())
            .Finalize(ret.data());
        return ret;
    }

    uint256 ComputePQEntry(const uint256 &material, bool admission) const {
        uint256 ret(uint256::Uninitialized);
        CSHA256()
            .Write((admission ? pqAdmissionNonce : pqNonce).data(), 32)
            .Write(material.data(), 32)
            .Finalize(ret.data());
        return ret;
    }

    bool Get(const uint256 &entry, const bool erase) {
        assert(ready);
        std::shared_lock lock(cs_sigcache);
        return setValid.contains(entry, erase);
    }

    void Set(const uint256 &entry) {
        assert(ready);
        std::unique_lock lock(cs_sigcache);
        setValid.insert(entry);
    }
    uint32_t setup_bytes(size_t n) {
        Reset();
        const uint32_t ret = setValid.setup_bytes(n);
        ready = true;
        return ret;
    }
};

/**
 * In previous versions of this code, signatureCache was a local static variable
 * in CachingTransactionSignatureChecker::VerifySignature. We initialize
 * signatureCache outside of VerifySignature to avoid the atomic operation per
 * call overhead associated with local static variables even though
 * signatureCache could be made local to VerifySignature.
 */
static CSignatureCache signatureCache;
} // namespace

void InitSignatureCache() {
    // nMaxCacheSize is unsigned. If -maxsigcachesize is set to zero,
    // setup_bytes creates the minimum possible cache (2 elements).
    size_t nMaxCacheSize = std::clamp(gArgs.GetArg("-maxsigcachesize", DEFAULT_MAX_SIG_CACHE_SIZE),
                                      int64_t{0},
                                      MAX_MAX_SIG_CACHE_SIZE) * (size_t{1} << 20);
    size_t nElems = signatureCache.setup_bytes(nMaxCacheSize);
    LogPrintf("Using %zu MiB out of %zu requested for signature cache, able to "
              "store %zu elements\n",
              (nElems * sizeof(uint256)) >> 20, nMaxCacheSize >> 20, nElems);
}

template <typename F>
bool RunMemoizedCheck(const uint256 &entry, bool storeOrErase, const F &fun) {
    if (signatureCache.Get(entry, !storeOrErase)) {
        return true;
    }
    if (!fun()) {
        return false;
    }
    if (storeOrErase) {
        signatureCache.Set(entry);
    }
    return true;
}

bool CachingTransactionSignatureChecker::IsCached(const ByteView &vchSig, const CPubKey &pubkey, const uint256 &sighash) const {
    return RunMemoizedCheck(signatureCache.ComputeEntry(sighash, vchSig, pubkey), true, [] { return false; });
}

bool CachingTransactionSignatureChecker::IsPQCached(const ByteView &rawSig, const ByteView &pubkey,
                                                    const uint256 &sighash) const {
    const uint256 material = CSignatureCache::ComputePQMaterial(sighash, rawSig, pubkey);
    return RunMemoizedCheck(signatureCache.ComputePQEntry(material, false), true, [] { return false; });
}

bool CachingTransactionSignatureChecker::VerifySignature(const ByteView &vchSig, const CPubKey &pubkey, const uint256 &sighash) const {
    return RunMemoizedCheck(signatureCache.ComputeEntry(sighash, vchSig, pubkey), store, [&] {
        return TransactionSignatureChecker::VerifySignature(vchSig, pubkey, sighash);
    });
}

namespace {
//! Depth of PQAdmissionScope on this thread, and the AVX2 results the outermost one relied on.
thread_local int g_admissionDepth = 0;
thread_local bool g_admissionUsedAVX2 = false;

/** A PQ signature check whose result came from the AVX2 build. */
struct PQSigCheck {
    std::vector<uint8_t> pubkey;
    std::vector<uint8_t> rawSig;
    uint256 sighash;
    uint256 material;
};
thread_local std::vector<PQSigCheck> g_admissionChecks;

/** An accepted transaction whose PQ signatures were verified with the AVX2 build, waiting for the portable build. */
struct PQAdmissionConfirmation {
    TxId txid;
    std::vector<PQSigCheck> checks;
    ScriptCacheKey scriptKey;
    int nSigChecks;
};

/** Most queued transactions (about 3.8 kB each); further ones are dropped and verified when a block needs them. */
static constexpr size_t MAX_PQ_ADMISSION_QUEUE = 20'000;
/** Script cache entries handed over at a time (onConfirmed takes cs_main). */
static constexpr size_t PQ_CONFIRMED_BATCH = 500;
/** Log the checker's counts every this many transactions. */
static constexpr int64_t PQ_ADMISSION_LOG_INTERVAL = 100'000;

class PQAdmissionChecker {
    std::mutex mutex;
    std::condition_variable cond;
    std::deque<PQAdmissionConfirmation> queue;
    bool running = false;
    std::thread thread;
    std::function<void(std::vector<std::pair<ScriptCacheKey, int>> &&)> onConfirmed;
    std::function<void(const TxId &)> onMismatch;
    int64_t checked = 0, dropped = 0;

    /** Verifies one transaction's signatures with the portable build; false if one is rejected. */
    bool Confirm(const PQAdmissionConfirmation &tx) {
        for (const PQSigCheck &check : tx.checks) {
            const uint256 entry = signatureCache.ComputePQEntry(check.material, false);
            if (signatureCache.Get(entry, false)) {
                continue;
            }
            if (!pqsig::Verify(check.pubkey, check.rawSig, check.sighash)) {
                return false;
            }
            signatureCache.Set(entry);
        }
        return true;
    }

    void Run() {
        util::ThreadRename("pqadmit");
        std::vector<std::pair<ScriptCacheKey, int>> scriptKeys;
        std::unique_lock lock(mutex);
        while (true) {
            if (queue.empty() && !scriptKeys.empty()) {
                lock.unlock();
                onConfirmed(std::move(scriptKeys));
                scriptKeys.clear();
                lock.lock();
                continue;
            }
            cond.wait(lock, [this] { return !running || !queue.empty(); });
            if (!running) {
                return;
            }
            PQAdmissionConfirmation tx = std::move(queue.front());
            queue.pop_front();
            lock.unlock();
            if (Confirm(tx)) {
                // The scripts are deterministic and every signature they relied on now has the portable build's
                // result, so the transaction's script cache entry is the one the portable build would have made.
                scriptKeys.emplace_back(tx.scriptKey, tx.nSigChecks);
                if (scriptKeys.size() >= PQ_CONFIRMED_BATCH) {
                    onConfirmed(std::move(scriptKeys));
                    scriptKeys.clear();
                }
            } else {
                LogPrintf("ERROR: the AVX2 build of ML-DSA accepted a signature in tx %s that the portable build "
                          "rejects; the AVX2 build is no longer used\n", tx.txid.ToString());
                pqsig::DisableAdmissionAVX2();
                onMismatch(tx.txid);
            }
            lock.lock();
            if (++checked % PQ_ADMISSION_LOG_INTERVAL == 0) {
                LogPrint(BCLog::BENCH, "PQ admission checks: %d txs checked with the portable build, %d dropped "
                         "(queue full), %u queued\n", checked, dropped, queue.size());
            }
        }
    }

public:
    void Start(std::function<void(std::vector<std::pair<ScriptCacheKey, int>> &&)> onConfirmedIn,
               std::function<void(const TxId &)> onMismatchIn) {
        std::unique_lock lock(mutex);
        assert(!running);
        onConfirmed = std::move(onConfirmedIn);
        onMismatch = std::move(onMismatchIn);
        running = true;
        thread = std::thread([this] { Run(); });
    }

    void Stop() {
        {
            std::unique_lock lock(mutex);
            if (!running) {
                return;
            }
            running = false;
            queue.clear();
        }
        cond.notify_all();
        thread.join();
    }

    void Push(PQAdmissionConfirmation &&tx) {
        {
            std::unique_lock lock(mutex);
            if (!running) {
                return;
            }
            if (queue.size() >= MAX_PQ_ADMISSION_QUEUE) {
                ++dropped;
                return;
            }
            queue.push_back(std::move(tx));
        }
        cond.notify_one();
    }
};

static PQAdmissionChecker pqAdmissionChecker;
} // namespace

PQAdmissionScope::PQAdmissionScope() {
    if (g_admissionDepth++ == 0) {
        g_admissionUsedAVX2 = false;
        g_admissionChecks.clear();
    }
}

PQAdmissionScope::~PQAdmissionScope() {
    --g_admissionDepth;
}

bool PQAdmissionScope::UsedAVX2Results() const {
    return g_admissionUsedAVX2;
}

void PQAdmissionScope::QueueConfirmation(const CTransaction &tx, const ScriptCacheKey &scriptKey,
                                         int nSigChecks) const {
    if (g_admissionChecks.empty()) {
        return;
    }
    pqAdmissionChecker.Push({tx.GetId(), std::move(g_admissionChecks), scriptKey, nSigChecks});
    g_admissionChecks.clear();
}

void StartPQAdmissionChecker(std::function<void(std::vector<std::pair<ScriptCacheKey, int>> &&)> onConfirmed,
                             std::function<void(const TxId &)> onMismatch) {
    pqAdmissionChecker.Start(std::move(onConfirmed), std::move(onMismatch));
}

void StopPQAdmissionChecker() {
    pqAdmissionChecker.Stop();
}

bool CachingTransactionSignatureChecker::VerifyPQSignature(const ByteView &rawSig, const ByteView &pubkey,
                                                           const uint256 &sighash) const {
    const uint256 material = CSignatureCache::ComputePQMaterial(sighash, rawSig, pubkey);
    const uint256 entry = signatureCache.ComputePQEntry(material, false);
    const auto verifyPortable = [&] {
        return RunMemoizedCheck(entry, store, [&] {
            return TransactionSignatureChecker::VerifyPQSignature(rawSig, pubkey, sighash);
        });
    };
    if (g_admissionDepth == 0 || !pqsig::AdmissionUsesAVX2()) {
        return verifyPortable();
    }

    // Mempool acceptance with the AVX2 build. A result of the portable build is as good as ever.
    if (signatureCache.Get(entry, false)) {
        return true;
    }
    const uint256 admissionEntry = signatureCache.ComputePQEntry(material, true);
    if (!signatureCache.Get(admissionEntry, false)) {
        if (!pqsig::VerifyForAdmission(pubkey, rawSig, sighash)) {
            // Never reject on the AVX2 build's word alone.
            return verifyPortable();
        }
        if (store) {
            signatureCache.Set(admissionEntry);
        }
    }
    g_admissionUsedAVX2 = true;
    // Both script passes check the same signatures; keep each once.
    if (std::none_of(g_admissionChecks.begin(), g_admissionChecks.end(),
                     [&](const PQSigCheck &c) { return c.material == material; })) {
        g_admissionChecks.push_back({std::vector<uint8_t>(pubkey.begin(), pubkey.end()),
                                     std::vector<uint8_t>(rawSig.begin(), rawSig.end()), sighash, material});
    }
    return true;
}
