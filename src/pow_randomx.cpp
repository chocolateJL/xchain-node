// Copyright (c) 2026 The XCHAIN developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow_randomx.h>

#include <arith_uint256.h>
#include <chain.h>
#include <consensus/params.h>
#include <logging.h>
#include <primitives/block.h>
#include <streams.h>
#include <sync.h>
#include <version.h>

#include <randomx/src/randomx.h>

#include <cstring>
#include <list>
#include <stdexcept>

namespace randomx_pow {

int SeedHeight(int height) {
    if (height <= SEED_EPOCH + SEED_LAG) {
        return 0;
    }
    return (height - SEED_LAG - 1) & ~(SEED_EPOCH - 1);
}

uint256 SeedHash(const CBlockIndex *pindexPrev) {
    if (pindexPrev == nullptr) {
        return uint256();
    }
    const CBlockIndex *seed = pindexPrev->GetAncestor(SeedHeight(pindexPrev->nHeight + 1));
    assert(seed != nullptr);
    return seed->GetBlockHash();
}

namespace {

/** A light-mode RandomX cache and VM for one seed. */
struct Context {
    uint256 seed;
    randomx_cache *cache = nullptr;
    randomx_vm *vm = nullptr;

    Context(const uint256 &seedIn, randomx_flags flags) : seed(seedIn) {
        cache = randomx_alloc_cache(flags);
        if (cache == nullptr) {
            // JIT or large pages may be unavailable; the portable interpreter gives the same hashes.
            flags = RANDOMX_FLAG_DEFAULT;
            cache = randomx_alloc_cache(flags);
        }
        if (cache == nullptr) {
            throw std::runtime_error("RandomX: cannot allocate the cache");
        }
        randomx_init_cache(cache, seed.begin(), seed.size());
        vm = randomx_create_vm(flags, cache, nullptr);
        if (vm == nullptr) {
            randomx_release_cache(cache);
            throw std::runtime_error("RandomX: cannot create a virtual machine");
        }
    }
    ~Context() {
        randomx_destroy_vm(vm);
        randomx_release_cache(cache);
    }
    Context(const Context &) = delete;
    Context &operator=(const Context &) = delete;
};

Mutex g_mutex;
/** Most recently used first; at most two seeds (the current epoch and the previous one during reorgs). */
std::list<Context> g_contexts GUARDED_BY(g_mutex);

} // namespace

uint256 Hash(const CBlockHeader &header, const uint256 &seed) {
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << header;
    assert(ss.size() == 80);

    uint256 out;
    LOCK(g_mutex);
    auto it = g_contexts.begin();
    while (it != g_contexts.end() && it->seed != seed) {
        ++it;
    }
    if (it == g_contexts.end()) {
        LogPrint(BCLog::BENCH, "RandomX: initializing cache for seed %s\n", seed.ToString());
        g_contexts.emplace_front(seed, randomx_get_flags());
        if (g_contexts.size() > 2) {
            g_contexts.pop_back();
        }
        it = g_contexts.begin();
    } else if (it != g_contexts.begin()) {
        g_contexts.splice(g_contexts.begin(), g_contexts, it);
        it = g_contexts.begin();
    }
    randomx_calculate_hash(it->vm, ss.data(), ss.size(), out.begin());
    return out;
}

bool CheckHash(const uint256 &rxHash, uint32_t nBits, const Consensus::Params &params) {
    bool fNegative, fOverflow;
    arith_uint256 target;
    target.SetCompact(nBits, &fNegative, &fOverflow);
    if (fNegative || target == 0 || fOverflow || target > UintToArith256(params.powLimit)) {
        return false;
    }
    return (UintToArith256(rxHash) >> TARGET_SHIFT) <= target;
}

bool CheckHeader(const CBlockHeader &header, const CBlockIndex *pindexPrev, const Consensus::Params &params) {
    return CheckHash(Hash(header, SeedHash(pindexPrev)), header.nBits, params);
}

} // namespace randomx_pow
