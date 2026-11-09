// Copyright (c) 2026 The XCHAIN developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Mempool acceptance of ordinary P2PQH transfers (one input, two outputs), as the message thread sees them once the
// pre-checkers have verified their signatures: the signature cache already holds them, so this measures what
// AcceptToMemoryPool itself costs per transaction (spec/parallel-admission.md in the project repository).

#include <bench/bench.h>
#include <chainparams.h>
#include <coins.h>
#include <config.h>
#include <consensus/activation.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <crypto/sha256.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/pqsig.h>
#include <script/script.h>
#include <script/script_execution_context.h>
#include <script/sigcache.h>
#include <script/scriptcache.h>
#include <script/sighashtype.h>
#include <test/util.h>
#include <txmempool.h>
#include <validation.h>

#include <array>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <vector>

namespace {

constexpr size_t NUM_TXS = 100;
constexpr uint32_t SIGHASH_FLAGS = STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_ENABLE_P2SH_32 | SCRIPT_ENABLE_TOKENS |
                                   SCRIPT_ENABLE_MAY2025 | SCRIPT_ENABLE_MAY2026 | SCRIPT_ENABLE_PQSIG;

CScript P2PQH(const std::vector<uint8_t> &pubkey) {
    std::vector<uint8_t> hash(CSHA256::OUTPUT_SIZE);
    CSHA256().Write(pubkey.data(), pubkey.size()).Finalize(hash.data());
    return CScript() << OP_DUP << OP_SHA256 << hash << OP_EQUALVERIFY << OP_CHECKPQSIG;
}

/** Signed transfers spending NUM_TXS mature coinbases paid to a P2PQH key. */
std::vector<CTransactionRef> MakeTransfers(const Config &config) {
    std::array<uint8_t, pqsig::SEED_SIZE> seed;
    seed.fill(7);
    std::vector<uint8_t> pubkey;
    pqsig::SecretKey secret;
    bool ok = pqsig::KeyPairFromSeed(seed, pubkey, secret);
    assert(ok);
    const CScript spk = P2PQH(pubkey);

    std::vector<CTxIn> coinbases;
    for (size_t i = 0; i < NUM_TXS; ++i) {
        coinbases.push_back(MineBlock(config, spk));
    }
    for (int i = 0; i < COINBASE_MATURITY + 1; ++i) {
        MineBlock(config, spk);
    }

    std::vector<CTransactionRef> txs;
    for (const CTxIn &in : coinbases) {
        const CTxOut spent = WITH_LOCK(cs_main, return pcoinsTip->AccessCoin(in.prevout).GetTxOut());
        CMutableTransaction mtx;
        mtx.vin.push_back(in);
        const Amount half = (spent.nValue - 4000 * SATOSHI) / 2;
        mtx.vout.emplace_back(half, spk);
        mtx.vout.emplace_back(spent.nValue - 4000 * SATOSHI - half, spk);
        const SigHashType sigHashType = SigHashType().withFork();
        const ScriptExecutionContext context{0, spent, mtx};
        const uint256 digest =
            SignatureHash(ByteView(spk.begin(), spk.end()), context, sigHashType, nullptr, SIGHASH_FLAGS)
                .signatureHash;
        std::vector<uint8_t> sig;
        ok = pqsig::SignDeterministic(secret, digest, sig);
        assert(ok);
        sig.push_back(uint8_t(sigHashType.getRawSigHashType()));
        mtx.vin[0].scriptSig = CScript() << sig << pubkey;
        txs.push_back(MakeTransactionRef(mtx));
    }
    return txs;
}

/**
 * `preChecked`: also record each transaction in the script execution cache under the standard flags, as a pre-check
 * that passed does (AddPassedPreCheck), so that acceptance skips its first script pass. Recording costs about a
 * microsecond and is inside the timed loop.
 */
void AcceptTransfers(benchmark::State &state, bool preChecked) {
    // The test setup keeps regtest on the inherited BCH rules; this chain runs the post-quantum rules from genesis.
    ::g_PQSigHeightOverride.emplace(0);
    const Config &config = GetConfig();
    const std::vector<CTransactionRef> txs = MakeTransfers(config);
    // As on a node: mempool acceptance verifies with the AVX2 build when the CPU has it. Then the consensus-flags pass
    // does not store its script-cache key (the background re-check does, and it is not running here), so every round
    // runs that pass; its signatures hit the cache, as after the pre-check.
    pqsig::InitAdmissionVerifier(true);

    LOCK(cs_main);
    const uint32_t standardFlags =
        GetMemPoolScriptFlags(config.GetChainParams().GetConsensus(), ::ChainActive().Tip(), nullptr);
    const auto acceptAll = [&] {
        for (const CTransactionRef &tx : txs) {
            if (preChecked) {
                AddKeyInScriptCache(ScriptCacheKey(*tx, standardFlags), 1);
            }
            CValidationState vstate;
            const bool accepted = AcceptToMemoryPool(config, g_mempool, vstate, tx, nullptr /* pfMissingInputs */,
                                                     false /* bypass_limits */, Amount::zero() /* nAbsurdFee */);
            if (!accepted) {
                std::fprintf(stderr, "MempoolAcceptPQ: rejected: %s\n", FormatStateMessage(vstate).c_str());
                std::abort();
            }
        }
        g_mempool.clear();
    };
    acceptAll(); // fill the signature cache
    BENCHMARK_LOOP {
        acceptAll();
    }
    pqsig::InitAdmissionVerifier(false);
    ::g_PQSigHeightOverride.emplace(Consensus::PQSIG_DISABLED_HEIGHT);
}

void MempoolAcceptPQ(benchmark::State &state) {
    AcceptTransfers(state, false);
}

void MempoolAcceptPQPreChecked(benchmark::State &state) {
    AcceptTransfers(state, true);
}

} // namespace

BENCHMARK(MempoolAcceptPQ, 30);
BENCHMARK(MempoolAcceptPQPreChecked, 30);
