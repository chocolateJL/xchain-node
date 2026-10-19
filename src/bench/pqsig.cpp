// Copyright (c) 2026 The XCHAIN developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ML-DSA-44 (OP_CHECKPQSIG) micro-benchmarks, with ECDSA and Schnorr P2PKH spends as the baseline.

#include <bench/bench.h>
#include <crypto/sha256.h>
#include <key.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/pqsig.h>
#include <script/script.h>
#include <script/script_execution_context.h>
#include <script/sighashtype.h>
#include <script/standard.h>

#include <array>
#include <cassert>
#include <vector>

namespace {

constexpr uint32_t PQ_FLAGS = STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_ENABLE_P2SH_32 | SCRIPT_ENABLE_TOKENS |
                              SCRIPT_ENABLE_MAY2025 | SCRIPT_ENABLE_MAY2026 | SCRIPT_ENABLE_PQSIG;
constexpr uint32_t BCH_FLAGS = PQ_FLAGS & ~SCRIPT_ENABLE_PQSIG;

struct Spend {
    CMutableTransaction credit, spend;
};

Spend MakeSpend(const CScript &scriptPubKey) {
    Spend s;
    s.credit.nVersion = 1;
    s.credit.vin.resize(1);
    s.credit.vin[0].scriptSig = CScript() << OP_0 << OP_0;
    s.credit.vout.resize(1);
    s.credit.vout[0].nValue = 1000 * SATOSHI;
    s.credit.vout[0].scriptPubKey = scriptPubKey;
    s.spend.nVersion = 1;
    s.spend.vin.resize(1);
    s.spend.vin[0].prevout = COutPoint(CTransaction(s.credit).GetId(), 0);
    s.spend.vout.resize(1);
    s.spend.vout[0].nValue = 1000 * SATOSHI;
    return s;
}

uint256 Digest(const Spend &s, uint32_t flags) {
    const CScript &spk = s.credit.vout[0].scriptPubKey;
    const ScriptExecutionContext context{0, s.credit.vout[0], s.spend};
    return SignatureHash(ByteView(spk.begin(), spk.end()), context, SigHashType().withFork(), nullptr, flags)
        .signatureHash;
}

struct PQFixture {
    std::vector<uint8_t> pubkey;
    pqsig::SecretKey secret;
    Spend spend;
    std::vector<uint8_t> rawSig;
    uint256 digest;

    PQFixture() {
        std::array<uint8_t, pqsig::SEED_SIZE> seed;
        seed.fill(7);
        assert(pqsig::KeyPairFromSeed(seed, pubkey, secret));
        std::vector<uint8_t> h(CSHA256::OUTPUT_SIZE);
        CSHA256().Write(pubkey.data(), pubkey.size()).Finalize(h.data());
        spend = MakeSpend(CScript() << OP_DUP << OP_SHA256 << h << OP_EQUALVERIFY << OP_CHECKPQSIG);
        digest = Digest(spend, PQ_FLAGS);
        assert(pqsig::Sign(secret, digest, rawSig));
        std::vector<uint8_t> sig = rawSig;
        sig.push_back(uint8_t(SigHashType().withFork().getRawSigHashType()));
        spend.spend.vin[0].scriptSig = CScript() << sig << pubkey;
    }
};

template <bool schnorr>
Spend MakeSignedP2PKH() {
    CKey key;
    key.MakeNewKey(true);
    Spend s = MakeSpend(GetScriptForDestination(key.GetPubKey().GetID()));
    std::vector<uint8_t> sig;
    const uint256 digest = Digest(s, BCH_FLAGS);
    assert(schnorr ? key.SignSchnorr(digest, sig) : key.SignECDSA(digest, sig));
    sig.push_back(uint8_t(SigHashType().withFork().getRawSigHashType()));
    const CPubKey pub = key.GetPubKey();
    s.spend.vin[0].scriptSig = CScript() << sig << std::vector<uint8_t>(pub.begin(), pub.end());
    return s;
}

void VerifySpend(benchmark::State &state, const Spend &s, uint32_t flags) {
    const CTransaction spend(s.spend);
    const ScriptExecutionContext context{0, s.credit.vout[0], spend};
    BENCHMARK_LOOP {
        ScriptError err;
        const bool ok = VerifyScript(spend.vin[0].scriptSig, s.credit.vout[0].scriptPubKey, flags,
                                     TransactionSignatureChecker(context), &err);
        assert(ok);
    }
}

} // namespace

/** One ML-DSA-44 verification over a 32-byte digest (the consensus build: portable C). */
static void PQSigVerify(benchmark::State &state) {
    const PQFixture f;
    BENCHMARK_LOOP {
        const bool ok = pqsig::Verify(f.pubkey, f.rawSig, f.digest);
        assert(ok);
    }
}

/** One hedged ML-DSA-44 signature (wallet side). */
static void PQSigSign(benchmark::State &state) {
    const PQFixture f;
    std::vector<uint8_t> sig;
    BENCHMARK_LOOP {
        const bool ok = pqsig::Sign(f.secret, f.digest, sig);
        assert(ok);
    }
}

/** Full script verification of a P2PQH input: hash check, sighash, ML-DSA verify. */
static void VerifyScriptP2PQH(benchmark::State &state) {
    const PQFixture f;
    VerifySpend(state, f.spend, PQ_FLAGS);
}

/** Baseline: full script verification of an ECDSA P2PKH input (BCH rules). */
static void VerifyScriptP2PKH_ECDSA(benchmark::State &state) {
    VerifySpend(state, MakeSignedP2PKH<false>(), BCH_FLAGS);
}

/** Baseline: full script verification of a Schnorr P2PKH input (BCH rules). */
static void VerifyScriptP2PKH_Schnorr(benchmark::State &state) {
    VerifySpend(state, MakeSignedP2PKH<true>(), BCH_FLAGS);
}

BENCHMARK(PQSigVerify, 5000);
BENCHMARK(PQSigSign, 1000);
BENCHMARK(VerifyScriptP2PQH, 5000);
BENCHMARK(VerifyScriptP2PKH_ECDSA, 5000);
BENCHMARK(VerifyScriptP2PKH_Schnorr, 5000);
