// Copyright (c) 2026 The XCHAIN developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Full OP_CHECKPQSIG spends under the XCHAIN script flags. A fuzzed transaction
// spends one of several PQ locking scripts with a correct signature, which must
// pass with the expected SigChecks count. Then fuzzed edits are made to the
// unlocking script, the spent amount or any signed transaction field; every such
// edit must make the spend fail (no third-party malleability, amounts committed).

#include <amount.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/pqsig.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/script_execution_context.h>
#include <script/script_flags.h>
#include <script/script_metrics.h>
#include <script/standard.h>

#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>

#include <array>
#include <cassert>
#include <cstdint>
#include <vector>

namespace {

constexpr uint32_t PQ_FLAGS = STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_ENABLE_P2SH_32 | SCRIPT_ENABLE_TOKENS |
                              SCRIPT_ENABLE_MAY2025 | SCRIPT_ENABLE_MAY2026 | SCRIPT_ENABLE_PQSIG;

using Bytes = std::vector<uint8_t>;

struct Key {
    Bytes pubkey;
    pqsig::SecretKey secret;
};

const std::array<Key, 2> &Keys() {
    static const std::array<Key, 2> keys = [] {
        std::array<Key, 2> out;
        for (uint8_t i = 0; i < out.size(); ++i) {
            std::array<uint8_t, pqsig::SEED_SIZE> seed;
            seed.fill(0x51 + i);
            assert(pqsig::KeyPairFromSeed(seed, out[i].pubkey, out[i].secret));
        }
        return out;
    }();
    return keys;
}

Bytes Sha256(const Bytes &data) {
    Bytes out(CSHA256::OUTPUT_SIZE);
    CSHA256().Write(data.data(), data.size()).Finalize(out.data());
    return out;
}

enum class Template { P2PQH, BARE, BARE_VERIFY, P2SH32_1OF2 };

struct Locking {
    CScript scriptPubKey;
    CScript scriptCode; // what the signature commits to
    CScript redeemScript;
};

Locking MakeLocking(Template t, const Key &key, const Key &other, bool keyFirst) {
    Locking l;
    switch (t) {
        case Template::P2PQH:
            l.scriptPubKey = CScript() << OP_DUP << OP_SHA256 << Sha256(key.pubkey) << OP_EQUALVERIFY << OP_CHECKPQSIG;
            l.scriptCode = l.scriptPubKey;
            break;
        case Template::BARE:
            l.scriptPubKey = CScript() << key.pubkey << OP_CHECKPQSIG;
            l.scriptCode = l.scriptPubKey;
            break;
        case Template::BARE_VERIFY:
            l.scriptPubKey = CScript() << key.pubkey << OP_CHECKPQSIGVERIFY << OP_1;
            l.scriptCode = l.scriptPubKey;
            break;
        case Template::P2SH32_1OF2: {
            const Key &a = keyFirst ? key : other;
            const Key &b = keyFirst ? other : key;
            l.redeemScript = CScript() << a.pubkey << OP_CHECKPQSIG << OP_SWAP << b.pubkey << OP_CHECKPQSIG << OP_ADD
                                       << OP_1 << OP_NUMEQUAL;
            const uint256 h = Hash(l.redeemScript);
            l.scriptPubKey = CScript() << OP_HASH256 << Bytes(h.begin(), h.end()) << OP_EQUAL;
            l.scriptCode = l.redeemScript;
            break;
        }
    }
    return l;
}

CScript MakeScriptSig(Template t, const Bytes &sig, const Key &key, const Locking &l, bool keyFirst) {
    switch (t) {
        case Template::P2PQH: return CScript() << sig << key.pubkey;
        case Template::BARE:
        case Template::BARE_VERIFY: return CScript() << sig;
        case Template::P2SH32_1OF2: {
            // Signatures are pushed for the second key first; the non-signing key gets an empty element.
            const Bytes empty;
            const CScript s = keyFirst ? CScript() << empty << sig : CScript() << sig << empty;
            return CScript(s) << Bytes(l.redeemScript.begin(), l.redeemScript.end());
        }
    }
    assert(false);
    return {};
}

CScript ToScript(const Bytes &b) { return CScript(b.begin(), b.end()); }

bool Verify(const CMutableTransaction &mtx, unsigned nIn, const CTxOut &spent, const CScript &scriptSig, int &sigChecks,
            ScriptError &err) {
    const CTransaction tx(mtx);
    const ScriptExecutionContext context{nIn, spent, tx};
    ScriptExecutionMetrics metrics;
    const bool ok = VerifyScript(scriptSig, spent.scriptPubKey, PQ_FLAGS, TransactionSignatureChecker(context),
                                 metrics, &err);
    assert(ok == (err == ScriptError::OK));
    sigChecks = metrics.GetSigChecks();
    return ok;
}

} // namespace

void test_one_input(Span<const uint8_t> buffer) {
    FuzzedDataProvider fdp(buffer.data(), buffer.size());
    const auto tmpl = Template(fdp.ConsumeIntegralInRange<int>(0, 3));
    const bool keyFirst = fdp.ConsumeBool();
    const Key &key = Keys()[0];
    const Locking locking = MakeLocking(tmpl, key, Keys()[1], keyFirst);
    const CTxOut spent(int64_t(fdp.ConsumeIntegralInRange<uint64_t>(0, MAX_MONEY / SATOSHI)) * SATOSHI,
                       locking.scriptPubKey);

    // A transaction with 1-3 inputs and 1-3 outputs; we sign input nIn.
    CMutableTransaction mtx;
    mtx.nVersion = fdp.ConsumeIntegral<int32_t>();
    mtx.nLockTime = fdp.ConsumeIntegral<uint32_t>();
    const size_t nInputs = fdp.ConsumeIntegralInRange<size_t>(1, 3);
    for (size_t i = 0; i < nInputs; ++i) {
        Bytes h = fdp.ConsumeBytes<uint8_t>(32);
        h.resize(32);
        mtx.vin.emplace_back(COutPoint(TxId(uint256(h)), fdp.ConsumeIntegral<uint32_t>()), CScript(),
                             fdp.ConsumeIntegral<uint32_t>());
    }
    const size_t nOutputs = fdp.ConsumeIntegralInRange<size_t>(1, 3);
    for (size_t i = 0; i < nOutputs; ++i) {
        mtx.vout.emplace_back(int64_t(fdp.ConsumeIntegralInRange<uint64_t>(0, MAX_MONEY / SATOSHI)) * SATOSHI,
                              ToScript(fdp.ConsumeBytes<uint8_t>(fdp.ConsumeIntegralInRange<size_t>(0, 40))));
    }
    const unsigned nIn = fdp.ConsumeIntegralInRange<unsigned>(0, nInputs - 1);

    // Any defined FORKID sighash type except UTXOS, which needs every spent output.
    const uint8_t baseType = fdp.ConsumeIntegralInRange<uint8_t>(uint8_t(SIGHASH_ALL), uint8_t(SIGHASH_SINGLE));
    const bool anyoneCanPay = fdp.ConsumeBool();
    const SigHashType sigHashType = SigHashType(baseType).withFork().withAnyoneCanPay(anyoneCanPay);

    const CTransaction unsignedTx(mtx);
    const ScriptExecutionContext context{nIn, spent, unsignedTx};
    const uint256 digest =
        SignatureHash(ByteView(locking.scriptCode.begin(), locking.scriptCode.end()), context, sigHashType, nullptr,
                      PQ_FLAGS)
            .signatureHash;
    Bytes sig;
    assert(pqsig::SignDeterministic(key.secret, digest, sig));
    sig.push_back(uint8_t(sigHashType.getRawSigHashType()));
    const CScript scriptSig = MakeScriptSig(tmpl, sig, key, locking, keyFirst);

    int sigChecks = 0;
    ScriptError err;
    const bool ok = Verify(mtx, nIn, spent, scriptSig, sigChecks, err);
    assert(ok);
    assert(sigChecks == 1); // the empty signature in 1-of-2 costs nothing

    // Now one edit that must invalidate the spend.
    CMutableTransaction mtx2 = mtx;
    CTxOut spent2 = spent;
    CScript scriptSig2 = scriptSig;
    switch (fdp.ConsumeIntegralInRange<int>(0, 5)) {
        case 0: { // flip a byte of the unlocking script
            const size_t pos = fdp.ConsumeIntegralInRange<size_t>(0, scriptSig2.size() - 1);
            const uint8_t mask = fdp.ConsumeIntegralInRange<uint8_t>(1, 255);
            scriptSig2[pos] ^= mask;
            break;
        }
        case 1: { // truncate or extend the unlocking script
            if (fdp.ConsumeBool()) {
                scriptSig2.resize(fdp.ConsumeIntegralInRange<size_t>(0, scriptSig2.size() - 1));
            } else {
                const Bytes extra = fdp.ConsumeBytes<uint8_t>(fdp.ConsumeIntegralInRange<size_t>(1, 8));
                if (extra.empty()) return;
                scriptSig2.insert(fdp.ConsumeBool() ? scriptSig2.begin() : scriptSig2.end(), extra.begin(),
                                  extra.end());
            }
            break;
        }
        case 2: { // the spent amount: always committed (BIP143-style digest)
            const int64_t delta = fdp.ConsumeIntegralInRange<int64_t>(1, 1'000'000);
            spent2.nValue = spent.nValue + (fdp.ConsumeBool() || spent.nValue < delta * SATOSHI ? 1 : -1) * delta * SATOSHI;
            break;
        }
        case 3: // version and locktime: always committed
            if (fdp.ConsumeBool()) {
                mtx2.nVersion ^= fdp.ConsumeIntegralInRange<int32_t>(1, INT32_MAX);
            } else {
                mtx2.nLockTime ^= fdp.ConsumeIntegralInRange<uint32_t>(1, UINT32_MAX);
            }
            break;
        case 4: // this input's outpoint and sequence: always committed
            if (fdp.ConsumeBool()) {
                mtx2.vin[nIn].prevout = COutPoint(mtx2.vin[nIn].prevout.GetTxId(), mtx2.vin[nIn].prevout.GetN() ^ 1);
            } else {
                mtx2.vin[nIn].nSequence ^= fdp.ConsumeIntegralInRange<uint32_t>(1, UINT32_MAX);
            }
            break;
        case 5: { // an output: committed by ALL, and by SINGLE for the output at nIn
            const bool committed = baseType == SIGHASH_ALL || (baseType == SIGHASH_SINGLE && nIn < mtx2.vout.size());
            if (!committed) return;
            const size_t out = baseType == SIGHASH_ALL ? fdp.ConsumeIntegralInRange<size_t>(0, mtx2.vout.size() - 1) : nIn;
            if (fdp.ConsumeBool()) {
                mtx2.vout[out].nValue += SATOSHI;
            } else {
                mtx2.vout[out].scriptPubKey << OP_1;
            }
            break;
        }
    }
    assert(!Verify(mtx2, nIn, spent2, scriptSig2, sigChecks, err));
}
