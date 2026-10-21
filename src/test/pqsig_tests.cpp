// Copyright (c) 2026 The XCHAIN developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Tests for OP_CHECKPQSIG / OP_CHECKPQSIGVERIFY and the disabled secp256k1
// opcodes. See spec/pq-signature.md.

#include <cashaddrenc.h>
#include <chain.h>
#include <chainparams.h>
#include <consensus/activation.h>
#include <core_io.h>
#include <key_io.h>
#include <pow.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <policy/policy.h>
#include <script/interpreter.h>
#include <script/pqsig.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/script_execution_context.h>
#include <script/standard.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <test/lib/transaction_utils.h>
#include <test/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace {

constexpr uint32_t PQ_FLAGS = STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_ENABLE_P2SH_32 | SCRIPT_ENABLE_TOKENS |
                              SCRIPT_ENABLE_MAY2025 | SCRIPT_ENABLE_MAY2026 | SCRIPT_ENABLE_PQSIG;

using Bytes = std::vector<uint8_t>;

struct PQKey {
    Bytes pubkey;
    pqsig::SecretKey secret;
};

PQKey MakeKey(uint8_t tag) {
    std::array<uint8_t, pqsig::SEED_SIZE> seed;
    seed.fill(tag);
    PQKey key;
    BOOST_REQUIRE(pqsig::KeyPairFromSeed(seed, key.pubkey, key.secret));
    return key;
}

Bytes Sha256(const Bytes &data) {
    Bytes out(CSHA256::OUTPUT_SIZE);
    CSHA256().Write(data.data(), data.size()).Finalize(out.data());
    return out;
}

CScript P2PQH(const Bytes &pubkey) {
    return CScript() << OP_DUP << OP_SHA256 << Sha256(pubkey) << OP_EQUALVERIFY << OP_CHECKPQSIG;
}

CScript P2SH32(const CScript &redeemScript) {
    const uint256 h = Hash(redeemScript);
    return CScript() << OP_HASH256 << Bytes(h.begin(), h.end()) << OP_EQUAL;
}

/** Signature stack element (raw signature + sighash byte) for input 0 of `tx`. */
Bytes SignInput(const CMutableTransaction &tx, const CTxOut &spent, const CScript &scriptCode, const PQKey &key,
                SigHashType sigHashType = SigHashType().withFork(), bool deterministic = false) {
    const ScriptExecutionContext context{0, spent, tx};
    const uint256 digest =
        SignatureHash(ByteView(scriptCode.begin(), scriptCode.end()), context, sigHashType, nullptr, PQ_FLAGS)
            .signatureHash;
    Bytes sig;
    BOOST_REQUIRE(deterministic ? pqsig::SignDeterministic(key.secret, digest, sig)
                                : pqsig::Sign(key.secret, digest, sig));
    sig.push_back(uint8_t(sigHashType.getRawSigHashType()));
    return sig;
}

/** Spending fixture: a crediting tx paying to `scriptPubKey` and a tx spending it. */
struct Spend {
    CMutableTransaction credit;
    CMutableTransaction tx;

    explicit Spend(const CScript &scriptPubKey)
        : credit(BuildCreditingTransaction(scriptPubKey, 1000 * SATOSHI)),
          tx(BuildSpendingTransaction(CScript(), CTransaction(credit))) {}

    const CTxOut &Spent() const { return credit.vout[0]; }

    bool Verify(const CScript &scriptSig, ScriptError &err, uint32_t flags = PQ_FLAGS,
                ScriptExecutionMetrics *metricsOut = nullptr) const {
        const ScriptExecutionContext context{0, Spent(), tx};
        ScriptExecutionMetrics metrics;
        const bool ok = VerifyScript(scriptSig, Spent().scriptPubKey, flags, TransactionSignatureChecker(context),
                                     metrics, &err);
        if (metricsOut) *metricsOut = metrics;
        return ok;
    }
};

/** k-of-n redeem script from spec/pq-signature.md section 5. */
CScript MultisigRedeemScript(int k, const std::vector<PQKey> &keys) {
    CScript script;
    for (size_t i = 0; i < keys.size(); ++i) {
        if (i > 0) script << OP_SWAP;
        script << keys[i].pubkey << OP_CHECKPQSIG;
        if (i > 0) script << OP_ADD;
    }
    return script << CScript::EncodeOP_N(k) << OP_NUMEQUAL;
}

/** Unlocking script: per-key signatures (empty = not signing), pushed s_n ... s_1, then the redeem script. */
CScript MultisigScriptSig(const std::vector<Bytes> &sigs, const CScript &redeemScript) {
    CScript scriptSig;
    for (auto it = sigs.rbegin(); it != sigs.rend(); ++it) {
        scriptSig << *it;
    }
    return scriptSig << Bytes(redeemScript.begin(), redeemScript.end());
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pqsig_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(wrapper_keys_and_signatures) {
    const PQKey a = MakeKey(1), a2 = MakeKey(1), b = MakeKey(2);
    BOOST_CHECK_EQUAL(a.pubkey.size(), pqsig::PUBKEY_SIZE);
    BOOST_CHECK_EQUAL(a.pubkey[0], pqsig::ALG_ML_DSA_44);
    BOOST_CHECK(a.pubkey == a2.pubkey);
    BOOST_CHECK(a.pubkey != b.pubkey);

    const uint256 digest = Hash(Bytes{1, 2, 3});
    Bytes sig1, sig2;
    BOOST_REQUIRE(pqsig::Sign(a.secret, digest, sig1));
    BOOST_REQUIRE(pqsig::Sign(a.secret, digest, sig2));
    BOOST_CHECK_EQUAL(sig1.size(), pqsig::RAW_SIG_SIZE);
    BOOST_CHECK(sig1 != sig2); // hedged signing
    BOOST_CHECK(pqsig::Verify(a.pubkey, sig1, digest));
    BOOST_CHECK(pqsig::Verify(a.pubkey, sig2, digest));
    BOOST_CHECK(!pqsig::Verify(b.pubkey, sig1, digest));
    BOOST_CHECK(!pqsig::Verify(a.pubkey, sig1, Hash(Bytes{1, 2, 4})));

    Bytes badAlg = a.pubkey;
    badAlg[0] = 0x02;
    BOOST_CHECK(!pqsig::IsValidPubKeyEncoding(badAlg));
    BOOST_CHECK(!pqsig::Verify(badAlg, sig1, digest));
    BOOST_CHECK(!pqsig::IsValidPubKeyEncoding(Bytes(a.pubkey.begin(), a.pubkey.end() - 1)));
    BOOST_CHECK(!pqsig::Verify(a.pubkey, Bytes(sig1.begin(), sig1.end() - 1), digest));
}

BOOST_AUTO_TEST_CASE(p2pqh_spend) {
    const PQKey key = MakeKey(7);
    Spend spend(P2PQH(key.pubkey));
    const CScript &spk = spend.Spent().scriptPubKey;
    BOOST_CHECK_EQUAL(spk.size(), 37u);

    const Bytes sig = SignInput(spend.tx, spend.Spent(), spk, key);
    BOOST_CHECK_EQUAL(sig.size(), pqsig::SIG_SIZE);
    const CScript scriptSig = CScript() << sig << key.pubkey;
    BOOST_CHECK_EQUAL(scriptSig.size(), 3740u);

    ScriptError err;
    ScriptExecutionMetrics metrics;
    BOOST_CHECK(spend.Verify(scriptSig, err, PQ_FLAGS, &metrics));
    BOOST_CHECK_MESSAGE(err == ScriptError::OK, ScriptErrorString(err));
    BOOST_CHECK_EQUAL(metrics.GetSigChecks(), 1);

    // Wrong public key: hash mismatch.
    const PQKey other = MakeKey(8);
    BOOST_CHECK(!spend.Verify(CScript() << SignInput(spend.tx, spend.Spent(), spk, other) << other.pubkey, err));
    BOOST_CHECK_EQUAL(err, ScriptError::EQUALVERIFY);

    // Transaction changed after signing: non-empty failing signature is a hard failure.
    Spend tampered = spend;
    tampered.tx.vout[0].nValue = 999 * SATOSHI;
    BOOST_CHECK(!tampered.Verify(scriptSig, err));
    BOOST_CHECK_EQUAL(err, ScriptError::SIG_NULLFAIL);
}

BOOST_AUTO_TEST_CASE(other_sighash_types) {
    const PQKey key = MakeKey(9);
    Spend spend(P2PQH(key.pubkey));
    const CScript &spk = spend.Spent().scriptPubKey;
    ScriptError err;

    for (const SigHashType t : {SigHashType().withFork().withAnyoneCanPay(),
                                SigHashType().withFork().withBaseType(BaseSigHashType::NONE),
                                SigHashType().withFork().withBaseType(BaseSigHashType::SINGLE)}) {
        const Bytes sig = SignInput(spend.tx, spend.Spent(), spk, key, t);
        BOOST_CHECK_MESSAGE(spend.Verify(CScript() << sig << key.pubkey, err), ScriptErrorString(err));
    }

    // FORKID is mandatory for PQ signatures even without STRICTENC.
    Bytes noFork = SignInput(spend.tx, spend.Spent(), spk, key);
    noFork.back() = SIGHASH_ALL;
    BOOST_CHECK(!spend.Verify(CScript() << noFork << key.pubkey, err, PQ_FLAGS & ~SCRIPT_VERIFY_STRICTENC));
    BOOST_CHECK_EQUAL(err, ScriptError::MUST_USE_FORKID);

    Bytes undefined = SignInput(spend.tx, spend.Spent(), spk, key);
    undefined.back() = 0x44; // FORKID with undefined base type
    BOOST_CHECK(!spend.Verify(CScript() << undefined << key.pubkey, err));
    BOOST_CHECK_EQUAL(err, ScriptError::SIG_HASHTYPE);
}

BOOST_AUTO_TEST_CASE(encoding_rules) {
    const PQKey key = MakeKey(10);
    Spend spend(CScript() << OP_CHECKPQSIG);
    ScriptError err;
    const Bytes sig = SignInput(spend.tx, spend.Spent(), spend.Spent().scriptPubKey, key);

    BOOST_CHECK(spend.Verify(CScript() << sig << key.pubkey, err));

    // Signature length must be exact.
    BOOST_CHECK(!spend.Verify(CScript() << Bytes(sig.begin() + 1, sig.end()) << key.pubkey, err));
    BOOST_CHECK_EQUAL(err, ScriptError::PQ_SIG_ENCODING);
    Bytes longer = sig;
    longer.insert(longer.begin(), 0x00);
    BOOST_CHECK(!spend.Verify(CScript() << longer << key.pubkey, err));
    BOOST_CHECK_EQUAL(err, ScriptError::PQ_SIG_ENCODING);

    // Public key length and algorithm identifier are checked, also with an empty signature.
    Bytes badAlg = key.pubkey;
    badAlg[0] = 0x02;
    BOOST_CHECK(!spend.Verify(CScript() << sig << badAlg, err));
    BOOST_CHECK_EQUAL(err, ScriptError::PQ_PUBKEY_ENCODING);
    BOOST_CHECK(!spend.Verify(CScript() << OP_0 << badAlg, err));
    BOOST_CHECK_EQUAL(err, ScriptError::PQ_PUBKEY_ENCODING);
    BOOST_CHECK(!spend.Verify(CScript() << OP_0 << Bytes(key.pubkey.begin(), key.pubkey.end() - 1), err));
    BOOST_CHECK_EQUAL(err, ScriptError::PQ_PUBKEY_ENCODING);

    // Too few stack items.
    BOOST_CHECK(!spend.Verify(CScript() << key.pubkey, err));
    BOOST_CHECK_EQUAL(err, ScriptError::INVALID_STACK_OPERATION);
}

BOOST_AUTO_TEST_CASE(empty_signature) {
    const PQKey key = MakeKey(11);
    ScriptError err;
    ScriptExecutionMetrics metrics;

    // OP_CHECKPQSIG with an empty signature pushes false and costs no SigCheck.
    Spend checksig(CScript() << OP_CHECKPQSIG << OP_NOT);
    BOOST_CHECK(checksig.Verify(CScript() << OP_0 << key.pubkey, err, PQ_FLAGS, &metrics));
    BOOST_CHECK_MESSAGE(err == ScriptError::OK, ScriptErrorString(err));
    BOOST_CHECK_EQUAL(metrics.GetSigChecks(), 0);

    // OP_CHECKPQSIGVERIFY fails on an empty signature.
    Spend verify(CScript() << OP_CHECKPQSIGVERIFY << OP_1);
    BOOST_CHECK(!verify.Verify(CScript() << OP_0 << key.pubkey, err));
    BOOST_CHECK_EQUAL(err, ScriptError::CHECKSIGVERIFY);

    // And succeeds with a valid one.
    const Bytes sig = SignInput(verify.tx, verify.Spent(), verify.Spent().scriptPubKey, key);
    BOOST_CHECK(verify.Verify(CScript() << sig << key.pubkey, err));
    BOOST_CHECK_MESSAGE(err == ScriptError::OK, ScriptErrorString(err));
}

BOOST_AUTO_TEST_CASE(flag_gating) {
    const PQKey key = MakeKey(12);
    ScriptError err;

    // Without the PQ rules the new codepoints are unassigned, as upstream.
    Spend pq(CScript() << OP_CHECKPQSIG);
    BOOST_CHECK(!pq.Verify(CScript() << OP_0 << key.pubkey, err, PQ_FLAGS & ~SCRIPT_ENABLE_PQSIG));
    BOOST_CHECK_EQUAL(err, ScriptError::BAD_OPCODE);

    // With the PQ rules, every secp256k1 signature opcode is disabled, even in an unexecuted branch.
    for (const opcodetype op : {OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY,
                                OP_CHECKDATASIG, OP_CHECKDATASIGVERIFY}) {
        Spend s(CScript() << OP_0 << OP_IF << op << OP_ENDIF << OP_1);
        BOOST_CHECK_MESSAGE(!s.Verify(CScript(), err), GetOpName(op));
        BOOST_CHECK_EQUAL(err, ScriptError::DISABLED_OPCODE);
        // Upstream behaviour is unchanged without the flag.
        BOOST_CHECK_MESSAGE(s.Verify(CScript(), err, PQ_FLAGS & ~SCRIPT_ENABLE_PQSIG), GetOpName(op));
    }
}

BOOST_AUTO_TEST_CASE(multisig_template) {
    const std::vector<PQKey> keys{MakeKey(21), MakeKey(22), MakeKey(23)};
    const CScript redeem = MultisigRedeemScript(2, keys);
    BOOST_CHECK_EQUAL(redeem.size(), 3957u);
    Spend spend(P2SH32(redeem));
    ScriptError err;
    ScriptExecutionMetrics metrics;

    const Bytes s1 = SignInput(spend.tx, spend.Spent(), redeem, keys[0]);
    const Bytes s2 = SignInput(spend.tx, spend.Spent(), redeem, keys[1]);
    const Bytes s3 = SignInput(spend.tx, spend.Spent(), redeem, keys[2]);

    // Any two of three.
    for (const auto &sigs : {std::vector<Bytes>{s1, s2, {}}, std::vector<Bytes>{s1, {}, s3},
                             std::vector<Bytes>{{}, s2, s3}}) {
        const CScript scriptSig = MultisigScriptSig(sigs, redeem);
        BOOST_CHECK(spend.Verify(scriptSig, err, PQ_FLAGS, &metrics));
        BOOST_CHECK_MESSAGE(err == ScriptError::OK, ScriptErrorString(err));
        BOOST_CHECK_EQUAL(metrics.GetSigChecks(), 2);
    }
    BOOST_CHECK_EQUAL(MultisigScriptSig({s1, s2, {}}, redeem).size(), 8809u);

    // Three valid signatures (11,232 bytes, within the 20,000-byte PQ unlocking limit of D10) make the sum 3,
    // so OP_NUMEQUAL fails: exactly k signatures are required.
    BOOST_CHECK(!spend.Verify(MultisigScriptSig({s1, s2, s3}, redeem), err));
    BOOST_CHECK_EQUAL(err, ScriptError::EVAL_FALSE);

    // The template requires exactly k signatures: a 1-of-2 with both signatures fails OP_NUMEQUAL.
    const std::vector<PQKey> pair{keys[0], keys[1]};
    const CScript redeem12 = MultisigRedeemScript(1, pair);
    Spend spend12(P2SH32(redeem12));
    const Bytes t1 = SignInput(spend12.tx, spend12.Spent(), redeem12, pair[0]);
    const Bytes t2 = SignInput(spend12.tx, spend12.Spent(), redeem12, pair[1]);
    BOOST_CHECK(spend12.Verify(MultisigScriptSig({{}, t2}, redeem12), err));
    BOOST_CHECK(!spend12.Verify(MultisigScriptSig({t1, t2}, redeem12), err));
    BOOST_CHECK_EQUAL(err, ScriptError::EVAL_FALSE);

    // One signature is not enough.
    BOOST_CHECK(!spend.Verify(MultisigScriptSig({s1, {}, {}}, redeem), err));
    BOOST_CHECK_EQUAL(err, ScriptError::EVAL_FALSE);

    // A signature in the wrong slot is a hard failure (NULLFAIL), not a skipped key.
    BOOST_CHECK(!spend.Verify(MultisigScriptSig({s2, s1, {}}, redeem), err));
    BOOST_CHECK_EQUAL(err, ScriptError::SIG_NULLFAIL);
}

BOOST_AUTO_TEST_CASE(multisig_size_limit) {
    // Decision D10: under the PQ rules a push-only unlocking script may be 20,000 bytes (other scripts and
    // stack elements stay at 10,000), so a 3-of-5 ML-DSA multisig (13,872 bytes) is valid and standard.
    std::vector<PQKey> keys;
    for (uint8_t i = 0; i < 7; ++i) keys.push_back(MakeKey(30 + i));
    const std::vector<PQKey> five(keys.begin(), keys.begin() + 5);
    const CScript redeem = MultisigRedeemScript(3, five);
    BOOST_CHECK_EQUAL(redeem.size(), 6595u);
    Spend spend(P2SH32(redeem));

    std::vector<Bytes> sigs(5);
    for (size_t i = 0; i < 3; ++i) sigs[i] = SignInput(spend.tx, spend.Spent(), redeem, five[i]);
    const CScript scriptSig = MultisigScriptSig(sigs, redeem);
    BOOST_CHECK_EQUAL(scriptSig.size(), 13872u);

    ScriptError err;
    ScriptExecutionMetrics metrics;
    BOOST_CHECK(spend.Verify(scriptSig, err, PQ_FLAGS, &metrics));
    BOOST_CHECK_MESSAGE(err == ScriptError::OK, ScriptErrorString(err));
    BOOST_CHECK_EQUAL(metrics.GetSigChecks(), 3);

    // The larger limit needs a push-only unlocking script: one non-push opcode brings back 10,000 bytes.
    CScript notPushOnly = scriptSig;
    notPushOnly << OP_NOP;
    BOOST_CHECK(!spend.Verify(notPushOnly, err, PQ_FLAGS & ~SCRIPT_VERIFY_SIGPUSHONLY));
    BOOST_CHECK_EQUAL(err, ScriptError::SCRIPT_SIZE);

    // Relay policy follows: 13,872 bytes pass the scriptSig size rule.
    std::string reason;
    CMutableTransaction tx = spend.tx;
    tx.vin[0].scriptSig = scriptSig;
    IsStandardTx(CTransaction(tx), reason, PQ_FLAGS);
    BOOST_CHECK(reason != "scriptsig-size");

    // 4-of-7 (18,935 bytes) still fits; 5-of-7 (21,358 bytes) is over the limit.
    const CScript redeem7 = MultisigRedeemScript(4, keys);
    Spend spend7(P2SH32(redeem7));
    std::vector<Bytes> sigs7(7);
    for (size_t i = 0; i < 4; ++i) sigs7[i] = SignInput(spend7.tx, spend7.Spent(), redeem7, keys[i]);
    const CScript fourOfSeven = MultisigScriptSig(sigs7, redeem7);
    BOOST_CHECK_EQUAL(fourOfSeven.size(), 18935u);
    BOOST_CHECK(spend7.Verify(fourOfSeven, err, PQ_FLAGS));
    BOOST_CHECK_MESSAGE(err == ScriptError::OK, ScriptErrorString(err));

    const CScript redeem57 = MultisigRedeemScript(5, keys);
    Spend spend57(P2SH32(redeem57));
    std::vector<Bytes> sigs57(7);
    for (size_t i = 0; i < 5; ++i) sigs57[i] = SignInput(spend57.tx, spend57.Spent(), redeem57, keys[i]);
    const CScript tooBig = MultisigScriptSig(sigs57, redeem57);
    BOOST_CHECK_EQUAL(tooBig.size(), 21358u);
    BOOST_CHECK(!spend57.Verify(tooBig, err, PQ_FLAGS));
    BOOST_CHECK_EQUAL(err, ScriptError::SCRIPT_SIZE);
    tx = spend57.tx;
    tx.vin[0].scriptSig = tooBig;
    BOOST_CHECK(!IsStandardTx(CTransaction(tx), reason, PQ_FLAGS));
    BOOST_CHECK_EQUAL(reason, "scriptsig-size");
}

BOOST_AUTO_TEST_CASE(standardness) {
    const PQKey key = MakeKey(50);
    const CScript p2pqh = P2PQH(key.pubkey);
    std::vector<Bytes> solutions;
    txnouttype type;

    // P2PQH is its own output type under the PQ rules, and plain pay-to-script without them.
    BOOST_CHECK_EQUAL(Solver(p2pqh, solutions, PQ_FLAGS), TX_PQPUBKEYHASH);
    BOOST_REQUIRE_EQUAL(solutions.size(), 1u);
    BOOST_CHECK(solutions[0] == Sha256(key.pubkey));
    BOOST_CHECK_EQUAL(Solver(p2pqh, solutions, PQ_FLAGS & ~SCRIPT_ENABLE_PQSIG), TX_SCRIPT);
    BOOST_CHECK_EQUAL(std::string(GetTxnOutputType(TX_PQPUBKEYHASH)), "pqpubkeyhash");
    BOOST_CHECK(IsStandard(p2pqh, type, PQ_FLAGS));

    // Outputs with secp256k1 signature opcodes are non-standard under the PQ rules.
    const CScript p2pkh = CScript() << OP_DUP << OP_HASH160 << Bytes(20, 0x11) << OP_EQUALVERIFY << OP_CHECKSIG;
    BOOST_CHECK(!IsStandard(p2pkh, type, PQ_FLAGS));
    BOOST_CHECK_EQUAL(type, TX_NONSTANDARD);
    BOOST_CHECK(IsStandard(p2pkh, type, PQ_FLAGS & ~SCRIPT_ENABLE_PQSIG));
    BOOST_CHECK_EQUAL(type, TX_PUBKEYHASH);
    const CScript p2s = CScript() << OP_0 << OP_IF << OP_CHECKDATASIG << OP_ENDIF << OP_1;
    BOOST_CHECK(!IsStandard(p2s, type, PQ_FLAGS));
    BOOST_CHECK(IsStandard(p2s, type, PQ_FLAGS & ~SCRIPT_ENABLE_PQSIG));

    // Data carriers are unaffected.
    BOOST_CHECK(IsStandard(CScript() << OP_RETURN << Bytes{0xac, 0xae}, type, PQ_FLAGS));
    BOOST_CHECK_EQUAL(type, TX_NULL_DATA);

    // Decision D17: at 1 sat/byte a P2PQH output (46 bytes) is dust below 46 + 3,783 = 3,829 satoshis,
    // the cost of spending it; BCH's rule would give 3 * (46 + 148) = 582.
    const CFeeRate oneSatPerByte(1000 * SATOSHI);
    BOOST_CHECK_EQUAL(GetDustThreshold(CTxOut(Amount::zero(), p2pqh), oneSatPerByte, PQ_FLAGS), 3829 * SATOSHI);
    BOOST_CHECK(IsDust(CTxOut(3828 * SATOSHI, p2pqh), oneSatPerByte, PQ_FLAGS));
    BOOST_CHECK(!IsDust(CTxOut(3829 * SATOSHI, p2pqh), oneSatPerByte, PQ_FLAGS));
    BOOST_CHECK_EQUAL(GetDustThreshold(CTxOut(Amount::zero(), p2pqh), oneSatPerByte, PQ_FLAGS & ~SCRIPT_ENABLE_PQSIG),
                      582 * SATOSHI);
    BOOST_CHECK_EQUAL(GetDustThreshold(CTxOut(Amount::zero(), CScript() << OP_RETURN), oneSatPerByte, PQ_FLAGS),
                      Amount::zero());
}

BOOST_AUTO_TEST_CASE(p2pqh_address) {
    const auto params = CreateChainParams(CBaseChainParams::XCPRIV);
    const PQKeyID id(uint256(Sha256(MakeKey(60).pubkey)));
    const CScript p2pqh = P2PQH(MakeKey(60).pubkey);

    // Script <-> destination.
    BOOST_CHECK(GetScriptForDestination(id) == p2pqh);
    CTxDestination dest;
    BOOST_REQUIRE(ExtractDestination(p2pqh, dest, PQ_FLAGS));
    BOOST_CHECK(std::get<PQKeyID>(dest) == id);
    BOOST_CHECK(!ExtractDestination(p2pqh, dest, PQ_FLAGS & ~SCRIPT_ENABLE_PQSIG));

    // CashAddr type 4 (and 5 for token-aware), 32-byte payload, round trip.
    const std::string addr = EncodeCashAddr(id, *params);
    BOOST_CHECK_MESSAGE(addr.rfind("xcpriv:", 0) == 0, addr);
    bool tokenAware = true;
    BOOST_CHECK(std::get<PQKeyID>(DecodeCashAddr(addr, *params, &tokenAware)) == id);
    BOOST_CHECK(!tokenAware);
    const std::string tokenAddr = EncodeCashAddr(id, *params, true);
    BOOST_CHECK(tokenAddr != addr);
    BOOST_CHECK(std::get<PQKeyID>(DecodeCashAddr(tokenAddr, *params, &tokenAware)) == id);
    BOOST_CHECK(tokenAware);
    BOOST_CHECK_EQUAL(DecodeCashAddrContent(addr, params->CashAddrPrefix()).type, PQPUBKEY_TYPE);

    // A 20-byte payload with the P2PQH type is invalid.
    const std::string bad = EncodeCashAddr(params->CashAddrPrefix(), CashAddrContent{PQPUBKEY_TYPE, Bytes(20, 1)});
    BOOST_CHECK(std::holds_alternative<CNoDestination>(DecodeCashAddr(bad, *params)));

    // No legacy (base58) form.
    BOOST_CHECK(EncodeLegacyAddr(id, *params).empty());
}

BOOST_AUTO_TEST_CASE(xcpriv_params) {
    const auto params = CreateChainParams(CBaseChainParams::XCPRIV);
    const Consensus::Params &consensus = params->GetConsensus();
    BOOST_CHECK_EQUAL(consensus.pqSigHeight, 0);
    BOOST_CHECK_EQUAL(consensus.nPowTargetSpacing, 120);
    BOOST_CHECK(CheckProofOfWork(params->GenesisBlock().GetHash(), params->GenesisBlock().nBits, consensus));
    BOOST_CHECK(params->GenesisBlock().GetHash() == consensus.hashGenesisBlock);
    BOOST_CHECK_EQUAL(params->CashAddrPrefix(), "xcpriv");
    BOOST_CHECK_EQUAL(params->GetDefaultPort(), 41733);
    BOOST_TEST_MESSAGE("xcpriv genesis " << consensus.hashGenesisBlock.ToString() << " merkle "
                                         << params->GenesisBlock().hashMerkleRoot.ToString());
}

// Decision D14: regtest enforces the PQ rules from block 1 like the XCHAIN networks; the inherited
// BCH networks do not. -pqsigheight=-1 (an override of PQSIG_DISABLED_HEIGHT) turns them off.
BOOST_AUTO_TEST_CASE(regtest_pq_default) {
    BOOST_CHECK_EQUAL(CreateChainParams(CBaseChainParams::REGTEST)->GetConsensus().pqSigHeight, 0);
    for (const auto &chain : {CBaseChainParams::MAIN, CBaseChainParams::TESTNET, CBaseChainParams::CHIPNET}) {
        BOOST_CHECK_EQUAL(CreateChainParams(chain)->GetConsensus().pqSigHeight, Consensus::PQSIG_DISABLED_HEIGHT);
    }
    const auto params = CreateChainParams(CBaseChainParams::REGTEST);
    CBlockIndex genesis;
    genesis.nHeight = 0;
    const auto saved = ::g_PQSigHeightOverride;
    ::g_PQSigHeightOverride.reset();
    BOOST_CHECK(!IsPQSigEnabled(params->GetConsensus(), nullptr));
    BOOST_CHECK(IsPQSigEnabled(params->GetConsensus(), &genesis)); // block 1 onwards
    ::g_PQSigHeightOverride.emplace(Consensus::PQSIG_DISABLED_HEIGHT);
    BOOST_CHECK(!IsPQSigEnabled(params->GetConsensus(), &genesis));
    ::g_PQSigHeightOverride = saved;
}

BOOST_AUTO_TEST_CASE(deterministic_signing) {
    const PQKey key = MakeKey(40);
    const uint256 digest = Hash(Bytes{9, 9, 9});
    Bytes a, b;
    BOOST_REQUIRE(pqsig::SignDeterministic(key.secret, digest, a));
    BOOST_REQUIRE(pqsig::SignDeterministic(key.secret, digest, b));
    BOOST_CHECK(a == b);
    BOOST_CHECK(pqsig::Verify(key.pubkey, a, digest));
}

/**
 * Builds the shared test vectors (spec/vectors/pqsig_v1.json) with deterministic signatures and checks every case.
 * Writes the file only when XCHAIN_WRITE_VECTORS is set to an output path.
 */
BOOST_AUTO_TEST_CASE(test_vectors) {
    const auto errName = [](ScriptError e) -> std::string {
        switch (e) {
            case ScriptError::OK: return "OK";
            case ScriptError::EVAL_FALSE: return "EVAL_FALSE";
            case ScriptError::EQUALVERIFY: return "EQUALVERIFY";
            case ScriptError::SIG_NULLFAIL: return "SIG_NULLFAIL";
            case ScriptError::PQ_SIG_ENCODING: return "PQ_SIG_ENCODING";
            case ScriptError::PQ_PUBKEY_ENCODING: return "PQ_PUBKEY_ENCODING";
            case ScriptError::MUST_USE_FORKID: return "MUST_USE_FORKID";
            case ScriptError::DISABLED_OPCODE: return "DISABLED_OPCODE";
            case ScriptError::SCRIPT_SIZE: return "SCRIPT_SIZE";
            default: return ScriptErrorString(e);
        }
    };
    const auto hex = [](const auto &bytes) { return HexStr(bytes.begin(), bytes.end()); };

    UniValue::Array cases;
    // Adds a case after checking that the interpreter gives the expected result.
    const auto addCase = [&](const std::string &name, const Spend &spend, const CScript &scriptSig,
                             ScriptError expected) {
        ScriptError err;
        const bool ok = spend.Verify(scriptSig, err);
        BOOST_CHECK_MESSAGE(ok == (expected == ScriptError::OK) && err == expected,
                            name << ": got " << errName(err) << ", expected " << errName(expected));
        CMutableTransaction tx = spend.tx;
        tx.vin[0].scriptSig = scriptSig;
        UniValue::Object c;
        c.emplace_back("name", name);
        c.emplace_back("credit_tx", EncodeHexTx(CTransaction(spend.credit)));
        c.emplace_back("spend_tx", EncodeHexTx(CTransaction(tx)));
        c.emplace_back("input", 0);
        c.emplace_back("expected", errName(expected));
        cases.emplace_back(std::move(c));
    };

    // Keys: seed -> public key element and its SHA-256 (the P2PQH hash).
    UniValue::Array keys;
    for (uint8_t tag : {1, 2, 3}) {
        std::array<uint8_t, pqsig::SEED_SIZE> seed;
        seed.fill(tag);
        const PQKey key = MakeKey(tag);
        const uint256 digest = Hash(Bytes{tag});
        Bytes sig;
        BOOST_REQUIRE(pqsig::SignDeterministic(key.secret, digest, sig));
        BOOST_CHECK(pqsig::Verify(key.pubkey, sig, digest));
        UniValue::Object k;
        k.emplace_back("seed", hex(seed));
        k.emplace_back("pubkey", hex(key.pubkey));
        k.emplace_back("pubkey_sha256", hex(Sha256(key.pubkey)));
        k.emplace_back("message_digest", hex(digest));
        k.emplace_back("signature_deterministic", hex(sig));
        keys.emplace_back(std::move(k));
    }

    // P2PQH.
    const PQKey key = MakeKey(1), other = MakeKey(2);
    Spend p2pqh(P2PQH(key.pubkey));
    const CScript &spk = p2pqh.Spent().scriptPubKey;
    const Bytes sig = SignInput(p2pqh.tx, p2pqh.Spent(), spk, key, SigHashType().withFork(), true);
    addCase("p2pqh_valid", p2pqh, CScript() << sig << key.pubkey, ScriptError::OK);
    addCase("p2pqh_wrong_pubkey", p2pqh,
            CScript() << SignInput(p2pqh.tx, p2pqh.Spent(), spk, other, SigHashType().withFork(), true)
                      << other.pubkey,
            ScriptError::EQUALVERIFY);
    Bytes flipped = sig;
    flipped[100] ^= 0x01;
    addCase("p2pqh_bad_signature", p2pqh, CScript() << flipped << key.pubkey, ScriptError::SIG_NULLFAIL);
    addCase("p2pqh_signature_short", p2pqh, CScript() << Bytes(sig.begin() + 1, sig.end()) << key.pubkey,
            ScriptError::PQ_SIG_ENCODING);
    Bytes noFork = sig;
    noFork.back() = SIGHASH_ALL;
    addCase("p2pqh_no_forkid", p2pqh, CScript() << noFork << key.pubkey, ScriptError::MUST_USE_FORKID);
    Bytes badAlg = key.pubkey;
    badAlg[0] = 0x02;
    Spend badAlgSpend(P2PQH(badAlg));
    addCase("p2pqh_unknown_algorithm", badAlgSpend, CScript() << sig << badAlg, ScriptError::PQ_PUBKEY_ENCODING);
    Spend emptySig(CScript() << OP_CHECKPQSIG << OP_NOT);
    addCase("empty_signature_pushes_false", emptySig, CScript() << OP_0 << key.pubkey, ScriptError::OK);
    Spend ecdsa(CScript() << OP_0 << OP_IF << OP_CHECKSIG << OP_ENDIF << OP_1);
    addCase("checksig_in_unexecuted_branch", ecdsa, CScript(), ScriptError::DISABLED_OPCODE);

    // 2-of-3 multisig in P2SH32.
    const std::vector<PQKey> msKeys{MakeKey(1), MakeKey(2), MakeKey(3)};
    const CScript redeem = MultisigRedeemScript(2, msKeys);
    Spend ms(P2SH32(redeem));
    const Bytes m1 = SignInput(ms.tx, ms.Spent(), redeem, msKeys[0], SigHashType().withFork(), true);
    const Bytes m2 = SignInput(ms.tx, ms.Spent(), redeem, msKeys[1], SigHashType().withFork(), true);
    const Bytes m3 = SignInput(ms.tx, ms.Spent(), redeem, msKeys[2], SigHashType().withFork(), true);
    addCase("multisig_2of3_keys_1_3", ms, MultisigScriptSig({m1, {}, m3}, redeem), ScriptError::OK);
    addCase("multisig_2of3_three_signatures", ms, MultisigScriptSig({m1, m2, m3}, redeem),
            ScriptError::EVAL_FALSE);
    const std::vector<PQKey> pair{msKeys[0], msKeys[1]};
    const CScript redeem12 = MultisigRedeemScript(1, pair);
    Spend ms12(P2SH32(redeem12));
    const Bytes p1 = SignInput(ms12.tx, ms12.Spent(), redeem12, pair[0], SigHashType().withFork(), true);
    const Bytes p2 = SignInput(ms12.tx, ms12.Spent(), redeem12, pair[1], SigHashType().withFork(), true);
    addCase("multisig_1of2_key_2", ms12, MultisigScriptSig({{}, p2}, redeem12), ScriptError::OK);
    addCase("multisig_1of2_two_signatures", ms12, MultisigScriptSig({p1, p2}, redeem12), ScriptError::EVAL_FALSE);
    addCase("multisig_2of3_one_signature", ms, MultisigScriptSig({m1, {}, {}}, redeem), ScriptError::EVAL_FALSE);
    addCase("multisig_2of3_swapped_slots", ms, MultisigScriptSig({m2, m1, {}}, redeem), ScriptError::SIG_NULLFAIL);

    UniValue::Object root;
    root.emplace_back("version", 1);
    root.emplace_back("spec", "spec/pq-signature.md v0.1");
    root.emplace_back("context", std::string(pqsig::CONTEXT));
    root.emplace_back("script_flags",
                      "STANDARD_SCRIPT_VERIFY_FLAGS | P2SH_32 | TOKENS | MAY2025 | MAY2026 | PQSIG");
    root.emplace_back("signing", "deterministic ML-DSA-44 (rnd = 0^32); verification does not depend on it");
    root.emplace_back("keys", std::move(keys));
    root.emplace_back("cases", std::move(cases));

    if (const char *path = std::getenv("XCHAIN_WRITE_VECTORS")) {
        std::ofstream out(path);
        BOOST_REQUIRE(out);
        out << UniValue::stringify(root, 2) << "\n";
    }
}

// Differential test against the SDKs: replays a case file from lab/difftest/gen_cases.py
// (random transactions signed by the Python SDK) and recomputes everything with the node's
// code. Skipped unless XCHAIN_DIFFTEST names the file.
BOOST_AUTO_TEST_CASE(difftest) {
    const char *path = std::getenv("XCHAIN_DIFFTEST");
    if (!path) {
        BOOST_TEST_MESSAGE("XCHAIN_DIFFTEST not set; skipping");
        return;
    }
    std::ifstream in(path);
    BOOST_REQUIRE(in);
    const std::string text{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    UniValue doc;
    BOOST_REQUIRE(doc.read(text));
    BOOST_REQUIRE_EQUAL(doc["format"].get_str(), "xchain-difftest/1");
    const auto hex = [](const auto &bytes) { return HexStr(bytes.begin(), bytes.end()); };

    std::vector<PQKey> keys;
    for (const UniValue &k : doc["keys"].get_array()) {
        const Bytes seedBytes = ParseHex(k["seed"].get_str());
        BOOST_REQUIRE_EQUAL(seedBytes.size(), pqsig::SEED_SIZE);
        std::array<uint8_t, pqsig::SEED_SIZE> seed;
        std::copy(seedBytes.begin(), seedBytes.end(), seed.begin());
        PQKey key;
        BOOST_REQUIRE(pqsig::KeyPairFromSeed(seed, key.pubkey, key.secret));
        BOOST_CHECK_EQUAL(hex(key.pubkey), k["pubkey"].get_str());
        keys.push_back(std::move(key));
    }

    size_t nCases = 0, nInputs = 0, nScripts = 0;
    for (const UniValue &c : doc["cases"].get_array()) {
        CMutableTransaction mtx;
        BOOST_REQUIRE(DecodeHexTx(mtx, c["tx"].get_str()));
        const CTransaction tx(mtx);
        BOOST_CHECK_EQUAL(EncodeHexTx(tx), c["tx"].get_str());
        BOOST_CHECK_EQUAL(tx.GetId().GetHex(), c["txid"].get_str());
        const auto &inputs = c["inputs"].get_array();
        BOOST_REQUIRE_EQUAL(inputs.size(), tx.vin.size());
        for (unsigned n = 0; n < inputs.size(); ++n) {
            const UniValue &inp = inputs[n];
            const std::string where = strprintf("case %u input %u (%s)", nCases, n, inp["kind"].get_str());
            const PQKey &key = keys.at(inp["key"].get_int());
            const Bytes codeBytes = ParseHex(inp["script_code"].get_str());
            const CScript scriptCode(codeBytes.begin(), codeBytes.end());
            const Amount amount = int64_t(std::stoull(inp["amount"].get_str())) * SATOSHI;
            const SigHashType sigHashType(uint32_t(inp["hash_type"].get_int()));
            const CTxOut coin(amount, scriptCode);

            const ScriptExecutionContext context{n, coin, tx};
            const uint256 digest =
                SignatureHash(ByteView(codeBytes.data(), codeBytes.size()), context, sigHashType, nullptr, PQ_FLAGS)
                    .signatureHash;
            BOOST_CHECK_MESSAGE(hex(digest) == inp["digest"].get_str(), where << ": signature hash differs");

            Bytes sig;
            BOOST_REQUIRE(pqsig::SignDeterministic(key.secret, digest, sig));
            sig.push_back(uint8_t(sigHashType.getRawSigHashType()));
            BOOST_CHECK_MESSAGE(hex(sig) == inp["sig"].get_str(), where << ": deterministic signature differs");

            const Bytes sdkSig = ParseHex(inp["sig"].get_str());
            BOOST_REQUIRE_EQUAL(sdkSig.size(), pqsig::SIG_SIZE);
            BOOST_CHECK_MESSAGE(pqsig::Verify(key.pubkey, ByteView(sdkSig.data(), pqsig::RAW_SIG_SIZE), digest),
                                where << ": SDK signature does not verify");

            // P2PQH coins: run the whole script, and check that the amount is committed.
            if (inp["kind"].get_str() == "p2pqh") {
                CMutableTransaction signedTx = mtx;
                signedTx.vin[n].scriptSig = CScript() << sdkSig << key.pubkey;
                const CTransaction stx(signedTx);
                const Amount otherAmount = amount > Amount::zero() ? amount - SATOSHI : amount + SATOSHI;
                for (const Amount &value : {amount, otherAmount}) {
                    const CTxOut spent(value, scriptCode);
                    const ScriptExecutionContext ctx{n, spent, stx};
                    ScriptError err;
                    const bool ok = VerifyScript(stx.vin[n].scriptSig, scriptCode, PQ_FLAGS,
                                                 TransactionSignatureChecker(ctx), &err);
                    if (value == amount) {
                        BOOST_CHECK_MESSAGE(ok, where << ": script fails: " << ScriptErrorString(err));
                    } else {
                        BOOST_CHECK_MESSAGE(!ok && err == ScriptError::SIG_NULLFAIL,
                                            where << ": passes with a different amount");
                    }
                }
                ++nScripts;
            }
            ++nInputs;
        }
        ++nCases;
    }
    BOOST_TEST_MESSAGE(strprintf("difftest: %u cases, %u inputs, %u full P2PQH scripts (seed %s)", nCases, nInputs,
                                 nScripts, doc["seed"].getValStr()));
    BOOST_CHECK(nInputs > 0);
}

BOOST_AUTO_TEST_SUITE_END()
