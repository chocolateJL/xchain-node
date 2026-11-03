// Copyright (c) 2026 The XCHAIN developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Arbitrary bytes into the OP_CHECKPQSIG encoding checks and the ML-DSA-44
// verifier. Checks that the encoding rules match spec/pq-signature.md and that
// nothing crashes or reads out of bounds on malformed keys and signatures.

#include <script/interpreter.h>
#include <script/pqsig.h>
#include <script/script_error.h>
#include <script/sigencoding.h>
#include <uint256.h>

#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>

#include <cassert>
#include <cstdint>
#include <vector>

void test_one_input(Span<const uint8_t> buffer) {
    FuzzedDataProvider fdp(buffer.data(), buffer.size());

    const uint32_t flags = fdp.ConsumeIntegral<uint32_t>();
    std::vector<uint8_t> digestBytes = fdp.ConsumeBytes<uint8_t>(32);
    digestBytes.resize(32);
    const uint256 digest{digestBytes};

    // Lengths are drawn near the real sizes so that both sides of every size check get hit.
    auto consumeElement = [&](size_t realSize) {
        const size_t size = fdp.ConsumeBool() ? realSize : fdp.ConsumeIntegralInRange<size_t>(0, realSize + 8);
        std::vector<uint8_t> v = fdp.ConsumeBytes<uint8_t>(size);
        v.resize(size);
        return v;
    };
    const std::vector<uint8_t> pubkey = consumeElement(pqsig::PUBKEY_SIZE);
    const std::vector<uint8_t> sig = consumeElement(pqsig::SIG_SIZE);

    // Public key: exactly 1,313 bytes starting with the ML-DSA-44 identifier.
    const bool pubkeyOk = pubkey.size() == pqsig::PUBKEY_SIZE && pubkey[0] == pqsig::ALG_ML_DSA_44;
    assert(pqsig::IsValidPubKeyEncoding(pubkey) == pubkeyOk);
    ScriptError err = ScriptError::OK;
    assert(CheckPQPubKeyEncoding(pubkey, &err) == pubkeyOk);
    assert(pubkeyOk || err == ScriptError::PQ_PUBKEY_ENCODING);

    // Signature element, checked against a well-formed ML-DSA-44 key: exactly 2,421 bytes; the
    // verdict depends only on the sighash byte and never on the STRICTENC / FORKID flags, which
    // are forced for PQ signatures.
    std::vector<uint8_t> mldsaPubkey(pqsig::PUBKEY_SIZE);
    mldsaPubkey[0] = pqsig::ALG_ML_DSA_44;
    err = ScriptError::OK;
    const bool sigOk = CheckPQSignatureEncoding(sig, mldsaPubkey, flags, &err);
    // The expected size comes from the key's algorithm, so a malformed key fails the signature too.
    assert(CheckPQSignatureEncoding(sig, pubkey, flags, nullptr) == (sigOk && pubkeyOk));
    if (sig.size() != pqsig::SIG_SIZE) {
        assert(!sigOk && err == ScriptError::PQ_SIG_ENCODING);
    } else {
        const uint32_t forced = SCRIPT_VERIFY_STRICTENC | SCRIPT_ENABLE_SIGHASH_FORKID;
        assert(CheckPQSignatureEncoding(sig, mldsaPubkey, flags & ~forced, nullptr) == sigOk);
        assert(CheckPQSignatureEncoding(sig, mldsaPubkey, flags | forced, nullptr) == sigOk);
        std::vector<uint8_t> other = sig;
        other[fdp.ConsumeIntegralInRange<size_t>(0, pqsig::RAW_SIG_SIZE - 1)] ^= fdp.ConsumeIntegral<uint8_t>();
        assert(CheckPQSignatureEncoding(other, mldsaPubkey, flags, nullptr) == sigOk);
        if (sigOk) {
            const SigHashType type = GetHashType(sig);
            assert(type.hasFork() && type.isDefined());
        }
    }

    // The verifier must reject (not crash on) every malformed input. Raw signatures of the
    // wrong length are passed through on purpose.
    const ByteView rawSig = sig.empty() ? ByteView() : ByteView(sig.data(), sig.size() - 1);
    const bool verified = pqsig::Verify(pubkey, rawSig, digest);
    if (!pubkeyOk || rawSig.size() != pqsig::RAW_SIG_SIZE) {
        assert(!verified);
    }
}
