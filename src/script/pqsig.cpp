// Copyright (c) 2026 The XCHAIN developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/pqsig.h>

#include <random.h>

#include <mldsa_native.h>

#include <algorithm>
#include <atomic>

#ifdef ENABLE_MLDSA_AVX2
// The AVX2 build of mldsa-native (src/crypto/CMakeLists.txt), namespaced xc_mldsa44_avx2.
extern "C" int xc_mldsa44_avx2_verify(const uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *ctx,
                                      size_t ctxlen, const uint8_t *pk);
#endif

static_assert(pqsig::RAW_PUBKEY_SIZE == MLDSA_PUBLICKEYBYTES(44));
static_assert(pqsig::RAW_SIG_SIZE == MLDSA_BYTES(44));
static_assert(pqsig::SECRET_KEY_SIZE == MLDSA_SECRETKEYBYTES(44));
static_assert(pqsig::SEED_SIZE == MLDSA_SEEDBYTES);
static_assert(pqsig::CONTEXT_SIZE <= 255, "FIPS 204 context strings are at most 255 bytes");
static_assert(pqsig::P2PQHInputSize(pqsig::ML_DSA_44) == 3783);

/** Randomness source required by mldsa-native (used for hedged signing only, never for verification). */
extern "C" int randombytes(uint8_t *out, size_t outlen) {
    while (outlen > 0) {
        // GetStrongRandBytes() returns at most 32 bytes per call.
        const size_t n = std::min<size_t>(outlen, 32);
        GetStrongRandBytes(out, static_cast<int>(n));
        out += n;
        outlen -= n;
    }
    return 0;
}

namespace pqsig {

static const uint8_t *ContextBytes() {
    return reinterpret_cast<const uint8_t *>(CONTEXT);
}

const Algorithm *GetPubKeyAlgorithm(ByteView pubkey) {
    if (pubkey.empty()) {
        return nullptr;
    }
    const Algorithm *alg = nullptr;
    switch (pubkey[0]) {
        case ALG_ML_DSA_44:
            alg = &ML_DSA_44;
            break;
        default:
            return nullptr;
    }
    return pubkey.size() == alg->PubKeySize() ? alg : nullptr;
}

bool IsValidPubKeyEncoding(ByteView pubkey) {
    return GetPubKeyAlgorithm(pubkey) != nullptr;
}

bool Verify(ByteView pubkey, ByteView rawSig, const uint256 &digest) {
    const Algorithm *alg = GetPubKeyAlgorithm(pubkey);
    if (alg == nullptr || rawSig.size() != alg->rawSigSize) {
        return false;
    }
    switch (alg->id) {
        case ALG_ML_DSA_44:
            return xc_mldsa44_verify(rawSig.data(), digest.begin(), digest.size(), ContextBytes(), CONTEXT_SIZE,
                                     pubkey.data() + 1) == 0;
    }
    return false;
}

static std::atomic<bool> g_admissionAVX2{false};

bool InitAdmissionVerifier(bool allowAVX2) {
#ifdef ENABLE_MLDSA_AVX2
    __builtin_cpu_init();
    g_admissionAVX2 = allowAVX2 && __builtin_cpu_supports("avx2") && __builtin_cpu_supports("bmi2") &&
                      __builtin_cpu_supports("popcnt");
#else
    g_admissionAVX2 = false;
#endif
    return g_admissionAVX2;
}

bool AdmissionUsesAVX2() {
    return g_admissionAVX2.load(std::memory_order_relaxed);
}

void DisableAdmissionAVX2() {
    g_admissionAVX2 = false;
}

bool VerifyForAdmission(ByteView pubkey, ByteView rawSig, const uint256 &digest) {
#ifdef ENABLE_MLDSA_AVX2
    if (AdmissionUsesAVX2()) {
        const Algorithm *alg = GetPubKeyAlgorithm(pubkey);
        if (alg == nullptr || rawSig.size() != alg->rawSigSize) {
            return false;
        }
        switch (alg->id) {
            case ALG_ML_DSA_44:
                return xc_mldsa44_avx2_verify(rawSig.data(), digest.begin(), digest.size(), ContextBytes(),
                                              CONTEXT_SIZE, pubkey.data() + 1) == 0;
        }
        return false;
    }
#endif
    return Verify(pubkey, rawSig, digest);
}

bool KeyPairFromSeed(const std::array<uint8_t, SEED_SIZE> &seed, std::vector<uint8_t> &pubkey, SecretKey &secret) {
    pubkey.assign(PUBKEY_SIZE, 0);
    secret.assign(SECRET_KEY_SIZE, 0);
    pubkey[0] = ALG_ML_DSA_44;
    if (xc_mldsa44_keypair_internal(pubkey.data() + 1, secret.data(), seed.data()) != 0) {
        pubkey.clear();
        secret.clear();
        return false;
    }
    return true;
}

bool Sign(const SecretKey &secret, const uint256 &digest, std::vector<uint8_t> &rawSig) {
    if (secret.size() != SECRET_KEY_SIZE) {
        return false;
    }
    rawSig.assign(RAW_SIG_SIZE, 0);
    if (xc_mldsa44_signature(rawSig.data(), digest.begin(), digest.size(), ContextBytes(), CONTEXT_SIZE,
                             secret.data()) != 0) {
        rawSig.clear();
        return false;
    }
    return true;
}

bool SignDeterministic(const SecretKey &secret, const uint256 &digest, std::vector<uint8_t> &rawSig) {
    if (secret.size() != SECRET_KEY_SIZE) {
        return false;
    }
    // Pure ML-DSA message prefix: 0x00 || len(ctx) || ctx (FIPS 204, Algorithm 2).
    std::vector<uint8_t> prefix{0x00, uint8_t(CONTEXT_SIZE)};
    prefix.insert(prefix.end(), ContextBytes(), ContextBytes() + CONTEXT_SIZE);
    const std::array<uint8_t, MLDSA_RNDBYTES> rnd{};
    rawSig.assign(RAW_SIG_SIZE, 0);
    if (xc_mldsa44_signature_internal(rawSig.data(), digest.begin(), digest.size(), prefix.data(), prefix.size(),
                                      rnd.data(), secret.data(), 0) != 0) {
        rawSig.clear();
        return false;
    }
    return true;
}

} // namespace pqsig
