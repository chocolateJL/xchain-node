// Copyright (c) 2026 The XCHAIN developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Take a valid ML-DSA-44 signature (one of a few precomputed ones, or a fresh one over
// a fuzzed digest), then flip fuzzed bytes of the public key, the signature and the
// digest. A signature must verify if and only if nothing was changed: no other key,
// digest or signature encoding may pass. (Signing is slow under the sanitizers, so
// most inputs reuse the precomputed signatures.)

#include <script/pqsig.h>
#include <uint256.h>

#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>

#include <array>
#include <cassert>
#include <cstdint>
#include <vector>

namespace {

struct Key {
    std::vector<uint8_t> pubkey;
    pqsig::SecretKey secret;
};

const std::array<Key, 3> &Keys() {
    static const std::array<Key, 3> keys = [] {
        std::array<Key, 3> out;
        for (uint8_t i = 0; i < out.size(); ++i) {
            std::array<uint8_t, pqsig::SEED_SIZE> seed;
            seed.fill(0xa0 + i);
            assert(pqsig::KeyPairFromSeed(seed, out[i].pubkey, out[i].secret));
        }
        return out;
    }();
    return keys;
}

struct Signed {
    size_t key;
    std::vector<uint8_t> digest;
    std::vector<uint8_t> sig;
};

const std::vector<Signed> &Precomputed() {
    static const std::vector<Signed> out = [] {
        std::vector<Signed> v;
        for (size_t k = 0; k < Keys().size(); ++k) {
            for (uint8_t d = 0; d < 4; ++d) {
                Signed s{k, std::vector<uint8_t>(32, uint8_t(0x10 * k + d)), {}};
                assert(pqsig::SignDeterministic(Keys()[k].secret, uint256{s.digest}, s.sig));
                v.push_back(std::move(s));
            }
        }
        return v;
    }();
    return out;
}

} // namespace

void test_one_input(Span<const uint8_t> buffer) {
    FuzzedDataProvider fdp(buffer.data(), buffer.size());
    Signed s;
    if (fdp.ConsumeIntegralInRange<int>(0, 15) == 0) {
        s.key = fdp.ConsumeIntegralInRange<size_t>(0, Keys().size() - 1);
        s.digest = fdp.ConsumeBytes<uint8_t>(32);
        s.digest.resize(32);
        assert(pqsig::SignDeterministic(Keys()[s.key].secret, uint256{s.digest}, s.sig));
    } else {
        s = Precomputed()[fdp.ConsumeIntegralInRange<size_t>(0, Precomputed().size() - 1)];
    }
    const Key &key = Keys()[s.key];
    const std::vector<uint8_t> &digestBytes = s.digest;
    const std::vector<uint8_t> &sig = s.sig;
    assert(sig.size() == pqsig::RAW_SIG_SIZE);
    assert(pqsig::Verify(key.pubkey, sig, uint256{digestBytes}));

    std::vector<uint8_t> pubkey = key.pubkey;
    std::vector<uint8_t> sig2 = sig;
    std::vector<uint8_t> digest2 = digestBytes;

    const int edits = fdp.ConsumeIntegralInRange<int>(0, 8);
    for (int i = 0; i < edits && fdp.remaining_bytes() > 0; ++i) {
        std::vector<uint8_t> &target = [&]() -> std::vector<uint8_t> & {
            switch (fdp.ConsumeIntegralInRange<int>(0, 2)) {
                case 0: return pubkey;
                case 1: return sig2;
                default: return digest2;
            }
        }();
        const uint8_t mask = fdp.ConsumeIntegral<uint8_t>();
        target[fdp.ConsumeIntegralInRange<size_t>(0, target.size() - 1)] ^= mask;
    }
    // Another of the fixed keys is a valid encoding with no relation to the signature.
    if (fdp.ConsumeBool()) {
        pubkey = Keys()[fdp.ConsumeIntegralInRange<size_t>(0, Keys().size() - 1)].pubkey;
    }

    const bool unchanged = pubkey == key.pubkey && sig2 == sig && digest2 == digestBytes;
    assert(pqsig::Verify(pubkey, sig2, uint256{digest2}) == unchanged);
}
