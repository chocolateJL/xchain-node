// Copyright (c) 2012-2015 The Bitcoin Core developers
// Copyright (c) 2019- The Bitcoin developers
// Copyright (c) 2019-2022 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
// (based on key_tests.cpp)

#include <script/sigcache.h>

#include <hash.h>
#include <key.h>
#include <key_io.h>
#include <script/pqsig.h>
#include <streams.h>
#include <tinyformat.h>
#include <util/strencodings.h>
#include <util/time.h>

#include <test/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <mutex>
#include <string>
#include <vector>

static const std::string strSecret1 =
    "5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj";
static const std::string strSecret1C =
    "Kwr371tjA9u2rFSMZjTNun2PXXP3WPZu2afRHTcta6KxEUdm1vEw";

/**
 * Sigcache is only accessible via CachingTransactionSignatureChecker
 * as friend.
 */
class TestCachingTransactionSignatureChecker {
    CachingTransactionSignatureChecker *pchecker;

public:
    TestCachingTransactionSignatureChecker(
        CachingTransactionSignatureChecker &checkerarg) {
        pchecker = &checkerarg;
    }

    inline bool VerifyAndStore(const std::vector<uint8_t> &vchSig,
                               const CPubKey &pubkey, const uint256 &sighash) {
        return pchecker->VerifySignature(vchSig, pubkey, sighash);
    }

    inline bool IsCached(const std::vector<uint8_t> &vchSig,
                         const CPubKey &pubkey, const uint256 &sighash) {
        return pchecker->IsCached(vchSig, pubkey, sighash);
    }

    inline bool VerifyPQAndStore(const std::vector<uint8_t> &rawSig, const std::vector<uint8_t> &pubkey,
                                 const uint256 &sighash) {
        return pchecker->VerifyPQSignature(rawSig, pubkey, sighash);
    }

    inline bool IsPQCached(const std::vector<uint8_t> &rawSig, const std::vector<uint8_t> &pubkey,
                           const uint256 &sighash) {
        return pchecker->IsPQCached(rawSig, pubkey, sighash);
    }
};

BOOST_FIXTURE_TEST_SUITE(sigcache_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(sig_pubkey_hash_variations) {
    /**
     * Making CachingTransactionSignatureChecker requires a tx. So we make a
     * dummy transaction (doesn't matter what it is) to construct it.
     */
    CDataStream stream(
        ParseHex(
            "010000000122739e70fbee987a8be1788395a2f2e6ad18ccb7ff611cd798071539"
            "dde3c38e000000000151ffffffff010000000000000000016a00000000"),
        SER_NETWORK, PROTOCOL_VERSION);
    CTransaction dummyTx(deserialize, stream);
    ScriptExecutionContext limitedContext(0, CTxOut{0 * SATOSHI, {}}, dummyTx);
    PrecomputedTransactionData txdata(limitedContext);
    CachingTransactionSignatureChecker checker(limitedContext, true, txdata);

    TestCachingTransactionSignatureChecker testChecker(checker);

    CKey key1 = DecodeSecret(strSecret1);
    BOOST_CHECK(key1.IsCompressed() == false);
    CKey key1C = DecodeSecret(strSecret1C);
    BOOST_CHECK(key1C.IsCompressed() == true);

    CPubKey pubkey1 = key1.GetPubKey();
    CPubKey pubkey1C = key1C.GetPubKey();

    for (int n = 0; n < 16; n++) {
        std::string strMsg = strprintf("Sigcache test1 %i: xx", n);
        uint256 const hashMsg = Hash(strMsg);
        uint256 const hashMsg2 = Hash(Span{strMsg}.subspan(1));

        std::vector<uint8_t> sig;
        BOOST_CHECK(key1.SignECDSA(hashMsg, sig));
        std::vector<uint8_t> sig2;
        BOOST_CHECK(key1.SignECDSA(hashMsg2, sig2));

        // cross-check
        BOOST_CHECK(!testChecker.VerifyAndStore(sig2, pubkey1, hashMsg));
        BOOST_CHECK(!testChecker.VerifyAndStore(sig, pubkey1, hashMsg2));
        // that should not have put them in cache...
        BOOST_CHECK(!testChecker.IsCached(sig2, pubkey1, hashMsg));
        BOOST_CHECK(!testChecker.IsCached(sig, pubkey1, hashMsg2));

        // check that it's not in cache at start
        BOOST_CHECK(!testChecker.IsCached(sig, pubkey1, hashMsg));
        BOOST_CHECK(!testChecker.IsCached(sig2, pubkey1, hashMsg2));
        // Insert into cache
        BOOST_CHECK(testChecker.VerifyAndStore(sig, pubkey1, hashMsg));
        BOOST_CHECK(testChecker.VerifyAndStore(sig2, pubkey1, hashMsg2));
        // check that it's in
        BOOST_CHECK(testChecker.IsCached(sig, pubkey1, hashMsg));
        BOOST_CHECK(testChecker.IsCached(sig2, pubkey1, hashMsg2));
        // check that different signature hits different entry
        BOOST_CHECK(!testChecker.IsCached(sig2, pubkey1, hashMsg));
        // check that compressed pubkey hits different entry
        BOOST_CHECK(!testChecker.IsCached(sig, pubkey1C, hashMsg));
        // check that different message hits different entry
        BOOST_CHECK(!testChecker.IsCached(sig, pubkey1, hashMsg2));

        // compressed key is for same privkey, so verifying works:
        BOOST_CHECK(testChecker.VerifyAndStore(sig, pubkey1C, hashMsg));
        // now we *should* get a hit
        BOOST_CHECK(testChecker.IsCached(sig, pubkey1C, hashMsg));
    }
}

BOOST_AUTO_TEST_CASE(pq_sig_pubkey_hash_variations) {
    CDataStream stream(
        ParseHex(
            "010000000122739e70fbee987a8be1788395a2f2e6ad18ccb7ff611cd798071539"
            "dde3c38e000000000151ffffffff010000000000000000016a00000000"),
        SER_NETWORK, PROTOCOL_VERSION);
    CTransaction dummyTx(deserialize, stream);
    ScriptExecutionContext limitedContext(0, CTxOut{0 * SATOSHI, {}}, dummyTx);
    PrecomputedTransactionData txdata(limitedContext);
    CachingTransactionSignatureChecker storing(limitedContext, true, txdata);
    CachingTransactionSignatureChecker notStoring(limitedContext, false, txdata);
    TestCachingTransactionSignatureChecker testChecker(storing);
    TestCachingTransactionSignatureChecker testNotStoring(notStoring);

    std::array<uint8_t, pqsig::SEED_SIZE> seed1, seed2;
    seed1.fill(1);
    seed2.fill(2);
    std::vector<uint8_t> pubkey1, pubkey2;
    pqsig::SecretKey secret1, secret2;
    BOOST_REQUIRE(pqsig::KeyPairFromSeed(seed1, pubkey1, secret1));
    BOOST_REQUIRE(pqsig::KeyPairFromSeed(seed2, pubkey2, secret2));

    const uint256 hashMsg = Hash(std::string("PQ sigcache test 1"));
    const uint256 hashMsg2 = Hash(std::string("PQ sigcache test 2"));
    std::vector<uint8_t> sig, sig2;
    BOOST_REQUIRE(pqsig::Sign(secret1, hashMsg, sig));
    BOOST_REQUIRE(pqsig::Sign(secret1, hashMsg2, sig2));

    // A failing verification is not cached.
    BOOST_CHECK(!testChecker.VerifyPQAndStore(sig2, pubkey1, hashMsg));
    BOOST_CHECK(!testChecker.IsPQCached(sig2, pubkey1, hashMsg));

    // A checker that does not store verifies without caching.
    BOOST_CHECK(testNotStoring.VerifyPQAndStore(sig, pubkey1, hashMsg));
    BOOST_CHECK(!testChecker.IsPQCached(sig, pubkey1, hashMsg));

    // A storing checker caches a valid signature, keyed on signature, public key and message.
    BOOST_CHECK(testChecker.VerifyPQAndStore(sig, pubkey1, hashMsg));
    BOOST_CHECK(testChecker.IsPQCached(sig, pubkey1, hashMsg));
    BOOST_CHECK(!testChecker.IsPQCached(sig2, pubkey1, hashMsg));
    BOOST_CHECK(!testChecker.IsPQCached(sig, pubkey2, hashMsg));
    BOOST_CHECK(!testChecker.IsPQCached(sig, pubkey1, hashMsg2));

    // A signature for another key fails even though the cache holds an entry for the same message.
    BOOST_CHECK(!testChecker.VerifyPQAndStore(sig, pubkey2, hashMsg));
    BOOST_CHECK(testNotStoring.VerifyPQAndStore(sig, pubkey1, hashMsg));
}

BOOST_AUTO_TEST_CASE(pq_admission_scope) {
    CDataStream stream(
        ParseHex(
            "010000000122739e70fbee987a8be1788395a2f2e6ad18ccb7ff611cd798071539"
            "dde3c38e000000000151ffffffff010000000000000000016a00000000"),
        SER_NETWORK, PROTOCOL_VERSION);
    CTransaction dummyTx(deserialize, stream);
    ScriptExecutionContext limitedContext(0, CTxOut{0 * SATOSHI, {}}, dummyTx);
    PrecomputedTransactionData txdata(limitedContext);
    CachingTransactionSignatureChecker checker(limitedContext, true, txdata);
    TestCachingTransactionSignatureChecker testChecker(checker);

    std::array<uint8_t, pqsig::SEED_SIZE> seed;
    seed.fill(3);
    std::vector<uint8_t> pubkey;
    pqsig::SecretKey secret;
    BOOST_REQUIRE(pqsig::KeyPairFromSeed(seed, pubkey, secret));
    std::vector<uint256> msgs;
    std::vector<std::vector<uint8_t>> sigs;
    for (int i = 0; i < 4; ++i) {
        msgs.push_back(Hash(strprintf("PQ admission test %d", i)));
        sigs.emplace_back();
        BOOST_REQUIRE(pqsig::Sign(secret, msgs.back(), sigs.back()));
    }

    if (!pqsig::InitAdmissionVerifier(true)) {
        // Without AVX2, acceptance uses the portable build and caches its results as before.
        const PQAdmissionScope scope;
        BOOST_CHECK(testChecker.VerifyPQAndStore(sigs[0], pubkey, msgs[0]));
        BOOST_CHECK(testChecker.IsPQCached(sigs[0], pubkey, msgs[0]));
        BOOST_CHECK(!scope.UsedAVX2Results());
        return;
    }

    {
        // An AVX2 result serves acceptance but stays out of the cache that block validation reads.
        const PQAdmissionScope scope;
        BOOST_CHECK(!scope.UsedAVX2Results());
        BOOST_CHECK(testChecker.VerifyPQAndStore(sigs[0], pubkey, msgs[0]));
        BOOST_CHECK(scope.UsedAVX2Results());
        BOOST_CHECK(!testChecker.IsPQCached(sigs[0], pubkey, msgs[0]));
        BOOST_CHECK(!testChecker.VerifyPQAndStore(sigs[1], pubkey, msgs[0]));
    }
    // Outside the scope, the signature is verified with the portable build.
    BOOST_CHECK(testChecker.VerifyPQAndStore(sigs[0], pubkey, msgs[0]));
    BOOST_CHECK(testChecker.IsPQCached(sigs[0], pubkey, msgs[0]));
    {
        // A result of the portable build counts as such during acceptance.
        const PQAdmissionScope scope;
        BOOST_CHECK(testChecker.VerifyPQAndStore(sigs[0], pubkey, msgs[0]));
        BOOST_CHECK(!scope.UsedAVX2Results());
    }

    // With the checker thread running, the portable build confirms an accepted transaction's AVX2 results into the
    // block validation cache, then hands over its script cache entry.
    std::mutex mutex;
    std::vector<std::pair<ScriptCacheKey, int>> confirmed;
    std::vector<TxId> mismatches;
    StartPQAdmissionChecker(
        [&](std::vector<std::pair<ScriptCacheKey, int>> &&keys) {
            const std::lock_guard lock(mutex);
            confirmed.insert(confirmed.end(), keys.begin(), keys.end());
        },
        [&](const TxId &txid) {
            const std::lock_guard lock(mutex);
            mismatches.push_back(txid);
        });
    const ScriptCacheKey scriptKey(dummyTx, 0);
    {
        const PQAdmissionScope scope;
        BOOST_CHECK(testChecker.VerifyPQAndStore(sigs[2], pubkey, msgs[2]));
        BOOST_CHECK(testChecker.VerifyPQAndStore(sigs[3], pubkey, msgs[3]));
        BOOST_CHECK(testChecker.VerifyPQAndStore(sigs[3], pubkey, msgs[3]));
        scope.QueueConfirmation(dummyTx, scriptKey, 2);
    }
    const auto waiting = [&] {
        const std::lock_guard lock(mutex);
        return confirmed.empty();
    };
    for (int i = 0; i < 500 && waiting(); ++i) {
        UninterruptibleSleep(std::chrono::milliseconds{10});
    }
    StopPQAdmissionChecker();
    BOOST_CHECK(testChecker.IsPQCached(sigs[2], pubkey, msgs[2]));
    BOOST_CHECK(testChecker.IsPQCached(sigs[3], pubkey, msgs[3]));
    BOOST_REQUIRE_EQUAL(confirmed.size(), 1u);
    BOOST_CHECK(confirmed[0].first == scriptKey);
    BOOST_CHECK_EQUAL(confirmed[0].second, 2);
    BOOST_CHECK(mismatches.empty());
    BOOST_CHECK(pqsig::AdmissionUsesAVX2());
    pqsig::InitAdmissionVerifier(false);
}

BOOST_AUTO_TEST_SUITE_END()
