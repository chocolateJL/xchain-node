// Copyright (c) 2026 The XCHAIN developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The xChain test network: chain parameters, RandomX proof of work and ASERT from genesis.

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <consensus/abla.h>
#include <consensus/activation.h>
#include <pow.h>
#include <pow_randomx.h>
#include <primitives/block.h>
#include <util/strencodings.h>

#include <randomx/src/randomx.h>

#include <test/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstring>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(xctest_tests, BasicTestingSetup)

// The library gives the published RandomX v1 test vectors (src/randomx/src/tests/tests.cpp, test_a and test_d).
BOOST_AUTO_TEST_CASE(randomx_reference_vectors) {
    const auto hash = [](const std::string &key, const std::string &input) {
        randomx_cache *cache = randomx_alloc_cache(RANDOMX_FLAG_DEFAULT);
        BOOST_REQUIRE(cache != nullptr);
        randomx_init_cache(cache, key.data(), key.size());
        randomx_vm *vm = randomx_create_vm(RANDOMX_FLAG_DEFAULT, cache, nullptr);
        BOOST_REQUIRE(vm != nullptr);
        std::vector<uint8_t> out(RANDOMX_HASH_SIZE);
        randomx_calculate_hash(vm, input.data(), input.size(), out.data());
        randomx_destroy_vm(vm);
        randomx_release_cache(cache);
        return HexStr(out.begin(), out.end());
    };
    BOOST_CHECK_EQUAL(hash("test key 000", "This is a test"),
                      "639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f");
    BOOST_CHECK_EQUAL(hash("test key 001", "sed do eiusmod tempor incididunt ut labore et dolore magna aliqua"),
                      "e9ff4503201c0c2cca26d285c93ae883f9b1d30c9eb240b820756f2d5a7905fc");
}

BOOST_AUTO_TEST_CASE(seed_schedule) {
    using randomx_pow::SeedHeight;
    // Genesis seeds the first 2,048 + 64 blocks; then the seed moves every 2,048 blocks, 64 blocks late.
    BOOST_CHECK_EQUAL(SeedHeight(1), 0);
    BOOST_CHECK_EQUAL(SeedHeight(2112), 0);
    BOOST_CHECK_EQUAL(SeedHeight(2113), 2048);
    BOOST_CHECK_EQUAL(SeedHeight(4160), 2048);
    BOOST_CHECK_EQUAL(SeedHeight(4161), 4096);
    for (int h = 1; h < 20000; h += 37) {
        BOOST_CHECK(SeedHeight(h) < h);
        BOOST_CHECK_EQUAL(SeedHeight(h) % randomx_pow::SEED_EPOCH, 0);
    }

    // SeedHash follows the ancestor chain; genesis itself uses an all-zero seed.
    std::vector<CBlockIndex> chain(2200);
    std::vector<BlockHash> hashes(chain.size());
    for (size_t i = 0; i < chain.size(); ++i) {
        hashes[i] = BlockHash(ArithToUint256(arith_uint256(i + 1)));
        chain[i].phashBlock = &hashes[i];
        chain[i].nHeight = i;
        chain[i].pprev = i ? &chain[i - 1] : nullptr;
        chain[i].BuildSkip();
    }
    BOOST_CHECK(randomx_pow::SeedHash(nullptr) == uint256());
    BOOST_CHECK(randomx_pow::SeedHash(&chain[0]) == hashes[0]);
    BOOST_CHECK(randomx_pow::SeedHash(&chain[2111]) == hashes[0]);
    BOOST_CHECK(randomx_pow::SeedHash(&chain[2112]) == hashes[2048]);
}

BOOST_AUTO_TEST_CASE(target_scale) {
    const auto params = CreateChainParams(CBaseChainParams::XCTEST);
    const Consensus::Params &consensus = params->GetConsensus();
    const uint32_t minDifficulty = UintToArith256(consensus.powLimit).GetCompact();
    BOOST_CHECK_EQUAL(minDifficulty, 0x1d00ffffu);

    // At the limit almost every RandomX hash qualifies: (hash >> 32) <= 0xffff << 208.
    BOOST_CHECK(randomx_pow::CheckHash(uint256S("0000ffff" + std::string(56, 'f')), minDifficulty, consensus));
    BOOST_CHECK(randomx_pow::CheckHash(uint256S("ffff" + std::string(60, '0')), minDifficulty, consensus));
    BOOST_CHECK(!randomx_pow::CheckHash(uint256S("ffff0001" + std::string(56, '0')), minDifficulty, consensus));
    BOOST_CHECK(!randomx_pow::CheckHash(uint256S(std::string(64, 'f')), minDifficulty, consensus));
    // A target 2^20 times smaller needs about 2^20 hashes.
    arith_uint256 harderTarget = UintToArith256(consensus.powLimit);
    harderTarget >>= 20;
    const uint32_t harder = harderTarget.GetCompact();
    BOOST_CHECK(randomx_pow::CheckHash(uint256S("00000fffff" + std::string(54, '0')), harder, consensus));
    BOOST_CHECK(!randomx_pow::CheckHash(uint256S("00001" + std::string(59, '0')), harder, consensus));
    // Targets above the limit are invalid however small the hash.
    BOOST_CHECK(!randomx_pow::CheckHash(uint256(), 0x1e00ffff, consensus));

    // On RandomX chains the SHA-256d check only validates the target range.
    BOOST_CHECK(CheckProofOfWork(BlockHash(uint256S(std::string(64, 'f'))), minDifficulty, consensus));
    BOOST_CHECK(!CheckProofOfWork(BlockHash(uint256()), 0x1e00ffff, consensus));
}

BOOST_AUTO_TEST_CASE(xctest_params) {
    const auto params = CreateChainParams(CBaseChainParams::XCTEST);
    const Consensus::Params &consensus = params->GetConsensus();
    BOOST_CHECK(consensus.powAlgorithm == Consensus::Params::PowAlgorithm::RANDOMX);
    BOOST_CHECK_EQUAL(params->CashAddrPrefix(), "xctest");
    BOOST_CHECK_EQUAL(params->GetDefaultPort(), 41433);
    BOOST_CHECK_EQUAL(consensus.nPowTargetSpacing, 120);
    BOOST_CHECK_EQUAL(consensus.pqSigHeight, 0);
    BOOST_CHECK_EQUAL(consensus.nDefaultConsensusBlockSize, 8'000'000u);
    // D22: miners fill blocks by default (ABLA hardly grows with half-full blocks, D20); same on the devnet.
    BOOST_CHECK_EQUAL(consensus.nDefaultGeneratedBlockSizePercent, 100.0);
    BOOST_CHECK_EQUAL(CreateChainParams(CBaseChainParams::XCPRIV)->GetConsensus().nDefaultGeneratedBlockSizePercent,
                      100.0);
    BOOST_CHECK(!consensus.fPowNoRetargeting);
    BOOST_REQUIRE(consensus.asertAnchorParams);
    BOOST_CHECK_EQUAL(consensus.asertAnchorParams->nHeight, 0);

    // Distinct from every other network.
    for (const auto &other : {CBaseChainParams::MAIN, CBaseChainParams::TESTNET, CBaseChainParams::REGTEST,
                              CBaseChainParams::CHIPNET, CBaseChainParams::XCPRIV}) {
        const auto p = CreateChainParams(other);
        BOOST_CHECK(std::memcmp(p->NetMagic().data(), params->NetMagic().data(), 4) != 0);
        BOOST_CHECK(p->GetDefaultPort() != params->GetDefaultPort());
        BOOST_CHECK(p->GenesisBlock().GetHash() != params->GenesisBlock().GetHash());
    }

    // Genesis meets the RandomX proof with the all-zero seed, and the post-quantum rules start at block 1.
    const CBlock &genesis = params->GenesisBlock();
    BOOST_CHECK(randomx_pow::CheckHash(randomx_pow::Hash(genesis, uint256()), genesis.nBits, consensus));
    BOOST_TEST_MESSAGE("xctest genesis " << genesis.GetHash().ToString() << " merkle "
                                         << genesis.hashMerkleRoot.ToString() << " randomx "
                                         << randomx_pow::Hash(genesis, uint256()).ToString());
    CBlockIndex genesisIndex(genesis);
    genesisIndex.nHeight = 0;
    BOOST_CHECK(IsPQSigEnabled(consensus, &genesisIndex));
}

BOOST_AUTO_TEST_CASE(xcscale_params) {
    const auto params = CreateChainParams(CBaseChainParams::XCSCALE);
    const auto test = CreateChainParams(CBaseChainParams::XCTEST);
    const Consensus::Params &consensus = params->GetConsensus();
    BOOST_CHECK_EQUAL(params->NetworkIDString(), "xcscale");
    BOOST_CHECK_EQUAL(params->CashAddrPrefix(), "xcscale");
    BOOST_CHECK_EQUAL(params->GetDefaultPort(), 41533);

    // A full block holds 1,000 P2PQH transfers (3,885 bytes) per second of 2-minute blocks, and miners fill it.
    BOOST_CHECK_EQUAL(consensus.nDefaultConsensusBlockSize, 512'000'000u);
    BOOST_CHECK_GE(consensus.nDefaultConsensusBlockSize, 1'000u * 120 * 3'885);
    BOOST_CHECK_EQUAL(consensus.GetDefaultGeneratedBlockSizeBytes(), consensus.nDefaultConsensusBlockSize);
    BOOST_CHECK_EQUAL(abla::State(consensus.ablaConfig, 0).GetBlockSizeLimit(), 512'000'000u);

    // Otherwise the same consensus as xctest.
    const Consensus::Params &xctest = test->GetConsensus();
    BOOST_CHECK(consensus.powAlgorithm == Consensus::Params::PowAlgorithm::RANDOMX);
    BOOST_CHECK_EQUAL(consensus.nPowTargetSpacing, xctest.nPowTargetSpacing);
    BOOST_CHECK_EQUAL(consensus.nASERTHalfLife, xctest.nASERTHalfLife);
    BOOST_CHECK_EQUAL(consensus.pqSigHeight, 0);
    BOOST_CHECK(consensus.powLimit == xctest.powLimit);
    BOOST_REQUIRE(consensus.asertAnchorParams);
    BOOST_CHECK_EQUAL(consensus.asertAnchorParams->nHeight, 0);
    BOOST_CHECK_EQUAL(consensus.asertAnchorParams->nPrevBlockTime, params->GenesisBlock().nTime);
    BOOST_CHECK(consensus.hashGenesisBlock == params->GenesisBlock().GetHash());

    for (const auto &other : {CBaseChainParams::MAIN, CBaseChainParams::TESTNET, CBaseChainParams::SCALENET,
                              CBaseChainParams::REGTEST, CBaseChainParams::CHIPNET, CBaseChainParams::XCPRIV,
                              CBaseChainParams::XCTEST}) {
        const auto p = CreateChainParams(other);
        BOOST_CHECK(std::memcmp(p->NetMagic().data(), params->NetMagic().data(), 4) != 0);
        BOOST_CHECK(std::memcmp(p->DiskMagic().data(), params->DiskMagic().data(), 4) != 0);
        BOOST_CHECK(p->GetDefaultPort() != params->GetDefaultPort());
        BOOST_CHECK(p->GenesisBlock().GetHash() != params->GenesisBlock().GetHash());
    }

    const CBlock &genesis = params->GenesisBlock();
    BOOST_CHECK(randomx_pow::CheckHash(randomx_pow::Hash(genesis, uint256()), genesis.nBits, consensus));
    BOOST_TEST_MESSAGE("xcscale genesis " << genesis.GetHash().ToString());
}

BOOST_AUTO_TEST_CASE(asert_from_genesis) {
    const auto params = CreateChainParams(CBaseChainParams::XCTEST);
    const Consensus::Params &consensus = params->GetConsensus();
    const CBlock &genesis = params->GenesisBlock();

    // Blocks every 30 s (four times too fast): the target keeps falling, i.e. difficulty rises.
    std::vector<CBlockIndex> chain(400);
    std::vector<BlockHash> hashes(chain.size());
    hashes[0] = genesis.GetHash();
    chain[0].phashBlock = &hashes[0];
    chain[0].nHeight = 0;
    chain[0].nTime = genesis.nTime;
    chain[0].nBits = genesis.nBits;
    for (size_t i = 1; i < chain.size(); ++i) {
        CBlockHeader header;
        header.nTime = genesis.nTime + 30 * i;
        chain[i].nTime = header.nTime;
        chain[i].nBits = GetNextWorkRequired(&chain[i - 1], &header, consensus);
        hashes[i] = BlockHash(ArithToUint256(arith_uint256(i + 7)));
        chain[i].phashBlock = &hashes[i];
        chain[i].nHeight = i;
        chain[i].pprev = &chain[i - 1];
        chain[i].BuildSkip();
    }
    const arith_uint256 first = arith_uint256().SetCompact(chain[1].nBits);
    const arith_uint256 last = arith_uint256().SetCompact(chain.back().nBits);
    BOOST_CHECK(first <= UintToArith256(consensus.powLimit));
    // 399 blocks, 299 * 120 s = 9.97 h ahead of schedule with a 1 h half-life: about 2^-9.97 of the target.
    BOOST_CHECK(last < first / 900);
    BOOST_CHECK(last > first / 1100);

    // ASERT works from the parent's time: the last block was again 90 s early, so the next target is a further
    // 2^(-90/3600), about 1.7 %, lower.
    CBlockHeader next;
    next.nTime = chain.back().nTime + 120;
    const arith_uint256 after = arith_uint256().SetCompact(GetNextWorkRequired(&chain.back(), &next, consensus));
    BOOST_CHECK(after < last);
    BOOST_CHECK(after > last - last / 40);
}

BOOST_AUTO_TEST_SUITE_END()
