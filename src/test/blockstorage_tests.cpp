// Copyright (c) 2025 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <node/blockstorage.h>
#include <util/defer.h>
#include <validation.h>

#include <test/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(blockstorage_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(readblock_hash_mismatch) {
    LOCK(cs_main);
    CBlockIndex *pindex = ::ChainActive().Tip();
    BOOST_REQUIRE(pindex != nullptr);
    const BlockHash badHash{g_insecure_rand_ctx.rand256()};
    const BlockHash *const origBlockHash = pindex->phashBlock;
    BOOST_REQUIRE(origBlockHash && *origBlockHash != badHash);
    Defer d([&]{ pindex->phashBlock = origBlockHash; }); // restore pindex's proper hash pointer on scope end
    const auto consensusParams = ::Params().GetConsensus();

    CBlock block;
    // First, ensure it works as intended when hashes match
    BOOST_CHECK(ReadBlockFromDisk(block, pindex, consensusParams));
    BOOST_CHECK(ReadBlockFromDisk(block, pindex->GetBlockPos(), consensusParams, *pindex->phashBlock));
    // Next, ensure it fails when hashes do not match expected
    BOOST_CHECK(!ReadBlockFromDisk(block, pindex->GetBlockPos(), consensusParams, badHash));
    pindex->phashBlock = &badHash; // Fudge block hash to be different (will be restored on scope end)
    BOOST_CHECK(!ReadBlockFromDisk(block, pindex, consensusParams));
}

// The steps ProcessNewBlock uses to write a block without cs_main, including a later block moving on to a new file
// (and finalizing the old one) before an earlier block is written.
BOOST_AUTO_TEST_CASE(deferred_block_write) {
    const CChainParams &params = ::Params();
    CBlock block;
    BOOST_REQUIRE(ReadBlockFromDisk(block, WITH_LOCK(cs_main, return ::ChainActive().Tip()), params.GetConsensus()));
    const BlockHash hash = block.GetHash();

    BlockReservation first, second;
    {
        LOCK(cs_main);
        first = ReserveBlockPos(block, 1000);
        // Make the current file look full, so that the next block starts a new one.
        WITH_LOCK(cs_LastBlockFile, vinfoBlockFile[nLastBlockFile].nSize = MAX_BLOCKFILE_SIZE - 1);
        second = ReserveBlockPos(block, 1001);
    }
    BOOST_REQUIRE(!first.pos.IsNull() && !second.pos.IsNull());
    BOOST_CHECK_EQUAL(first.fileToFinalize, -1);
    BOOST_CHECK_EQUAL(second.pos.nFile, first.pos.nFile + 1);
    BOOST_CHECK_EQUAL(second.fileToFinalize, first.pos.nFile);
    BOOST_CHECK_EQUAL(first.blockSize, ::GetSerializeSize(block, PROTOCOL_VERSION));

    // The second block's writer finalizes the first file before the first block is written.
    BOOST_CHECK(FinalizeBlockFile(second.fileToFinalize));
    const FlatFilePos secondPos = WriteReservedBlock(block, second, params);
    const FlatFilePos firstPos = WriteReservedBlock(block, first, params);
    BOOST_REQUIRE(!firstPos.IsNull() && !secondPos.IsNull());
    BOOST_CHECK(CommitBlockFileIfOld(firstPos.nFile));
    BOOST_CHECK(CommitBlockFileIfOld(secondPos.nFile));

    for (const FlatFilePos &pos : {firstPos, secondPos}) {
        CBlock read;
        BOOST_CHECK(ReadBlockFromDisk(read, pos, params.GetConsensus(), hash));
    }
}

BOOST_AUTO_TEST_SUITE_END()
