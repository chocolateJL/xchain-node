// Copyright (c) 2026 The XCHAIN developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <uint256.h>

#include <cstdint>

class CBlockHeader;
class CBlockIndex;

namespace Consensus {
struct Params;
}

/**
 * RandomX proof of work for the xChain networks (decision D5; spec/randomx-pow.md in the project repository).
 *
 * - The block id stays the SHA-256d of the 80-byte header. The proof of work is RandomX v1 ("rx/0", standard
 *   configuration) of the same 80 bytes, keyed by a seed block hash.
 * - The seed changes every SEED_EPOCH blocks and lags by SEED_LAG blocks, as in Monero: for a block at height h
 *   the seed is the hash of the block at SeedHeight(h). Genesis uses an all-zero seed.
 * - Difficulty scale: the RandomX hash, shifted right by 32 bits, must not exceed the nBits target. Targets keep
 *   BCHN's limit (powLimit < 2^224, needed by ASERT), and the minimum difficulty is about one RandomX hash.
 * - Nodes verify in RandomX light mode (a 256 MiB cache per seed, the last two seeds are kept).
 */
namespace randomx_pow {

inline constexpr int SEED_EPOCH = 2048;
inline constexpr int SEED_LAG = 64;
/** Bits the RandomX hash is shifted right by before it is compared with the target. */
inline constexpr unsigned TARGET_SHIFT = 32;

/** Height of the block whose hash keys RandomX for a block at `height` (>= 1). */
int SeedHeight(int height);

/** Seed for the block that would follow `pindexPrev` (nullptr: genesis, all-zero seed). */
uint256 SeedHash(const CBlockIndex *pindexPrev);

/** RandomX hash of the serialized 80-byte header under `seed`. Thread-safe; light mode. */
uint256 Hash(const CBlockHeader &header, const uint256 &seed);

/** True if `rxHash` meets the target encoded in nBits (scaled by TARGET_SHIFT) and nBits is within range. */
bool CheckHash(const uint256 &rxHash, uint32_t nBits, const Consensus::Params &params);

/** Full check of a header that follows `pindexPrev`: computes the RandomX hash and checks it. */
bool CheckHeader(const CBlockHeader &header, const CBlockIndex *pindexPrev, const Consensus::Params &params);

} // namespace randomx_pow
