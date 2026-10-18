#!/usr/bin/env python3
# Copyright (c) 2026 The XCHAIN developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""ML-DSA-44 keys and signatures for functional tests (spec/pq-signature.md).

Uses the node's own vendored mldsa-native through the shared library built as
src/crypto/libxc_mldsa44.so, so tests sign with exactly the code the node
verifies with.
"""

import ctypes
import os

from .messages import sha256
from .script import (
    OP_CHECKPQSIG,
    OP_DUP,
    OP_EQUALVERIFY,
    OP_SHA256,
    SIGHASH_ALL,
    SIGHASH_FORKID,
    CScript,
    SignatureHashForkId,
)

ALG_ML_DSA_44 = 0x01
RAW_PUBKEY_SIZE = 1312
SECRET_KEY_SIZE = 2560
RAW_SIG_SIZE = 2420
PUBKEY_SIZE = 1 + RAW_PUBKEY_SIZE
SIG_SIZE = RAW_SIG_SIZE + 1
# Placeholder until the chain is named (decision D13); must match script/pqsig.h.
CONTEXT = b"XCHAIN-tx-v1"

_lib = None


def load_library(builddir):
    """Load libxc_mldsa44.so from the build directory (once)."""
    global _lib
    if _lib is None:
        path = os.path.join(builddir, "src", "crypto", "libxc_mldsa44.so")
        lib = ctypes.CDLL(path)
        size_t, buf = ctypes.c_size_t, ctypes.c_char_p
        lib.xc_mldsa44_keypair_internal.argtypes = [buf, buf, buf]
        lib.xc_mldsa44_signature.argtypes = [buf, buf, size_t, buf, size_t, buf]
        lib.xc_mldsa44_verify.argtypes = [buf, buf, size_t, buf, size_t, buf]
        for f in (lib.xc_mldsa44_keypair_internal, lib.xc_mldsa44_signature, lib.xc_mldsa44_verify):
            f.restype = ctypes.c_int
        _lib = lib
    return _lib


class PQKey:
    """An ML-DSA-44 key pair derived from a 32-byte seed."""

    def __init__(self, seed):
        assert _lib is not None, "call load_library() first"
        assert len(seed) == 32
        pk = ctypes.create_string_buffer(RAW_PUBKEY_SIZE)
        sk = ctypes.create_string_buffer(SECRET_KEY_SIZE)
        assert _lib.xc_mldsa44_keypair_internal(pk, sk, seed) == 0
        self.pubkey = bytes([ALG_ML_DSA_44]) + pk.raw
        self._secret = sk.raw

    def sign_digest(self, digest):
        """Raw 2,420-byte hedged signature over a 32-byte digest."""
        assert len(digest) == 32
        sig = ctypes.create_string_buffer(RAW_SIG_SIZE)
        assert _lib.xc_mldsa44_signature(sig, digest, len(digest), CONTEXT, len(CONTEXT), self._secret) == 0
        return sig.raw

    def verify_digest(self, raw_sig, digest):
        return _lib.xc_mldsa44_verify(raw_sig, digest, len(digest), CONTEXT, len(CONTEXT), self.pubkey[1:]) == 0

    def sign_input(self, tx, n, script_code, amount, hashtype=SIGHASH_ALL | SIGHASH_FORKID):
        """Signature stack element (raw signature + sighash byte) for input n of tx."""
        digest = SignatureHashForkId(script_code, tx, n, hashtype, amount)
        return self.sign_digest(digest) + bytes([hashtype])


def p2pqh_script(pubkey):
    """Standard P2PQH locking script: OP_DUP OP_SHA256 <H> OP_EQUALVERIFY OP_CHECKPQSIG."""
    return CScript([OP_DUP, OP_SHA256, sha256(pubkey), OP_EQUALVERIFY, OP_CHECKPQSIG])
