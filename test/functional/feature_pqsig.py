#!/usr/bin/env python3
# Copyright (c) 2026 The XCHAIN developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""End-to-end ML-DSA-44 spends on regtest with the PQ rules active (spec/pq-signature.md).

- Mines 101 blocks whose coinbases pay to a P2PQH script.
- Spends a mature coinbase with an OP_CHECKPQSIG signature through the mempool and into a block.
- Checks that a bad signature, a wrong-length signature and an ECDSA opcode are rejected,
  and that outputs containing ECDSA opcodes are not relayed.
"""

from test_framework.blocktools import create_block, create_coinbase
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut, ToHex
from test_framework.pqsig import PQKey, load_library, p2pqh_script
from test_framework.script import OP_0, OP_1, OP_CHECKSIG, OP_ENDIF, OP_IF, CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

FEE = 10000


class PQSigTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # Standard relay policy: P2PQH (37 bytes) is standard as a pay-to-script output since upgrade 12.
        self.extra_args = [["-pqsigheight=0", "-acceptnonstdtxn=0"]]

    def mine(self, txns=(), script_pubkey=None):
        node = self.nodes[0]
        tip = node.getbestblockhash()
        height = node.getblockcount() + 1
        block_time = node.getblockheader(tip)["time"] + 1
        coinbase = create_coinbase(height, scriptPubKey=script_pubkey or self.spk)
        block = create_block(tip, coinbase, block_time, txns=list(txns))
        block.solve()
        assert_equal(node.submitblock(ToHex(block)), None)
        assert_equal(node.getbestblockhash(), block.hash)
        return coinbase

    def spend(self, prev_tx, n, script_sig_fn, script_pubkey):
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(prev_tx.sha256, n), b""))
        tx.vout.append(CTxOut(prev_tx.vout[n].nValue - FEE, script_pubkey))
        tx.vin[0].scriptSig = script_sig_fn(tx)
        tx.rehash()
        return tx

    def run_test(self):
        node = self.nodes[0]
        load_library(self.config["environment"]["BUILDDIR"])
        self.key = PQKey(bytes([7] * 32))
        self.spk = p2pqh_script(self.key.pubkey)

        self.log.info("Mine 101 blocks paying to P2PQH")
        coinbases = [self.mine() for _ in range(101)]
        cb = coinbases[0]
        amount = cb.vout[0].nValue

        def good_sig(tx):
            return CScript([self.key.sign_input(tx, 0, self.spk, amount), self.key.pubkey])

        self.log.info("A P2PQH spend is accepted to the mempool and mined")
        dest = PQKey(bytes([8] * 32))
        tx = self.spend(cb, 0, good_sig, p2pqh_script(dest.pubkey))
        assert_equal(len(tx.vin[0].scriptSig), 3740)
        txid = node.sendrawtransaction(ToHex(tx))
        assert txid in node.getrawmempool()
        self.mine([tx])
        assert_equal(node.getrawmempool(), [])
        assert_equal(node.gettxout(txid, 0)["value"] * 100000000, amount - FEE)

        cb = coinbases[1]

        self.log.info("A failing non-empty signature is rejected (NULLFAIL)")

        def bad_sig(tx):
            sig = bytearray(self.key.sign_input(tx, 0, self.spk, amount))
            sig[100] ^= 1
            return CScript([bytes(sig), self.key.pubkey])

        assert_raises_rpc_error(-26, "Signature must be zero for failed CHECK(MULTI)SIG operation",
                                node.sendrawtransaction, ToHex(self.spend(cb, 0, bad_sig, self.spk)))

        self.log.info("A wrong-length signature is rejected")

        def short_sig(tx):
            return CScript([self.key.sign_input(tx, 0, self.spk, amount)[1:], self.key.pubkey])

        assert_raises_rpc_error(-26, "Post-quantum signature has the wrong length",
                                node.sendrawtransaction, ToHex(self.spend(cb, 0, short_sig, self.spk)))

        self.log.info("An output with an ECDSA opcode is not relayed")
        ecdsa_spk = CScript([OP_0, OP_IF, OP_CHECKSIG, OP_ENDIF, OP_1])
        to_ecdsa = self.spend(cb, 0, good_sig, ecdsa_spk)
        assert_raises_rpc_error(-26, "scriptpubkey", node.sendrawtransaction, ToHex(to_ecdsa))

        self.log.info("Mined anyway, it can never be spent, even with the opcode in an unexecuted branch")
        self.mine([to_ecdsa])
        back = self.spend(to_ecdsa, 0, lambda tx: CScript([]), self.spk)
        assert_raises_rpc_error(-26, "Attempted to use a disabled opcode",
                                node.sendrawtransaction, ToHex(back))


if __name__ == "__main__":
    PQSigTest().main()
