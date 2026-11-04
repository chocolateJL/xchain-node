#!/usr/bin/env python3
# Copyright (c) 2026 The xChain developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test which transactions a node serves in reply to getdata.

The node keeps no relay map. It answers a getdata for a transaction:
- from the mempool, only once it has announced that transaction (or a later
  one) to the peer; before that it replies notfound;
- from the most recent block, if the transaction was just mined;
- with notfound, if the transaction was mined in an older block.
"""

from test_framework.blocktools import create_block, create_coinbase, create_tx_with_script
from test_framework.messages import COIN, CInv, MSG_TX, msg_getdata
from test_framework.p2p import P2PInterface
from test_framework.script import OP_TRUE, CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class TxInvRecorder(P2PInterface):
    """Records the transaction announcements it receives and does not request them."""

    def __init__(self):
        super().__init__()
        self.tx_invs = set()

    def on_inv(self, message):
        for inv in message.inv:
            if inv.type == MSG_TX:
                self.tx_invs.add(inv.hash)


class P2PGetDataTxTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def get_tx(self, peer, tx):
        """Sends a getdata for tx; returns True if the node sent the tx, False if it replied notfound."""
        peer.last_message.pop("tx", None)
        peer.last_message.pop("notfound", None)
        peer.send_and_ping(msg_getdata([CInv(MSG_TX, tx.sha256)]))
        if "tx" in peer.last_message:
            assert_equal(peer.last_message["tx"].tx.rehash(), tx.hash)
            return True
        assert_equal(peer.last_message["notfound"].vec[0].hash, tx.sha256)
        return False

    def run_test(self):
        node = self.nodes[0]
        peer = node.add_p2p_connection(TxInvRecorder())

        self.log.info("Mine a block with an anyone-can-spend coinbase and mature it")
        tip = node.getbestblockhash()
        block = create_block(int(tip, 16), create_coinbase(1), node.getblock(tip)["time"] + 1)
        block.solve()
        assert_equal(node.submitblock(block.serialize().hex()), None)
        self.generatetoaddress(node, 100, node.get_deterministic_priv_key().address)

        # A chain of anyone-can-spend transactions, one per check
        prev, amount = block.vtx[0], 50 * COIN

        def next_tx():
            nonlocal prev, amount
            amount -= 10000
            prev = create_tx_with_script(prev, 0, amount=amount, script_pub_key=CScript([OP_TRUE]))
            return prev

        self.log.info("A transaction not yet announced to the peer is not served")
        for _ in range(20):
            tx = next_tx()
            node.sendrawtransaction(tx.serialize().hex())
            if not self.get_tx(peer, tx):
                break
            # The node may already have announced it; then it must have been served.
            assert tx.sha256 in peer.tx_invs
        else:
            raise AssertionError("every transaction was announced before the getdata")

        self.log.info("Once announced, it is served from the mempool")
        peer.wait_until(lambda: tx.sha256 in peer.tx_invs)
        assert self.get_tx(peer, tx)

        self.log.info("Once mined, it is served from the most recent block")
        self.generatetoaddress(node, 1, node.get_deterministic_priv_key().address)
        assert tx.hash not in node.getrawmempool()
        assert tx.hash in node.getblock(node.getbestblockhash())["tx"]
        assert self.get_tx(peer, tx)

        self.log.info("Mined in an older block, it is no longer served")
        self.generatetoaddress(node, 1, node.get_deterministic_priv_key().address)
        assert not self.get_tx(peer, tx)


if __name__ == '__main__':
    P2PGetDataTxTest().main()
