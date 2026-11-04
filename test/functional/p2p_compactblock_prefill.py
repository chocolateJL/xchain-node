#!/usr/bin/env python3
# Copyright (c) 2026 The xChain developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test which transactions a node prefills in the compact blocks it announces.

Besides the coinbase, the node prefills the block's transactions that it has
not announced to the peer and that the peer has not sent or announced to it, so
that the peer does not need a getblocktxn round trip for them.
"""

from test_framework.blocktools import create_block, create_coinbase, create_tx_with_script
from test_framework.messages import COIN, MSG_TX, HeaderAndShortIDs, msg_getheaders, msg_sendcmpct, msg_tx
from test_framework.p2p import P2PInterface
from test_framework.script import OP_TRUE, CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class CmpctBlockRecorder(P2PInterface):
    """Records the transaction announcements and the compact blocks it receives."""

    def __init__(self):
        super().__init__()
        self.tx_invs = set()
        # block hash -> (HeaderAndShortIDs, the tx announcements received before it)
        self.cmpctblocks = {}

    def on_inv(self, message):
        for inv in message.inv:
            if inv.type == MSG_TX:
                self.tx_invs.add(inv.hash)

    def on_cmpctblock(self, message):
        cmpct = HeaderAndShortIDs(message.header_and_shortids)
        cmpct.header.calc_sha256()
        self.cmpctblocks[cmpct.header.sha256] = (cmpct, set(self.tx_invs))


class CompactBlockPrefillTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # Announce transactions every 5 s on average, so that those sent just before a block are rarely announced.
        self.extra_args = [["-acceptnonstdtxn=1", "-txbroadcastinterval=5000"]]

    def mine(self, peer):
        """Mines a block; returns its hash, the compact block the peer got and the announcements before it."""
        node = self.nodes[0]
        bhash = int(self.generatetoaddress(node, 1, node.get_deterministic_priv_key().address)[0], 16)
        peer.wait_until(lambda: bhash in peer.cmpctblocks)
        peer.sync_with_ping()
        return (bhash,) + peer.cmpctblocks[bhash]

    def run_test(self):
        node = self.nodes[0]
        peer = node.add_p2p_connection(CmpctBlockRecorder())
        peer.send_and_ping(msg_sendcmpct(announce=True, version=1))

        self.log.info("Mine a block with an anyone-can-spend coinbase and mature it")
        tip = node.getbestblockhash()
        block = create_block(int(tip, 16), create_coinbase(1), node.getblock(tip)["time"] + 1)
        block.solve()
        assert_equal(node.submitblock(block.serialize().hex()), None)
        self.generatetoaddress(node, 100, node.get_deterministic_priv_key().address)

        # A chain of anyone-can-spend transactions
        prev, amount = block.vtx[0], 50 * COIN

        def next_tx():
            nonlocal prev, amount
            amount -= 10000
            prev = create_tx_with_script(prev, 0, amount=amount, script_pub_key=CScript([OP_TRUE]))
            return prev

        self.log.info("Sync headers so that the next blocks are announced as compact blocks right away")
        getheaders = msg_getheaders()
        getheaders.locator.vHave = [int(node.getbestblockhash(), 16)]
        peer.send_and_ping(getheaders)
        self.mine(peer)

        self.log.info("A transaction announced to the peer and one the peer sent are not prefilled")
        announced = next_tx()
        node.sendrawtransaction(announced.serialize().hex())
        peer.wait_until(lambda: announced.sha256 in peer.tx_invs, timeout=120)
        from_peer = next_tx()
        peer.send_and_ping(msg_tx(from_peer))
        assert from_peer.hash in node.getrawmempool()

        self.log.info("Transactions not yet announced to the peer are prefilled")
        for attempt in range(5):
            for _ in range(3):
                node.sendrawtransaction(next_tx().serialize().hex())
            bhash, cmpct, invs_before = self.mine(peer)
            txids = [int(txid, 16) for txid in node.getblock("%064x" % bhash)["tx"]]
            prefilled = {}
            for p in cmpct.prefilled_txn:
                p.tx.rehash()
                prefilled[p.tx.sha256] = p.index
            assert_equal(len(prefilled) + len(cmpct.shortids), len(txids))
            assert_equal(prefilled.get(txids[0]), 0)
            for i, txid in enumerate(txids[1:], 1):
                if txid in prefilled:
                    assert_equal(prefilled[txid], i)
                    assert txid not in invs_before and txid != from_peer.sha256
                else:
                    # Not prefilled: the peer sent it, or we announced it (possibly just after the block).
                    assert txid in peer.tx_invs or txid == from_peer.sha256
            if attempt == 0:
                assert announced.sha256 in txids and announced.sha256 not in prefilled
                assert from_peer.sha256 in txids and from_peer.sha256 not in prefilled
            if len(prefilled) > 1:
                break
        else:
            raise AssertionError("every transaction was announced before its block")


if __name__ == '__main__':
    CompactBlockPrefillTest().main()
