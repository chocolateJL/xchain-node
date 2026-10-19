#!/usr/bin/env python3
# Copyright (c) 2026 The XCHAIN developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Reorgs and majority-hashrate double spends on a PQ-rules chain (XCHAIN W3).

Three nodes: node0 is a merchant, node1 an honest miner, node2 an attacker with more hashrate. In each scenario the
attacker pays the merchant from a P2PQH coin on the public chain, privately mines a chain that spends the same coin
back to itself, and then releases it.

A. Shallow fork (2 honest blocks vs 4): the attacker chain wins, the merchant's payment disappears.
B. Deep fork (6 honest blocks vs 8): BCHN parks the deeper chain until it has twice the honest work since the fork;
   at 13 attacker blocks it wins.
C. Fork below the finalization point (12 honest blocks vs 30, -finalizationdelay=0 on the honest nodes): the honest
   nodes refuse the attacker headers outright, so the attack fails and the network splits.
"""

import time

from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut, ToHex
from test_framework.pqsig import PQKey, load_library, p2pqh_script
from test_framework.script import CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, connect_nodes, disconnect_nodes, wait_until

FEE = 10000


class PQSigReorgTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        self.extra_args = [["-pqsigheight=0"]] * 3

    def setup_network(self):
        self.setup_nodes()
        self.join()

    # --- helpers ---------------------------------------------------------------------------------------------------

    def split(self):
        """node2 (attacker) on its own; node0 and node1 stay connected."""
        for i in (0, 1):
            disconnect_nodes(self.nodes[2], self.nodes[i])
            disconnect_nodes(self.nodes[i], self.nodes[2])

    def join(self):
        connect_nodes(self.nodes[0], self.nodes[1])
        connect_nodes(self.nodes[2], self.nodes[0])
        connect_nodes(self.nodes[2], self.nodes[1])

    def addr(self, key):
        return self.nodes[0].decodescript(p2pqh_script(key.pubkey).hex())["addresses"][0]

    def spend(self, coin, dest_key):
        """Spend one of the attacker's coins to dest_key."""
        txid, vout, value = coin
        spk = p2pqh_script(self.attacker.pubkey)
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(int(txid, 16), vout), b""))
        tx.vout.append(CTxOut(value - FEE, p2pqh_script(dest_key.pubkey)))
        tx.vin[0].scriptSig = CScript([self.attacker.sign_input(tx, 0, spk, value), self.attacker.pubkey])
        tx.rehash()
        return tx

    def double_spend_setup(self, coin):
        """Payment to the merchant on the public side, conflicting spend back to the attacker on node2."""
        pay = self.spend(coin, self.merchant)
        steal = self.spend(coin, self.attacker2)
        self.nodes[0].sendrawtransaction(ToHex(pay))
        self.sync_mempools(self.nodes[:2])
        self.nodes[2].sendrawtransaction(ToHex(steal))
        return pay, steal

    def chain_tip_status(self, node, tip_hash):
        return {t["hash"]: t["status"] for t in node.getchaintips()}.get(tip_hash)

    # --- test ------------------------------------------------------------------------------------------------------

    def run_test(self):
        load_library(self.config["environment"]["BUILDDIR"])
        self.attacker = PQKey(bytes([1] * 32))
        self.attacker2 = PQKey(bytes([2] * 32))
        self.merchant = PQKey(bytes([3] * 32))
        self.honest = PQKey(bytes([4] * 32))
        n0, n1, n2 = self.nodes

        self.log.info("Fund the attacker with mature P2PQH coinbases")
        n1.generatetoaddress(110, self.addr(self.attacker))
        self.sync_blocks()
        coins = []
        for h in range(1, 4):
            cb = n0.getblock(n0.getblockhash(h), 2)["tx"][0]
            coins.append((cb["txid"], 0, int(cb["vout"][0]["value"] * 100_000_000)))

        self.log.info("A. Shallow fork: 2 honest blocks vs 4 attacker blocks")
        self.split()
        pay, steal = self.double_spend_setup(coins[0])
        n1.generatetoaddress(2, self.addr(self.honest))
        self.sync_blocks(self.nodes[:2])
        assert_equal(n0.gettxout(pay.hash, 0)["confirmations"], 2)
        attacker_tip = n2.generatetoaddress(4, self.addr(self.attacker))[-1]
        self.join()
        self.sync_blocks()
        assert_equal(n0.getbestblockhash(), attacker_tip)
        assert n0.gettxout(pay.hash, 0) is None, "merchant payment should be reorged away"
        assert pay.hash not in n0.getrawmempool(), "conflicting payment must not return to the mempool"
        assert_equal(n0.gettxout(steal.hash, 0)["confirmations"], 4)

        self.log.info("B. Deep fork: 6 honest blocks vs 8 attacker blocks is parked")
        self.split()
        pay, steal = self.double_spend_setup(coins[1])
        honest_tip = n1.generatetoaddress(6, self.addr(self.honest))[-1]
        self.sync_blocks(self.nodes[:2])
        attacker_tip = n2.generatetoaddress(8, self.addr(self.attacker))[-1]
        self.join()
        wait_until(lambda: self.chain_tip_status(n0, attacker_tip) == "parked", timeout=60)
        assert_equal(n0.getbestblockhash(), honest_tip)
        assert_equal(n0.gettxout(pay.hash, 0)["confirmations"], 6)

        self.log.info("   ... and wins once it has more than twice the honest work since the fork (13 blocks)")
        attacker_tip = n2.generatetoaddress(5, self.addr(self.attacker))[-1]
        wait_until(lambda: n0.getbestblockhash() == attacker_tip, timeout=60)
        assert n0.gettxout(pay.hash, 0) is None
        assert_equal(n0.gettxout(steal.hash, 0)["confirmations"], 13)
        self.sync_blocks()

        self.log.info("C. Fork below the finalization point: honest nodes finalize at depth 10")
        for i in (0, 1):
            self.restart_node(i, extra_args=["-pqsigheight=0", "-finalizationdelay=0"])
        self.join()
        self.sync_blocks()
        self.split()
        pay, steal = self.double_spend_setup(coins[2])
        honest_tip = n1.generatetoaddress(12, self.addr(self.honest))[-1]
        self.sync_blocks(self.nodes[:2])
        assert_equal(n0.getbestblockhash(), honest_tip)
        attacker_tip = n2.generatetoaddress(30, self.addr(self.attacker))[-1]
        with n0.assert_debug_log(["rejected due to existing finalized header"], timeout=30):
            # The attacker gets banned for sending headers below the finalized block, so don't wait on a handshake.
            n2.addnode("127.0.0.1:%d" % n0.p2p_port, "onetry")
        time.sleep(2)
        assert_equal(n0.getbestblockhash(), honest_tip)
        assert_equal(n0.gettxout(pay.hash, 0)["confirmations"], 12)
        assert n2.getbestblockhash() == attacker_tip, "the attacker stays on its own chain: the network splits"


if __name__ == "__main__":
    PQSigReorgTest().main()
