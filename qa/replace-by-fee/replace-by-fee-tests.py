#!/usr/bin/env python3
# Copyright (c) 2015 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# Test replace-by-fee
#

import os
import sys

# Add python-bitcoinlib to module search path:
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "python-bitcoinlib"))

import unittest

import bitcoin
bitcoin.SelectParams('regtest')

import bitcoin.rpc

from bitcoin.core import *
from bitcoin.core.script import *
from bitcoin.wallet import *

MAX_REPLACEMENT_LIMIT = 100

class Test_ReplaceByFee(unittest.TestCase):
    proxy = None

    @classmethod
    def setUpClass(cls):
        if cls.proxy is None:
            cls.proxy = bitcoin.rpc.Proxy()

    @classmethod
    def tearDownClass(cls):
        # Make sure mining works
        while len(cls.proxy.getrawmempool()):
            cls.proxy.setgenerate(True, 1)

    def make_txout(self, amount, scriptPubKey=CScript([1])):
        """Create a txout with a given amount and scriptPubKey

        Mines coins as needed.
        """
        fee = 1*COIN
        while self.proxy.getbalance() < amount + fee:
            self.proxy.setgenerate(True, 100)

        addr = P2SHBitcoinAddress.from_redeemScript(CScript([]))
        txid = self.proxy.sendtoaddress(addr, amount + fee)

        tx1 = self.proxy.getrawtransaction(txid)

        i = None
        for i, txout in enumerate(tx1.vout):
            if txout.scriptPubKey == addr.to_scriptPubKey():
                break
        assert i is not None

        tx2 = CTransaction([CTxIn(COutPoint(txid, i), CScript([1, CScript([])]))],
                           [CTxOut(amount, scriptPubKey)])

        tx2_txid = self.proxy.sendrawtransaction(tx2, True)

        return COutPoint(tx2_txid, 0)

    def test_simple_doublespend(self):
        """Simple doublespend"""
        tx0_outpoint = self.make_txout(1.1*COIN)

        tx1a = CTransaction([CTxIn(tx0_outpoint)],
                            [CTxOut(1*COIN, CScript([b'a']))])
        tx1a_txid = self.proxy.sendrawtransaction(tx1a, True)

        # Should fail because we haven't changed the fee
        tx0b_outpoint = self.make_txout(0.1*COIN)
        tx1b = CTransaction([CTxIn(tx0_outpoint), CTxIn(tx0b_outpoint)],
                            [CTxOut(1.1*COIN, CScript([b'a']))])

        try:
            tx1b_txid = self.proxy.sendrawtransaction(tx1b, True)
        except bitcoin.rpc.JSONRPCException as exp:
            self.assertEqual(exp.error['code'], -26) # RPC_VERIFY_REJECTED
        else:
            self.fail()

        # Should fail because 'a' isn't being paid out the same amount
        # even though we've added more fee.
        tx1b = CTransaction([CTxIn(tx0_outpoint)],
                            [CTxOut(0.9*COIN, CScript([b'a']))])
        try:
            tx1b_txid = self.proxy.sendrawtransaction(tx1b, True)
        except bitcoin.rpc.JSONRPCException as exp:
            self.assertEqual(exp.error['code'], -26) # RPC_VERIFY_REJECTED
        else:
            self.fail()

        # Extra 0.1 BTC fee from new input and 'a' is being paid out the
        # same amount.
        tx1b = CTransaction([CTxIn(tx0_outpoint), CTxIn(tx0b_outpoint)],
                            [CTxOut(1*COIN, CScript([b'a']))])

        tx1b_txid = self.proxy.sendrawtransaction(tx1b, True)

        # tx1a is in fact replaced
        with self.assertRaises(IndexError):
            self.proxy.getrawtransaction(tx1a_txid)

        self.assertEqual(tx1b, self.proxy.getrawtransaction(tx1b_txid))

    def test_doublespend_chain(self):
        """Doublespend of a long chain"""

        initial_nValue = 50*COIN
        tx0_outpoint = self.make_txout(initial_nValue)

        prevout = tx0_outpoint
        remaining_value = initial_nValue
        chain_txids = []
        while remaining_value > 10*COIN:
            remaining_value -= 1*COIN
            tx = CTransaction([CTxIn(prevout)],
                              [CTxOut(remaining_value, CScript([1]))])
            txid = self.proxy.sendrawtransaction(tx, True)
            chain_txids.append(txid)
            prevout = COutPoint(txid, 0)

        # Whether the double-spend is allowed is evaluated by including all
        # child fees - 40 BTC - so this attempt is rejected.
        dbl_tx = CTransaction([CTxIn(tx0_outpoint)],
                              [CTxOut(initial_nValue - 30*COIN, CScript([1]))])

        try:
            self.proxy.sendrawtransaction(dbl_tx, True)
        except bitcoin.rpc.JSONRPCException as exp:
            self.assertEqual(exp.error['code'], -26) # RPC_VERIFY_REJECTED
        else:
            self.fail()

        # Rejected as '1' isn't being paid equal or better.
        dbl_tx = CTransaction([CTxIn(tx0_outpoint)],
                              [CTxOut(1*COIN, CScript([1]))])

        try:
            self.proxy.sendrawtransaction(dbl_tx, True)
        except bitcoin.rpc.JSONRPCException as exp:
            self.assertEqual(exp.error['code'], -26) # RPC_VERIFY_REJECTED
        else:
            self.fail()

        # Accepted with sufficient fee and '1' still being paid 10 BTC.
        tx0b_outpoint = self.make_txout(initial_nValue)
        dbl_tx = CTransaction([CTxIn(tx0_outpoint), CTxIn(tx0b_outpoint)],
                              [CTxOut(10*COIN, CScript([1]))])

        self.proxy.sendrawtransaction(dbl_tx, True)

        for doublespent_txid in chain_txids:
            with self.assertRaises(IndexError):
                self.proxy.getrawtransaction(doublespent_txid)

    def test_doublespend_tree(self):
        """Doublespend of a big tree of transactions"""

        initial_nValue = 50*COIN
        default_tree_width = 5
        tx0_outpoint = self.make_txout(initial_nValue)

        # Record the aggregate unspent amounts paid out per recipient.
        amounts = {i+1: 0 for i in range(default_tree_width)}

        def branch(prevout, initial_value, max_txs, *, tree_width=default_tree_width, fee=0.0001*COIN, _total_txs=None):
            if _total_txs is None:
                _total_txs = [0]
            if _total_txs[0] >= max_txs:
                return

            txout_value = (initial_value - fee) // tree_width
            if txout_value < fee:
                return

            if initial_value < initial_nValue:
                amounts[prevout.n+1] -= initial_value

            vout = [CTxOut(txout_value, CScript([i+1]))
                    for i in range(tree_width)]
            tx = CTransaction([CTxIn(prevout)],
                              vout)

            for i in range(tree_width):
                amounts[i+1] += txout_value

            self.assertTrue(len(tx.serialize()) < 100000)
            txid = self.proxy.sendrawtransaction(tx, True)
            yield tx
            _total_txs[0] += 1

            for i, txout in enumerate(tx.vout):
                yield from branch(COutPoint(txid, i), txout_value,
                                  max_txs,
                                  tree_width=tree_width, fee=fee,
                                  _total_txs=_total_txs)

        fee = 0.0001*COIN
        n = MAX_REPLACEMENT_LIMIT
        tree_txs = list(branch(tx0_outpoint, initial_nValue, n, fee=fee))
        self.assertEqual(len(tree_txs), n)

        # Attempt double-spend, will fail because too little fee paid
        tx0b_outpoint = self.make_txout(1*COIN)
        vout = [CTxOut(amounts[i+1], CScript([i+1]))
                for i in range(default_tree_width)]
        vout.append(CTxOut(1*COIN, CScript([1])))
        dbl_tx = CTransaction([CTxIn(tx0_outpoint), CTxIn(tx0b_outpoint)],
                              vout)
        try:
            self.proxy.sendrawtransaction(dbl_tx, True)
        except bitcoin.rpc.JSONRPCException as exp:
            self.assertEqual(exp.error['code'], -26) # RPC_VERIFY_REJECTED
        else:
            self.fail()

        # 1 BTC isn't enough because existing outputs aren't paid out equally.
        dbl_tx = CTransaction([CTxIn(tx0_outpoint)],
                              [CTxOut(initial_nValue - fee*n - 1*COIN, CScript([1]))])
        try:
            self.proxy.sendrawtransaction(dbl_tx, True)
        except bitcoin.rpc.JSONRPCException as exp:
            self.assertEqual(exp.error['code'], -26) # RPC_VERIFY_REJECTED
        else:
            self.fail()

        # 1 BTC is enough w/equal payouts
        vout = [CTxOut(amounts[i+1], CScript([i+1]))
                for i in range(default_tree_width)]
        dbl_tx = CTransaction([CTxIn(tx0_outpoint), CTxIn(tx0b_outpoint)],
                              vout)

        self.proxy.sendrawtransaction(dbl_tx, True)

        for tx in tree_txs:
            with self.assertRaises(IndexError):
                self.proxy.getrawtransaction(tx.GetHash())

        # Try again, but with more total transactions than the "max txs
        # double-spent at once" anti-DoS limit.
        for n in (MAX_REPLACEMENT_LIMIT+1, MAX_REPLACEMENT_LIMIT*2):
            fee = 0.0001*COIN
            tx0_outpoint = self.make_txout(initial_nValue)
            for i in range(default_tree_width):
                amounts[i+1] = 0

            tree_txs = list(branch(tx0_outpoint, initial_nValue, n, fee=fee))
            self.assertEqual(len(tree_txs), n)

            tx0b_outpoint = self.make_txout(1*COIN)
            vout = [CTxOut(amounts[i+1], CScript([i+1]))
                    for i in range(default_tree_width)]
            dbl_tx = CTransaction([CTxIn(tx0_outpoint), CTxIn(tx0b_outpoint)],
                                  vout)
            try:
                self.proxy.sendrawtransaction(dbl_tx, True)
            except bitcoin.rpc.JSONRPCException as exp:
                self.assertEqual(exp.error['code'], -26)
            else:
                self.fail()

            for tx in tree_txs:
                self.proxy.getrawtransaction(tx.GetHash())

    def test_huge_chain(self):
        """Doublespend of a huge (in size) transaction chain"""

        def fat_chain(n, remaining_value):
            fee = 0.1*COIN

            initial_nValue = (n * fee) + remaining_value
            tx0_outpoint = self.make_txout(initial_nValue)

            yield tx0_outpoint

            prevout = tx0_outpoint
            prevout_nValue = initial_nValue

            fat_txout = CTxOut(1, CScript([b'\xff'*99900]))

            for i in range(n):
                tx = CTransaction([CTxIn(prevout)],
                                  [CTxOut(prevout_nValue - fee, CScript([1])),
                                   fat_txout])

                txid = self.proxy.sendrawtransaction(tx, True)

                prevout = COutPoint(txid, 0)
                prevout_nValue = tx.vout[0].nValue

                yield tx

        n = MAX_REPLACEMENT_LIMIT
        tx0_outpoint, *chain_txs = fat_chain(n, 1*COIN)
        self.assertEqual(len(chain_txs), n)

        # Attempt double-spend, will fail because too little fee paid
        tx0b_outpoint = self.make_txout(1*COIN)
        dbl_tx = CTransaction([CTxIn(tx0_outpoint), CTxIn(tx0b_outpoint)],
                              [CTxOut(2*COIN, CScript([1])),
                               CTxOut(100, CScript([b'\xff'*99900]))])
        try:
            self.proxy.sendrawtransaction(dbl_tx, True)
        except bitcoin.rpc.JSONRPCException as exp:
            self.assertEqual(exp.error['code'], -26) # RPC_VERIFY_REJECTED
        else:
            self.fail()

        # Attempt double-spend, will fail because of inequality
        dbl_tx = CTransaction([CTxIn(tx0_outpoint), CTxIn(tx0b_outpoint)],
                              [CTxOut(0.9*COIN, CScript([1])),
                               CTxOut(100, CScript([b'\xff'*99900]))])
        try:
            self.proxy.sendrawtransaction(dbl_tx, True)
        except bitcoin.rpc.JSONRPCException as exp:
            self.assertEqual(exp.error['code'], -26) # RPC_VERIFY_REJECTED
        else:
            self.fail()

        # Fine with more fees and equal output amounts
        dbl_tx = CTransaction([CTxIn(tx0_outpoint), CTxIn(tx0b_outpoint)],
                              [CTxOut(1*COIN, CScript([1])),
                               CTxOut(100, CScript([b'\xff'*99900]))])

        self.proxy.sendrawtransaction(dbl_tx, True)

        for tx in chain_txs:
            with self.assertRaises(IndexError):
                self.proxy.getrawtransaction(tx.GetHash())

    def test_replacement_feeperkb(self):
        """Replacement requires overall fee-per-KB to be higher"""
        tx0_outpoint = self.make_txout(1.1*COIN)

        tx1a = CTransaction([CTxIn(tx0_outpoint)],
                            [CTxOut(1*COIN, CScript([b'a']))])
        tx1a_txid = self.proxy.sendrawtransaction(tx1a, True)

        # Higher fee, but the fee per KB is much lower, so the replacement is
        # rejected.
        tx0b_outpoint = self.make_txout(1*COIN)
        tx1b = CTransaction([CTxIn(tx0_outpoint), CTxIn(tx0b_outpoint)],
                            [CTxOut(1*COIN, CScript([b'a'])),
                            CTxOut(0.001*COIN,
                                    CScript([b'b'*999000]))])

        try:
            tx1b_txid = self.proxy.sendrawtransaction(tx1b, True)
        except bitcoin.rpc.JSONRPCException as exp:
            self.assertEqual(exp.error['code'], -26) # RPC_VERIFY_REJECTED
        else:
            self.fail()

if __name__ == '__main__':
    unittest.main()
