#include <boost/test/unit_test.hpp>

#include "init.h"
#include "main.h"
#include "uint256.h"
#include "util.h"

BOOST_AUTO_TEST_SUITE(mempool_tests)

static
struct {
    unsigned char extranonce;
    unsigned int nonce;
} blockinfo[] = {
    {4, 0xa4a3e223}, {2, 0x15c32f9e}, {1, 0x0375b547}, {1, 0x7004a8a5},
    {2, 0xce440296}, {2, 0x52cfe198}, {1, 0x77a72cd0}, {2, 0xbb5d6f84},
    {2, 0x83f30c2c}, {1, 0x48a73d5b}, {1, 0xef7dcd01}, {2, 0x6809c6c4},
    {2, 0x0883ab3c}, {1, 0x087bbbe2}, {2, 0x2104a814}, {2, 0xdffb6daa},
    {1, 0xee8a0a08}, {2, 0xba4237c1}, {1, 0xa70349dc}, {1, 0x344722bb},
    {3, 0xd6294733}, {2, 0xec9f5c94}, {2, 0xca2fbc28}, {1, 0x6ba4f406},
    {2, 0x015d4532}, {1, 0x6e119b7c}, {2, 0x43e8f314}, {2, 0x27962f38},
    {2, 0xb571b51b}, {2, 0xb36bee23}, {2, 0xd17924a8}, {2, 0x6bc212d9},
    {1, 0x630d4948}, {2, 0x9a4c4ebb}, {2, 0x554be537}, {1, 0xd63ddfc7},
    {2, 0xa10acc11}, {1, 0x759a8363}, {2, 0xfb73090d}, {1, 0xe82c6a34},
    {1, 0xe33e92d7}, {3, 0x658ef5cb}, {2, 0xba32ff22}, {5, 0x0227a10c},
    {1, 0xa9a70155}, {5, 0xd096d809}, {1, 0x37176174}, {1, 0x830b8d0f},
    {1, 0xc6e3910e}, {2, 0x823f3ca8}, {1, 0x99850849}, {1, 0x7521fb81},
    {1, 0xaacaabab}, {1, 0xd645a2eb}, {5, 0x7aea1781}, {5, 0x9d6e4b78},
    {1, 0x4ce90fd8}, {1, 0xabdc832d}, {6, 0x4a34f32a}, {2, 0xf2524c1c},
    {2, 0x1bbeb08a}, {1, 0xad47f480}, {1, 0x9f026aeb}, {1, 0x15a95049},
    {2, 0xd1cb95b2}, {2, 0xf84bbda5}, {1, 0x0fa62cd1}, {1, 0xe05f9169},
    {1, 0x78d194a9}, {5, 0x3e38147b}, {5, 0x737ba0d4}, {1, 0x63378e10},
    {1, 0x6d5f91cf}, {2, 0x88612eb8}, {2, 0xe9639484}, {1, 0xb7fabc9d},
    {2, 0x19b01592}, {1, 0x5a90dd31}, {2, 0x5bd7e028}, {2, 0x94d00323},
    {1, 0xa9b9c01a}, {1, 0x3a40de61}, {1, 0x56e7eec7}, {5, 0x859f7ef6},
    {1, 0xfd8e5630}, {1, 0x2b0c9f7f}, {1, 0xba700e26}, {1, 0x7170a408},
    {1, 0x70de86a8}, {1, 0x74d64cd5}, {1, 0x49e738a1}, {2, 0x6910b602},
    {0, 0x643c565f}, {1, 0x54264b3f}, {2, 0x97ea6396}, {2, 0x55174459},
    {2, 0x03e8779a}, {1, 0x98f34d8f}, {1, 0xc07b2b07}, {1, 0xdfe29668},
    {1, 0x3141c7c1}, {1, 0xb3b595f4}, {1, 0x735abf08}, {5, 0x623bfbce},
    {2, 0xd351e722}, {1, 0xf4ca48c9}, {1, 0x5b19c670}, {1, 0xa164bf0e},
    {2, 0xbbbeb305}, {2, 0xfe1c810a},
};


BOOST_AUTO_TEST_CASE(CTxMemPool_priority)
{
    CReserveKey reservekey(pwalletMain);
    CBlockTemplate *pblocktemplate;
    CValidationState state;
    CTransaction tx,tx1,tx2,tx3,tx4,tx5;
    uint256 hash;

    // Allow non-standard transactions for testing
    fTestNet = true;

    BOOST_CHECK(pblocktemplate = CreateNewBlock(reservekey));

    // We can't make transactions until we have inputs
    // Therefore, load 100 blocks :)
    std::vector<CTransaction*>txFirst;
    for (unsigned int i = 0; i < sizeof(blockinfo)/sizeof(*blockinfo); ++i)
    {
        CBlock *pblock = &pblocktemplate->block; // pointer for convenience
        pblock->nVersion = 1;
        pblock->nTime = pindexBest->GetMedianTimePast()+1;
        pblock->vtx[0].vin[0].scriptSig = CScript();
        pblock->vtx[0].vin[0].scriptSig.push_back(blockinfo[i].extranonce);
        pblock->vtx[0].vin[0].scriptSig.push_back(pindexBest->nHeight);
        pblock->vtx[0].vout[0].scriptPubKey = CScript();
        txFirst.push_back(new CTransaction(pblock->vtx[0]));
        pblock->hashMerkleRoot = pblock->BuildMerkleTree();
        pblock->nNonce = blockinfo[i].nonce;
        BOOST_CHECK(ProcessBlock(state, NULL, pblock));
        BOOST_CHECK(state.IsValid());
        pblock->hashPrevBlock = pblock->GetHash();
    }
    delete pblocktemplate;

    BOOST_CHECK(mempool.heapTxPriority.size() == 0);

    // First transaction, 2BTC fee
    tx1.vin.resize(1);
    tx1.vin[0].scriptSig = CScript() << OP_1;
    tx1.vin[0].prevout.hash = txFirst[0]->GetHash();
    tx1.vin[0].prevout.n = 0;
    tx1.vout.resize(1);
    tx1.vout[0].nValue = 48LL * COIN;
    BOOST_CHECK(mempool.accept(state, tx1, false, NULL));

    // Exactly one item in the heap
    BOOST_CHECK_EQUAL(mempool.heapTxPriority.size(), 1);
    BOOST_CHECK(mempool.heapTxPriority.top().tx == tx1);
    BOOST_CHECK_EQUAL(mempool.heapTxPriority.top().nSumTxFees, 2LL * COIN);
    BOOST_CHECK_EQUAL(mempool.heapTxPriority.top().nTxDepth, 1);


    // Second transaction, 3BTC fee
    tx2.vin.resize(1);
    tx2.vin[0].scriptSig = CScript() << OP_1;
    tx2.vin[0].prevout.hash = txFirst[1]->GetHash();
    tx2.vin[0].prevout.n = 0;
    tx2.vout.resize(1);
    tx2.vout[0].nValue = 47LL * COIN;
    BOOST_CHECK(mempool.accept(state, tx2, false, NULL));

    // Two items in the heap
    BOOST_CHECK_EQUAL(mempool.heapTxPriority.size(), 2);

    // Top of heap should now be the second transaction
    BOOST_CHECK(mempool.heapTxPriority.top().tx == tx2);
    BOOST_CHECK_EQUAL(mempool.heapTxPriority.top().nSumTxFees, 3LL * COIN);
    BOOST_CHECK_EQUAL(mempool.heapTxPriority.top().nTxDepth, 1);


    // Third transaction, 1BTC fee
    tx3.vin.resize(1);
    tx3.vin[0].scriptSig = CScript() << OP_1;
    tx3.vin[0].prevout.hash = txFirst[2]->GetHash();
    tx3.vin[0].prevout.n = 0;
    tx3.vout.resize(1);
    tx3.vout[0].nValue = 49LL * COIN;
    BOOST_CHECK(mempool.accept(state, tx3, false, NULL));
    BOOST_CHECK_EQUAL(mempool.heapTxPriority.size(), 3);

    // Top of heap unchanged
    BOOST_CHECK(mempool.heapTxPriority.top().tx == tx2);
    BOOST_CHECK_EQUAL(mempool.heapTxPriority.top().nSumTxFees, 3LL * COIN);
    BOOST_CHECK_EQUAL(mempool.heapTxPriority.top().nSumTxSize, 61);
    BOOST_CHECK_EQUAL(mempool.heapTxPriority.top().nTxDepth, 1);


    // Fourth transaction. 4BTC fee, and depends on tx2
    tx4.vin.resize(1);
    tx4.vin[0].scriptSig = CScript() << OP_1;
    tx4.vin[0].prevout.hash = tx2.GetHash();
    tx4.vin[0].prevout.n = 0;
    tx4.vout.resize(1);
    tx4.vout[0].nValue = 43LL * COIN;
    BOOST_CHECK(mempool.accept(state, tx4, false, NULL));
    BOOST_CHECK_EQUAL(mempool.heapTxPriority.size(), 4);

    // Top of the heap is still unchanged, however the sum of all fees for tx2
    // now includes tx4, and tx4 is a dependent of tx2
    BOOST_CHECK(mempool.heapTxPriority.top().tx == tx2);
    BOOST_CHECK_EQUAL(mempool.heapTxPriority.top().nSumTxFees, 7LL * COIN);
    BOOST_CHECK_EQUAL(mempool.heapTxPriority.top().nSumTxSize, 61*2);
    BOOST_CHECK_EQUAL(mempool.heapTxPriority.top().nTxDepth, 1);

    // Fifth transaction. Depends on tx4 and pays a 1BTC fee, so it's ignored
    // in dependency calculations.
    tx5.vin.resize(1);
    tx5.vin[0].scriptSig = CScript() << OP_1;
    tx5.vin[0].prevout.hash = tx4.GetHash();
    tx5.vin[0].prevout.n = 0;
    tx5.vout.resize(1);
    tx5.vout[0].nValue = 42LL * COIN;
    BOOST_CHECK(mempool.accept(state, tx5, false, NULL));
    BOOST_CHECK_EQUAL(mempool.heapTxPriority.size(), 5);

    // No change
    BOOST_CHECK(mempool.heapTxPriority.top().tx == tx2);
    BOOST_CHECK_EQUAL(mempool.heapTxPriority.top().nSumTxFees, 7LL * COIN);
    BOOST_CHECK_EQUAL(mempool.heapTxPriority.top().nSumTxSize, 61*2);
    BOOST_CHECK_EQUAL(mempool.heapTxPriority.top().nTxDepth, 1);
    BOOST_CHECK_EQUAL((*mempool.mapTxPriority[tx5.GetHash()]).nTxDepth, 3);


    // Remove transactions, as though they were mined.
    BOOST_CHECK_EQUAL(mempool.heapTxPriority.size(),5);
    mempool.remove(tx1, true);
    BOOST_CHECK_EQUAL(mempool.heapTxPriority.size(),4);
    mempool.remove(tx3, true);
    BOOST_CHECK_EQUAL(mempool.heapTxPriority.size(),3);
    mempool.remove(tx4, true);
    BOOST_CHECK_EQUAL(mempool.heapTxPriority.size(),1);
    mempool.remove(tx2, true);
    BOOST_CHECK(mempool.heapTxPriority.empty());

    mempool.cleanupDirtyParents();
    mempool.cleanupDirtyChildren();
}

BOOST_AUTO_TEST_SUITE_END()
