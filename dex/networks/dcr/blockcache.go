// This code is available on the terms of the project LICENSE.md file,
// also available online at https://blueoakcouncil.org/license/1.0.0.

package dcr

import (
	"fmt"
	"sync"

	"decred.org/dcrdex/dex"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/gcs/v3"
	chainjson "github.com/decred/dcrd/rpc/jsonrpc/types/v3"
)

// Block defines basic information about a block.
type Block struct {
	Hash         *chainhash.Hash
	Height       int64
	PreviousHash string
	Vote         bool // stakeholder vote result for the previous block
	TxIDs        []string
	Txs          []*chainjson.TxRawResult
}

// BlockCache caches block information to prevent repeated calls to
// rpcclient.GetblockVerbose. Also caches block v2 cfilters.
type BlockCache struct {
	log dex.Logger

	blocksMtx sync.RWMutex
	blocks    map[chainhash.Hash]*Block
	mainchain map[int64]*chainhash.Hash
	bestBlock struct {
		hash   *chainhash.Hash
		height int64
	}

	filterMtx sync.RWMutex
	filters   map[chainhash.Hash]*BlockFilter
}

type BlockFilter struct {
	v2cfilters *gcs.FilterV2
	key        [gcs.KeySize]byte
}

func (bf *BlockFilter) Match(data []byte) bool {
	return bf.v2cfilters.Match(bf.key, data)
}

func (bf *BlockFilter) MatchAny(data [][]byte) bool {
	return bf.v2cfilters.MatchAny(bf.key, data)
}

func NewBlockCache(log dex.Logger) *BlockCache {
	return &BlockCache{
		log:       log,
		blocks:    make(map[chainhash.Hash]*Block),
		mainchain: make(map[int64]*chainhash.Hash),
		filters:   make(map[chainhash.Hash]*BlockFilter),
	}
}

// Add adds a block to the BlockCache. This method will translate the RPC result
// to a *Block, returning the *Block. If the block is not orphaned, it will be
// added to the mainchain.
func (cache *BlockCache) Add(block *chainjson.GetBlockVerboseResult) (*Block, error) {
	cache.blocksMtx.Lock()
	defer cache.blocksMtx.Unlock()

	hash, err := chainhash.NewHashFromStr(block.Hash)
	if err != nil {
		return nil, fmt.Errorf("error decoding block hash %s: %w", block.Hash, err)
	}

	blk := &Block{
		Hash:         hash,
		Height:       block.Height,
		PreviousHash: block.PreviousHash,
		Vote:         block.VoteBits&1 != 0,
		TxIDs:        append(block.Tx, block.STx...),
	}
	for i := range block.RawTx {
		blk.Txs = append(blk.Txs, &block.RawTx[i])
	}
	for i := range block.RawSTx {
		blk.Txs = append(blk.Txs, &block.RawSTx[i])
	}
	cache.blocks[*hash] = blk

	// Orphaned blocks will have -1 confirmations. Don't add them to mainchain.
	if block.Confirmations > -1 {
		cache.mainchain[block.Height] = hash
		if block.Height > cache.bestBlock.height {
			cache.bestBlock.height = block.Height
			cache.bestBlock.hash = hash
		}
	}

	return blk, nil
}

// AddCFilter adds the provided block filters to the cache.
func (cache *BlockCache) AddCFilter(blockHash *chainhash.Hash, v2cfilters *gcs.FilterV2, key [gcs.KeySize]byte) *BlockFilter {
	cache.filterMtx.Lock()
	defer cache.filterMtx.Unlock()
	bf := &BlockFilter{
		v2cfilters: v2cfilters,
		key:        key,
	}
	cache.filters[*blockHash] = bf
	return bf
}

// Tip returns the best known block hash and height for the blockCache.
func (cache *BlockCache) BlockFilter(blockHash *chainhash.Hash) (*BlockFilter, bool) {
	cache.filterMtx.RLock()
	defer cache.filterMtx.RUnlock()
	filter, found := cache.filters[*blockHash]
	return filter, found
}

// Tip returns the best known block hash and height for the blockCache.
func (cache *BlockCache) Tip() (*chainhash.Hash, int64) {
	cache.blocksMtx.RLock()
	defer cache.blocksMtx.RUnlock()
	return cache.bestBlock.hash, cache.bestBlock.height
}

// MainchainHash returns the hash for the mainchain block at the specified height.
// This method does not attempt to fetch the required hash from the blockchain
// if it is not cached.
func (cache *BlockCache) MainchainHash(blockHeight int64) (*chainhash.Hash, bool) {
	cache.blocksMtx.RLock()
	defer cache.blocksMtx.RUnlock()
	hash, found := cache.mainchain[blockHeight]
	return hash, found
}

// BlockAt returns basic information about the block with the specified height.
// If withTxs is true, the returned block object will contain all transactions
// in the block, otherwise only the transaction IDs will be returned with the block.
func (cache *BlockCache) BlockAt(height int64) (*Block, bool) {
	blockHash, found := cache.MainchainHash(height)
	if !found {
		return nil, false
	}
	return cache.Block(blockHash)
}

// Block returns basic information about the block with the specified hash. This
// method does not attempt to fetch the required hash from the blockchain if it
// is not cached.
func (cache *BlockCache) Block(hash *chainhash.Hash) (*Block, bool) {
	cache.blocksMtx.RLock()
	defer cache.blocksMtx.RUnlock()
	block, found := cache.blocks[*hash]
	return block, found
}

// PurgeMainchainBlocks deletes all blocks at and above the specified height
// from the mainchain but not the blocks map. This should be done if a reorg
// occurs on the blockchain or it is no longer certain that the blocks in the
// specified range still belong in the mainchain.
// NOTE: PurgeMainchainBlocks clears the best block, so should always be followed
// with the addition of a new mainchain block which would become the best block.
func (cache *BlockCache) PurgeMainchainBlocks(fromHeight int64) {
	if fromHeight < 0 {
		return
	}

	cache.blocksMtx.Lock()
	defer cache.blocksMtx.Unlock()
	for blockHeight := fromHeight; blockHeight <= cache.bestBlock.height; blockHeight++ {
		delete(cache.mainchain, blockHeight)
	}
	cache.clearBestBlock()
}

// Reset resets the block cache.
func (cache *BlockCache) Reset() {
	cache.blocksMtx.Lock()
	defer cache.blocksMtx.Unlock()
	cache.filterMtx.Lock()
	defer cache.filterMtx.Unlock()

	cache.blocks = make(map[chainhash.Hash]*Block)
	cache.mainchain = make(map[int64]*chainhash.Hash)
	cache.filters = make(map[chainhash.Hash]*BlockFilter)
	cache.clearBestBlock()
}

// mtx must be locked for write.
func (cache *BlockCache) clearBestBlock() {
	cache.bestBlock.hash = nil
	cache.bestBlock.height = 0
}
