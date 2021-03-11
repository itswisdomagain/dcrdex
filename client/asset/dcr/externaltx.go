// This code is available on the terms of the project LICENSE.md file,
// also available online at https://blueoakcouncil.org/license/1.0.0.

package dcr

import (
	"fmt"
	"sync"

	"decred.org/dcrdex/client/asset"
	"github.com/decred/dcrd/chaincfg/chainhash"
	chainjson "github.com/decred/dcrd/rpc/jsonrpc/types/v3"
)

type externalTx struct {
	hash *chainhash.Hash

	outputsMtx sync.RWMutex
	outputs    map[uint32]*externalTxOut

	scanMtx          sync.Mutex
	blockHash        *chainhash.Hash
	lastScannedBlock *chainhash.Hash
}

type externalTxOut struct {
	pkScript []byte

	scanMtx          sync.Mutex
	spenderBlockHash *chainhash.Hash
	lastScannedBlock *chainhash.Hash
}

// trackExternalTxOut records the script associated with a tx output to enable
// spv wallets easily locate the tx in a block when it's mined and to easily
// determine if the output is spent in a mined transaction.
func (dcr *ExchangeWallet) trackExternalTxOut(hash *chainhash.Hash, vout uint32, pkScript []byte) {
	if !dcr.spvMode {
		return
	}

	dcr.externalTxMtx.Lock()
	defer func() {
		dcr.externalTxMtx.Unlock()
		dcr.log.Debugf("Script cached for non-wallet output %s:%d.", hash, vout)
	}()

	if tx, exists := dcr.externalTxs[*hash]; exists {
		tx.outputsMtx.Lock()
		tx.outputs[vout] = &externalTxOut{
			pkScript: pkScript,
		}
		tx.outputsMtx.Unlock()
		return
	}

	dcr.externalTxs[*hash] = &externalTx{
		hash: hash,
		outputs: map[uint32]*externalTxOut{
			vout: {
				pkScript: pkScript,
			},
		},
	}
}

// externalTxOutConfirmations uses the script associated with a tx output to
// find the block in which the tx is mined and to determine if the output has
// been spent. The tx output's script must have been previously recorded using
// dcr.trackExternalTxOut, otherwise this will return asset.CoinNotFoundError.
func (dcr *ExchangeWallet) externalTxOutConfirmations(hash *chainhash.Hash, vout uint32) (uint32, bool, error) {
	dcr.externalTxMtx.RLock()
	tx, tracked := dcr.externalTxs[*hash]
	dcr.externalTxMtx.RUnlock()
	if !tracked {
		dcr.log.Errorf("Attempted to find txout confirmations without a cached script for %s:%d.", hash, vout)
		return 0, false, asset.CoinNotFoundError
	}

	tx.outputsMtx.RLock()
	output, tracked := tx.outputs[vout]
	tx.outputsMtx.RUnlock()
	if !tracked {
		return 0, false, asset.CoinNotFoundError
	}

	// If this tx output is not yet known to be spent, scan block filters
	// to try to locate a spender. If some other process got here first, a
	// block scan might be underway already. This process will be forced to
	// wait until the previous call completes.
	output.scanMtx.Lock()
	defer output.scanMtx.Unlock()

	confs, err := dcr.externalTxConfirmations(tx)
	if confs == 0 || err != nil {
		return confs, false, err
	}

	if output.spenderBlockHash != nil {
		// Output was previously spent in this block. Confirm that this block
		// is still valid.
		// TODO: Instead of checking block validity everytime, why not delete
		// this value if the block becomes orphaned.
		_, valid, err := dcr.isMainchainBlock(output.spenderBlockHash)
		if valid || err != nil {
			return confs, valid, err
		}
		// If !valid and err == nil, the block previously found to contain
		// this output's spender has been orphaned. Rescan again.
		output.spenderBlockHash = nil
	}

	checkSpentError := func(err error) (uint32, bool, error) {
		return confs, false, fmt.Errorf("unable to determine if output %s:%d is spent: %v", hash, vout, err)
	}

	startBlockHash := tx.blockHash
	if output.lastScannedBlock != nil {
		startBlockHash, err = dcr.mainChainAncestor(output.lastScannedBlock)
		if err != nil {
			return checkSpentError(err)
		}
	}
	startBlock, err := dcr.getDcrBlock(startBlockHash, false)
	if err != nil {
		return checkSpentError(err)
	}

	// Attempt to find a tx that spends this output in the blocks between the
	// last scanned block and the latest/best block.
	_, bestBlockHeight := dcr.blockCache.Tip()
	for blockHeight := startBlock.Height; blockHeight <= bestBlockHeight; blockHeight++ {
		blockHash, err := dcr.getBlockHash(blockHeight)
		if err != nil {
			return checkSpentError(err)
		}
		blockFilter, err := dcr.getBlockFilterV2(blockHash)
		if err != nil {
			return checkSpentError(err)
		}
		if !blockFilter.Match(output.pkScript) {
			continue // check next block's filters (blockHeight++)
		}
		block, err := dcr.getDcrBlock(blockHash, true)
		if err != nil {
			return checkSpentError(err)
		}
		for _, blkTx := range block.Txs {
			if txSpendsOutput(blkTx, hash, vout) {
				return confs, true, nil
			}
		}
		output.lastScannedBlock = blockHash
	}

	return confs, false, nil // scanned up to best block, no spender found
}

// externalTxConfirmations uses the output script(s) associated with the
// specified tx to find the block in which the tx is mined.
func (dcr *ExchangeWallet) externalTxConfirmations(tx *externalTx) (uint32, error) {
	// If this tx's block is not yet known, scan block filters to try to
	// locate it. If some other process got here first, a block scan might
	// be underway already. This process will be forced to wait until the
	// previous call completes.
	tx.scanMtx.Lock()
	defer tx.scanMtx.Unlock()

	// Check if a previous scan already found this tx's block.
	if tx.blockHash != nil {
		confs, err := dcr.blockConfirmations(tx.blockHash)
		if confs > -1 || err != nil {
			return uint32(confs), err
		}
		// If confs == -1 and err == nil, the block previously found to contain
		// this tx has been orphaned. Rescan again.
		tx.blockHash = nil
	}

	// Start a new search for this tx's block using the output scripts.
	tx.outputsMtx.RLock()
	outputScripts := make([][]byte, 0, len(tx.outputs))
	for _, output := range tx.outputs {
		outputScripts = append(outputScripts, output.pkScript)
	}
	tx.outputsMtx.RUnlock()

	// Scan block filters in reverse from the current best block (-1) to the
	// last scanned block. If the last scanned block has been re-orged out of
	// the main chain, scan back to the mainchain ancestor of the oprhaned block.
	var stopHeight int64
	var stopHash *chainhash.Hash
	if tx.lastScannedBlock != nil {
		var err error
		stopHash, err = dcr.mainChainAncestor(tx.lastScannedBlock)
		if err != nil {
			return 0, err
		}
		stopBlock, err := dcr.getDcrBlock(stopHash, false)
		if err != nil {
			return 0, err
		}
		stopHeight = stopBlock.Height
	} else {
		// TODO: Determine a stopHeight to use based on when this tx was first seen
		// or some constant min block height value.
	}

	// Run cfilters scan in reverse.
	currentTipHash, currentTipHeight := dcr.blockCache.Tip()
	dcr.log.Debugf("Searching for tx %s in blocks %d (%s) to %d (%s).", tx.hash,
		currentTipHeight, currentTipHash, stopHeight, stopHash)
	for blockHeight := currentTipHeight; blockHeight > stopHeight; blockHeight-- {
		blockHash, err := dcr.getBlockHash(blockHeight)
		if err != nil {
			return 0, err
		}
		blockFilter, err := dcr.getBlockFilterV2(blockHash)
		if err != nil {
			return 0, err
		}
		if !blockFilter.MatchAny(outputScripts) {
			continue // check previous block's filters (blockHeight--)
		}
		dcr.log.Debugf("Block %d (%s) likely contains tx %s. Confirming.", blockHeight, blockHash, tx.hash)
		block, err := dcr.getDcrBlock(blockHash, false)
		if err != nil {
			return 0, err
		}
		for _, blkTxID := range block.TxIDs {
			if blkTxID == tx.hash.String() {
				dcr.log.Debugf("Found mined tx %s in block %d (%s).", tx.hash, blockHeight, blockHash)
				tx.blockHash = blockHash
				return uint32(currentTipHeight - block.Height + 1), nil
			}
		}
	}

	// Scan completed from current tip to last scanned block. Set the
	// current tip as the last scanned block so subsequent scans cover
	// the latest tip back to this current tip (excluded).
	tx.lastScannedBlock = currentTipHash
	dcr.log.Debugf("Tx %s NOT found in blocks %d (%s) to %d (%s).", tx.hash,
		currentTipHeight, currentTipHash, stopHeight, stopHash)
	return 0, nil
}

func (dcr *ExchangeWallet) blockConfirmations(blockHash *chainhash.Hash) (int32, error) {
	block, isMainchain, err := dcr.isMainchainBlock(blockHash)
	if !isMainchain || err != nil {
		return -1, err
	}
	_, bestBlockHeight := dcr.blockCache.Tip()
	return int32(bestBlockHeight - block.Height + 1), nil
}

// spendingInputIndex returns the index of the input in the provided tx that
// spends the provided output, if such input exists in the tx.
func txSpendsOutput(tx *chainjson.TxRawResult, prevOut *chainhash.Hash, prevOutIndex uint32) bool {
	for i := range tx.Vin {
		input := &tx.Vin[i]
		if input.Vout == prevOutIndex && input.Txid == prevOut.String() {
			return true // found spender
		}
	}
	return false
}
