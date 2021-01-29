// This code is available on the terms of the project LICENSE.md file,
// also available online at https://blueoakcouncil.org/license/1.0.0.

package dcr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"decred.org/dcrdex/client/asset"
	"decred.org/dcrwallet/rpc/client/dcrwallet"
	walletjson "decred.org/dcrwallet/rpc/jsonrpc/types"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrutil/v3"
	chainjson "github.com/decred/dcrd/rpc/jsonrpc/types/v2"
	"github.com/decred/dcrd/rpcclient/v6"
	"github.com/decred/dcrd/wire"
)

type walletClient = dcrwallet.Client

// combinedClient implements rpcClient using matching methods in rpcclient.Client
// and dcrwallet.Client, or rpcclient.Client's RawRequest where a rpcClient method
// does not have a matching method in rpcclient.Client and dcrwallet.Client.
type combinedClient struct {
	*rpcclient.Client
	*walletClient
}

var _ rpcClient = (*combinedClient)(nil)

// RawRequest RPC methods
const (
	methodEstimateSmartFee   = "estimatesmartfee"
	methodGetTxOut           = "gettxout"
	methodListUnspent        = "listunspent"
	methodListLockUnspent    = "listlockunspent"
	methodSignRawTransaction = "signrawtransaction"
)

// anylist is a list of RPC parameters to be converted to []json.RawMessage and
// sent via RawRequest.
type anylist []interface{}

// EstimateSmartFee uses RawRequest for estimatesmartfee to circumvent unmarshal
// errors in rpcclient.
// This method can be dropped when (*rpcclient.Client).EstimateSmartFee is updated
// to return *chainjson.EstimateSmartFeeResult instead of float64.
func (cc *combinedClient) EstimateSmartFee(ctx context.Context, confirmations int64, mode chainjson.EstimateSmartFeeMode) (*chainjson.EstimateSmartFeeResult, error) {
	var res *chainjson.EstimateSmartFeeResult
	err := cc.rawRequest(ctx, methodEstimateSmartFee, anylist{}, &res)
	return res, err
}

// GetTxOut uses RawRequest for gettxout to allow passing tree param.
// This method can be dropped when (*rpcclient.Client).GetTxOut is updated to
// allow passing tree param.
func (cc *combinedClient) GetTxOut(ctx context.Context, txHash *chainhash.Hash, index uint32, tree int8, mempool bool) (*chainjson.GetTxOutResult, error) {
	var txout *chainjson.GetTxOutResult
	err := cc.rawRequest(ctx, methodGetTxOut, anylist{txHash.String(), index, tree, mempool}, &txout)
	return txout, err
}

// ListUnspent uses RawRequest for listunspent to allow passing account param.
func (cc *combinedClient) ListUnspent(ctx context.Context, acctName string) ([]walletjson.ListUnspentResult, error) {
	var unspents []walletjson.ListUnspentResult
	params := anylist{0, 9999999, nil, acctName} // minconf, maxconf (rpcdefault=9999999), [address], account
	err := cc.rawRequest(ctx, methodListUnspent, params, &unspents)
	return unspents, err
}

// ListLockUnspent uses RawRequest for listlockunspent to allow passing account
// param. Returns []chainjson.TransactionInput instead of []*wire.OutPoint that
// is returned by dcrwallet.Client.
func (cc *combinedClient) ListLockUnspent(ctx context.Context, acctName string) ([]chainjson.TransactionInput, error) {
	var res []chainjson.TransactionInput
	err := cc.rawRequest(ctx, methodListLockUnspent, anylist{acctName}, &res)
	return res, err
}

// SignRawTransaction uses RawRequest for signrawtransaction, to allow inspecting
// the *walletjson.SignRawTransactionResult.Errors field, which dcrwallet.Client
// drops.
func (cc *combinedClient) SignRawTransaction(ctx context.Context, tx *wire.MsgTx) (*walletjson.SignRawTransactionResult, error) {
	txHex, err := msgTxToHex(tx)
	if err != nil {
		return nil, fmt.Errorf("failed to encode MsgTx: %w", err)
	}
	var res *walletjson.SignRawTransactionResult
	err = cc.rawRequest(ctx, methodSignRawTransaction, anylist{txHex}, &res)
	return res, err
}

// ValidateAddress disambiguates the node and wallet methods.
func (cc *combinedClient) ValidateAddress(ctx context.Context, address dcrutil.Address) (*walletjson.ValidateAddressWalletResult, error) {
	return cc.walletClient.ValidateAddress(ctx, address)
}

// rawRequest is used to marshal parameters and send requests to the RPC server
// via (*rpcclient.Client).RawRequest. If `thing` is non-nil, the response will be
// unmarshaled into `thing`.
func (cc *combinedClient) rawRequest(ctx context.Context, method string, args anylist, thing interface{}) error {
	params := make([]json.RawMessage, 0, len(args))
	for i := range args {
		p, err := json.Marshal(args[i])
		if err != nil {
			return err
		}
		params = append(params, p)
	}
	response, err := cc.RawRequest(ctx, method, params)
	if err != nil {
		return fmt.Errorf("rawrequest error: %w", translateRPCCancelErr(err))
	}
	if thing != nil {
		return json.Unmarshal(response, thing)
	}
	return nil
}

// The rpcclient package functions will return a rpcclient.ErrRequestCanceled
// error if the context is canceled. Translate these to asset.ErrRequestTimeout.
func translateRPCCancelErr(err error) error {
	if errors.Is(err, rpcclient.ErrRequestCanceled) {
		err = asset.ErrRequestTimeout
	}
	return err
}
