// This code is available on the terms of the project LICENSE.md file,
// also available online at https://blueoakcouncil.org/license/1.0.0.

package dcr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"decred.org/dcrdex/server/asset"
	"github.com/decred/dcrd/chaincfg/chainhash"
	chainjson "github.com/decred/dcrd/rpc/jsonrpc/types/v2"
	"github.com/decred/dcrd/rpcclient/v6"
)

// rpcClient implements dcrNode using matching methods in rpcclient.Client, or
// rpcclient.Client's RawRequest where a dcrNode method does not have a matching
// method in rpcclient.Client.
type rpcClient struct {
	*rpcclient.Client
}

// RawRequest RPC methods
const (
	methodEstimateSmartFee = "estimatesmartfee"
	methodGetTxOut         = "gettxout"
)

// anylist is a list of RPC parameters to be converted to []json.RawMessage and
// sent via RawRequest.
type anylist []interface{}

// EstimateSmartFee uses RawRequest for estimatesmartfee to circumvent unmarshal
// errors in rpcclient.
// This method can be dropped when (*rpcclient.Client).EstimateSmartFee is updated
// to return *chainjson.EstimateSmartFeeResult instead of float64.
func (rpc *rpcClient) EstimateSmartFee(ctx context.Context, confirmations int64, mode chainjson.EstimateSmartFeeMode) (*chainjson.EstimateSmartFeeResult, error) {
	var res *chainjson.EstimateSmartFeeResult
	err := rpc.rawRequest(ctx, methodEstimateSmartFee, anylist{}, &res)
	return res, err
}

// GetTxOut uses RawRequest for gettxout to allow passing tree param.
// This method can be dropped when (*rpcclient.Client).GetTxOut is updated to
// allow passing tree param.
func (rpc *rpcClient) GetTxOut(ctx context.Context, txHash *chainhash.Hash, index uint32, tree int8, mempool bool) (*chainjson.GetTxOutResult, error) {
	var txout *chainjson.GetTxOutResult
	err := rpc.rawRequest(ctx, methodGetTxOut, anylist{txHash.String(), index, tree, mempool}, &txout)
	return txout, err
}

// rawRequest is used to marshal parameters and send requests to the RPC server
// via (*rpcclient.Client).RawRequest. If `thing` is non-nil, the response will be
// unmarshaled into `thing`.
func (rpc *rpcClient) rawRequest(ctx context.Context, method string, args anylist, thing interface{}) error {
	params := make([]json.RawMessage, 0, len(args))
	for i := range args {
		p, err := json.Marshal(args[i])
		if err != nil {
			return err
		}
		params = append(params, p)
	}
	response, err := rpc.RawRequest(ctx, method, params)
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
