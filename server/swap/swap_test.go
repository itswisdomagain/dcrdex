// This code is available on the terms of the project LICENSE.md file,
// also available online at https://blueoakcouncil.org/license/1.0.0.

package swap

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"decred.org/dcrdex/dex"
	"decred.org/dcrdex/dex/encode"
	"decred.org/dcrdex/dex/msgjson"
	"decred.org/dcrdex/dex/order"
	"decred.org/dcrdex/server/account"
	"decred.org/dcrdex/server/asset"
	"decred.org/dcrdex/server/coinlock"
	"decred.org/dcrdex/server/comms"
	"decred.org/dcrdex/server/db"
	"decred.org/dcrdex/server/matcher"
	"github.com/decred/dcrd/dcrec/secp256k1/v2"
)

const (
	ABCID = 123
	XYZID = 789
)

var (
	testCtx      context.Context
	acctTemplate = account.AccountID{
		0x22, 0x4c, 0xba, 0xaa, 0xfa, 0x80, 0xbf, 0x3b, 0xd1, 0xff, 0x73, 0x15,
		0x90, 0xbc, 0xbd, 0xda, 0x5a, 0x76, 0xf9, 0x1e, 0x60, 0xa1, 0x56, 0x99,
		0x46, 0x34, 0xe9, 0x1c, 0xaa, 0xaa, 0xaa, 0xaa,
	}
	acctCounter uint32 = 0
	dexPrivKey  *secp256k1.PrivateKey
)

type tUser struct {
	sig      []byte
	sigHex   string
	acct     account.AccountID
	addr     string
	lbl      string
	matchIDs []order.MatchID
}

func tickMempool() {
	time.Sleep(recheckInterval * 3 / 2)
}

func timeOutMempool() {
	time.Sleep(txWaitExpiration * 3 / 2)
}

func timeoutBroadcast() {
	// swapper.bTimeout is 5*txWaitExpiration for testing
	time.Sleep(txWaitExpiration * 6)
}

func dirtyEncode(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		fmt.Printf("dirtyEncode error for input '%s': %v", s, err)
	}
	return b
}

// A new tUser with a unique account ID, signature, and address.
func tNewUser(lbl string) *tUser {
	intBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(intBytes, acctCounter)
	acctID := account.AccountID{}
	copy(acctID[:], acctTemplate[:])
	copy(acctID[account.HashSize-4:], intBytes)
	addr := strconv.Itoa(int(acctCounter))
	sig := []byte{0xab} // Just to differentiate from the addr.
	sig = append(sig, intBytes...)
	sigHex := hex.EncodeToString(sig)
	acctCounter++
	return &tUser{
		sig:    sig,
		sigHex: sigHex,
		acct:   acctID,
		addr:   addr,
		lbl:    lbl,
	}
}

type TRequest struct {
	req      *msgjson.Message
	respFunc func(comms.Link, *msgjson.Message)
}

// This stub satisfies AuthManager.
type TAuthManager struct {
	mtx         sync.Mutex
	authErr     error
	privkey     *secp256k1.PrivateKey
	reqs        map[account.AccountID][]*TRequest
	resps       map[account.AccountID][]*msgjson.Message
	suspensions map[account.AccountID]account.Rule
}

func newTAuthManager() *TAuthManager {
	// Reuse any previously generated dex server private key.
	if dexPrivKey == nil {
		dexPrivKey, _ = secp256k1.GeneratePrivateKey()
	}
	return &TAuthManager{
		privkey:     dexPrivKey,
		reqs:        make(map[account.AccountID][]*TRequest),
		resps:       make(map[account.AccountID][]*msgjson.Message),
		suspensions: make(map[account.AccountID]account.Rule),
	}
}

func (m *TAuthManager) Send(user account.AccountID, msg *msgjson.Message) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	l := m.resps[user]
	if l == nil {
		l = make([]*msgjson.Message, 0, 1)
	}
	m.resps[user] = append(l, msg)
	return nil
}

func (m *TAuthManager) SendWhenConnected(user account.AccountID, msg *msgjson.Message, _ time.Duration, _ func()) {
	_ = m.Send(user, msg)
}

func (m *TAuthManager) Request(user account.AccountID, msg *msgjson.Message,
	f func(comms.Link, *msgjson.Message)) error {
	return m.RequestWithTimeout(user, msg, f, time.Hour, func() {})
}

func (m *TAuthManager) RequestWhenConnected(user account.AccountID, req *msgjson.Message, handlerFunc func(comms.Link, *msgjson.Message),
	expireTimeout, connectTimeout time.Duration, expireFunc func()) {
	// TODO
	_ = m.RequestWithTimeout(user, req, handlerFunc, expireTimeout, expireFunc)
}
func (m *TAuthManager) RequestWithTimeout(user account.AccountID, msg *msgjson.Message,
	f func(comms.Link, *msgjson.Message), _ time.Duration, _ func()) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	tReq := &TRequest{
		req:      msg,
		respFunc: f,
	}
	l := m.reqs[user]
	if l == nil {
		l = make([]*TRequest, 0, 1)
	}
	m.reqs[user] = append(l, tReq)
	return nil
}
func (m *TAuthManager) Sign(signables ...msgjson.Signable) error {
	for _, signable := range signables {
		sig, err := m.privkey.Sign(signable.Serialize())
		if err != nil {
			return fmt.Errorf("signature error: %v", err)
		}
		signable.SetSig(sig.Serialize())
	}
	return nil
}
func (m *TAuthManager) Suspended(user account.AccountID) (found, suspended bool) {
	var rule account.Rule
	rule, found = m.suspensions[user]
	suspended = rule != account.NoRule
	return // TODO: test suspended account handling (no trades, just cancels)
}
func (m *TAuthManager) Auth(user account.AccountID, msg, sig []byte) error {
	return m.authErr
}
func (m *TAuthManager) Route(string,
	func(account.AccountID, *msgjson.Message) *msgjson.Error) {
}

func (m *TAuthManager) Penalize(id account.AccountID, rule account.Rule) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.suspensions[id] = rule
	return nil
}

func (m *TAuthManager) RecordCancel(user account.AccountID, oid, target order.OrderID, t time.Time) {}
func (m *TAuthManager) RecordCompletedOrder(account.AccountID, order.OrderID, time.Time)            {}
func (m *TAuthManager) Unban(account.AccountID) error                                               { return nil }

func (m *TAuthManager) flushPenalty(user account.AccountID) (found bool, rule account.Rule) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	rule, found = m.suspensions[user]
	if found {
		delete(m.suspensions, user)
	}
	return
}

// pop front
func (m *TAuthManager) getReq(id account.AccountID) *TRequest {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	reqs := m.reqs[id]
	if len(reqs) == 0 {
		return nil
	}
	req := reqs[0]
	m.reqs[id] = reqs[1:]
	return req
}

// push front
func (m *TAuthManager) pushReq(id account.AccountID, req *TRequest) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.reqs[id] = append([]*TRequest{req}, m.reqs[id]...)
}

// push front
func (m *TAuthManager) pushResp(id account.AccountID, msg *msgjson.Message) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.resps[id] = append([]*msgjson.Message{msg}, m.resps[id]...)
}

// pop front
func (m *TAuthManager) getResp(id account.AccountID) (*msgjson.Message, *msgjson.ResponsePayload) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	msgs := m.resps[id]
	if len(msgs) == 0 {
		return nil, nil
	}
	msg := msgs[0]
	m.resps[id] = msgs[1:]
	resp, _ := msg.Response()
	return msg, resp
}

type TStorage struct {
	fatalMtx  sync.RWMutex
	fatal     chan struct{}
	fatalErr  error
	stateHash []byte
}

func (ts *TStorage) LastErr() error {
	ts.fatalMtx.RLock()
	defer ts.fatalMtx.RUnlock()
	return ts.fatalErr
}

func (ts *TStorage) Fatal() <-chan struct{} {
	ts.fatalMtx.RLock()
	defer ts.fatalMtx.RUnlock()
	return ts.fatal
}

func (ts *TStorage) fatalBackendErr(err error) {
	ts.fatalMtx.Lock()
	if ts.fatal == nil {
		ts.fatal = make(chan struct{})
		close(ts.fatal)
	}
	ts.fatalErr = err // consider slice and append
	ts.fatalMtx.Unlock()
}

func (s *TStorage) InsertMatch(match *order.Match) error { return nil }
func (s *TStorage) CancelOrder(*order.LimitOrder) error  { return nil }
func (s *TStorage) RevokeOrder(order.Order) (cancelID order.OrderID, t time.Time, err error) {
	return
}
func (s *TStorage) SetOrderCompleteTime(ord order.Order, compTime int64) error { return nil }
func (s *TStorage) SwapData(mid db.MarketMatchID) (order.MatchStatus, *db.SwapData, error) {
	return 0, nil, nil
}
func (s *TStorage) SaveMatchAckSigA(mid db.MarketMatchID, sig []byte) error { return nil }
func (s *TStorage) SaveMatchAckSigB(mid db.MarketMatchID, sig []byte) error { return nil }

// Contract data.
func (s *TStorage) SaveContractA(mid db.MarketMatchID, contract []byte, coinID []byte, timestamp int64) error {
	return nil
}
func (s *TStorage) SaveAuditAckSigB(mid db.MarketMatchID, sig []byte) error { return nil }
func (s *TStorage) SaveContractB(mid db.MarketMatchID, contract []byte, coinID []byte, timestamp int64) error {
	return nil
}
func (s *TStorage) SaveAuditAckSigA(mid db.MarketMatchID, sig []byte) error { return nil }

// Redeem data.
func (s *TStorage) SaveRedeemA(mid db.MarketMatchID, coinID, secret []byte, timestamp int64) error {
	return nil
}
func (s *TStorage) SaveRedeemAckSigB(mid db.MarketMatchID, sig []byte) error {
	return nil
}
func (s *TStorage) SaveRedeemB(mid db.MarketMatchID, coinID []byte, timestamp int64) error {
	return nil
}
func (s *TStorage) SaveRedeemAckSigA(mid db.MarketMatchID, sig []byte) error {
	return nil
}
func (s *TStorage) SetMatchInactive(mid db.MarketMatchID) error { return nil }

func (s *TStorage) GetStateHash() ([]byte, error) {
	return s.stateHash, nil
}

func (s *TStorage) SetStateHash(h []byte) error {
	s.stateHash = h
	return nil
}

// This stub satisfies asset.Backend.
type TAsset struct {
	mtx           sync.RWMutex
	contracts     map[string]asset.Contract
	contractErr   error
	funds         asset.FundingCoin
	fundsErr      error
	redemptions   map[string]asset.Coin
	redemptionErr error
	bChan         chan *asset.BlockUpdate // to trigger processBlock and eventually (after up to BroadcastTimeout) checkInaction depending on block time
	lbl           string
}

func newTAsset(lbl string) *TAsset {
	return &TAsset{
		bChan:       make(chan *asset.BlockUpdate, 5),
		lbl:         lbl,
		contracts:   make(map[string]asset.Contract),
		redemptions: make(map[string]asset.Coin),
		fundsErr:    asset.CoinNotFoundError,
	}
}

func (a *TAsset) FundingCoin(coinID, redeemScript []byte) (asset.FundingCoin, error) {
	a.mtx.RLock()
	defer a.mtx.RUnlock()
	return a.funds, a.fundsErr
}
func (a *TAsset) Contract(coinID, redeemScript []byte) (asset.Contract, error) {
	a.mtx.RLock()
	defer a.mtx.RUnlock()
	if a.contractErr != nil {
		return nil, a.contractErr
	}
	contract, found := a.contracts[string(coinID)]
	if !found || contract == nil {
		return nil, asset.CoinNotFoundError
	}
	return contract, nil
}
func (a *TAsset) Redemption(redemptionID, _ /*contractID*/ []byte) (asset.Coin, error) {
	a.mtx.RLock()
	defer a.mtx.RUnlock()
	if a.redemptionErr != nil {
		return nil, a.redemptionErr
	}
	redeem, found := a.redemptions[string(redemptionID)]
	if !found || redeem == nil {
		return nil, asset.CoinNotFoundError
	}
	return redeem, nil
}
func (a *TAsset) ValidateCoinID(coinID []byte) (string, error) {
	return "", nil
}
func (a *TAsset) ValidateContract(contract []byte) error {
	return nil
}
func (a *TAsset) BlockChannel(size int) <-chan *asset.BlockUpdate { return a.bChan }
func (a *TAsset) InitTxSize() uint32                              { return 100 }
func (a *TAsset) InitTxSizeBase() uint32                          { return 66 }
func (a *TAsset) FeeRate() (uint64, error)                        { return 10, nil }
func (a *TAsset) CheckAddress(string) bool                        { return true }
func (a *TAsset) Run(context.Context)                             {}
func (a *TAsset) ValidateSecret(secret, contract []byte) bool     { return true }
func (a *TAsset) VerifyUnspentCoin(coinID []byte) error           { return nil }

func (a *TAsset) setContractErr(err error) {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	a.contractErr = err
}
func (a *TAsset) setContract(contract asset.Contract, resetErr bool) {
	a.mtx.Lock()
	a.contracts[string(contract.ID())] = contract
	if resetErr {
		a.contractErr = nil
	}
	a.mtx.Unlock()
}

func (a *TAsset) setRedemptionErr(err error) {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	a.redemptionErr = err
}
func (a *TAsset) setRedemption(redeem asset.Coin, resetErr bool) {
	a.mtx.Lock()
	a.redemptions[string(redeem.ID())] = redeem
	if resetErr {
		a.redemptionErr = nil
	}
	a.mtx.Unlock()
}

// This stub satisfies asset.Transaction, used by asset.Backend.
type TCoin struct {
	mtx       sync.RWMutex
	id        []byte
	confs     int64
	confsErr  error
	auditAddr string
	auditVal  uint64
	lockTime  time.Time
}

func (coin *TCoin) Confirmations() (int64, error) {
	coin.mtx.RLock()
	defer coin.mtx.RUnlock()
	return coin.confs, coin.confsErr
}

func (coin *TCoin) SwapAddress() string {
	return coin.auditAddr
}

func (coin *TCoin) Addresses() []string {
	return []string{coin.auditAddr}
}

func (coin *TCoin) LockTime() time.Time {
	return coin.lockTime
}

func (coin *TCoin) setConfs(confs int64) {
	coin.mtx.Lock()
	defer coin.mtx.Unlock()
	coin.confs = confs
}

func (coin *TCoin) Auth(pubkeys, sigs [][]byte, msg []byte) error { return nil }
func (coin *TCoin) ID() []byte                                    { return coin.id }
func (coin *TCoin) TxID() string                                  { return hex.EncodeToString(coin.id) }
func (coin *TCoin) Value() uint64                                 { return coin.auditVal }
func (coin *TCoin) SpendSize() uint32                             { return 0 }
func (coin *TCoin) String() string                                { return hex.EncodeToString(coin.id) /* not txid:vout */ }

func (coin *TCoin) FeeRate() uint64 {
	return 72 // make sure it's at least the required fee if you want it to pass (test fail TODO)
}

func (coin *TCoin) RedeemScript() []byte { return nil }

func TNewAsset(backend asset.Backend) *asset.BackedAsset {
	return &asset.BackedAsset{
		Backend: backend,
		Asset: dex.Asset{
			Symbol:     "qwe",
			MaxFeeRate: 12,
			SwapConf:   2,
		},
	}
}

var testMsgID uint64

func nextID() uint64 {
	return atomic.AddUint64(&testMsgID, 1)
}

func tNewResponse(id uint64, resp []byte) *msgjson.Message {
	msg, _ := msgjson.NewResponse(id, json.RawMessage(resp), nil)
	return msg
}

// testRig is the primary test data structure.
type testRig struct {
	abc           *asset.BackedAsset
	abcNode       *TAsset
	xyz           *asset.BackedAsset
	xyzNode       *TAsset
	auth          *TAuthManager
	swapper       *Swapper
	swapperWaiter *dex.StartStopWaiter
	storage       *TStorage
	matches       *tMatchSet
	matchInfo     *tMatch
	swapDataDir   string
	statePath     string
	ignoreState   bool
}

func tNewTestRig(matchInfo *tMatch, seed ...*testRig) (*testRig, func()) {
	var abcBackend, xyzBackend *TAsset
	storage := &TStorage{}
	var swapDataDir, statePath string
	var ignoreState bool
	manualMode := len(seed) > 0
	if manualMode && seed[0] != nil {
		seedRig := seed[0]
		abcBackend, xyzBackend = seedRig.abcNode, seedRig.xyzNode
		storage = seedRig.storage
		// state := conf[0].state
		swapDataDir = seedRig.swapDataDir
		statePath = seedRig.statePath
		ignoreState = seedRig.ignoreState
	} else {
		abcBackend = newTAsset("abc")
		xyzBackend = newTAsset("xyz")
		var err error
		swapDataDir, err = ioutil.TempDir("", "swapstates")
		if err != nil {
			panic(err.Error())
		}
	}

	abcAsset := TNewAsset(abcBackend)
	abcCoinLocker := coinlock.NewAssetCoinLocker()

	xyzAsset := TNewAsset(xyzBackend)
	xyzCoinLocker := coinlock.NewAssetCoinLocker()

	authMgr := newTAuthManager()

	swapper, err := NewSwapper(&Config{
		DataDir: swapDataDir,
		Assets: map[uint32]*LockableAsset{
			ABCID: {abcAsset, abcCoinLocker},
			XYZID: {xyzAsset, xyzCoinLocker},
		},
		Storage:          storage,
		AuthManager:      authMgr,
		BroadcastTimeout: txWaitExpiration * 5,
		LockTimeTaker:    dex.LockTimeTaker(dex.Testnet),
		LockTimeMaker:    dex.LockTimeMaker(dex.Testnet),
		UnbookHook:       func(*order.LimitOrder) bool { return true },
		IgnoreState:      ignoreState,
		StatePath:        statePath,
	})
	if err != nil {
		panic(err.Error())
	}

	ssw := dex.NewStartStopWaiter(swapper)
	ssw.Start(testCtx)
	cleanup := func() {
		ssw.Stop()
		ssw.WaitForShutdown()
		// If state was passed, even if nil, do not clean up the swapDataDir.
		// Leave it to the test that used the state arg to do
		// os.RemoveAll(rig.swapDataDir) after cleanup().
		if !manualMode {
			os.RemoveAll(swapDataDir)
		} else {
			time.Sleep(10 * time.Millisecond) // to avoid swap state files with the same ms stamp
		}
	}

	return &testRig{
		abc:           abcAsset,
		abcNode:       abcBackend,
		xyz:           xyzAsset,
		xyzNode:       xyzBackend,
		auth:          authMgr,
		swapper:       swapper,
		swapperWaiter: ssw,
		storage:       storage,
		matchInfo:     matchInfo,
		swapDataDir:   swapDataDir,
		statePath:     statePath,
		ignoreState:   ignoreState,
	}, cleanup
}

func (rig *testRig) getTracker() *matchTracker {
	rig.swapper.matchMtx.Lock()
	defer rig.swapper.matchMtx.Unlock()
	return rig.swapper.matches[rig.matchInfo.matchID]
}

// Taker: Acknowledge the servers match notification.
func (rig *testRig) ackMatch_maker(checkSig bool) (err error) {
	matchInfo := rig.matchInfo
	err = rig.ackMatch(matchInfo.maker, matchInfo.makerOID, matchInfo.taker.addr)
	if err != nil {
		return err
	}
	if checkSig {
		tracker := rig.getTracker()
		if !bytes.Equal(tracker.Sigs.MakerMatch, matchInfo.maker.sig) {
			return fmt.Errorf("expected maker audit signature '%x', got '%x'", matchInfo.maker.sig, tracker.Sigs.MakerMatch)
		}
	}
	return nil
}

// Maker: Acknowledge the servers match notification.
func (rig *testRig) ackMatch_taker(checkSig bool) error {
	matchInfo := rig.matchInfo
	err := rig.ackMatch(matchInfo.taker, matchInfo.takerOID, matchInfo.maker.addr)
	if err != nil {
		return err
	}
	if checkSig {
		tracker := rig.getTracker()
		if !bytes.Equal(tracker.Sigs.TakerMatch, matchInfo.taker.sig) {
			return fmt.Errorf("expected taker audit signature '%x', got '%x'", matchInfo.taker.sig, tracker.Sigs.TakerMatch)
		}
	}
	return nil
}

func (rig *testRig) ackMatch(user *tUser, oid order.OrderID, counterAddr string) error {
	// If the match is already acked, which might be the case for the taker when
	// an order.MatchSet hash multiple makers, skip the this step without error.
	req := rig.auth.getReq(user.acct)
	if req == nil {
		return fmt.Errorf("failed to find match notification for %s", user.lbl)
	}
	if req.req.Route != msgjson.MatchRoute {
		return fmt.Errorf("expected method '%s', got '%s'", msgjson.MatchRoute, req.req.Route)
	}
	err := rig.checkMatchNotification(req.req, oid, counterAddr)
	if err != nil {
		return err
	}
	// The maker and taker would sign the notifications and return a list of
	// authorizations.
	resp := tNewResponse(req.req.ID, tAckArr(user, user.matchIDs))
	req.respFunc(nil, resp) // e.g. processMatchAcks, may Send resp on error
	return nil
}

// helper to check the match notifications.
func (rig *testRig) checkMatchNotification(msg *msgjson.Message, oid order.OrderID, counterAddr string) error {
	matchInfo := rig.matchInfo
	var notes []*msgjson.Match
	err := json.Unmarshal(msg.Payload, &notes)
	if err != nil {
		fmt.Printf("checkMatchNotification unmarshal error: %v\n", err)
	}
	var notification *msgjson.Match
	for _, n := range notes {
		if bytes.Equal(n.MatchID, matchInfo.matchID[:]) {
			notification = n
			break
		}
		if err = checkSigS256(n, rig.auth.privkey.PubKey()); err != nil {
			return fmt.Errorf("incorrect server signature: %v", err)
		}
	}
	if notification == nil {
		return fmt.Errorf("did not find match ID %s in match notifications", matchInfo.matchID)
	}
	if notification.OrderID.String() != oid.String() {
		return fmt.Errorf("expected order ID %s, got %s", oid, notification.OrderID)
	}
	if notification.Quantity != matchInfo.qty {
		return fmt.Errorf("expected order quantity %d, got %d", matchInfo.qty, notification.Quantity)
	}
	if notification.Rate != matchInfo.rate {
		return fmt.Errorf("expected match rate %d, got %d", matchInfo.rate, notification.Rate)
	}
	if notification.Address != counterAddr {
		return fmt.Errorf("expected match address %s, got %s", counterAddr, notification.Address)
	}
	return nil
}

// Can be used to ensure that a non-error response is returned from the swapper.
func (rig *testRig) checkResponse(user *tUser, txType string) error {
	msg, resp := rig.auth.getResp(user.acct)
	if msg == nil {
		return fmt.Errorf("unexpected nil response to %s's '%s'", user.lbl, txType)
	}
	if resp.Error != nil {
		return fmt.Errorf("%s swap rpc error. code: %d, msg: %s", user.lbl, resp.Error.Code, resp.Error.Message)
	}
	return nil
}

// Maker: Send swap transaction.
func (rig *testRig) sendSwap_maker(checkStatus bool) (err error) {
	matchInfo := rig.matchInfo
	swap, err := rig.sendSwap(matchInfo.maker, matchInfo.makerOID, matchInfo.taker.addr)
	if err != nil {
		return fmt.Errorf("error sending maker swap transaction: %v", err)
	}
	matchInfo.db.makerSwap = swap
	tracker := rig.getTracker()
	// Check the match status.
	if checkStatus {
		if tracker.Status != order.MakerSwapCast {
			return fmt.Errorf("unexpected swap status %d after maker swap notification", tracker.Status)
		}
		err := rig.checkResponse(matchInfo.maker, "init")
		if err != nil {
			return err
		}
	}
	return nil
}

// Taker: Send swap transaction.
func (rig *testRig) sendSwap_taker(checkStatus bool) (err error) {
	matchInfo := rig.matchInfo
	taker := matchInfo.taker
	swap, err := rig.sendSwap(taker, matchInfo.takerOID, matchInfo.maker.addr)
	if err != nil {
		return fmt.Errorf("error sending taker swap transaction: %v", err)
	}
	matchInfo.db.takerSwap = swap
	if err != nil {
		return err
	}
	tracker := rig.getTracker()
	// Check the match status.
	if checkStatus {
		if tracker.Status != order.TakerSwapCast {
			return fmt.Errorf("unexpected swap status %d after taker swap notification", tracker.Status)
		}
		err := rig.checkResponse(matchInfo.taker, "init")
		if err != nil {
			return err
		}
	}
	return nil
}

func (rig *testRig) sendSwap(user *tUser, oid order.OrderID, recipient string) (*tSwap, error) {
	matchInfo := rig.matchInfo
	swap := tNewSwap(matchInfo, oid, recipient, user)
	if isQuoteSwap(user, matchInfo.match) {
		rig.xyzNode.setContract(swap.coin, false)
	} else {
		rig.abcNode.setContract(swap.coin, false)
	}
	rpcErr := rig.swapper.handleInit(user.acct, swap.req)
	if rpcErr != nil {
		resp, _ := msgjson.NewResponse(swap.req.ID, nil, rpcErr)
		rig.auth.Send(user.acct, resp)
		return nil, fmt.Errorf("%s swap rpc error. code: %d, msg: %s", user.lbl, rpcErr.Code, rpcErr.Message)
	}
	return swap, nil
}

// Taker: Process the 'audit' request from the swapper. The request should be
// acknowledged separately with ackAudit_taker.
func (rig *testRig) auditSwap_taker() error {
	matchInfo := rig.matchInfo
	req := rig.auth.getReq(matchInfo.taker.acct)
	matchInfo.db.takerAudit = req
	if req == nil {
		return fmt.Errorf("failed to find audit request for taker after maker's init")
	}
	return rig.auditSwap(req.req, matchInfo.takerOID, matchInfo.db.makerSwap.contract, "taker", matchInfo.taker)
}

// Maker: Process the 'audit' request from the swapper. The request should be
// acknowledged separately with ackAudit_maker.
func (rig *testRig) auditSwap_maker() error {
	matchInfo := rig.matchInfo
	req := rig.auth.getReq(matchInfo.maker.acct)
	matchInfo.db.makerAudit = req
	if req == nil {
		return fmt.Errorf("failed to find audit request for maker after taker's init")
	}
	return rig.auditSwap(req.req, matchInfo.makerOID, matchInfo.db.takerSwap.contract, "maker", matchInfo.maker)
}

// checkSigS256 checks that the message's signature was created with the
// private key for the provided secp256k1 public key.
func checkSigS256(msg msgjson.Signable, pubKey *secp256k1.PublicKey) error {
	signature, err := secp256k1.ParseDERSignature(msg.SigBytes())
	if err != nil {
		return fmt.Errorf("error decoding secp256k1 Signature from bytes: %v", err)
	}
	if !signature.Verify(msg.Serialize(), pubKey) {
		return fmt.Errorf("secp256k1 signature verification failed")
	}
	return nil
}

func (rig *testRig) auditSwap(msg *msgjson.Message, oid order.OrderID, contract, tag string, user *tUser) error {
	if msg == nil {
		return fmt.Errorf("no %s 'audit' request from DEX", user.lbl)
	}

	if msg.Route != msgjson.AuditRoute {
		return fmt.Errorf("expected method '%s', got '%s'", msgjson.AuditRoute, msg.Route)
	}
	var params *msgjson.Audit
	err := json.Unmarshal(msg.Payload, &params)
	if err != nil {
		return fmt.Errorf("error unmarshaling audit params: %v", err)
	}
	if err = checkSigS256(params, rig.auth.privkey.PubKey()); err != nil {
		return fmt.Errorf("incorrect server signature: %v", err)
	}
	if params.OrderID.String() != oid.String() {
		return fmt.Errorf("%s : incorrect order ID in auditSwap, expected '%s', got '%s'", tag, oid, params.OrderID)
	}
	matchID := rig.matchInfo.matchID
	if params.MatchID.String() != matchID.String() {
		return fmt.Errorf("%s : incorrect match ID in auditSwap, expected '%s', got '%s'", tag, matchID, params.MatchID)
	}
	if params.Contract.String() != contract {
		return fmt.Errorf("%s : incorrect contract. expected '%s', got '%s'", tag, contract, params.Contract)
	}
	return nil
}

// Maker: Acknowledge the DEX 'audit' request.
func (rig *testRig) ackAudit_maker(checkSig bool) error {
	maker := rig.matchInfo.maker
	err := rig.ackAudit(maker, rig.matchInfo.db.makerAudit)
	if err != nil {
		return err
	}
	if checkSig {
		tracker := rig.getTracker()
		if !bytes.Equal(tracker.Sigs.MakerAudit, maker.sig) {
			return fmt.Errorf("expected taker audit signature '%x', got '%x'", maker.sig, tracker.Sigs.MakerAudit)
		}
	}
	return nil
}

// Taker: Acknowledge the DEX 'audit' request.
func (rig *testRig) ackAudit_taker(checkSig bool) error {
	taker := rig.matchInfo.taker
	err := rig.ackAudit(taker, rig.matchInfo.db.takerAudit)
	if err != nil {
		return err
	}
	if checkSig {
		tracker := rig.getTracker()
		if !bytes.Equal(tracker.Sigs.TakerAudit, taker.sig) {
			return fmt.Errorf("expected taker audit signature '%x', got '%x'", taker.sig, tracker.Sigs.TakerAudit)
		}
	}
	return nil
}

func (rig *testRig) ackAudit(user *tUser, req *TRequest) error {
	if req == nil {
		return fmt.Errorf("no %s 'audit' request from DEX", user.lbl)
	}
	req.respFunc(nil, tNewResponse(req.req.ID, tAck(user, rig.matchInfo.matchID)))
	return nil
}

// Maker: Redeem taker's swap transaction.
func (rig *testRig) redeem_maker(checkStatus bool) error {
	matchInfo := rig.matchInfo
	matchInfo.db.makerRedeem = rig.redeem(matchInfo.maker, matchInfo.makerOID)
	tracker := rig.getTracker()
	// Check the match status
	if checkStatus {
		if tracker.Status != order.MakerRedeemed {
			return fmt.Errorf("unexpected swap status %d after maker redeem notification", tracker.Status)
		}
		err := rig.checkResponse(matchInfo.maker, "redeem")
		if err != nil {
			return err
		}
	}
	return nil
}

// Taker: Redeem maker's swap transaction.
func (rig *testRig) redeem_taker(checkStatus bool) error {
	matchInfo := rig.matchInfo
	matchInfo.db.takerRedeem = rig.redeem(matchInfo.taker, matchInfo.takerOID)
	tracker := rig.getTracker()
	// Check the match status
	if checkStatus {
		if tracker.Status != order.MatchComplete {
			return fmt.Errorf("unexpected swap status %d after taker redeem notification", tracker.Status)
		}
		err := rig.checkResponse(matchInfo.taker, "redeem")
		if err != nil {
			return err
		}
	}
	return nil
}

func (rig *testRig) redeem(user *tUser, oid order.OrderID) *tRedeem {
	matchInfo := rig.matchInfo
	redeem := tNewRedeem(matchInfo, oid, user)
	if isQuoteSwap(user, matchInfo.match) {
		// do not clear redemptionErr yet
		rig.abcNode.setRedemption(redeem.coin, false)
	} else {
		rig.xyzNode.setRedemption(redeem.coin, false)
	}
	rpcErr := rig.swapper.handleRedeem(user.acct, redeem.req)
	if rpcErr != nil {
		msg, _ := msgjson.NewResponse(redeem.req.ID, nil, rpcErr)
		rig.auth.Send(user.acct, msg)
	}
	return redeem
}

// Taker: Acknowledge the DEX 'redemption' request.
func (rig *testRig) ackRedemption_taker(checkSig bool) error {
	matchInfo := rig.matchInfo
	err := rig.ackRedemption(matchInfo.taker, matchInfo.takerOID, matchInfo.db.makerRedeem)
	if err != nil {
		return err
	}
	if checkSig {
		tracker := rig.getTracker()
		if !bytes.Equal(tracker.Sigs.TakerRedeem, matchInfo.taker.sig) {
			return fmt.Errorf("expected taker redemption signature '%x', got '%x'", matchInfo.taker.sig, tracker.Sigs.TakerRedeem)
		}
	}
	return nil
}

// Maker: Acknowledge the DEX 'redemption' request.
func (rig *testRig) ackRedemption_maker(checkSig bool) error {
	matchInfo := rig.matchInfo
	err := rig.ackRedemption(matchInfo.maker, matchInfo.makerOID, matchInfo.db.takerRedeem)
	if err != nil {
		return err
	}
	if checkSig {
		tracker := rig.getTracker()
		if !bytes.Equal(tracker.Sigs.MakerRedeem, matchInfo.maker.sig) {
			return fmt.Errorf("expected maker redemption signature '%x', got '%x'", matchInfo.maker.sig, tracker.Sigs.MakerRedeem)
		}
	}
	return nil
}

func (rig *testRig) ackRedemption(user *tUser, oid order.OrderID, redeem *tRedeem) error {
	if redeem == nil {
		return fmt.Errorf("nil redeem info")
	}
	req := rig.auth.getReq(user.acct)
	if req == nil {
		return fmt.Errorf("failed to find audit request for %s after counterparty's init", user.lbl)
	}
	err := rig.checkRedeem(req.req, oid, redeem.coin.ID(), user.lbl)
	if err != nil {
		return err
	}
	req.respFunc(nil, tNewResponse(req.req.ID, tAck(user, rig.matchInfo.matchID)))
	return nil
}

func (rig *testRig) checkRedeem(msg *msgjson.Message, oid order.OrderID, coinID []byte, tag string) error {
	var params *msgjson.Redemption
	err := json.Unmarshal(msg.Payload, &params)
	if err != nil {
		return fmt.Errorf("error unmarshaling redeem params: %v", err)
	}
	if err = checkSigS256(params, rig.auth.privkey.PubKey()); err != nil {
		return fmt.Errorf("incorrect server signature: %v", err)
	}
	if params.OrderID.String() != oid.String() {
		return fmt.Errorf("%s : incorrect order ID in checkRedeem, expected '%s', got '%s'", tag, oid, params.OrderID)
	}
	matchID := rig.matchInfo.matchID
	if params.MatchID.String() != matchID.String() {
		return fmt.Errorf("%s : incorrect match ID in checkRedeem, expected '%s', got '%s'", tag, matchID, params.MatchID)
	}
	if !bytes.Equal(params.CoinID, coinID) {
		return fmt.Errorf("%s : incorrect coinID in checkRedeem. expected '%x', got '%x'", tag, coinID, params.CoinID)
	}
	return nil
}

func makeCancelOrder(limitOrder *order.LimitOrder, user *tUser) *order.CancelOrder {
	return &order.CancelOrder{
		P: order.Prefix{
			AccountID:  user.acct,
			BaseAsset:  limitOrder.BaseAsset,
			QuoteAsset: limitOrder.QuoteAsset,
			OrderType:  order.CancelOrderType,
			ClientTime: unixMsNow(),
			ServerTime: unixMsNow(),
		},
		TargetOrderID: limitOrder.ID(),
	}
}

func makeLimitOrder(qty, rate uint64, user *tUser, makerSell bool) *order.LimitOrder {
	return &order.LimitOrder{
		P: order.Prefix{
			AccountID:  user.acct,
			BaseAsset:  ABCID,
			QuoteAsset: XYZID,
			OrderType:  order.LimitOrderType,
			ClientTime: encode.UnixTimeMilli(1566497654000),
			ServerTime: encode.UnixTimeMilli(1566497655000),
		},
		T: order.Trade{
			Sell:     makerSell,
			Quantity: qty,
			Address:  user.addr,
		},
		Rate: rate,
	}
}

func makeMarketOrder(qty uint64, user *tUser, makerSell bool) *order.MarketOrder {
	return &order.MarketOrder{
		P: order.Prefix{
			AccountID:  user.acct,
			BaseAsset:  ABCID,
			QuoteAsset: XYZID,
			OrderType:  order.LimitOrderType,
			ClientTime: encode.UnixTimeMilli(1566497654000),
			ServerTime: encode.UnixTimeMilli(1566497655000),
		},
		T: order.Trade{
			Sell:     makerSell,
			Quantity: qty,
			Address:  user.addr,
		},
	}
}

func limitLimitPair(makerQty, takerQty, makerRate, takerRate uint64, maker, taker *tUser, makerSell bool) (*order.LimitOrder, *order.LimitOrder) {
	return makeLimitOrder(makerQty, makerRate, maker, makerSell), makeLimitOrder(takerQty, takerRate, taker, !makerSell)
}

func marketLimitPair(makerQty, takerQty, rate uint64, maker, taker *tUser, makerSell bool) (*order.LimitOrder, *order.MarketOrder) {
	return makeLimitOrder(makerQty, rate, maker, makerSell), makeMarketOrder(takerQty, taker, !makerSell)
}

func tLimitPair(makerQty, takerQty, matchQty, makerRate, takerRate uint64, makerSell bool) *tMatchSet {
	set := new(tMatchSet)
	maker, taker := tNewUser("maker"), tNewUser("taker")
	makerOrder, takerOrder := limitLimitPair(makerQty, takerQty, makerRate, takerRate, maker, taker, makerSell)
	return set.add(tMatchInfo(maker, taker, matchQty, makerRate, makerOrder, takerOrder))
}

func tPerfectLimitLimit(qty, rate uint64, makerSell bool) *tMatchSet {
	return tLimitPair(qty, qty, qty, rate, rate, makerSell)
}

func tMarketPair(makerQty, takerQty, rate uint64, makerSell bool) *tMatchSet {
	set := new(tMatchSet)
	maker, taker := tNewUser("maker"), tNewUser("taker")
	makerOrder, takerOrder := marketLimitPair(makerQty, takerQty, rate, maker, taker, makerSell)
	return set.add(tMatchInfo(maker, taker, makerQty, rate, makerOrder, takerOrder))
}

func tPerfectLimitMarket(qty, rate uint64, makerSell bool) *tMatchSet {
	return tMarketPair(qty, qty, rate, makerSell)
}

func tCancelPair() *tMatchSet {
	set := new(tMatchSet)
	user := tNewUser("user")
	qty := uint64(1e8)
	rate := uint64(1e8)
	makerOrder := makeLimitOrder(qty, rate, user, true)
	cancelOrder := makeCancelOrder(makerOrder, user)
	return set.add(tMatchInfo(user, user, qty, rate, makerOrder, cancelOrder))
}

// tMatch is the match info for a single match. A tMatch is typically created
// with tMatchInfo.
type tMatch struct {
	match    *order.Match
	matchID  order.MatchID
	makerOID order.OrderID
	takerOID order.OrderID
	qty      uint64
	rate     uint64
	maker    *tUser
	taker    *tUser
	db       struct {
		makerRedeem *tRedeem
		takerRedeem *tRedeem
		makerSwap   *tSwap
		takerSwap   *tSwap
		makerAudit  *TRequest
		takerAudit  *TRequest
	}
}

func makeAck(mid order.MatchID, sig []byte) msgjson.Acknowledgement {
	return msgjson.Acknowledgement{
		MatchID: mid[:],
		Sig:     sig,
	}
}

func tAck(user *tUser, matchID order.MatchID) []byte {
	b, _ := json.Marshal(makeAck(matchID, user.sig))
	return b
}

func tAckArr(user *tUser, matchIDs []order.MatchID) []byte {
	ackArr := make([]msgjson.Acknowledgement, 0, len(matchIDs))
	for _, matchID := range matchIDs {
		ackArr = append(ackArr, makeAck(matchID, user.sig))
	}
	b, _ := json.Marshal(ackArr)
	return b
}

func tMatchInfo(maker, taker *tUser, matchQty, matchRate uint64, makerOrder *order.LimitOrder, takerOrder order.Order) *tMatch {
	match := &order.Match{
		Taker:    takerOrder,
		Maker:    makerOrder,
		Quantity: matchQty,
		Rate:     matchRate,
	}
	mid := match.ID()
	maker.matchIDs = append(maker.matchIDs, mid)
	taker.matchIDs = append(taker.matchIDs, mid)
	return &tMatch{
		match:    match,
		qty:      matchQty,
		rate:     matchRate,
		matchID:  mid,
		makerOID: makerOrder.ID(),
		takerOID: takerOrder.ID(),
		maker:    maker,
		taker:    taker,
	}
}

// Matches are submitted to the swapper in small batches, one for each taker.
type tMatchSet struct {
	matchSet   *order.MatchSet
	matchInfos []*tMatch
}

// Add a new match to the tMatchSet.
func (set *tMatchSet) add(matchInfo *tMatch) *tMatchSet {
	match := matchInfo.match
	if set.matchSet == nil {
		set.matchSet = &order.MatchSet{Taker: match.Taker}
	}
	if set.matchSet.Taker.User() != match.Taker.User() {
		fmt.Println("!!!tMatchSet taker mismatch!!!")
	}
	ms := set.matchSet
	ms.Makers = append(ms.Makers, match.Maker)
	ms.Amounts = append(ms.Amounts, matchInfo.qty)
	ms.Rates = append(ms.Rates, matchInfo.rate)
	ms.Total += matchInfo.qty
	set.matchInfos = append(set.matchInfos, matchInfo)
	return set
}

// Either a market or limit order taker, and any number of makers.
func tMultiMatchSet(matchQtys, rates []uint64, makerSell bool, isMarket bool) *tMatchSet {
	var sum uint64
	for _, v := range matchQtys {
		sum += v
	}
	// Taker order can be > sum of match amounts
	taker := tNewUser("taker")
	var takerOrder order.Order
	if isMarket {
		takerOrder = makeMarketOrder(sum*5/4, taker, !makerSell)
	} else {
		takerOrder = makeLimitOrder(sum*5/4, rates[0], taker, !makerSell)
	}
	set := new(tMatchSet)
	for i, v := range matchQtys {
		maker := tNewUser("maker" + strconv.Itoa(i))
		// Alternate market and limit orders
		makerOrder := makeLimitOrder(v, rates[i], maker, makerSell)
		matchInfo := tMatchInfo(maker, taker, v, rates[i], makerOrder, takerOrder)
		set.add(matchInfo)
	}
	return set
}

// tSwap is the information needed for spoofing a swap transaction.
type tSwap struct {
	coin     *TCoin
	req      *msgjson.Message
	contract string
}

var tValSpoofer uint64 = 1
var tRecipientSpoofer = ""
var tLockTimeSpoofer time.Time

func tNewSwap(matchInfo *tMatch, oid order.OrderID, recipient string, user *tUser) *tSwap {
	auditVal := matchInfo.qty
	if isQuoteSwap(user, matchInfo.match) {
		auditVal = matcher.BaseToQuote(matchInfo.rate, matchInfo.qty)
	}
	coinID := randBytes(36)
	swap := &TCoin{
		confs:     0,
		auditAddr: recipient + tRecipientSpoofer,
		auditVal:  auditVal * tValSpoofer,
		id:        coinID,
	}

	swap.lockTime = encode.DropMilliseconds(matchInfo.match.Epoch.End().Add(dex.LockTimeTaker(dex.Testnet)))
	if user == matchInfo.maker {
		swap.lockTime = encode.DropMilliseconds(matchInfo.match.Epoch.End().Add(dex.LockTimeMaker(dex.Testnet)))
	}

	if !tLockTimeSpoofer.IsZero() {
		swap.lockTime = tLockTimeSpoofer
	}

	contract := "01234567" + user.sigHex
	req, _ := msgjson.NewRequest(nextID(), msgjson.InitRoute, &msgjson.Init{
		OrderID: oid[:],
		MatchID: matchInfo.matchID[:],
		// We control what the backend returns, so the txid doesn't matter right now.
		CoinID: coinID,
		//Time:     encode.UnixMilliU(unixMsNow()),
		Contract: dirtyEncode(contract),
	})

	return &tSwap{
		coin:     swap,
		req:      req,
		contract: contract,
	}
}

func isQuoteSwap(user *tUser, match *order.Match) bool {
	makerSell := match.Maker.Sell
	isMaker := user.acct == match.Maker.User()
	return (isMaker && !makerSell) || (!isMaker && makerSell)
}

func randBytes(len int) []byte {
	bytes := make([]byte, len)
	rand.Read(bytes)
	return bytes
}

// tRedeem is the information needed to spoof a redemption transaction.
type tRedeem struct {
	req  *msgjson.Message
	coin *TCoin
}

func tNewRedeem(matchInfo *tMatch, oid order.OrderID, user *tUser) *tRedeem {
	coinID := randBytes(36)
	req, _ := msgjson.NewRequest(nextID(), msgjson.RedeemRoute, &msgjson.Redeem{
		OrderID: oid[:],
		MatchID: matchInfo.matchID[:],
		CoinID:  coinID,
		//Time:    encode.UnixMilliU(unixMsNow()),
	})
	return &tRedeem{
		req:  req,
		coin: &TCoin{id: coinID},
	}
}

// Create a closure that will call t.Fatal if an error is non-nil.
func makeEnsureNilErr(t *testing.T) func(error) {
	return func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf(err.Error())
		}
	}
}

func makeMustBeError(t *testing.T) func(error, string) {
	return func(err error, tag string) {
		t.Helper()
		if err == nil {
			t.Fatalf("no error for %s", tag)
		}
	}
}

// Create a closure that will call t.Fatal if a user doesn't have an
// msgjson.RPCError of the correct type.
func rpcErrorChecker(t *testing.T, rig *testRig, code int) func(*tUser) {
	return func(user *tUser) {
		t.Helper()
		msg, resp := rig.auth.getResp(user.acct)
		if msg == nil {
			t.Fatalf("no response for %s", user.lbl)
		}
		if resp.Error == nil {
			t.Fatalf("no error for %s", user.lbl)
		}
		if resp.Error.Code != code {
			t.Fatalf("wrong error code for %s. expected %d, got %d", user.lbl, msgjson.SignatureError, resp.Error.Code)
		}
	}
}

func TestMain(m *testing.M) {
	recheckInterval = time.Millisecond * 20
	txWaitExpiration = recheckInterval * 10
	logger := dex.StdOutLogger("TEST", dex.LevelTrace)
	UseLogger(logger)
	db.UseLogger(logger)
	matcher.UseLogger(logger)
	comms.UseLogger(logger)
	var shutdown func()
	testCtx, shutdown = context.WithCancel(context.Background())
	defer shutdown()
	os.Exit(m.Run())
}

func TestFatalStorageErr(t *testing.T) {
	rig, cleanup := tNewTestRig(nil)
	defer cleanup()

	// Test a fatal storage backend error that causes the main loop to return
	// first, the anomalous shutdown route.
	rig.storage.fatalBackendErr(errors.New("backend error"))

	rig.swapperWaiter.WaitForShutdown()
}

func testSwap(t *testing.T, rig *testRig) {
	t.Helper()
	ensureNilErr := makeEnsureNilErr(t)

	// Step through the negotiation process. No errors should be generated.
	var takerAcked bool
	for _, matchInfo := range rig.matches.matchInfos {
		rig.matchInfo = matchInfo
		ensureNilErr(rig.ackMatch_maker(true))
		if !takerAcked {
			ensureNilErr(rig.ackMatch_taker(true))
			takerAcked = true
		}
		ensureNilErr(rig.sendSwap_maker(true))
		ensureNilErr(rig.auditSwap_taker())
		ensureNilErr(rig.ackAudit_taker(true))
		ensureNilErr(rig.sendSwap_taker(true))
		ensureNilErr(rig.auditSwap_maker())
		ensureNilErr(rig.ackAudit_maker(true))
		ensureNilErr(rig.redeem_maker(true))
		ensureNilErr(rig.ackRedemption_taker(true))
		ensureNilErr(rig.redeem_taker(true))
		ensureNilErr(rig.ackRedemption_maker(true))
	}
}

func TestSwaps(t *testing.T) {
	rig, cleanup := tNewTestRig(nil)
	defer cleanup()
	for _, makerSell := range []bool{true, false} {
		sellStr := " buy"
		if makerSell {
			sellStr = " sell"
		}
		t.Run("perfect limit-limit match"+sellStr, func(t *testing.T) {
			rig.matches = tPerfectLimitLimit(uint64(1e8), uint64(1e8), makerSell)
			rig.swapper.Negotiate([]*order.MatchSet{rig.matches.matchSet}, nil)
			testSwap(t, rig)
		})
		t.Run("perfect limit-market match"+sellStr, func(t *testing.T) {
			rig.matches = tPerfectLimitMarket(uint64(1e8), uint64(1e8), makerSell)
			rig.swapper.Negotiate([]*order.MatchSet{rig.matches.matchSet}, nil)
			testSwap(t, rig)
		})
		t.Run("imperfect limit-market match"+sellStr, func(t *testing.T) {
			// only requirement is that maker val > taker val.
			rig.matches = tMarketPair(uint64(10e8), uint64(2e8), uint64(5e8), makerSell)
			rig.swapper.Negotiate([]*order.MatchSet{rig.matches.matchSet}, nil)
			testSwap(t, rig)
		})
		t.Run("imperfect limit-limit match"+sellStr, func(t *testing.T) {
			rig.matches = tLimitPair(uint64(10e8), uint64(2e8), uint64(2e8), uint64(5e8), uint64(5e8), makerSell)
			rig.swapper.Negotiate([]*order.MatchSet{rig.matches.matchSet}, nil)
			testSwap(t, rig)
		})
		for _, isMarket := range []bool{true, false} {
			marketStr := " limit"
			if isMarket {
				marketStr = " market"
			}
			t.Run("three match set"+sellStr+marketStr, func(t *testing.T) {
				matchQtys := []uint64{uint64(1e8), uint64(9e8), uint64(3e8)}
				rates := []uint64{uint64(10e8), uint64(11e8), uint64(12e8)}
				rig.matches = tMultiMatchSet(matchQtys, rates, makerSell, isMarket)
				rig.swapper.Negotiate([]*order.MatchSet{rig.matches.matchSet}, nil)
				testSwap(t, rig)
			})
		}
	}
}

func TestNoAck(t *testing.T) {
	set := tPerfectLimitLimit(uint64(1e8), uint64(1e8), true)
	matchInfo := set.matchInfos[0]
	rig, cleanup := tNewTestRig(matchInfo)
	defer cleanup()
	rig.swapper.Negotiate([]*order.MatchSet{set.matchSet}, nil)
	ensureNilErr := makeEnsureNilErr(t)
	mustBeError := makeMustBeError(t)
	maker, taker := matchInfo.maker, matchInfo.taker

	// Check that the response from the Swapper is an
	// msgjson.SettlementSequenceError.
	checkSeqError := func(user *tUser) {
		msg, resp := rig.auth.getResp(user.acct)
		if msg == nil {
			t.Fatalf("checkSeqError: no message")
		}
		if resp.Error == nil {
			t.Fatalf("no error for %s", user.lbl)
		}
		if resp.Error.Code != msgjson.SettlementSequenceError {
			t.Fatalf("wrong rpc error for %s. expected %d, got %d", user.lbl, msgjson.SettlementSequenceError, resp.Error.Code)
		}
	}

	// Don't acknowledge from either side yet. Have the maker broadcast their swap
	// transaction
	mustBeError(rig.sendSwap_maker(true), "maker swap send")
	checkSeqError(maker)
	ensureNilErr(rig.ackMatch_maker(true))
	// Should be good to send the swap now.
	ensureNilErr(rig.sendSwap_maker(true))
	// For the taker, there must be two acknowledgements before broadcasting the
	// swap transaction, the match ack and the audit ack.
	mustBeError(rig.sendSwap_taker(true), "no match-ack taker swap send")
	checkSeqError(taker)
	ensureNilErr(rig.ackMatch_taker(true))
	// Try to send the swap without acknowledging the 'audit'.
	mustBeError(rig.sendSwap_taker(true), "no audit-ack taker swap send")
	checkSeqError(taker)
	ensureNilErr(rig.auditSwap_taker())
	ensureNilErr(rig.ackAudit_taker(true))
	ensureNilErr(rig.sendSwap_taker(true))
	// The maker should have received an 'audit' request. Don't acknowledge yet.
	mustBeError(rig.redeem_maker(true), "maker redeem")
	checkSeqError(maker)
	ensureNilErr(rig.auditSwap_maker())
	ensureNilErr(rig.ackAudit_maker(true))
	ensureNilErr(rig.redeem_maker(true))
	// The taker should have received a 'redemption' request. Don't acknowledge
	// yet.
	mustBeError(rig.redeem_taker(true), "taker redeem")
	checkSeqError(taker)
	ensureNilErr(rig.ackRedemption_taker(true))
	ensureNilErr(rig.redeem_taker(true))
	ensureNilErr(rig.ackRedemption_maker(true))
}

func TestTxWaiters(t *testing.T) {
	set := tPerfectLimitLimit(uint64(1e8), uint64(1e8), true)
	matchInfo := set.matchInfos[0]
	rig, cleanup := tNewTestRig(matchInfo)
	defer cleanup()
	rig.swapper.Negotiate([]*order.MatchSet{set.matchSet}, nil)
	ensureNilErr := makeEnsureNilErr(t)
	dummyError := fmt.Errorf("test error")

	// Get the MatchNotifications that the swapper sent to the clients and check
	// the match notification length, content, IDs, etc.
	if err := rig.ackMatch_maker(true); err != nil {
		t.Fatal(err)
	}
	if err := rig.ackMatch_taker(true); err != nil {
		t.Fatal(err)
	}
	// Set a non-latency error.
	rig.abcNode.setContractErr(dummyError)
	rig.sendSwap_maker(false)
	msg, resp := rig.auth.getResp(matchInfo.maker.acct)
	if msg == nil {
		t.Fatalf("no response for erroneous maker swap")
	}
	// Set an error for the maker's swap asset
	rig.abcNode.setContractErr(asset.CoinNotFoundError)
	// The error will be generated by the chainWaiter thread, so will need to
	// check the response.
	if err := rig.sendSwap_maker(false); err != nil {
		t.Fatal(err)
	}
	timeOutMempool()
	// Should have an rpc error.
	msg, resp = rig.auth.getResp(matchInfo.maker.acct)
	if msg == nil {
		t.Fatalf("no response for missing tx after timeout")
	}
	if resp.Error == nil {
		t.Fatalf("no rpc error for erroneous maker swap")
	}

	rig.abcNode.setContractErr(nil)
	// Everything should work now.
	if err := rig.sendSwap_maker(true); err != nil {
		t.Fatal(err)
	}
	if err := rig.auditSwap_taker(); err != nil {
		t.Fatal(err)
	}
	if err := rig.ackAudit_taker(true); err != nil {
		t.Fatal(err)
	}
	// Non-latency error.
	rig.xyzNode.setContractErr(dummyError)
	rig.sendSwap_taker(false)
	msg, _ = rig.auth.getResp(matchInfo.taker.acct)
	if msg == nil {
		t.Fatalf("no response for erroneous taker swap")
	}
	// For the taker swap, simulate latency.
	rig.xyzNode.setContractErr(asset.CoinNotFoundError)
	ensureNilErr(rig.sendSwap_taker(false))
	// Wait a tick
	tickMempool()
	// There should not be a response yet.
	msg, _ = rig.auth.getResp(matchInfo.taker.acct)
	if msg != nil {
		t.Fatalf("unexpected response for latent taker swap")
	}
	// Clear the error.
	rig.xyzNode.setContractErr(nil)
	tickMempool()
	msg, resp = rig.auth.getResp(matchInfo.taker.acct)
	if msg == nil {
		t.Fatalf("no response for erroneous taker swap")
	}
	if resp.Error != nil {
		t.Fatalf("unexpected rpc error for erroneous taker swap. code: %d, msg: %s",
			resp.Error.Code, resp.Error.Message)
	}
	ensureNilErr(rig.auditSwap_maker())
	ensureNilErr(rig.ackAudit_maker(true))

	// Set a transaction error for the maker's redemption.
	rig.xyzNode.setRedemptionErr(asset.CoinNotFoundError)
	ensureNilErr(rig.redeem_maker(false))
	tickMempool()
	tickMempool()
	msg, _ = rig.auth.getResp(matchInfo.maker.acct)
	if msg != nil {
		t.Fatalf("unexpected response for latent maker redeem")
	}
	// Clear the error.
	rig.xyzNode.setRedemptionErr(nil)
	tickMempool()
	msg, resp = rig.auth.getResp(matchInfo.maker.acct)
	if msg == nil {
		t.Fatalf("no response for erroneous maker redeem")
	}
	if resp.Error != nil {
		t.Fatalf("unexpected rpc error for erroneous maker redeem. code: %d, msg: %s",
			resp.Error.Code, resp.Error.Message)
	}
	// Back to the taker, but let it timeout first, and then rebroadcast.
	// Get the tracker now, since it will be removed from the match dict if
	// everything goes right
	tracker := rig.getTracker()
	ensureNilErr(rig.ackRedemption_taker(true))
	rig.abcNode.setRedemptionErr(asset.CoinNotFoundError)
	ensureNilErr(rig.redeem_taker(false))
	timeOutMempool()
	msg, _ = rig.auth.getResp(matchInfo.taker.acct)
	if msg == nil {
		t.Fatalf("no response for erroneous taker redeem")
	}
	rig.abcNode.setRedemptionErr(nil)
	ensureNilErr(rig.redeem_taker(true))
	// Set the number of confirmations on the redemptions.
	matchInfo.db.makerRedeem.coin.setConfs(int64(rig.xyz.SwapConf))
	matchInfo.db.takerRedeem.coin.setConfs(int64(rig.abc.SwapConf))
	// send a block through for either chain to trigger a completion check.
	rig.xyzNode.bChan <- &asset.BlockUpdate{Err: nil}
	tickMempool()
	if tracker.Status != order.MatchComplete {
		t.Fatalf("match not marked as complete: %d", tracker.Status)
	}
	// Make sure that the tracker is removed from swappers match map.
	if rig.getTracker() != nil {
		t.Fatalf("matchTracker not removed from swapper's match map")
	}
}

func TestBroadcastTimeouts(t *testing.T) {
	rig, cleanup := tNewTestRig(nil)
	defer cleanup()
	ensureNilErr := makeEnsureNilErr(t)
	sendBlock := func(node *TAsset) {
		node.bChan <- &asset.BlockUpdate{Err: nil}
		tickMempool()
	}
	checkRevokeMatch := func(user *tUser, i int) {
		req := rig.auth.getReq(user.acct)
		if req == nil {
			t.Fatalf("no match_cancellation")
		}
		params := new(msgjson.RevokeMatch)
		err := json.Unmarshal(req.req.Payload, &params)
		if err != nil {
			t.Fatalf("unmarshal error for %s at step %d: %s", user.lbl, i, string(req.req.Payload))
		}
		if err = checkSigS256(params, rig.auth.privkey.PubKey()); err != nil {
			t.Fatalf("incorrect server signature: %v", err)
		}
		if !bytes.Equal(params.MatchID, rig.matchInfo.matchID[:]) {
			t.Fatalf("unexpected revocation match ID for %s at step %d. expected %s, got %s",
				user.lbl, i, rig.matchInfo.matchID, params.MatchID)
		}
		if req.req.Route != msgjson.RevokeMatchRoute {
			t.Fatalf("wrong request method for %s at step %d: expected '%s', got '%s'",
				user.lbl, i, msgjson.RevokeMatchRoute, req.req.Route)
		}
	}
	// tryExpire will sleep for the duration of a BroadcastTimeout, and then
	// check that a penalty was assigned to the appropriate user, and that a
	// revoke_match message is sent to both users.
	tryExpire := func(i, j int, step order.MatchStatus, jerk, victim *tUser, node *TAsset) bool {
		if i != j {
			return false
		}
		// Sending a block through should schedule an inaction check after duration
		// BroadcastTimeout.
		sendBlock(node)
		timeoutBroadcast()
		found, rule := rig.auth.flushPenalty(jerk.acct)
		if !found {
			t.Fatalf("failed to penalize user at step %d", i)
		}
		if rule == account.NoRule {
			t.Fatalf("no penalty at step %d (status %v)", i, step)
		}
		// Make sure the specified user has a cancellation for this order
		checkRevokeMatch(jerk, i)
		checkRevokeMatch(victim, i)
		return true
	}
	// Run a timeout test after every important step.
	for i := 0; i <= 7; i++ {
		set := tPerfectLimitLimit(uint64(1e8), uint64(1e8), true) // same orders, different users
		matchInfo := set.matchInfos[0]
		rig.matchInfo = matchInfo
		rig.swapper.Negotiate([]*order.MatchSet{set.matchSet}, nil)
		// Step through the negotiation process. No errors should be generated.
		ensureNilErr(rig.ackMatch_maker(true))
		ensureNilErr(rig.ackMatch_taker(true))
		if tryExpire(i, 0, order.NewlyMatched, matchInfo.maker, matchInfo.taker, rig.abcNode) {
			continue
		}
		if tryExpire(i, 1, order.NewlyMatched, matchInfo.maker, matchInfo.taker, rig.abcNode) {
			continue
		}
		ensureNilErr(rig.sendSwap_maker(true))
		matchInfo.db.makerSwap.coin.setConfs(int64(rig.abc.SwapConf))
		// Do the audit here to clear the 'audit' request from the comms queue.
		ensureNilErr(rig.auditSwap_taker())
		sendBlock(rig.abcNode)
		if tryExpire(i, 2, order.MakerSwapCast, matchInfo.taker, matchInfo.maker, rig.xyzNode) {
			continue
		}
		ensureNilErr(rig.ackAudit_taker(true))
		if tryExpire(i, 3, order.MakerSwapCast, matchInfo.taker, matchInfo.maker, rig.xyzNode) {
			continue
		}
		ensureNilErr(rig.sendSwap_taker(true))
		matchInfo.db.takerSwap.coin.setConfs(int64(rig.xyz.SwapConf))
		// Do the audit here to clear the 'audit' request from the comms queue.
		ensureNilErr(rig.auditSwap_maker())
		sendBlock(rig.xyzNode)
		if tryExpire(i, 4, order.TakerSwapCast, matchInfo.maker, matchInfo.taker, rig.xyzNode) {
			continue
		}
		ensureNilErr(rig.ackAudit_maker(true))
		if tryExpire(i, 5, order.TakerSwapCast, matchInfo.maker, matchInfo.taker, rig.xyzNode) {
			continue
		}
		ensureNilErr(rig.redeem_maker(true))
		matchInfo.db.makerRedeem.coin.setConfs(int64(rig.xyz.SwapConf))
		// Ack the redemption here to clear the 'audit' request from the comms queue.
		ensureNilErr(rig.ackRedemption_taker(true))
		sendBlock(rig.xyzNode)
		if tryExpire(i, 6, order.MakerRedeemed, matchInfo.taker, matchInfo.maker, rig.abcNode) {
			continue
		}
		if tryExpire(i, 7, order.MakerRedeemed, matchInfo.taker, matchInfo.maker, rig.abcNode) {
			continue
		}
		return
	}
}

func TestSigErrors(t *testing.T) {
	dummyError := fmt.Errorf("test error")
	set := tPerfectLimitLimit(uint64(1e8), uint64(1e8), true)
	matchInfo := set.matchInfos[0]
	rig, cleanup := tNewTestRig(matchInfo)
	defer cleanup()

	rig.swapper.Negotiate([]*order.MatchSet{set.matchSet}, nil) // pushes a new req to m.reqs
	ensureNilErr := makeEnsureNilErr(t)

	// ensureSigErr makes sure that the specified user has a signature error
	// response from the swapper.
	ensureSigErr := rpcErrorChecker(t, rig, msgjson.SignatureError)

	// We need a way to restore the state of the queue after testing an auth error.
	var tReq *TRequest
	var msg *msgjson.Message
	apply := func(user *tUser) {
		if msg != nil {
			rig.auth.pushResp(user.acct, msg)
		}
		if tReq != nil {
			rig.auth.pushReq(user.acct, tReq)
		}
	}
	stash := func(user *tUser) {
		msg, _ = rig.auth.getResp(user.acct)
		tReq = rig.auth.getReq(user.acct)
		apply(user) // put them back now that we have a copy
	}
	testAction := func(stepFunc func(bool) error, user *tUser) {
		// First do it with an auth error.
		rig.auth.authErr = dummyError
		stash(user) // make a copy of this user's next req/resp pair
		// The error will be pulled from the auth manager.
		_ = stepFunc(false) // getReq => req.respFunc(..., tNewResponse()) => send error to client (m.resps)
		ensureSigErr(user)  // getResp
		// Again with no auth error to go to the next step.
		rig.auth.authErr = nil
		apply(user) // restore the initial live request
		ensureNilErr(stepFunc(true))
	}
	maker, taker := matchInfo.maker, matchInfo.taker
	// 1 live match, 2 pending client acks
	testAction(rig.ackMatch_maker, maker)
	testAction(rig.ackMatch_taker, taker)
	testAction(rig.sendSwap_maker, maker)
	ensureNilErr(rig.auditSwap_taker())
	testAction(rig.ackAudit_taker, taker)
	testAction(rig.sendSwap_taker, taker)
	ensureNilErr(rig.auditSwap_maker())
	testAction(rig.ackAudit_maker, maker)
	testAction(rig.redeem_maker, maker)
	testAction(rig.ackRedemption_taker, taker)
	testAction(rig.redeem_taker, taker)
	testAction(rig.ackRedemption_maker, maker)
}

func TestMalformedSwap(t *testing.T) {
	set := tPerfectLimitLimit(uint64(1e8), uint64(1e8), true)
	matchInfo := set.matchInfos[0]
	rig, cleanup := tNewTestRig(matchInfo)
	defer cleanup()
	rig.swapper.Negotiate([]*order.MatchSet{set.matchSet}, nil)
	ensureNilErr := makeEnsureNilErr(t)
	checkContractErr := rpcErrorChecker(t, rig, msgjson.ContractError)

	ensureNilErr(rig.ackMatch_maker(true))
	ensureNilErr(rig.ackMatch_taker(true))
	// Bad contract value
	tValSpoofer = 2
	ensureNilErr(rig.sendSwap_maker(false))
	checkContractErr(matchInfo.maker)
	tValSpoofer = 1
	// Bad contract recipient
	tRecipientSpoofer = "2"
	ensureNilErr(rig.sendSwap_maker(false))
	checkContractErr(matchInfo.maker)
	tRecipientSpoofer = ""
	// Bad locktime
	tLockTimeSpoofer = time.Unix(1, 0)
	ensureNilErr(rig.sendSwap_maker(false))
	checkContractErr(matchInfo.maker)
	tLockTimeSpoofer = time.Time{}
	// Now make sure it works.
	ensureNilErr(rig.sendSwap_maker(true))
}

func TestBadParams(t *testing.T) {
	set := tPerfectLimitLimit(uint64(1e8), uint64(1e8), true)
	matchInfo := set.matchInfos[0]
	rig, cleanup := tNewTestRig(matchInfo)
	defer cleanup()
	rig.swapper.Negotiate([]*order.MatchSet{set.matchSet}, nil)
	swapper := rig.swapper
	match := rig.getTracker()
	user := matchInfo.maker
	acker := &messageAcker{
		user:    user.acct,
		match:   match,
		isMaker: true,
		isAudit: true,
	}
	checkParseErr := rpcErrorChecker(t, rig, msgjson.RPCParseError)
	checkAckCountErr := rpcErrorChecker(t, rig, msgjson.AckCountError)

	ackArr := make([]*msgjson.Acknowledgement, 0)
	matches := []*messageAcker{
		{match: rig.getTracker()},
	}

	encodedAckArray := func() json.RawMessage {
		b, _ := json.Marshal(ackArr)
		return json.RawMessage(b)
	}

	// Invalid result.
	msg, _ := msgjson.NewResponse(1, nil, nil)
	msg.Payload = json.RawMessage(`{"result":?}`)
	swapper.processAck(msg, acker)
	checkParseErr(user)
	swapper.processMatchAcks(user.acct, msg, []*messageAcker{})
	checkParseErr(user)

	msg, _ = msgjson.NewResponse(1, encodedAckArray(), nil)
	swapper.processMatchAcks(user.acct, msg, matches)
	checkAckCountErr(user)
}

func TestCancel(t *testing.T) {
	set := tCancelPair()
	matchInfo := set.matchInfos[0]
	rig, cleanup := tNewTestRig(matchInfo)
	defer cleanup()
	rig.swapper.Negotiate([]*order.MatchSet{set.matchSet}, nil)
	// There should be no matchTracker
	if rig.getTracker() != nil {
		t.Fatalf("found matchTracker for a cancellation")
	}
	// The user should have two match requests.
	user := matchInfo.maker
	req := rig.auth.getReq(user.acct)
	if req == nil {
		t.Fatalf("no request sent from Negotiate")
	}
	matchNotes := make([]*msgjson.Match, 0)
	err := json.Unmarshal(req.req.Payload, &matchNotes)
	if err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if len(matchNotes) != 2 {
		t.Fatalf("expected 2 match notification, got %d", len(matchNotes))
	}
	for _, match := range matchNotes {
		if err = checkSigS256(match, rig.auth.privkey.PubKey()); err != nil {
			t.Fatalf("incorrect server signature: %v", err)
		}
	}
	makerNote, takerNote := matchNotes[0], matchNotes[1]
	if makerNote.OrderID.String() != matchInfo.makerOID.String() {
		t.Fatalf("expected maker ID %s, got %s", matchInfo.makerOID, makerNote.OrderID)
	}
	if takerNote.OrderID.String() != matchInfo.takerOID.String() {
		t.Fatalf("expected taker ID %s, got %s", matchInfo.takerOID, takerNote.OrderID)
	}
	if makerNote.MatchID.String() != takerNote.MatchID.String() {
		t.Fatalf("match ID mismatch. %s != %s", makerNote.MatchID, takerNote.MatchID)
	}
}

func TestState(t *testing.T) {
	sendBlock := func(node *TAsset) {
		node.bChan <- &asset.BlockUpdate{Err: nil}
		tickMempool() // look for another signal
	}

	var rig *testRig
	var stop func()
	loadLatestState := func() (*State, error) {
		stateFile, err := LatestStateFile(rig.swapDataDir)
		if err != nil {
			return nil, fmt.Errorf("error finding swap state files: %v", err)
		}
		if stateFile == nil {
			return nil, fmt.Errorf("no swap state file found.")
		}
		state, err := LoadStateFile(stateFile.Name)
		if err != nil {
			return nil, fmt.Errorf("error loading swap state file %q: %v", stateFile.Name, err)
		}
		return state, nil
	}

	// Start a swap negotiation with two pending match acks, then shutdown.
	// ABC is base, XYZ is quote
	makerSell := true // maker: swap = ABC, redeem = XYZ / taker: swap = XYZ, redeem = ABC
	set := tPerfectLimitLimit(uint64(1e8), uint64(1e8), makerSell)
	matchInfo := set.matchInfos[0]
	rig, stop = tNewTestRig(matchInfo, nil)
	defer os.RemoveAll(rig.swapDataDir)
	rig.swapper.Negotiate([]*order.MatchSet{set.matchSet}, nil)

	abc, xyz := rig.abcNode, rig.xyzNode

	maker, taker := matchInfo.maker, matchInfo.taker
	users := []account.AccountID{maker.acct, taker.acct}
	userFound := func(user account.AccountID) bool {
		for i := range users {
			if user == users[i] {
				return true
			}
		}
		return false
	}

	stop()

	// Swap state is now written into a file in rig.swapDataDir.
	state, err := loadLatestState()
	if err != nil {
		t.Fatal(err)
	}
	if len(state.LiveAckers) != 2 {
		t.Fatalf("expected 2 live ackers, got %d", len(state.LiveAckers))
	}
	for _, acker := range state.LiveAckers {
		if acker.Request.Route != msgjson.MatchRoute {
			t.Fatalf("acker for route %v, expected %v", acker.Request.Route, msgjson.MatchRoute)
		}
		if !userFound(acker.AckData[0].User) {
			t.Fatalf("unexpected acker user %v", acker.AckData[0].User)
		}
	}

	// Loading with ignoreState = true should result in no matches being loaded.
	// Set a different swapDataDir so the temporary rig doesn't dump it's empty
	// state file on stop().
	ogSwapDir := rig.swapDataDir
	ogHash := rig.storage.stateHash
	otherDir, err := ioutil.TempDir("", "otherstate")
	if err != nil {
		panic(err.Error())
	}
	rig.swapDataDir = otherDir
	rig.ignoreState = true
	rig, stop = tNewTestRig(matchInfo, rig)
	rig.ignoreState = false
	defer os.RemoveAll(otherDir)
	defer stop()

	if len(rig.swapper.matches) != 0 {
		t.Errorf("expected 0 tracked matches for ignoreState = true, got %d", len(rig.swapper.matches))
	}
	stop()

	// Loading the file from a different location should work as well.
	stateFile, err := LatestStateFile(ogSwapDir)
	if err != nil {
		t.Errorf("unable to read datadir: %v", err)
	}
	rig.statePath = stateFile.Name
	rig, stop = tNewTestRig(matchInfo, rig)
	rig.statePath = ""
	defer stop()
	if len(rig.swapper.matches) != 1 {
		t.Errorf("expected 1 tracked match for custom state file, got %d", len(rig.swapper.matches))
	}
	stop()
	rig.swapDataDir = ogSwapDir
	rig.storage.stateHash = ogHash

	// Now load the state in the default way.
	rig, stop = tNewTestRig(matchInfo, rig)
	defer os.RemoveAll(rig.swapDataDir)
	defer stop()

	if len(rig.swapper.matches) != 1 {
		t.Errorf("expected 1 tracked match, got %d", len(rig.swapper.matches))
	}

	tracker := rig.getTracker()
	if tracker.Status != order.NewlyMatched {
		t.Fatalf("match not marked as NewlyMatched: %v", tracker.Status)
	}

	// Maker acks match.
	err = rig.ackMatch_maker(false)
	if err != nil {
		t.Fatalf("maker failed to ack the match: %v", err)
	}

	stop()

	// Swap state is now written into a file in rig.swapDataDir.
	state, err = loadLatestState()
	if err != nil {
		t.Fatal(err)
	}

	if len(state.LiveAckers) != 1 {
		t.Fatalf("expected 1 live ackers, got %d", len(state.LiveAckers))
	}
	// Still have to range over the map even though there is just one element
	// since we don't know the msgID (map key).
	for _, acker := range state.LiveAckers {
		if acker.Request.Route != msgjson.MatchRoute {
			t.Fatalf("acker for route %v, expected %v", acker.Request.Route, msgjson.MatchRoute)
		}
		// should be just taker left
		if acker.AckData[0].User != taker.acct {
			t.Fatalf("unexpected acker user %v, expected %v", acker.AckData[0].User, taker.acct)
		}
	}

	// Start the swapper back up.
	rig, stop = tNewTestRig(matchInfo, rig)
	defer stop()

	if len(rig.swapper.matches) != 1 {
		t.Errorf("expected 1 tracked match, got %d", len(rig.swapper.matches))
	}

	// Taker acks match.
	err = rig.ackMatch_taker(false)
	if err != nil {
		t.Fatalf("taker failed to ack the match: %v", err)
	}

	stop() // Swap state is now written into a file in rig.swapDataDir.

	state, err = loadLatestState()
	if err != nil {
		t.Fatal(err)
	}

	if len(state.LiveAckers) != 0 {
		t.Fatalf("expected 0 live ackers, got %d", len(state.LiveAckers))
	}

	rig, stop = tNewTestRig(matchInfo, rig)
	defer stop()

	if len(rig.swapper.matches) != 1 {
		t.Errorf("expected 1 tracked match, got %d", len(rig.swapper.matches))
	}

	// handleInit for maker
	makerSwap := tNewSwap(matchInfo, matchInfo.makerOID, matchInfo.taker.addr, maker)
	// do not "broadcast" the contract yet: abc.setContract(makerSwap.coin, true)
	// TAsset can't find it yet, TryAgain back to the coinwaiter
	rpcErr := rig.swapper.handleInit(maker.acct, makerSwap.req)
	if rpcErr != nil {
		t.Fatalf("handleInit failed: %v", rpcErr)
	}

	// There is now a live coin waiter for the maker's swap, no audit request
	// yet since that is triggered after accounting for latency, calling
	// processInit>processAck.

	stop() // Swap state is now written into a file in rig.swapDataDir.

	state, err = loadLatestState()
	if err != nil {
		t.Fatal(err)
	}

	if len(state.LiveAckers) != 0 {
		t.Fatalf("expected 0 live ackers, got %d", len(state.LiveAckers))
	}
	if len(state.LiveWaiters) != 1 {
		t.Fatalf("expected 1 live coin waiter, got %d", len(state.LiveWaiters))
	}

	// Restarting the swapper should call handleInit again with the same args to
	// recreate the same coinwaiter.
	rig, stop = tNewTestRig(matchInfo, rig)
	defer stop()

	if len(rig.swapper.matches) != 1 {
		t.Errorf("expected 1 tracked match, got %d", len(rig.swapper.matches))
	}

	// Should still be NewlyMatched since the contract has not been bcasted yet.
	tracker = rig.getTracker()
	if tracker.Status != order.NewlyMatched {
		t.Fatalf("match not marked as NewlyMatched: %v", tracker.Status)
	}

	// "broadcast" the contract and signal a new block.
	abc.setContract(makerSwap.coin, true)
	makerSwap.coin.setConfs(int64(rig.abc.SwapConf))
	sendBlock(abc) // wait recheckInterval*3/2 for the coin waiter, plus trigger processBlock
	// processInit should have succeeded, requesting an ack from taker of the maker's contract.

	matchInfo.db.makerSwap = makerSwap // for taker's audit

	// The match status should now be MakerSwapCast, and there should be one ack (taker audit request)

	stop() // Swap state is now written into a file in rig.swapDataDir.

	if tracker.Status != order.MakerSwapCast {
		t.Fatalf("match not marked as MakerSwapCast: %v", tracker.Status)
	}

	state, err = loadLatestState()
	if err != nil {
		t.Fatal(err)
	}

	if len(state.LiveAckers) != 1 {
		t.Fatalf("expected 1 live ackers, got %d", len(state.LiveAckers))
	}
	if len(state.LiveWaiters) != 0 {
		t.Fatalf("expected 0 live coin waiter, got %d", len(state.LiveWaiters))
	}

	if state.MatchTrackers[matchInfo.matchID].Match.Status != order.MakerSwapCast {
		t.Fatalf("state's match tracker in status %v, expected %v",
			state.MatchTrackers[matchInfo.matchID].Match.Status, order.MakerSwapCast)
	}

	// Check that it's a taker audit request.
	for _, acker := range state.LiveAckers {
		if acker.Request.Route != msgjson.AuditRoute {
			t.Fatalf("acker for route %v, expected %v", acker.Request.Route, msgjson.AuditRoute)
		}
		// taker
		if acker.AckData[0].User != taker.acct {
			t.Fatalf("unexpected acker user %v, expected %v", acker.AckData[0].User, taker.acct)
		}
	}

	rig, stop = tNewTestRig(matchInfo, rig)
	defer stop()

	if len(rig.swapper.matches) != 1 {
		t.Errorf("expected 1 tracked match, got %d", len(rig.swapper.matches))
	}

	tracker = rig.getTracker()
	if tracker.Status != order.MakerSwapCast {
		t.Fatalf("match not marked as MakerSwapCast: %v", tracker.Status)
	}

	if err = rig.auditSwap_taker(); err != nil {
		t.Fatalf("taker failed to audit the maker's contract: %v", err)
	}
	if err = rig.ackAudit_taker(true); err != nil {
		t.Fatalf("taker failed to ack their audit of maker's contract: %v", err)
	}

	// There are now no live acks or coin waiters. Next step is for the taker to
	// init for their contract.

	// handleInit for taker
	takerSwap := tNewSwap(matchInfo, matchInfo.takerOID, matchInfo.maker.addr, taker)
	// do not "broadcast" the contract yet: xyz.setContract(takerSwap.coin, true)
	// TAsset can't find it yet, TryAgain back to the coinwaiter
	rpcErr = rig.swapper.handleInit(taker.acct, takerSwap.req)
	if rpcErr != nil {
		t.Fatalf("handleInit failed: %v", rpcErr)
	}

	// There is now a live coin waiter for the taker's swap, no audit request
	// yet since that is triggered after accounting for latency, calling
	// processInit>processAck.

	stop() // Swap state is now written into a file in rig.swapDataDir.

	state, err = loadLatestState()
	if err != nil {
		t.Fatal(err)
	}

	if len(state.LiveAckers) != 0 {
		t.Fatalf("expected 0 live ackers, got %d", len(state.LiveAckers))
	}
	if len(state.LiveWaiters) != 1 {
		t.Fatalf("expected 1 live coin waiter, got %d", len(state.LiveWaiters))
	}

	// Restarting the swapper should call handleInit again with the same args to
	// recreate the same coinwaiter.
	rig, stop = tNewTestRig(matchInfo, rig)
	defer stop()

	// Should still be MakerSwapCast since the contract has not been bcasted yet.
	tracker = rig.getTracker()
	if tracker.Status != order.MakerSwapCast {
		t.Fatalf("match not marked as MakerSwapCast: %v", tracker.Status)
	}

	// "broadcast" the contract and signal a new block.
	xyz.setContract(takerSwap.coin, true)
	takerSwap.coin.setConfs(int64(rig.xyz.SwapConf))
	sendBlock(xyz) // wait recheckInterval*3/2 for the coin waiter, plus trigger processBlock
	// processInit should have succeeded, requesting an ack from taker of the maker's contract.

	matchInfo.db.takerSwap = takerSwap // for maker's audit

	// The match status should now be TakerSwapCast, and there should be one ack (maker audit request)

	stop() // Swap state is now written into a file in rig.swapDataDir.

	if tracker.Status != order.TakerSwapCast {
		t.Fatalf("match not marked as TakerSwapCast: %v", tracker.Status)
	}

	state, err = loadLatestState()
	if err != nil {
		t.Fatal(err)
	}

	if len(state.LiveAckers) != 1 {
		t.Fatalf("expected 1 live ackers, got %d", len(state.LiveAckers))
	}
	if len(state.LiveWaiters) != 0 {
		t.Fatalf("expected 0 live coin waiter, got %d", len(state.LiveWaiters))
	}

	if state.MatchTrackers[matchInfo.matchID].Match.Status != order.TakerSwapCast {
		t.Fatalf("state's match tracker in status %v, expected %v",
			state.MatchTrackers[matchInfo.matchID].Match.Status, order.TakerSwapCast)
	}

	// Check that it's a maker audit request.
	for _, acker := range state.LiveAckers {
		if acker.Request.Route != msgjson.AuditRoute {
			t.Fatalf("acker for route %v, expected %v", acker.Request.Route, msgjson.AuditRoute)
		}
		// maker
		if acker.AckData[0].User != maker.acct {
			t.Fatalf("unexpected acker user %v, expected %v", acker.AckData[0].User, maker.acct)
		}
	}

	rig, stop = tNewTestRig(matchInfo, rig)
	defer stop()

	tracker = rig.getTracker()
	if tracker.Status != order.TakerSwapCast {
		t.Fatalf("match not marked as TakerSwapCast: %v", tracker.Status)
	}

	if err = rig.auditSwap_maker(); err != nil {
		t.Fatalf("maker failed to audit the taker's contract: %v", err)
	}
	if err = rig.ackAudit_maker(true); err != nil {
		t.Fatalf("maker failed to ack their audit of taker's contract: %v", err)
	}

	// handleRedeem for maker
	makerRedeem := tNewRedeem(matchInfo, matchInfo.makerOID, maker)
	// do not "broadcast" the redeem yet: xyz.setRedemption(makerRedeem.coin, true)
	// TAsset can't find it yet, TryAgain back to the coinwaiter
	rpcErr = rig.swapper.handleRedeem(maker.acct, makerRedeem.req)
	if rpcErr != nil {
		t.Fatalf("handleRedeem failed: %v", rpcErr)
	}

	// There is now a live coin waiter for the maker's redeem, no redeem ack
	// request yet since that is triggered after accounting for latency, calling
	// processRedeem>processAck.

	stop() // Swap state is now written into a file in rig.swapDataDir.

	state, err = loadLatestState()
	if err != nil {
		t.Fatal(err)
	}

	if len(state.LiveAckers) != 0 {
		t.Fatalf("expected 0 live ackers, got %d", len(state.LiveAckers))
	}
	if len(state.LiveWaiters) != 1 {
		t.Fatalf("expected 1 live coin waiter, got %d", len(state.LiveWaiters))
	}

	// Restarting the swapper should call handleRedeem again with the same args to
	// recreate the same coinwaiter.
	rig, stop = tNewTestRig(matchInfo, rig)
	defer stop()

	if len(rig.swapper.matches) != 1 {
		t.Errorf("expected 1 tracked match, got %d", len(rig.swapper.matches))
	}

	// Should still be TakerSwapCast since the maker's redeem has not been bcasted yet.
	tracker = rig.getTracker()
	if tracker.Status != order.TakerSwapCast {
		t.Fatalf("match not marked as TakerSwapCast: %v", tracker.Status)
	}

	// "broadcast" the redeem and signal a new block.
	xyz.setRedemption(makerRedeem.coin, true)
	makerRedeem.coin.setConfs(int64(rig.xyz.SwapConf))
	sendBlock(xyz) // wait recheckInterval*3/2 for the coin waiter, plus trigger processBlock
	// processRedeem should have succeeded, requesting an ack from taker of the maker's redeem.

	matchInfo.db.makerRedeem = makerRedeem // for taker's redeem ack

	// The match status should now be MakerRedeemed, and there should be one ack
	// (taker redemption ack request).

	stop() // Swap state is now written into a file in rig.swapDataDir.

	if tracker.Status != order.MakerRedeemed {
		t.Fatalf("match not marked as MakerRedeemed: %v", tracker.Status)
	}

	state, err = loadLatestState()
	if err != nil {
		t.Fatal(err)
	}

	if len(state.LiveAckers) != 1 {
		t.Fatalf("expected 1 live ackers, got %d", len(state.LiveAckers))
	}
	if len(state.LiveWaiters) != 0 {
		t.Fatalf("expected 0 live coin waiter, got %d", len(state.LiveWaiters))
	}

	if state.MatchTrackers[matchInfo.matchID].Match.Status != order.MakerRedeemed {
		t.Fatalf("state's match tracker in status %v, expected %v",
			state.MatchTrackers[matchInfo.matchID].Match.Status, order.MakerRedeemed)
	}

	// Check that it's a taker ack request.
	for _, acker := range state.LiveAckers {
		if acker.Request.Route != msgjson.RedemptionRoute {
			t.Fatalf("acker for route %v, expected %v", acker.Request.Route, msgjson.RedemptionRoute)
		}
		// taker
		if acker.AckData[0].User != taker.acct {
			t.Fatalf("unexpected acker user %v, expected %v", acker.AckData[0].User, taker.acct)
		}
	}

	rig, stop = tNewTestRig(matchInfo, rig)
	defer stop()

	tracker = rig.getTracker()
	if tracker.Status != order.MakerRedeemed {
		t.Fatalf("match not marked as MakerRedeemed: %v", tracker.Status)
	}

	if err = rig.ackRedemption_taker(true); err != nil {
		t.Fatalf("taker failed to ack the maker's redemption: %v", err)
	}

	// handleRedeem for taker
	takerRedeem := tNewRedeem(matchInfo, matchInfo.takerOID, taker)
	// do not "broadcast" the redeem yet: abc.setRedemption(takerRedeem.coin, true)
	// TAsset can't find it yet, TryAgain back to the coinwaiter
	rpcErr = rig.swapper.handleRedeem(taker.acct, takerRedeem.req)
	if rpcErr != nil {
		t.Fatalf("handleRedeem failed: %v", rpcErr)
	}

	// There is now a live coin waiter for the taker's redeem, no redeem ack
	// request yet since that is triggered after accounting for latency, calling
	// processRedeem>processAck.

	stop() // Swap state is now written into a file in rig.swapDataDir.

	state, err = loadLatestState()
	if err != nil {
		t.Fatal(err)
	}

	if len(state.LiveAckers) != 0 {
		t.Fatalf("expected 0 live ackers, got %d", len(state.LiveAckers))
	}
	if len(state.LiveWaiters) != 1 {
		t.Fatalf("expected 1 live coin waiter, got %d", len(state.LiveWaiters))
	}

	// Restarting the swapper should call handleRedeem again with the same args to
	// recreate the same coinwaiter.
	rig, stop = tNewTestRig(matchInfo, rig)
	defer stop()

	// Should still be MakerRedeemed since the taker's redeem has not been bcasted yet.
	tracker = rig.getTracker()
	if tracker.Status != order.MakerRedeemed {
		t.Fatalf("match not marked as MakerRedeemed: %v", tracker.Status)
	}

	// "broadcast" the redeem and signal a new block.
	abc.setRedemption(takerRedeem.coin, true)
	takerRedeem.coin.setConfs(int64(rig.abc.SwapConf))
	sendBlock(abc) // wait recheckInterval*3/2 for the coin waiter, plus trigger processBlock
	// processRedeem should have succeeded, requesting an ack from maker of the taker's redeem.

	matchInfo.db.takerRedeem = takerRedeem // for maker's redeem ack

	// The match status should now be MatchComplete, and there should be one ack
	// (maker redemption ack request).

	stop() // Swap state is now written into a file in rig.swapDataDir.

	if tracker.Status != order.MatchComplete {
		t.Fatalf("match not marked as MatchComplete: %v", tracker.Status)
	}

	state, err = loadLatestState()
	if err != nil {
		t.Fatal(err)
	}

	if len(state.LiveAckers) != 1 {
		t.Fatalf("expected 1 live ackers, got %d", len(state.LiveAckers))
	}
	if len(state.LiveWaiters) != 0 {
		t.Fatalf("expected 0 live coin waiter, got %d", len(state.LiveWaiters))
	}

	if state.MatchTrackers[matchInfo.matchID].Match.Status != order.MatchComplete {
		t.Fatalf("state's match tracker in status %v, expected %v",
			state.MatchTrackers[matchInfo.matchID].Match.Status, order.MatchComplete)
	}

	// Check that it's a maker ack request.
	for _, acker := range state.LiveAckers {
		if acker.Request.Route != msgjson.RedemptionRoute {
			t.Fatalf("acker for route %v, expected %v", acker.Request.Route, msgjson.RedemptionRoute)
		}
		// maker
		if acker.AckData[0].User != maker.acct {
			t.Fatalf("unexpected acker user %v, expected %v", acker.AckData[0].User, maker.acct)
		}
	}

	rig, stop = tNewTestRig(matchInfo, rig)
	defer stop()

	if len(rig.swapper.matches) != 1 {
		t.Errorf("expected 1 tracked match, got %d", len(rig.swapper.matches))
	}

	tracker = rig.getTracker()
	if tracker.Status != order.MatchComplete {
		t.Fatalf("match not marked as MatchComplete: %v", tracker.Status)
	}

	if err = rig.ackRedemption_maker(true); err != nil {
		t.Fatalf("maker failed to ack the taker's redemption: %v", err)
	}

	sendBlock(abc)

	// match should be gone now
	if rig.getTracker() != nil {
		t.Fatalf("expected matchTracker to be removed")
	}
}
