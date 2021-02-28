// This code is available on the terms of the project LICENSE.md file,
// also available online at https://blueoakcouncil.org/license/1.0.0.

// This file should compiled from the commit the file was introduced, otherwise
// it may not compile due to API changes, or may not create the database with
// the correct old version.  This file should not be updated for API changes.

package main

import (
	"compress/gzip"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"os"

	"decred.org/dcrdex/client/db"
	"decred.org/dcrdex/client/db/bolt"
	"decred.org/dcrdex/dex"
	"decred.org/dcrdex/dex/order"
	"decred.org/dcrdex/dex/order/test"
)

const dbname = "v2.db"

func main() {
	err := setup()
	if err != nil {
		fmt.Fprintf(os.Stderr, "setup: %v\n", err)
		os.Exit(1)
	}
	err = compress()
	if err != nil {
		fmt.Fprintf(os.Stderr, "compress: %v\n", err)
		os.Exit(1)
	}
}

func setup() error {
	db, err := bolt.NewDB(dbname, dex.StdOutLogger("db_TEST", dex.LevelOff))
	if err != nil {
		return err
	}
	bdb, ok := db.(*bolt.BoltDB)
	if !ok {
		return fmt.Errorf("database is not a BoltDB")
	}
	defer bdb.DB.Close()
	return mockData(db)
}

func mockData(tdb db.DB) error {
	// Create matches and log IDs.
	saveMatchAndLogID := func(desc string, modifyMatch func(*db.MetaMatch) bool) error {
		match := &db.MetaMatch{
			Match: &order.UserMatch{
				MatchID: test.RandomMatchID(),
			},
			MetaData: &db.MatchMetaData{
				DEX:   "somedex.ltd",
				Base:  42,
				Quote: 0,
			},
		}
		retired := modifyMatch(match)
		if err := tdb.UpdateMatch(match); err != nil {
			return err
		}
		// "matchID-String": retired-Bool, // desc-String
		fmt.Printf("\t%q: %t, // %s\n", hex.EncodeToString(match.ID()), retired, desc)
		return nil
	}

	// Active match, status < MatchComplete, not revoked, not refunded.
	err := saveMatchAndLogID("status < MatchComplete, not revoked, not refunded", func(match *db.MetaMatch) bool {
		match.SetStatus(order.MatchStatus(rand.Intn(4)))
		return false // active
	})
	if err != nil {
		return err
	}

	// Inactive match, status < MatchComplete, revoked but requires no further action.
	err = saveMatchAndLogID("status < MatchComplete, revoked at NewlyMatched", func(match *db.MetaMatch) bool {
		match.SetStatus(order.MatchStatus(rand.Intn(4)))
		match.MetaData.Proof.SelfRevoked = true
		return true // retired
	})
	if err != nil {
		return err
	}

	// Active match, status == MakerSwapCast, revoked but requires maker auto-refund.
	err = saveMatchAndLogID("status == MakerSwapCast, side Maker, revoked, requires refund", func(match *db.MetaMatch) bool {
		match.SetStatus(order.MakerSwapCast)
		match.Match.Side = order.Maker
		match.MetaData.Proof.ServerRevoked = true
		// match.MetaData.Proof.RefundCoin = []byte{0}
		return false // active
	})
	if err != nil {
		return err
	}

	// Inactive match, status == TakerSwapCast, revoked and refunded (requires no further action).
	err = saveMatchAndLogID("status == TakerSwapCast, side Maker, revoked, refunded", func(match *db.MetaMatch) bool {
		match.SetStatus(order.TakerSwapCast)
		match.Match.Side = order.Maker
		match.MetaData.Proof.SelfRevoked = true
		match.MetaData.Proof.RefundCoin = []byte{0}
		return true // retired
	})
	if err != nil {
		return err
	}

	// Active match, status == MatchComplete, no RedeemSig.
	err = saveMatchAndLogID("status == MatchComplete, no RedeemSig", func(match *db.MetaMatch) bool {
		match.SetStatus(order.MatchComplete)
		return false // active
	})
	if err != nil {
		return err
	}

	// Inactive match, status == MatchComplete, RedeemSig set.
	err = saveMatchAndLogID("status == MatchComplete, RedeemSig set", func(match *db.MetaMatch) bool {
		match.SetStatus(order.MatchComplete)
		match.MetaData.Proof.Auth.RedeemSig = []byte{1}
		return true // retired
	})
	if err != nil {
		return err
	}

	return nil
}

func compress() error {
	db, err := os.Open(dbname)
	if err != nil {
		return err
	}
	defer os.Remove(dbname)
	defer db.Close()
	dbgz, err := os.Create(dbname + ".gz")
	if err != nil {
		return err
	}
	defer dbgz.Close()
	gz := gzip.NewWriter(dbgz)
	_, err = io.Copy(gz, db)
	if err != nil {
		return err
	}
	return gz.Close()
}
