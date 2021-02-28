// This code is available on the terms of the project LICENSE.md file,
// also available online at https://blueoakcouncil.org/license/1.0.0.

package bolt

import (
	"fmt"
	"path/filepath"

	dexdb "decred.org/dcrdex/client/db"
	"decred.org/dcrdex/dex/encode"
	"decred.org/dcrdex/dex/order"
	"go.etcd.io/bbolt"
)

type upgradefunc func(tx *bbolt.Tx) error

// Each database upgrade function should be keyed by the database
// version it upgrades.
var upgrades = [...]upgradefunc{
	// v0 => v1 adds a version key. Upgrades the MatchProof struct to
	// differentiate between server revokes and self revokes.
	v1Upgrade,
	// v1 => v2 adds a MaxFeeRate field to the OrderMetaData, used for match
	// validation.
	v2Upgrade,
	// v2 => v3 adds a Retired field to the MatchMetaData, to provide a more
	// straightforward way of determining completed matches without performing
	// extensive checks on a match.
	v3Upgrade,
}

// DBVersion is the latest version of the database that is understood. Databases
// with recorded versions higher than this will fail to open (meaning any
// upgrades prevent reverting to older software).
const DBVersion = uint32(len(upgrades))

func fetchDBVersion(tx *bbolt.Tx) (uint32, error) {
	bucket := tx.Bucket(appBucket)
	if bucket == nil {
		return 0, fmt.Errorf("app bucket not found")
	}

	versionB := bucket.Get(versionKey)
	if versionB == nil {
		return 0, fmt.Errorf("database version not found")
	}

	return intCoder.Uint32(versionB), nil
}

func setDBVersion(tx *bbolt.Tx, newVersion uint32) error {
	bucket := tx.Bucket(appBucket)
	if bucket == nil {
		return fmt.Errorf("app bucket not found")
	}

	return bucket.Put(versionKey, encode.Uint32Bytes(newVersion))
}

// upgradeDB checks whether any upgrades are necessary before the database is
// ready for application usage.  If any are, they are performed.
func (db *BoltDB) upgradeDB() error {
	var version uint32
	version, err := db.getVersion()
	if err != nil {
		return err
	}

	if version > DBVersion {
		return fmt.Errorf("unknown database version %d, "+
			"client recognizes up to %d", version, DBVersion)
	}

	if version == DBVersion {
		// No upgrades necessary.
		return nil
	}

	db.log.Infof("Upgrading database from version %d to %d", version, DBVersion)

	// Backup the current version's DB file before processing the upgrades to
	// DBVersion. Note that any intermediate versions are not stored.
	currentFile := filepath.Base(db.Path())
	backupPath := fmt.Sprintf("%s.v%d.bak", currentFile, version) // e.g. dexc.db.v1.bak
	if err = db.backup(backupPath); err != nil {
		return fmt.Errorf("failed to backup DB prior to upgrade: %w", err)
	}

	return db.Update(func(tx *bbolt.Tx) error {
		// Execute all necessary upgrades in order.
		for i, upgrade := range upgrades[version:] {
			err := doUpgrade(tx, upgrade, version+uint32(i)+1)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// Get the currently stored DB version.
func (db *BoltDB) getVersion() (version uint32, err error) {
	return version, db.View(func(tx *bbolt.Tx) error {
		version, err = getVersionTx(tx)
		return err
	})
}

// Get the uint32 stored in the appBucket's versionKey entry.
func getVersionTx(tx *bbolt.Tx) (uint32, error) {
	bucket := tx.Bucket(appBucket)
	if bucket == nil {
		return 0, fmt.Errorf("appBucket not found")
	}
	versionB := bucket.Get(versionKey)
	if versionB == nil {
		// A nil version indicates a version 0 database.
		return 0, nil
	}
	return intCoder.Uint32(versionB), nil
}

func v1Upgrade(dbtx *bbolt.Tx) error {
	const oldVersion = 0

	dbVersion, err := fetchDBVersion(dbtx)
	if err != nil {
		return fmt.Errorf("error fetching database version: %w", err)
	}

	if dbVersion != oldVersion {
		return fmt.Errorf("v1Upgrade inappropriately called")
	}

	bkt := dbtx.Bucket(appBucket)
	if bkt == nil {
		return fmt.Errorf("appBucket not found")
	}

	// Upgrade the match proof. We just have to retrieve and re-store the
	// buckets. The decoder will recognize the the old version and add the new
	// field.
	matches := dbtx.Bucket(matchesBucket)
	return matches.ForEach(func(k, _ []byte) error {
		mBkt := matches.Bucket(k)
		if mBkt == nil {
			return fmt.Errorf("match %x bucket is not a bucket", k)
		}
		proofB := getCopy(mBkt, proofKey)
		if len(proofB) == 0 {
			return fmt.Errorf("empty match proof")
		}
		proof, err := dexdb.DecodeMatchProof(proofB)
		if err != nil {
			return fmt.Errorf("error decoding proof: %w", err)
		}
		err = mBkt.Put(proofKey, proof.Encode())
		if err != nil {
			return fmt.Errorf("error re-storing match proof: %w", err)
		}
		return nil
	})
}

// v2Upgrade adds a MaxFeeRate field to the OrderMetaData. The upgrade sets the
// MaxFeeRate field for all historical orders to the max uint64. This avoids any
// chance of rejecting a pre-existing active match.
func v2Upgrade(dbtx *bbolt.Tx) error {
	const oldVersion = 1

	dbVersion, err := fetchDBVersion(dbtx)
	if err != nil {
		return fmt.Errorf("error fetching database version: %w", err)
	}

	if dbVersion != oldVersion {
		return fmt.Errorf("v2Upgrade inappropriately called")
	}

	// For each order, set a maxfeerate of max uint64.
	maxFeeB := uint64Bytes(^uint64(0))

	master := dbtx.Bucket(ordersBucket)
	if master == nil {
		return fmt.Errorf("failed to open orders bucket")
	}

	return master.ForEach(func(oid, _ []byte) error {
		oBkt := master.Bucket(oid)
		if oBkt == nil {
			return fmt.Errorf("order %x bucket is not a bucket", oid)
		}
		return oBkt.Put(maxFeeRateKey, maxFeeB)
	})
}

// v3Upgrade adds a Retired field to the MatchMetaData. The upgrade sets the
// Retired field appropriately for all historical matches, providing a more
// straightforward way of determining completed matches without performing
// extensive checks on a match.
func v3Upgrade(dbtx *bbolt.Tx) error {
	const oldVersion = 2

	dbVersion, err := fetchDBVersion(dbtx)
	if err != nil {
		return fmt.Errorf("error fetching database version: %w", err)
	}

	if dbVersion != oldVersion {
		return fmt.Errorf("v3Upgrade inappropriately called on db version %d", dbVersion)
	}

	// Upgrade the match metadata. Set Retired to true if (1) status is
	// MatchComplete and Proof.RedeemSig is set, (2) match is refunded,
	// or (3) match is revoked and this side of the match requires no
	// further action like refund or auto-redeem.
	matches := dbtx.Bucket(matchesBucket)
	return matches.ForEach(func(k, _ []byte) error {
		mBkt := matches.Bucket(k)
		if mBkt == nil {
			return fmt.Errorf("match %x bucket is not a bucket", k)
		}
		// We need the proof to confirm if this match is completed.
		proofB := getCopy(mBkt, proofKey)
		if len(proofB) == 0 {
			return fmt.Errorf("empty match proof")
		}
		proof, err := dexdb.DecodeMatchProof(proofB)
		if err != nil {
			return fmt.Errorf("error decoding proof: %w", err)
		}
		// Retire if refunded.
		if len(proof.RefundCoin) > 0 {
			return mBkt.Put(retiredKey, byteTrue)
		}
		// Retire if status=MatchComplete and Proof.RedeemSig is set.
		statusB := mBkt.Get(statusKey)
		if len(statusB) != 1 {
			return fmt.Errorf("match %x has no status set", k)
		}
		status := order.MatchStatus(statusB[0])
		if status == order.MatchComplete && len(proof.Auth.RedeemSig) != 0 {
			return mBkt.Put(retiredKey, byteTrue)
		}
		// Retire if revoked without requiring further action.
		// TakerSwapCast match status requires action on both sides.
		if proof.IsRevoked() && status != order.TakerSwapCast {
			// NewlyMatched requires no further action from either side.
			if status == order.NewlyMatched {
				return mBkt.Put(retiredKey, byteTrue)
			}
			// Load the UserMatch to check the match Side.
			matchB := mBkt.Get(matchKey) // no copy, just need Side
			if matchB == nil {
				return fmt.Errorf("nil match bytes for %x", k)
			}
			match, err := order.DecodeMatch(matchB)
			if err != nil {
				return fmt.Errorf("error decoding match %x: %v", k, err)
			}
			side := match.Side // done with match and matchB

			// MakerSwapCast requires no further action from the taker.
			// MakerRedeemed requires no further action from the maker.
			if (status == order.MakerSwapCast && side == order.Taker) ||
				(status == order.MakerRedeemed && side == order.Maker) {
				return mBkt.Put(retiredKey, byteTrue)
			}
		}
		return mBkt.Put(retiredKey, byteFalse) // still active
	})
}

func doUpgrade(tx *bbolt.Tx, upgrade upgradefunc, newVersion uint32) error {
	err := upgrade(tx)
	if err != nil {
		return fmt.Errorf("error upgrading DB: %v", err)
	}
	// Persist the database version.
	err = setDBVersion(tx, newVersion)
	if err != nil {
		return fmt.Errorf("error setting DB version: %v", err)
	}
	return nil
}
