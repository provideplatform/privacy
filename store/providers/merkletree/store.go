package merkletree

import (
	"errors"
	"fmt"
	"hash"
	"strings"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	mimc "github.com/consensys/gnark-crypto/hash"
	"github.com/jinzhu/gorm"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/privacy/common"
	provide "github.com/provideplatform/provide-go/api"
)

// DurableMerkleTree is a full MerkleTree impl backed by a postgres persistence provider
type DurableMerkleTree struct {
	provide.Model
	FullMerkleTree

	db    *gorm.DB
	id    uuid.UUID
	mutex sync.Mutex
}

func hashFactory(hash *string) hash.Hash {
	switch strings.ToLower(*hash) {
	case ecc.BLS12_377.String():
		return mimc.MIMC_BLS12_377.New("seed")
	case ecc.BLS12_381.String():
		return mimc.MIMC_BLS12_381.New("seed")
	case ecc.BN254.String():
		return mimc.MIMC_BN254.New("seed")
	case ecc.BW6_761.String():
		return mimc.MIMC_BW6_761.New("seed")
	case ecc.BLS24_315.String():
		return mimc.MIMC_BLS24_315.New("seed")
	default:
		common.Log.Warningf("failed to resolve hash type string; unknown or unsupported hash: %s", *hash)
	}

	return nil
}

// LoadMerkleTree loads a MerkleTree by id and enables persistence using the given db connection
func LoadMerkleTree(db *gorm.DB, id uuid.UUID, hash *string) (*DurableMerkleTree, error) {
	h := hashFactory(hash)
	tree := NewMerkleTree(h)
	err := getAndInsertStoredHashes(db, id, tree)
	if err != nil {
		common.Log.Warningf("failed to load merkle tree store %s; %s", id, err.Error())
		return nil, err
	}

	return &DurableMerkleTree{
		db:             db,
		FullMerkleTree: tree,
		id:             id,
	}, nil
}

// Add hashes the given data, adds it to the tree and triggers recalculation
func (tree *DurableMerkleTree) Add(data []byte) (index int, hash string) {
	tree.mutex.Lock()
	defer tree.mutex.Unlock()
	index, hash = tree.FullMerkleTree.Add(data)
	tree.addHashToDB(hash)
	return index, hash
}

// Contains returns true if the given hash exists in the store
func (tree *DurableMerkleTree) Contains(val string) bool {
	hash := tree.FullMerkleTree.(*MemoryMerkleTree).HashFunc([]byte(val))
	rows, err := tree.db.Raw("SELECT hash from hashes WHERE store_id = ? AND hash = ?", tree.id, hash).Rows()
	if err != nil {
		common.Log.Warningf("failed to query merkle tree store for inclusion of hash: %s: store id: %s; %s", string(hash), tree.id, err.Error())
		return false
	}

	for rows.Next() {
		var _hash string
		err = rows.Scan(&_hash)
		if err != nil {
			common.Log.Warningf("failed to scan the store for merkle tree hash; %s", err.Error())
			return false
		}
		return string(hash) == _hash
	}
	return false
}

func (tree *DurableMerkleTree) Get(key []byte) (val []byte, err error) {
	return nil, errors.New("not implemented")
}

func (tree *DurableMerkleTree) Height() int {
	return tree.Height()
}

// Length returns the count of hashes in the store
func (tree *DurableMerkleTree) Length() int {
	rows, err := tree.db.Raw("SELECT count(hash) FROM hashes WHERE store_id = ?", tree.id).Rows()
	if err != nil {
		common.Log.Warningf("failed to resolve merkle tree from store: %s; %s", tree.id, err.Error())
		return 0
	}

	var len int
	for rows.Next() {
		err = rows.Scan(&len)
		if err != nil {
			common.Log.Warningf("failed to scan the store for merkle tree hashes; %s", err.Error())
			return 0
		}
		break
	}

	return len
}

// RawAdd hashes the given data and adds it to the tree but does not trigger recalculation
func (tree *DurableMerkleTree) RawAdd(val []byte) (index int, hash string) {
	tree.mutex.Lock()
	defer tree.mutex.Unlock()
	index, hash = tree.FullMerkleTree.RawAdd(val)
	tree.addHashToDB(hash)
	return index, hash
}

func (tree *DurableMerkleTree) addHashToDB(hash string) error {
	db := tree.db.Exec("INSERT INTO hashes (store_id, hash) VALUES (?, ?)", tree.id, hash)
	if db.RowsAffected == 0 {
		return fmt.Errorf("failed to persist hash within merkle tree: %s", hash)
	}

	return nil
}

func getAndInsertStoredHashes(db *gorm.DB, id uuid.UUID, tree InternalMerkleTree) error {
	rows, err := db.Raw("SELECT hash from hashes WHERE store_id = ? ORDER BY id", id).Rows()
	if err != nil {
		return fmt.Errorf("failed to resolve merkle tree from store: %s; %s", id, err.Error())
	}

	for rows.Next() {
		var hash string
		err = rows.Scan(&hash)
		if err != nil {
			return fmt.Errorf("failed to scan the store for merkle tree hashes; %s", err.Error())
		}
		tree.RawInsert(hash)
	}

	tree.Recalculate()
	return nil
}
