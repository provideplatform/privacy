package merkletree

import (
	"encoding/hex"
	"fmt"
	"hash"
	"math/big"
	"sync"

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

// LoadMerkleTree loads a MerkleTree by id and enables persistence using the given db connection
func LoadMerkleTree(db *gorm.DB, id uuid.UUID, hash hash.Hash) (*DurableMerkleTree, error) {
	tree := NewMerkleTree(hash)
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

// Insert the given value to the tree and trigger recalculation
func (tree *DurableMerkleTree) Insert(val string) ([]byte, error) {
	tree.Add([]byte(val))
	tree.Recalculate()
	root, err := tree.Root()
	if err != nil {
		return nil, err
	}
	return []byte(*root), nil
}

// Add the given value to the tree and trigger recalculation
func (tree *DurableMerkleTree) Add(val []byte) (index int, hash string) {
	tree.mutex.Lock()
	defer tree.mutex.Unlock()
	index, hash = tree.FullMerkleTree.Add(val)
	tree.addHashToDB(hash, val)
	return index, hash
}

// Contains returns true if the given hash exists in the store
func (tree *DurableMerkleTree) Contains(val string) bool {
	hash := tree.FullMerkleTree.(*MemoryMerkleTree).HashFunc([]byte(val))
	rows, err := tree.db.Raw("SELECT hash from hashes WHERE store_id = ? AND hash = ?", tree.id, hex.EncodeToString(hash)).Rows()
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
	rows, err := tree.db.Raw("SELECT value from hashes WHERE store_id = ? ORDER by id", tree.id).Rows()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve merkle tree hash from store: %s; %s", tree.id, err.Error())
	}

	results := make([]string, 0)

	for rows.Next() {
		var value []byte
		err = rows.Scan(&value)
		if err != nil {
			return nil, fmt.Errorf("failed to scan the store for merkle tree hashes; %s", err.Error())
		}
		results = append(results, string(value))
	}

	index := new(big.Int).SetBytes(key).Uint64()
	if index >= uint64(len(results)) {
		return nil, fmt.Errorf("failed to resolve merkle tree hash for store; %s; index %d out of bounds", tree.id, index)
	}

	return []byte(results[index]), nil
}

func (tree *DurableMerkleTree) Height() int {
	return tree.Length()
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
	tree.addHashToDB(hash, val)
	return index, hash
}

func (tree *DurableMerkleTree) addHashToDB(hash string, value []byte) error {
	db := tree.db.Exec("INSERT INTO hashes (store_id, hash, value) VALUES (?, ?, ?)", tree.id, hash, value)
	if db.RowsAffected == 0 {
		return fmt.Errorf("failed to persist hash within merkle tree: %s", hash)
	}

	return nil
}

func getAndInsertStoredHashes(db *gorm.DB, id uuid.UUID, tree InternalMerkleTree) error {
	rows, err := db.Raw("SELECT value from hashes WHERE store_id = ? ORDER BY id", id).Rows()
	if err != nil {
		return fmt.Errorf("failed to resolve merkle tree from store: %s; %s", id, err.Error())
	}

	for rows.Next() {
		var val []byte
		err = rows.Scan(&val)
		if err != nil {
			return fmt.Errorf("failed to scan the store for merkle tree values; %s", err.Error())
		}
		tree.RawAdd(val)
	}

	tree.Recalculate()
	return nil
}
