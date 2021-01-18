package merkletree

import (
	"fmt"
	"sync"

	"github.com/jinzhu/gorm"
	uuid "github.com/kthomas/go.uuid"
	provide "github.com/provideservices/provide-go/api"
)

const (
	insertQuery = "INSERT INTO hashes (hash) VALUES ($1)"
	selectQuery = "SELECT hash FROM hashes ORDER BY id"
	// CreateQuery       = "CREATE TABLE hashes(id SERIAL PRIMARY KEY,hash VARCHAR(66) NOT NULL);"
	// CreateIfNotExists = "CREATE TABLE IF NOT EXISTS hashes(id SERIAL PRIMARY KEY,hash VARCHAR(66) NOT NULL);"
)

// DurableMerkleTree is a full MerkleTree impl backed by a postgres persistence provider
type DurableMerkleTree struct {
	provide.Model

	FullMerkleTree
	db    *gorm.DB
	mutex sync.Mutex
}

// LoadMerkleTree loads a MerkleTree by id and enables persistence using the given db connection
func LoadMerkleTree(db *gorm.DB, id uuid.UUID) (*DurableMerkleTree, error) {
	tree := NewMerkleTree()
	err := getAndInsertStoredHashes(db, id, tree)
	if err != nil {
		return nil, err
	}

	return &DurableMerkleTree{
		db:             db,
		FullMerkleTree: tree,
	}, nil
}

// Add hashes the given datam, adds it to the tree and triggers recalculation
func (tree *DurableMerkleTree) Add(data []byte) (index int, hash string) {
	tree.mutex.Lock()
	index, hash = tree.FullMerkleTree.Add(data)
	tree.addHashToDB(hash)
	tree.mutex.Unlock()
	return index, hash
}

// RawAdd hashes the given data and adds it to the tree but does not trigger recalculation
func (tree *DurableMerkleTree) RawAdd(data []byte) (index int, hash string) {
	tree.mutex.Lock()
	index, hash = tree.FullMerkleTree.RawAdd(data)
	tree.addHashToDB(hash)
	tree.mutex.Unlock()
	return index, hash
}

func (tree *DurableMerkleTree) addHashToDB(hash string) error {
	db := tree.db.Exec(insertQuery, hash)
	if db.RowsAffected == 0 {
		return fmt.Errorf("failed to persist hash within merkle tree: %s", hash)
	}

	return nil
}

func getAndInsertStoredHashes(db *gorm.DB, id uuid.UUID, tree InternalMerkleTree) error {
	rows, err := db.Select(selectQuery).Rows()
	if err != nil {
		return fmt.Errorf("failed to resolve merkle tree from persistence: %s; %s", id, err.Error())
	}

	for rows.Next() {
		var hash string
		err = rows.Scan(&hash)
		if err != nil {
			return fmt.Errorf("failed to scan the persistence for merkle tree hashes; %s", err.Error())
		}
		tree.RawInsert(hash)
	}

	tree.Recalculate()
	return nil
}
