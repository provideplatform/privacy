package merkletree

import (
	"fmt"
	"sync"

	"github.com/jinzhu/gorm"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/privacy/common"
	provide "github.com/provideservices/provide-go/api"
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
func LoadMerkleTree(db *gorm.DB, id uuid.UUID) (*DurableMerkleTree, error) {
	tree := NewMerkleTree(nil)
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

// Add proofes the given data, adds it to the tree and triggers recalculation
func (tree *DurableMerkleTree) Add(data []byte) (index int, proof string) {
	tree.mutex.Lock()
	index, proof = tree.FullMerkleTree.Add(data)
	tree.addHashToDB(proof)
	tree.mutex.Unlock()
	return index, proof
}

// Contains returns true if the given proof exists in the store
func (tree *DurableMerkleTree) Contains(proof string) bool {
	proofs, err := tree.IntermediaryHashesByIndex(tree.Length())
	if err != nil {
		common.Log.Warningf("failed to scan store for merkle tree proofs; %s", err.Error())
		return false
	}

	common.Log.Debugf("proofs: %s", proofs)
	return false

	// rows, err := tree.db.Raw("SELECT proof from proofs WHERE store_id = ? ORDER BY id", tree.id).Rows()
	// if err != nil {
	// 	common.Log.Warningf("failed to resolve merkle tree from store: %s; %s", tree.id, err.Error())
	// 	return false
	// }

	// for rows.Next() {
	// 	var _proof string
	// 	err = rows.Scan(&_proof)
	// 	if err != nil {
	// 		common.Log.Warningf("failed to scan store for merkle tree proofs; %s", err.Error())
	// 		return false
	// 	}
	// 	return err == nil
	// }

	// return false
}

// RawAdd proofes the given data and adds it to the tree but does not trigger recalculation
func (tree *DurableMerkleTree) RawAdd(data []byte) (index int, proof string) {
	tree.mutex.Lock()
	index, proof = tree.FullMerkleTree.RawAdd(data)
	tree.addHashToDB(proof)
	tree.mutex.Unlock()
	return index, proof
}

func (tree *DurableMerkleTree) addHashToDB(proof string) error {
	db := tree.db.Raw("INSERT INTO proofs (store_id, proof) VALUES (?, ?)", tree.id, proof)
	if db.RowsAffected == 0 {
		return fmt.Errorf("failed to persist proof within merkle tree: %s", proof)
	}

	return nil
}

func getAndInsertStoredHashes(db *gorm.DB, id uuid.UUID, tree InternalMerkleTree) error {
	rows, err := db.Raw("SELECT proof from proofs WHERE store_id = ? ORDER BY id", id).Rows()
	if err != nil {
		return fmt.Errorf("failed to resolve merkle tree from store: %s; %s", id, err.Error())
	}

	for rows.Next() {
		var proof string
		err = rows.Scan(&proof)
		if err != nil {
			return fmt.Errorf("failed to scan the store for merkle tree proofs; %s", err.Error())
		}
		tree.RawInsert(proof)
	}

	tree.Recalculate()
	return nil
}
