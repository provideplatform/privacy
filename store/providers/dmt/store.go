package dmt

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"sync"

	"github.com/cbergoon/merkletree"
	"github.com/jinzhu/gorm"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/privacy/common"
	"github.com/provideplatform/privacy/state"
)

// DMT dense merkle tree
type DMT struct {
	db     *gorm.DB
	hash   hash.Hash
	id     *uuid.UUID
	mutex  *sync.Mutex
	tree   *merkletree.MerkleTree
	values []merkletree.Content
}

func InitDMT(db *gorm.DB, id uuid.UUID, h hash.Hash) *DMT {
	tree, err := loadTree(db, id, h)
	if err != nil {
		return nil
	}

	if tree == nil {
		tree, err = merkletree.NewTreeWithHashStrategy(
			make([]merkletree.Content, 0),
			func() hash.Hash {
				return h
			},
		)
	}

	instance := &DMT{
		db:    db,
		hash:  h,
		id:    &id,
		mutex: &sync.Mutex{},
		tree:  tree,
	}

	return instance
}

func loadTree(db *gorm.DB, id uuid.UUID, h hash.Hash) (*merkletree.MerkleTree, error) {
	var tree *merkletree.MerkleTree

	rows, err := db.Raw("SELECT value from hashes WHERE store_id = ? ORDER BY id", id).Rows()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve merkle tree from store: %s; %s", id, err.Error())
	}

	var values []merkletree.Content

	for rows.Next() {
		var nodesRaw json.RawMessage
		var valuesRaw json.RawMessage
		var root string

		err = rows.Scan(&nodesRaw, &valuesRaw, &root)
		if err != nil {
			return nil, fmt.Errorf("failed to scan the store for dense merkle tree; %s", err.Error())
		}

		// var nodes *smt.SimpleMap
		// var values *smt.SimpleMap

		// json.Unmarshal(nodesRaw, &nodes)
		// json.Unmarshal(valuesRaw, &values)
		// rootBytes, _ := hex.DecodeString(root)

		// tree = smt.ImportSparseMerkleTree(
		// 	nodes,
		// 	values,
		// 	hash,
		// 	rootBytes,
		// )
	}

	tree, err = merkletree.NewTreeWithHashStrategy(
		values,
		func() hash.Hash {
			return h
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to scan the store for dense merkle tree; %s", err.Error())
	}

	valid, err := tree.VerifyTree()
	if err != nil {
		return nil, fmt.Errorf("failed to verify dense merkle tree; %s", err.Error())
	}

	if !valid {
		return nil, fmt.Errorf("failed to verify dense merkle tree for store %s", id)
	}

	common.Log.Debugf("imported dense merkle tree for store %s; root: %s", id, tree.MerkleRoot())

	if tree != nil {
		return tree, nil
	}

	return nil, nil
}

// commit the current state of the dense merkle tree to the database
// TODO-- audit this approach; as the trees grow in size, we will want something else...
func (s *DMT) commit() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	values, _ := json.Marshal(s.values)
	root := s.tree.MerkleRoot()

	common.Log.Debugf("ROOT: %v", hex.EncodeToString(root))
	common.Log.Debugf("VALUES: %v", values)

	db := s.db.Exec("INSERT INTO trees (store_id, values, root) VALUES (?, ?, ?)", s.id, values, hex.EncodeToString(root))
	if db.RowsAffected == 0 {
		return fmt.Errorf("failed to persist hash within merkle tree: %s", s.id)
	}

	return nil
}

func (s *DMT) Contains(val string) bool {
	var v merkletree.Content
	incl, err := s.tree.VerifyContent(v)
	if err != nil {
		return false
	}
	return incl
}

func (s *DMT) Get(key []byte) (val []byte, err error) {
	return nil, errors.New("dense merkle tree Get() not implemented... yet")
}

func (s *DMT) Height() int {
	return len(s.tree.Leafs) * 2
}

func (s *DMT) Insert(val string) (root []byte, err error) {
	var v merkletree.Content
	s.values = append(s.values, v)
	err = s.tree.RebuildTreeWith(s.values)
	if err != nil {
		return nil, err
	}
	s.commit()
	return s.tree.MerkleRoot(), nil
}

func (s *DMT) Root() (root *string, err error) {
	if s.tree.MerkleRoot() == nil || len(s.tree.MerkleRoot()) == 0 {
		return nil, errors.New("tree does not contain a valid root")
	}
	return common.StringOrNil(string(s.tree.MerkleRoot())), nil
}

// StateAt returns the state at the given epoch
func (s *DMT) StateAt(epoch uint64) (*state.State, error) {
	claims := make([]*state.StateClaim, 0)

	root, err := s.Root() // impl RootAt()
	if err != nil {
		return nil, err
	}

	claims = append(claims, &state.StateClaim{
		Cardinality: uint64(1),
		Path:        []string{},
		Root:        root,
		Values:      []string{},
	})

	// FIXME!!!
	state := &state.State{
		// ID        uuid.UUID  `json:"id"`
		// AccountID *uuid.UUID `json:"account_id"`
		// Address   *string    `json:"address"` // FIXME... int type this address
		CircuitID:   s.id,
		Epoch:       epoch,
		StateClaims: claims,
	}

	return state, nil
}
