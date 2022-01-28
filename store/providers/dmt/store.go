package dmt

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"sync"

	"github.com/jinzhu/gorm"
	uuid "github.com/kthomas/go.uuid"
	"github.com/providenetwork/merkletree"
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

func InitDMT(db *gorm.DB, id uuid.UUID, h hash.Hash) (*DMT, error) {
	tree, values, err := loadTree(db, id, h)
	if err != nil {
		return nil, fmt.Errorf("error loading tree: %v", err)
	}

	if tree == nil {
		values = make([]merkletree.Content, 0)
		tree, err = merkletree.NewTreeWithHashStrategy(
			values,
			func() hash.Hash {
				h.Reset()
				return h
			},
		)
		if err != nil {
			return nil, fmt.Errorf("error creating tree: %v", err)
		}
	}

	instance := &DMT{
		db:     db,
		hash:   h,
		id:     &id,
		mutex:  &sync.Mutex{},
		tree:   tree,
		values: values,
	}

	return instance, nil
}

func loadTree(db *gorm.DB, id uuid.UUID, h hash.Hash) (*merkletree.MerkleTree, []merkletree.Content, error) {
	values, err := loadValues(db, id, h)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to scan the store for dense merkle tree; %s", err.Error())
	}
	if len(values) == 0 {
		return nil, values, nil
	}

	tree, err := merkletree.NewTreeWithHashStrategy(
		values,
		func() hash.Hash {
			h.Reset()
			return h
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to scan the store for dense merkle tree; %s", err.Error())
	}

	valid, err := tree.VerifyTree()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to verify dense merkle tree; %s", err.Error())
	}

	if !valid {
		return nil, nil, fmt.Errorf("failed to verify dense merkle tree for store %s", id)
	}

	common.Log.Debugf("imported dense merkle tree for store %s; root: %s", id, hex.EncodeToString(tree.MerkleRoot()))
	return tree, values, nil
}

func loadValues(db *gorm.DB, id uuid.UUID, h hash.Hash) ([]merkletree.Content, error) {
	values := make([]merkletree.Content, 0)

	rows, err := db.Raw("SELECT values from trees WHERE store_id = ? ORDER BY id DESC LIMIT 1", id).Rows()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve dense merkle tree from store: %s; %s", id, err.Error())
	}

	for rows.Next() {
		var valuesRaw json.RawMessage
		err = rows.Scan(&valuesRaw)
		if err != nil {
			return nil, fmt.Errorf("failed to scan the store for dense merkle tree; %s", err.Error())
		}

		var vals []*treeContent
		err = json.Unmarshal(valuesRaw, &vals)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal dense merkle tree for store %s; %s", id, err.Error())
		}

		for _, v := range vals {
			values = append(values, &treeContent{
				hash:  h,
				value: v.value,
			})
		}
	}

	return values, nil
}

func (s *DMT) contentFactory(val []byte) *treeContent {
	return &treeContent{
		hash:  s.hash,
		value: val,
	}
}

// commit the current state of the dense merkle tree to the database
// TODO-- audit this approach; as the trees grow in size, we will want something else...
func (s *DMT) commit() error {
	values, _ := json.Marshal(s.values)
	root := s.tree.MerkleRoot()

	db := s.db.Exec("INSERT INTO trees (store_id, nodes, values, root) VALUES (?, ?, ?, ?)", s.id, []byte("{}"), values, hex.EncodeToString(root))
	if db.RowsAffected == 0 {
		return fmt.Errorf("failed to persist value within dense merkle tree: %s", s.id)
	}

	common.Log.Debugf("committed state (%d values) within dense merkle tree %s; root: %s", len(s.values), s.id, hex.EncodeToString(root))
	return nil
}

func (s *DMT) Contains(val string) (bool, error) {
	v := s.contentFactory([]byte(val))
	incl, err := s.tree.VerifyContent(v)
	if err != nil {
		return false, err
	}
	return incl, nil
}

func (s *DMT) Get(key []byte) (val []byte, err error) {
	i := new(big.Int).SetBytes(key).Uint64()
	if len(s.values) == 0 {
		return nil, fmt.Errorf("failed to resolve value within dense merkle tree at index %d; tree is empty", i)
	}

	if i >= uint64(len(s.values)) {
		return nil, fmt.Errorf("failed to resolve value within dense merkle tree at index %d; index out of bounds", i)
	}

	return s.values[i].(*treeContent).value, nil
}

func (s *DMT) Height() int {
	return len(s.tree.Leafs) * 2
}

func (s *DMT) Insert(val string) (root []byte, err error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	v := s.contentFactory([]byte(val))
	s.values = append(s.values, v)
	err = s.tree.RebuildTreeWith(s.values)
	if err != nil {
		return nil, err
	}

	err = s.commit()
	if err != nil {
		return nil, err
	}

	common.Log.Debugf("inserted value in dense merkle tree at index %d; current root: %s", s.Size()-1, hex.EncodeToString(s.tree.MerkleRoot()))
	return s.tree.MerkleRoot(), nil
}

func (s *DMT) Root() (root *string, err error) {
	if s.tree.MerkleRoot() == nil || len(s.tree.MerkleRoot()) == 0 {
		return nil, errors.New("tree does not contain a valid root")
	}
	return common.StringOrNil(hex.EncodeToString(s.tree.MerkleRoot())), nil
}

func (s *DMT) Size() int {
	return len(s.values)
}

func (s *DMT) CalculateKey(val string) []byte {
	return []byte{}
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
		ProverID:    s.id,
		Epoch:       epoch,
		StateClaims: claims,
	}

	return state, nil
}
