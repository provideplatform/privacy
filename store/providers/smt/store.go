package smt

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"sync"

	"github.com/jinzhu/gorm"
	uuid "github.com/kthomas/go.uuid"
	"github.com/providenetwork/smt"
	"github.com/provideplatform/privacy/common"
	"github.com/provideplatform/privacy/state"
)

// SMT is the sparse merkle tree
type SMT struct {
	db    *gorm.DB
	hash  hash.Hash
	id    *uuid.UUID
	mutex *sync.Mutex
	tree  *smt.SparseMerkleTree
}

func InitSMT(db *gorm.DB, id uuid.UUID, hash hash.Hash) *SMT {
	tree, err := loadTree(db, id, hash)
	if err != nil {
		return nil
	}

	if tree == nil {
		tree = smt.NewSparseMerkleTree(smt.NewSimpleMap(), smt.NewSimpleMap(), hash)
	}

	instance := &SMT{
		db:    db,
		hash:  hash,
		id:    &id,
		mutex: &sync.Mutex{},
		tree:  tree,
	}

	return instance
}

func loadTree(db *gorm.DB, id uuid.UUID, hash hash.Hash) (*smt.SparseMerkleTree, error) {
	var tree *smt.SparseMerkleTree

	rows, err := db.Raw("SELECT nodes, values, root from trees WHERE store_id = ? ORDER BY id", id).Rows()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve merkle tree from store: %s; %s", id, err.Error())
	}

	for rows.Next() {
		var nodesRaw json.RawMessage
		var valuesRaw json.RawMessage
		var root string

		err = rows.Scan(&nodesRaw, &valuesRaw, &root)
		if err != nil {
			return nil, fmt.Errorf("failed to scan the store for sparse merkle tree; %s", err.Error())
		}

		var nodes *smt.SimpleMap
		var values *smt.SimpleMap

		json.Unmarshal(nodesRaw, &nodes)
		json.Unmarshal(valuesRaw, &values)
		rootBytes, _ := hex.DecodeString(root)

		tree = smt.ImportSparseMerkleTree(
			nodes,
			values,
			hash,
			rootBytes,
		)

		common.Log.Debugf("imported sparse merkle tree with root: %s", root)
	}

	if tree != nil {
		return tree, nil
	}

	return nil, nil
}

// commit the current state of the sparse merkle tree to the database
// TODO-- audit this approach; as the trees grow in size, we will want something else...
func (s *SMT) commit() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	nodes, _ := json.Marshal(s.tree.Nodes())
	values, _ := json.Marshal(s.tree.Values())
	root := s.tree.Root()

	common.Log.Debugf("NODES: %v", nodes)
	common.Log.Debugf("VALUES: %v", values)

	db := s.db.Exec("INSERT INTO trees (store_id, nodes, values, root) VALUES (?, ?, ?, ?)", s.id, nodes, values, hex.EncodeToString(root))
	if db.RowsAffected == 0 {
		return fmt.Errorf("failed to persist hash within merkle tree: %s", s.id)
	}

	return nil
}

func (s *SMT) digest(val []byte) []byte {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.hash.Reset()
	s.hash.Write([]byte(val))
	hash := s.hash.Sum(nil)
	s.hash.Reset()
	return hash
}

func (s *SMT) Contains(val string) bool {
	_val := []byte(val)
	key := s.digest(_val)

	proof, err := s.tree.Prove(key)
	if err != nil {
		common.Log.Warningf("failed to generate merkle proof; %s", err.Error())
		return false
	}

	siblingPath := make([]string, len(proof.SideNodes))
	for i := range proof.SideNodes {
		siblingPath = append(siblingPath, hex.EncodeToString(proof.SideNodes[i]))
	}
	common.Log.Debugf("sibling path: %v", siblingPath)

	return smt.VerifyProof(proof, s.tree.Root(), key, _val, s.hash)
}

func (s *SMT) Get(key []byte) (val []byte, err error) {
	return s.tree.Get(key)
}

func (s *SMT) Height() int {
	return s.tree.Height()
}

func (s *SMT) Insert(val string) (root []byte, err error) {
	_val := []byte(val)
	key := s.digest(_val)
	root, err = s.tree.Update(key, _val)
	if err != nil {
		return nil, err
	}
	s.commit()
	common.Log.Debugf("inserted key... %s; current root: %s", hex.EncodeToString(key), hex.EncodeToString(s.tree.Root()))
	return root, nil
}

func (s *SMT) Root() (root *string, err error) {
	if s.tree.Root() == nil || len(s.tree.Root()) == 0 {
		return nil, errors.New("tree does not contain a valid root")
	}
	return common.StringOrNil(string(s.tree.Root())), nil
}

// StateAt returns the state at the given epoch
func (s *SMT) StateAt(epoch uint64) (*state.State, error) {
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
