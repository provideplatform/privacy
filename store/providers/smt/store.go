package smt

import (
	"crypto/sha256"
	"errors"
	"os"

	triedb "github.com/aergoio/aergo-lib/db"
	"github.com/aergoio/aergo/pkg/trie"
	"github.com/jinzhu/gorm"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/privacy/common"
	"github.com/provideplatform/privacy/state"
)

// SMT is the sparse merkle tree
type SMT struct {
	db       *gorm.DB
	hashFunc func(data ...[]byte) []byte
	id       *uuid.UUID
	tree     *trie.Trie
}

func InitSMT(db *gorm.DB, id *uuid.UUID, hashFunc func(data ...[]byte) []byte) *SMT {
	_hashFunc := hashFunc
	if _hashFunc == nil {
		_hashFunc = func(data ...[]byte) []byte {
			sha := sha256.New()
			for i := 0; i < len(data); i++ {
				sha.Write(data[i])
			}
			return sha.Sum(nil)
		}
	}
	tree := trie.NewTrie(nil, _hashFunc, triedb.NewDB(triedb.MemoryImpl, os.TempDir()))
	instance := &SMT{
		db:       db,
		hashFunc: _hashFunc,
		id:       id,
		tree:     tree,
	}

	return instance
}

func (s *SMT) Contains(val string) bool {
	_val := []byte(val)
	key := s.hashFunc(_val)
	path, inc, _, _, _ := s.tree.MerkleProof(key)
	common.Log.Debugf("trie path: %v", path)
	if inc {
		common.Log.Debug("Included!")
	}
	return s.tree.VerifyInclusion(path, key, _val)
}

func (s *SMT) Get(key []byte) (val []byte, err error) {
	return s.tree.Get(key)
}

func (s *SMT) Height() int {
	return s.tree.TrieHeight
}

func (s *SMT) Insert(val string) (root []byte, err error) {
	_val := []byte(val)
	key := s.hashFunc(_val)
	root, err = s.tree.Update([][]byte{key}, [][]byte{_val})
	if err != nil {
		return nil, err
	}
	err = s.tree.Commit()
	if err != nil {
		return nil, err
	}
	return root, nil
}

func (s *SMT) Root() (root *string, err error) {
	if s.tree.Root == nil || len(s.tree.Root) == 0 {
		return nil, errors.New("tree does not contain a valid root")
	}
	return common.StringOrNil(string(s.tree.Root)), nil
}

// StateAt returns the state at the given epoch
func (s *SMT) StateAt(epoch uint64) (*state.State, error) {
	claims := make([]*state.StateClaim, 0)

	root, err := s.Root() // impl RootAt()
	if err != nil {
		return nil, err
	}

	claims = append(claims, &state.StateClaim{
		Cardinality: uint64(0),
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
