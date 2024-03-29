/*
 * Copyright 2017-2022 Provide Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package smt

import (
	"bytes"
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

func InitSMT(db *gorm.DB, id uuid.UUID, hash hash.Hash) (*SMT, error) {
	tree, err := loadTree(db, id, hash)
	if err != nil {
		return nil, err
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

	return instance, nil
}

func loadTree(db *gorm.DB, id uuid.UUID, hash hash.Hash) (*smt.SparseMerkleTree, error) {
	var tree *smt.SparseMerkleTree

	rows, err := db.Raw("SELECT nodes, values, root from trees WHERE store_id = ? ORDER BY id DESC LIMIT 1", id).Rows()
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

	db := s.db.Exec("INSERT INTO trees (store_id, nodes, values, root) VALUES (?, ?, ?, ?)", s.id, nodes, values, hex.EncodeToString(root))
	if db.RowsAffected == 0 {
		return fmt.Errorf("failed to persist hash within sparse merkle tree: %s", s.id)
	}

	common.Log.Debugf("committed state (%d nodes, %d values) within sparse merkle tree %s; root: %s", s.tree.Nodes().Size(), s.tree.Values().Size(), s.id, hex.EncodeToString(root))
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

func (s *SMT) Contains(val string) (bool, error) {
	_val := []byte(val)
	key := s.digest(_val)

	proof, err := s.tree.Prove(key)
	if err != nil {
		common.Log.Warningf("failed to generate merkle proof; %s", err.Error())
		return false, err
	}

	zeroVal := make([]byte, s.hash.Size())
	siblingPath := make([]string, len(proof.SideNodes))
	for i := range proof.SideNodes {
		if !bytes.Equal(proof.SideNodes[i], zeroVal) {
			siblingPath = append(siblingPath, hex.EncodeToString(proof.SideNodes[i]))
		}
	}
	common.Log.Debugf("sibling path: %v", siblingPath)

	return smt.VerifyProof(proof, s.tree.Root(), key, _val, s.hash), nil
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

	err = s.commit()
	if err != nil {
		return nil, err
	}

	common.Log.Debugf("inserted key in sparse merkle tree: %s; current root: %s", hex.EncodeToString(key), hex.EncodeToString(s.tree.Root()))
	return root, nil
}

func (s *SMT) Root() (root *string, err error) {
	if s.tree.Root() == nil || len(s.tree.Root()) == 0 {
		return nil, errors.New("tree does not contain a valid root")
	}
	return common.StringOrNil(hex.EncodeToString(s.tree.Root())), nil
}

func (s *SMT) Size() int {
	return s.tree.Values().Size()
}

func (s *SMT) CalculateKey(val string) []byte {
	return s.digest([]byte(val))
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
		ProverID:    s.id,
		Epoch:       epoch,
		StateClaims: claims,
	}

	return state, nil
}
