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

package merkletree

import (
	"encoding/json"
	"fmt"
)

// MerkleTree defines and represents the methods a generic Merkle tree should have
type MerkleTree interface {
	fmt.Stringer
	Add(val []byte) (index int, hash string)
	RawAdd(val []byte) (index int, hash string)
	IntermediaryHashesByIndex(index int) (intermediaryHashes []string, err error)
	ValidateExistence(original []byte, index int, intermediaryHashes []string) (bool, error)
	HashAt(index uint64) (string, error)
	Root() (*string, error)
	Length() int
}

// MerkleTreeNode represents a single node in a merkle tree
type MerkleTreeNode interface {
	fmt.Stringer
	Hash() string
	Index() int
}

type internaler interface {
	Insert(val string) (root []byte, err error)
	RawInsert(hash string) (index int, leaf MerkleTreeNode)
	Recalculate() (root string)
}

// InternalMerkleTree defines additional functions that are not supposed to be exposed to outside user to call.
// These functions deal with direct inserts of hashes and tree recalculation
type InternalMerkleTree interface {
	MerkleTree
	internaler
}

type externaler interface {
	json.Marshaler
}

// ExternalMerkleTree defines additional functions that are to be exported when the tree is communicated with the outside world.
type ExternalMerkleTree interface {
	MerkleTree
	externaler
}

// FullMerkleTree is both Internal and External
type FullMerkleTree interface {
	MerkleTree
	internaler
	externaler
}
