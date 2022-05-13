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

package providers

import (
	"fmt"
	"hash"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	gnarkhash "github.com/consensys/gnark-crypto/hash"
	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/privacy/store/providers/dmt"
	"github.com/provideplatform/privacy/store/providers/smt"
)

// StoreProviderDenseMerkleTree dense merkle tree storage provider
const StoreProviderDenseMerkleTree = "dmt"

// StoreProviderSparseMerkleTree sparse merkle tree storage provider
const StoreProviderSparseMerkleTree = "smt"

// StoreProvider provides a common interface to interact with proof storage facilities
type StoreProvider interface {
	Contains(val string) (bool, error)
	Get(key []byte) (val []byte, err error)
	Height() int
	Insert(val string) (root []byte, err error)
	Root() (root *string, err error)
	Size() int
	CalculateKey(val string) []byte
}

// InitDenseMerkleTreeStoreProvider initializes a durable merkle tree
func InitDenseMerkleTreeStoreProvider(id uuid.UUID, curve *string) (*dmt.DMT, error) {
	h, err := hashFactory(curve)
	if err != nil {
		return nil, err
	}
	return dmt.InitDMT(dbconf.DatabaseConnection(), id, h)
}

// InitSparseMerkleTreeStoreProvider initializes a sparse merkle tree
func InitSparseMerkleTreeStoreProvider(id uuid.UUID, curve *string) (*smt.SMT, error) {
	h, err := hashFactory(curve)
	if err != nil {
		return nil, err
	}
	return smt.InitSMT(dbconf.DatabaseConnection(), id, h)
}

func hashFactory(curve *string) (hash.Hash, error) {
	switch strings.ToLower(*curve) {
	case ecc.BLS12_377.String():
		return gnarkhash.MIMC_BLS12_377.New("seed"), nil
	case ecc.BLS12_381.String():
		return gnarkhash.MIMC_BLS12_381.New("seed"), nil
	case ecc.BN254.String():
		return gnarkhash.MIMC_BN254.New("seed"), nil
	case ecc.BW6_761.String():
		return gnarkhash.MIMC_BW6_761.New("seed"), nil
	case ecc.BLS24_315.String():
		return gnarkhash.MIMC_BLS24_315.New("seed"), nil
	default:
		return nil, fmt.Errorf("failed to resolve hash type string; unknown or unsupported curve: %s", *curve)
	}
}
