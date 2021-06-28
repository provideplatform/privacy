package providers

import (
	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/privacy/store/providers/merkletree"
	"github.com/provideplatform/privacy/store/providers/smt"
)

// StoreProviderMerkleTree merkle tree storage provider
const StoreProviderMerkleTree = "merkle_tree"

// StoreProviderSparseMerkleTree merkle tree storage provider
const StoreProviderSparseMerkleTree = "smt"

// StoreProvider provides a common interface to interact with proof storage facilities
type StoreProvider interface {
	Contains(val string) bool
	Get(key []byte) (val []byte, err error)
	Height() int
	Insert(val string) (root []byte, err error)
	Root() (root *string, err error)
}

// InitMerkleTreeStoreProvider initializes a durable merkle tree
func InitMerkleTreeStoreProvider(id uuid.UUID, hash *string) *merkletree.DurableMerkleTree {
	tree, _ := merkletree.LoadMerkleTree(dbconf.DatabaseConnection(), id, hash)
	return tree // FIXME-- check err
}

// InitSparseMerkleTreeStoreProvider initializes a durable merkle tree
func InitSparseMerkleTreeStoreProvider(id *uuid.UUID) *smt.SMT {
	return smt.InitSMT(dbconf.DatabaseConnection(), id, nil)
}
