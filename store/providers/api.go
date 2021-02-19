package providers

import (
	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/privacy/store/providers/merkletree"
)

// StoreProviderMerkleTree merkle tree storage provider
const StoreProviderMerkleTree = "merkle_tree"

// StoreProvider provides a common interface to interact with proof storage facilities
type StoreProvider interface {
	Contains(proof string) bool
	Insert(proof string) (index int)
	Recalculate() (root string)
}

// InitMerkleTreeStoreProvider initializes a durable merkle tree
func InitMerkleTreeStoreProvider(id uuid.UUID) *merkletree.DurableMerkleTree {
	tree, _ := merkletree.LoadMerkleTree(dbconf.DatabaseConnection(), id)
	return tree // FIXME-- check err
}
