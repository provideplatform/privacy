package providers

import (
	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/privacy/store/providers/merkletree"
)

// StoreProviderMerkleTree merkle tree storage provider
const StoreProviderMerkleTree = "merkle_tree"

// StoreProvider provides a common interface to interact with proof storage facilities
type StoreProvider interface {
	Contains(hash string) bool
	Add(data []byte) (index int, hash string)
	RawAdd(data []byte) (index int, hash string)
	HashAt(index uint64) (hash string, err error)
	Insert(hash string) (index int)
	Length() int
	Recalculate() (root string)
	Root() (root *string, err error)
}

// InitMerkleTreeStoreProvider initializes a durable merkle tree
func InitMerkleTreeStoreProvider(id uuid.UUID, hash *string) *merkletree.DurableMerkleTree {
	tree, _ := merkletree.LoadMerkleTree(dbconf.DatabaseConnection(), id, hash)
	return tree // FIXME-- check err
}
