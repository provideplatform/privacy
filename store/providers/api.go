package providers

import (
	"hash"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	gnarkhash "github.com/consensys/gnark-crypto/hash"
	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/privacy/common"
	"github.com/provideplatform/privacy/store/providers/dmt"
	"github.com/provideplatform/privacy/store/providers/smt"
)

// StoreProviderDenseMerkleTree dense merkle tree storage provider
const StoreProviderDenseMerkleTree = "dmt"

// StoreProviderSparseMerkleTree sparse merkle tree storage provider
const StoreProviderSparseMerkleTree = "smt"

// StoreProvider provides a common interface to interact with proof storage facilities
type StoreProvider interface {
	Contains(val string) bool
	Get(key []byte) (val []byte, err error)
	Height() int
	Insert(val string) (root []byte, err error)
	Root() (root *string, err error)
}

// InitDenseMerkleTreeStoreProvider initializes a durable merkle tree
func InitDenseMerkleTreeStoreProvider(id uuid.UUID, curve *string) *dmt.DMT {
	return dmt.InitDMT(dbconf.DatabaseConnection(), id, hashFactory(curve))
}

// InitSparseMerkleTreeStoreProvider initializes a sparse merkle tree
func InitSparseMerkleTreeStoreProvider(id uuid.UUID, curve *string) *smt.SMT {
	return smt.InitSMT(dbconf.DatabaseConnection(), id, hashFactory(curve))
}

func hashFactory(curve *string) hash.Hash {
	switch strings.ToLower(*curve) {
	case ecc.BLS12_377.String():
		return gnarkhash.MIMC_BLS12_377.New("seed")
	case ecc.BLS12_381.String():
		return gnarkhash.MIMC_BLS12_381.New("seed")
	case ecc.BN254.String():
		return gnarkhash.MIMC_BN254.New("seed")
	case ecc.BW6_761.String():
		return gnarkhash.MIMC_BW6_761.New("seed")
	case ecc.BLS24_315.String():
		return gnarkhash.MIMC_BLS24_315.New("seed")
	default:
		common.Log.Warningf("failed to resolve hash type string; unknown or unsupported curve: %s", *curve)
	}

	return nil
}
