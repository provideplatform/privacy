package gnark

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gurvy"
)

// BaselineDocumentCircuit defines a pre-image knowledge proof
// mimc(secret PreImage) = public hash
type BaselineDocumentCircuit struct {
	PreImage frontend.Variable
	Hash     frontend.Variable `gnark:",public"`
}

// Define declares the circuit constraints
// Hash = mimc(PreImage)
func (circuit *BaselineDocumentCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	// hash function
	mimc, _ := mimc.NewMiMC("seed", curveID)

	// specify constraints
	// mimc(PreImage) == hash

	hash := mimc.Hash(cs, circuit.PreImage)
	cs.AssertIsEqual(circuit.Hash, hash)

	return nil
}
