package gnark

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gurvy"
)

// BaselineRollupCircuit defines a rollup verification circuit
// methodology TBD
type BaselineRollupCircuit struct {
	PreImage frontend.Variable
	Root     frontend.Variable `gnark:",public"`
}

// Define declares the circuit constraints
func (circuit *BaselineRollupCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	// hash function
	mimc, _ := mimc.NewMiMC("seed", curveID)

	// specify constraints
	// mimc(PreImage) == hash
	hash := mimc.Hash(cs, circuit.PreImage)
	cs.AssertIsEqual(circuit.Root, hash)

	return nil
}
