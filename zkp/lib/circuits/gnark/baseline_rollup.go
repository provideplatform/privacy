package gnark

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/consensys/gnark/std/hash/mimc"
)

// BaselineRollupCircuit defines a mrkle root verification proof
type BaselineRollupCircuit struct {
	Proofs, Helpers []frontend.Variable
	RootHash        frontend.Variable `gnark:",public"`
}

// Define declares the circuit constraints
func (circuit *BaselineRollupCircuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	// hash function
	mimc, err := mimc.NewMiMC("seed", curveID, cs)
	if err != nil {
		return err
	}

	merkle.VerifyProof(cs, mimc, circuit.RootHash, circuit.Proofs, circuit.Helpers)

	return nil
}
