package gnark

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/consensys/gnark/std/hash/mimc"
)

// BaselineRollupProver defines a mrkle root verification proof
type BaselineRollupProver struct {
	Proofs, Helpers []frontend.Variable
	RootHash        frontend.Variable `gnark:",public"`
}

// Define declares the prover constraints
func (prover *BaselineRollupProver) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	// hash function
	mimc, err := mimc.NewMiMC("seed", curveID)
	if err != nil {
		return err
	}

	merkle.VerifyProof(cs, mimc, prover.RootHash, prover.Proofs, prover.Helpers)

	return nil
}
