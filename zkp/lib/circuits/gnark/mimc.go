package gnark

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

// MimcProver defines a pre-image knowledge proof
// mimc(secret preImage) = public hash
type MimcProver struct {
	// struct tag on a variable is optional
	// default uses variable name and secret visibility.
	Preimage frontend.Variable
	Hash     frontend.Variable `gnark:",public"`
}

// Define declares the prover's constraints
// Hash = mimc(Preimage)
func (prover *MimcProver) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	// hash function
	mimc, _ := mimc.NewMiMC("seed", curveID)

	// specify constraints
	// mimc(preImage) == hash
	cs.AssertIsEqual(prover.Hash, mimc.Hash(cs, prover.Preimage))

	return nil
}
