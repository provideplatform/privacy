package gnark

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

// MimcCircuit defines a pre-image knowledge proof
// mimc(secret preImage) = public hash
type MimcCircuit struct {
	// struct tag on a variable is optional
	// default uses variable name and secret visibility.
	Preimage frontend.Variable
	Hash     frontend.Variable `gnark:",public"`
}

// Define declares the circuit's constraints
// Hash = mimc(Preimage)
func (circuit *MimcCircuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	// hash function
	mimc, _ := mimc.NewMiMC("seed", curveID, cs)

	// specify constraints
	// mimc(preImage) == hash
	mimc.Write(circuit.Preimage)
	cs.AssertIsEqual(circuit.Hash, mimc.Sum())

	return nil
}
