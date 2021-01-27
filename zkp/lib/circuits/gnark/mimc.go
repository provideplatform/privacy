package gnark

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gurvy"
)

// Circuit defines a pre-image knowledge proof
// mimc(secret preImage) = public hash
type MimcCircuit struct {
	// struct tag on a variable is optional
	// default uses variable name and secret visibility.
	PreImage frontend.Variable
	Hash     frontend.Variable `gnark:",public"`
}

// Define declares the circuit's constraints
// Hash = mimc(PreImage)
func (circuit *MimcCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	// hash function
	mimc, _ := mimc.NewMiMC("seed", curveID)

	fmt.Println(mimc.Hash(cs, circuit.PreImage))
	fmt.Println(circuit.Hash)
	// specify constraints
	// mimc(preImage) == hash
	cs.AssertIsEqual(circuit.Hash, mimc.Hash(cs, circuit.PreImage))

	return nil
}
