package gnark

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

// PreimageHashCircuit proves knowledge of a hashed secret
type PreimageHashCircuit struct {
	Preimage frontend.Variable // pre-image of the hash secret known to the prover only
	Hash     frontend.Variable `gnark:",public"`
}

// Define the preimage hash circuit
func (circuit *PreimageHashCircuit) Define(api frontend.API) error {
	mimc, _ := mimc.NewMiMC(api)
	mimc.Write(circuit.Preimage)
	api.AssertIsEqual(circuit.Hash, mimc.Sum())
	return nil
}
