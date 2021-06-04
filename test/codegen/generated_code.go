package test

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/consensys/gnark/std/hash/mimc"
)

type GenRollupCircuit struct {
	Proofs [2]frontend.Variable
	Helpers [1]frontend.Variable
	RootHash frontend.Variable `gnark:",public"`
}

func (circuit *GenRollupCircuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	mimc, err := mimc.NewMiMC("seed", curveID)
	if err != nil {
		return err
	}
	merkle.VerifyProof(cs, mimc, circuit.RootHash, circuit.Proofs[:], circuit.Helpers[:])
	return nil
}

