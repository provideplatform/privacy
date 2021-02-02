package gnark

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
	"github.com/consensys/gurvy"
)

// Document is similar to MimcCircuit
type Document struct {
	PreImage frontend.Variable
	Hash     frontend.Variable `gnark:",public"`
}

// BaselineDocumentCompleteCircuit combines proof of ownership of sk, proof of knowledge of secret preimage to hash and verifies eddsa signature
type BaselineDocumentCompleteCircuit struct {
	Doc Document
	Pk  eddsa.PublicKey `gnark:",public"`
	Sk  frontend.Variable
	Sig eddsa.Signature `gnark:",public"`
}

// Define declares the circuit's contraints
func (circuit *BaselineDocumentCompleteCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	params, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}
	circuit.Pk.Curve = params

	// Check for ownership of sk
	computedPk := twistededwards.Point{}
	computedPk.ScalarMulFixedBase(cs, circuit.Pk.Curve.BaseX, circuit.Pk.Curve.BaseY, circuit.Sk, circuit.Pk.Curve)
	computedPk.MustBeOnCurve(cs, circuit.Pk.Curve)

	cs.AssertIsEqual(circuit.Pk.A.X, computedPk.X)
	cs.AssertIsEqual(circuit.Pk.A.Y, computedPk.Y)

	// Check for valid signature
	eddsa.Verify(cs, circuit.Sig, circuit.Doc.Hash, circuit.Pk)

	// Check for knowledge of preimage
	// Hash = mimc(PreImage)
	mimc, _ := mimc.NewMiMC("seed", curveID)
	cs.AssertIsEqual(circuit.Doc.Hash, mimc.Hash(cs, circuit.Doc.PreImage))

	return nil
}
