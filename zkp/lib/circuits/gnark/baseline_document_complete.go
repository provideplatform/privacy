package gnark

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
	"github.com/consensys/gurvy"
)

// FIX: Use MimcCircuit here
type Document struct {
	PreImage frontend.Variable
	Hash     frontend.Variable `gnark:",public"`
}

type BaselineDocumentCompleteCircuit struct {
	Doc Document
	Pk  eddsa.PublicKey `gnark:",public"`
	Sk  frontend.Variable
	Sig eddsa.Signature `gnark:",public"`
}

func (circuit *BaselineDocumentCompleteCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	// Check for ownership of sk
	// FIX: Use OwnershipSkCircuit here
	computedPk := twistededwards.Point{}
	computedPk.ScalarMulFixedBase(cs, circuit.Pk.Curve.BaseX, circuit.Pk.Curve.BaseY, circuit.Sk, circuit.Pk.Curve)
	computedPk.MustBeOnCurve(cs, circuit.Pk.Curve)

	cs.AssertIsEqual(circuit.Pk.A.X, computedPk.X)
	cs.AssertIsEqual(circuit.Pk.A.Y, computedPk.Y)

	// Check for valid signature
	// FIX: pass MimcCircuit as witness here, pass OwnershipSkCircuit as witness too
	eddsa.Verify(cs, circuit.Sig, circuit.Doc.Hash, circuit.Pk)

	// Check for knowledge of preimage
	// Hash = mimc(PreImage)
	mimc, _ := mimc.NewMiMC("seed", curveID)
	cs.AssertIsEqual(circuit.Doc.Hash, mimc.Hash(cs, circuit.Doc.PreImage))

	return nil
}
