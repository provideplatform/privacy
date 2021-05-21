package gnark

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
)

// EddsaPrivateKey defines eddsa private key in two chunks (upper and lower)
type EddsaPrivateKey struct {
	Upper frontend.Variable
	Lower frontend.Variable
}

// Document is similar to MimcCircuit
type Document struct {
	Preimage frontend.Variable
	Hash     frontend.Variable `gnark:",public"`
}

// BaselineDocumentCompleteCircuit combines proof of ownership of sk, proof of knowledge of secret preimage to hash and verifies eddsa signature
type BaselineDocumentCompleteCircuit struct {
	Doc Document
	Pk  eddsa.PublicKey `gnark:",public"`
	Sk  EddsaPrivateKey
	Sig eddsa.Signature `gnark:",public"`
}

// Define declares the circuit's contraints
func (circuit *BaselineDocumentCompleteCircuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	params, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}
	circuit.Pk.Curve = params

	// Reuse existing circuits, eg OwnershipSK?

	// Check for ownership of sk
	var i big.Int
	if curveID == ecc.BW6_761 {
		// two chunks of 192bits each
		i.SetString("6277101735386680763835789423207666416102355444464034512896", 10) // 2**192
	} else {
		// two chunks of 128bits each
		i.SetString("340282366920938463463374607431768211456", 10) // 2**128
	}
	scalar := cs.Constant(i)

	computedPk := twistededwards.Point{}
	computedPk.ScalarMulFixedBase(cs, circuit.Pk.Curve.BaseX, circuit.Pk.Curve.BaseY, circuit.Sk.Upper, circuit.Pk.Curve)
	computedPk.ScalarMulNonFixedBase(cs, &computedPk, scalar, circuit.Pk.Curve)
	lower := twistededwards.Point{}
	lower.ScalarMulFixedBase(cs, circuit.Pk.Curve.BaseX, circuit.Pk.Curve.BaseY, circuit.Sk.Lower, circuit.Pk.Curve)

	computedPk.AddGeneric(cs, &lower, &computedPk, circuit.Pk.Curve)
	computedPk.MustBeOnCurve(cs, circuit.Pk.Curve)

	cs.AssertIsEqual(circuit.Pk.A.X, computedPk.X)
	cs.AssertIsEqual(circuit.Pk.A.Y, computedPk.Y)

	// Check for valid signature
	eddsa.Verify(cs, circuit.Sig, circuit.Doc.Hash, circuit.Pk)

	// Check for knowledge of preimage
	// Hash = mimc(Preimage)
	mimc, _ := mimc.NewMiMC("seed", curveID)
	cs.AssertIsEqual(circuit.Doc.Hash, mimc.Hash(cs, circuit.Doc.Preimage))

	return nil
}
