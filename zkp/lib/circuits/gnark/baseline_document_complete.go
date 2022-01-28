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

// Document is similar to MimcProver
type Document struct {
	Preimage frontend.Variable
	Hash     frontend.Variable `gnark:",public"`
}

// BaselineDocumentCompleteProver combines proof of ownership of sk, proof of knowledge of secret preimage to hash and verifies eddsa signature
type BaselineDocumentCompleteProver struct {
	Doc Document
	Pk  eddsa.PublicKey `gnark:",public"`
	Sk  EddsaPrivateKey
	Sig eddsa.Signature `gnark:",public"`
}

// Define declares the prover's contraints
func (prover *BaselineDocumentCompleteProver) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	params, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}
	prover.Pk.Curve = params

	// Reuse existing provers, eg OwnershipSK?

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
	computedPk.ScalarMulFixedBase(cs, prover.Pk.Curve.BaseX, prover.Pk.Curve.BaseY, prover.Sk.Upper, prover.Pk.Curve)
	computedPk.ScalarMulNonFixedBase(cs, &computedPk, scalar, prover.Pk.Curve)
	lower := twistededwards.Point{}
	lower.ScalarMulFixedBase(cs, prover.Pk.Curve.BaseX, prover.Pk.Curve.BaseY, prover.Sk.Lower, prover.Pk.Curve)

	computedPk.AddGeneric(cs, &lower, &computedPk, prover.Pk.Curve)
	computedPk.MustBeOnCurve(cs, prover.Pk.Curve)

	cs.AssertIsEqual(prover.Pk.A.X, computedPk.X)
	cs.AssertIsEqual(prover.Pk.A.Y, computedPk.Y)

	// Check for valid signature
	eddsa.Verify(cs, prover.Sig, prover.Doc.Hash, prover.Pk)

	// Check for knowledge of preimage
	// Hash = mimc(Preimage)
	mimc, _ := mimc.NewMiMC("seed", curveID)
	cs.AssertIsEqual(prover.Doc.Hash, mimc.Hash(cs, prover.Doc.Preimage))

	return nil
}
