package gnark

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/signature/eddsa"
)

// OwnershipSkProver defines prover for prove of ownership of sk
type OwnershipSkProver struct {
	Pk eddsa.PublicKey `gnark:",public"`
	Sk EddsaPrivateKey
}

// Define declares the prover's constraints
func (prover *OwnershipSkProver) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	params, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}
	prover.Pk.Curve = params

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

	return nil
}
