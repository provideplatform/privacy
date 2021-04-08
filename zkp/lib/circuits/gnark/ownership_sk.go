package gnark

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/signature/eddsa"
)

// OwnershipSkCircuit defines circuit for prove of ownership of sk
type OwnershipSkCircuit struct {
	Pk eddsa.PublicKey `gnark:",public"`
	Sk EddsaPrivateKey
}

// Define declares the circuit's constraints
func (circuit *OwnershipSkCircuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	params, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}
	circuit.Pk.Curve = params

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

	return nil
}
