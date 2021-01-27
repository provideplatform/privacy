package gnark

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/signature/eddsa"
	"github.com/consensys/gurvy"
)

type OwnershipSkCircuit struct {
	Pk eddsa.PublicKey   `gnark:"pk,public"`
	Sk frontend.Variable `gnark:"sk"`
}

func (circuit *OwnershipSkCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	computedPk := twistededwards.Point{}
	computedPk.ScalarMulFixedBase(cs, circuit.Pk.Curve.BaseX, circuit.Pk.Curve.BaseY, circuit.Sk, circuit.Pk.Curve)
	computedPk.MustBeOnCurve(cs, circuit.Pk.Curve)

	cs.AssertIsEqual(circuit.Pk.A.X, computedPk.X)
	cs.AssertIsEqual(circuit.Pk.A.Y, computedPk.Y)

	return nil
}
