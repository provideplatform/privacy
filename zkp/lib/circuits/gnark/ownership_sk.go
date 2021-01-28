package gnark

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/signature/eddsa"
	"github.com/consensys/gurvy"
)

type OwnershipSkCircuit struct {
	Pk eddsa.PublicKey `gnark:",public"`
	Sk frontend.Variable
}

func (circuit *OwnershipSkCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	params, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}
	circuit.Pk.Curve = params

	computedPk := twistededwards.Point{}
	computedPk.ScalarMulFixedBase(cs, circuit.Pk.Curve.BaseX, circuit.Pk.Curve.BaseY, circuit.Sk, circuit.Pk.Curve)
	computedPk.MustBeOnCurve(cs, circuit.Pk.Curve)

	cs.AssertIsEqual(circuit.Pk.A.X, computedPk.X)
	cs.AssertIsEqual(circuit.Pk.A.Y, computedPk.Y)

	return nil
}
