package gnark

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

// CubicProver defines a simple prover
// x**3 + x + 5 == y
type CubicProver struct {
	// struct tags on a variable is optional
	// default uses variable name and secret visibility.
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

// Define declares the prover constraints
// x**3 + x + 5 == y
func (prover *CubicProver) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	x3 := cs.Mul(prover.X, prover.X, prover.X)
	cs.AssertIsEqual(prover.Y, cs.Add(x3, prover.X, 5))
	return nil
}
