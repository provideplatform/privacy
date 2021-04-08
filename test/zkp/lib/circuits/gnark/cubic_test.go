// +build unit

package gnark

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	libgnark "github.com/provideapp/privacy/zkp/lib/circuits/gnark"
)

func TestCubicEquation(t *testing.T) {
	assert := groth16.NewAssert(t)

	var cubicCircuit libgnark.CubicCircuit

	// compiles our circuit into a R1CS
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &cubicCircuit)
	assert.NoError(err)

	{
		var witness libgnark.CubicCircuit
		witness.X.Assign(42)
		witness.Y.Assign(42)

		assert.ProverFailed(r1cs, &witness)
	}

	{
		var witness libgnark.CubicCircuit
		witness.X.Assign(3)
		witness.Y.Assign(35)
		assert.ProverSucceeded(r1cs, &witness)
	}

}
