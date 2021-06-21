// +build unit

package gnark

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	libgnark "github.com/provideplatform/privacy/zkp/lib/circuits/gnark"
)

func TestCubicEquationGroth16(t *testing.T) {
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

func TestCubicEquationPlonk(t *testing.T) {
	assert := plonk.NewAssert(t)

	var cubicCircuit libgnark.CubicCircuit

	// compiles our circuit into a R1CS
	sparseR1cs, err := frontend.Compile(ecc.BN254, backend.PLONK, &cubicCircuit)
	assert.NoError(err)

	{
		var witness libgnark.CubicCircuit
		witness.X.Assign(42)
		witness.Y.Assign(42)

		assert.ProverFailed(sparseR1cs, &witness)
	}

	{
		var witness libgnark.CubicCircuit
		witness.X.Assign(3)
		witness.Y.Assign(35)
		assert.ProverSucceeded(sparseR1cs, &witness)
	}

}

func TestCubicEquationPlonkElaborated(t *testing.T) {
	assert := plonk.NewAssert(t)

	var cubicCircuit libgnark.CubicCircuit

	// compiles our circuit into a R1CS
	sparseR1cs, err := frontend.Compile(ecc.BN254, backend.PLONK, &cubicCircuit)
	assert.NoError(err)

	{
		var witness libgnark.CubicCircuit
		witness.X.Assign(3)
		witness.Y.Assign(35)

		pk, vk, err := plonk.Setup(sparseR1cs, getKzgScheme(sparseR1cs))
		assert.NoError(err, "Generating public data should not have failed")

		proof, err := plonk.Prove(sparseR1cs, pk, &witness)
		assert.NoError(err, "Proving with good witness should not output an error")

		err = plonk.Verify(proof, vk, &witness)
		assert.NoError(err, "Verifying correct proof with correct witness should not output an error")
	}

}

func TestCubicEquationPlonkElaboratedWithSpecifiedMockCommitment(t *testing.T) {
	assert := plonk.NewAssert(t)

	var cubicCircuit libgnark.CubicCircuit

	// compiles our circuit into a R1CS
	sparseR1cs, err := frontend.Compile(ecc.BN254, backend.PLONK, &cubicCircuit)
	assert.NoError(err)

	{
		var witness libgnark.CubicCircuit
		witness.X.Assign(3)
		witness.Y.Assign(35)

		pk, vk, err := plonk.Setup(sparseR1cs, getKzgScheme(sparseR1cs))
		assert.NoError(err, "Generating public data should not have failed")

		proof, err := plonk.Prove(sparseR1cs, pk, &witness)
		assert.NoError(err, "Proving with good witness should not output an error")

		err = plonk.Verify(proof, vk, &witness)
		assert.NoError(err, "Verifying correct proof with correct witness should not output an error")
	}

}

func TestCubicEquationPlonkElaboratedWithSpecifiedKzgCommitment(t *testing.T) {
	assert := plonk.NewAssert(t)

	var cubicCircuit libgnark.CubicCircuit

	// compiles our circuit into a R1CS
	sparseR1cs, err := frontend.Compile(ecc.BN254, backend.PLONK, &cubicCircuit)
	assert.NoError(err)

	{
		var witness libgnark.CubicCircuit
		witness.X.Assign(3)
		witness.Y.Assign(35)

		pk, vk, err := plonk.Setup(sparseR1cs, getKzgScheme(sparseR1cs))
		assert.NoError(err, "Generating public data should not have failed")

		proof, err := plonk.Prove(sparseR1cs, pk, &witness)
		assert.NoError(err, "Proving with good witness should not output an error")

		err = plonk.Verify(proof, vk, &witness)
		assert.NoError(err, "Verifying correct proof with correct witness should not output an error")
	}

}
