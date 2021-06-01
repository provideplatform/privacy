// +build unit

package gnark

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	kzgcommitment_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/polynomial/kzg"
	mockcommitment_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/polynomial/mockcommitment"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	libgnark "github.com/provideapp/privacy/zkp/lib/circuits/gnark"
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

		publicData, err := plonk.SetupDummyCommitment(sparseR1cs, &witness)
		assert.NoError(err, "Generating public data should not have failed")

		proof, err := plonk.Prove(sparseR1cs, publicData, &witness)
		assert.NoError(err, "Proving with good witness should not output an error")

		err = plonk.Verify(proof, publicData, &witness)
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

		polynomialCommitment := &mockcommitment_bn254.Scheme{}

		publicData, err := plonk.Setup(sparseR1cs, polynomialCommitment, &witness)
		assert.NoError(err, "Generating public data should not have failed")

		proof, err := plonk.Prove(sparseR1cs, publicData, &witness)
		assert.NoError(err, "Proving with good witness should not output an error")

		err = plonk.Verify(proof, publicData, &witness)
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

		polynomialCommitment := &kzgcommitment_bn254.Scheme{}

		publicData, err := plonk.Setup(sparseR1cs, polynomialCommitment, &witness)
		assert.NoError(err, "Generating public data should not have failed")

		proof, err := plonk.Prove(sparseR1cs, publicData, &witness)
		// FIXME-- this gets error ":"the size of the polynomials exceeds the capacity of the SRS" from gnark-crypto
		assert.NoError(err, "Proving with good witness should not output an error")

		err = plonk.Verify(proof, publicData, &witness)
		assert.NoError(err, "Verifying correct proof with correct witness should not output an error")
	}

}
