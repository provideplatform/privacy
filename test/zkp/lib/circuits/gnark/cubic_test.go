// +build unit

package gnark

import (
	"bytes"
	"io"
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

func TestCubicEquationPlonkElaboratedWithMarshalling(t *testing.T) {
	assert := plonk.NewAssert(t)

	var cubicCircuit libgnark.CubicCircuit

	// compiles our circuit into a R1CS
	sparseR1cs, err := frontend.Compile(ecc.BN254, backend.PLONK, &cubicCircuit)
	assert.NoError(err)

	{
		var witness libgnark.CubicCircuit
		witness.X.Assign(3)
		witness.Y.Assign(35)

		kzgSRS := getKzgScheme(sparseR1cs)
		pk, vk, err := plonk.Setup(sparseR1cs, kzgSRS)
		assert.NoError(err, "Generating public data should not have failed")

		var buf *bytes.Buffer
		buf = new(bytes.Buffer)
		_, err = pk.(io.WriterTo).WriteTo(buf)
		if err != nil {
			t.Errorf("failed to write proving key to buffer")
		}

		t.Logf("proving key size in bytes: %d", buf.Len())

		pkCopy := plonk.NewProvingKey(ecc.BN254)
		n, err := pkCopy.ReadFrom(buf)

		t.Logf("bytes read back from proving key: %d", n)

		pkCopy.InitKZG(kzgSRS)

		proof, err := plonk.Prove(sparseR1cs, pkCopy, &witness)
		assert.NoError(err, "Proving with good witness should not output an error")

		err = plonk.Verify(proof, vk, &witness)
		assert.NoError(err, "Verifying correct proof with correct witness should not output an error")
	}

}
