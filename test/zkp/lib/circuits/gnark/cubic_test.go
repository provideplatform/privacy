// +build unit

package gnark

import (
	"bytes"
	"encoding/hex"
	"io"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/provideplatform/privacy/common"
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

		buf.Reset()
		_, err = vk.(io.WriterTo).WriteTo(buf)
		if err != nil {
			t.Errorf("failed to write verifying key to buffer")
		}

		t.Logf("verifying key size in bytes: %d", buf.Len())

		vkCopy := plonk.NewVerifyingKey(ecc.BN254)
		n, err = vkCopy.ReadFrom(buf)

		t.Logf("bytes read back from verifying key: %d", n)

		vkCopy.InitKZG(kzgSRS)

		err = plonk.Verify(proof, vkCopy, &witness)
		assert.NoError(err, "Verifying correct proof with correct witness should not output an error")
	}

}

func TestCubicEquationPlonkSRSEntropy(t *testing.T) {
	assert := plonk.NewAssert(t)

	var cubicCircuit libgnark.CubicCircuit

	// compiles our circuit into a R1CS
	r1cs, err := frontend.Compile(ecc.BN254, backend.PLONK, &cubicCircuit)
	assert.NoError(err)

	{
		var witness libgnark.CubicCircuit
		witness.X.Assign(3)
		witness.Y.Assign(35)

		alpha := new(big.Int).SetUint64(42)
		nbConstraints := r1cs.GetNbConstraints()
		internal, secret, public := r1cs.GetNbVariables()
		nbVariables := internal + secret + public
		var s, size int
		if nbConstraints > nbVariables {
			s = nbConstraints
		} else {
			s = nbVariables
		}
		size = common.NextPowerOfTwo(s)

		srs1 := kzg.NewSRS(size, alpha)

		var buf1 *bytes.Buffer
		buf1 = new(bytes.Buffer)
		_, err := srs1.WriteTo(buf1)
		assert.NoError(err)

		bufString := hex.EncodeToString(buf1.Bytes())
		t.Logf("%v", bufString)

		var buf2 *bytes.Buffer
		buf2 = new(bytes.Buffer)
		srs2 := kzg.NewSRS(size, alpha)
		_, err = srs2.WriteTo(buf2)
		assert.NoError(err)

		bufString = hex.EncodeToString(buf2.Bytes())
		t.Logf("%v", bufString)

		if bytes.Compare(buf1.Bytes(), buf2.Bytes()) == 0 {
			t.Log("srs objects initialized with same value are equal")
		} else {
			t.Log("srs objects initialized with same value are NOT equal")
		}
	}

}
