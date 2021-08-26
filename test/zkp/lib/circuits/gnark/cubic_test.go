// +build unit

package gnark

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
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
		var witness, publicWitness libgnark.CubicCircuit
		witness.X.Assign(3)
		witness.Y.Assign(35)

		kzgSRS, err := getKzgScheme(sparseR1cs)
		assert.NoError(err, "Getting KZG scheme should not have failed")

		pk, vk, err := plonk.Setup(sparseR1cs, kzgSRS)
		assert.NoError(err, "Generating public data should not have failed")

		proof, err := plonk.Prove(sparseR1cs, pk, &witness)
		assert.NoError(err, "Proving with good witness should not output an error")

		// assign only public variable for verification
		publicWitness.Y.Assign(35)

		err = plonk.Verify(proof, vk, &publicWitness)
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
		var witness, publicWitness libgnark.CubicCircuit
		witness.X.Assign(3)
		witness.Y.Assign(35)

		kzgSRS, err := getKzgScheme(sparseR1cs)
		assert.NoError(err, "Getting KZG scheme should not have failed")

		pk, vk, err := plonk.Setup(sparseR1cs, kzgSRS)
		assert.NoError(err, "Generating public data should not have failed")

		buf := new(bytes.Buffer)
		_, err = pk.WriteTo(buf)
		assert.NoError(err, "failed to write proving key to buffer")

		t.Logf("proving key size in bytes: %d", buf.Len())

		pkCopy := plonk.NewProvingKey(ecc.BN254)
		n, err := pkCopy.ReadFrom(buf)

		t.Logf("bytes read back from proving key: %d", n)

		pkCopy.InitKZG(kzgSRS)

		proof, err := plonk.Prove(sparseR1cs, pkCopy, &witness)
		assert.NoError(err, "Proving with good witness should not output an error")

		buf.Reset()
		_, err = vk.WriteTo(buf)
		assert.NoError(err, "failed to write verifying key to buffer")

		t.Logf("verifying key size in bytes: %d", buf.Len())

		vkCopy := plonk.NewVerifyingKey(ecc.BN254)
		n, err = vkCopy.ReadFrom(buf)

		t.Logf("bytes read back from verifying key: %d", n)

		vkCopy.InitKZG(kzgSRS)

		// assign only public variable for verification
		publicWitness.Y.Assign(35)

		err = plonk.Verify(proof, vkCopy, &publicWitness)
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

		nbConstraints := r1cs.GetNbConstraints()
		internal, secret, public := r1cs.GetNbVariables()
		nbVariables := internal + secret + public

		var s int
		var size uint64
		if nbConstraints > nbVariables {
			s = nbConstraints
		} else {
			s = nbVariables
		}

		size = ecc.NextPowerOfTwo(uint64(s))
		alpha := new(big.Int).SetUint64(42)

		srs1, err := kzg.NewSRS(size, alpha)
		assert.NoError(err, "Getting KZG scheme should not have failed")

		buf1 := new(bytes.Buffer)
		_, err = srs1.WriteTo(buf1)
		assert.NoError(err)

		buf2 := new(bytes.Buffer)
		srs2, err := kzg.NewSRS(size, alpha)
		assert.NoError(err, "Getting KZG scheme should not have failed")

		_, err = srs2.WriteTo(buf2)
		assert.NoError(err)

		assert.Equal(buf1.Bytes(), buf2.Bytes(), "srs objects initialized with same value are NOT equal")

		t.Log("srs objects initialized with same value are equal")
	}

}

func TestCubicEquationDeterminism(t *testing.T) {
	assert := plonk.NewAssert(t)

	var cubicCircuit1, cubicCircuit2 libgnark.CubicCircuit

	// compiles our circuit into a R1CS
	sparseR1cs1, err := frontend.Compile(ecc.BN254, backend.PLONK, &cubicCircuit1)
	assert.NoError(err)

	sparseR1cs2, err := frontend.Compile(ecc.BN254, backend.PLONK, &cubicCircuit2)
	assert.NoError(err)

	{
		var witness1 libgnark.CubicCircuit
		witness1.X.Assign(3)
		witness1.Y.Assign(35)

		kzgSRS1, err := getKzgScheme(sparseR1cs1)
		assert.NoError(err, "Getting KZG scheme should not have failed")

		pk1, vk1, err := plonk.Setup(sparseR1cs1, kzgSRS1)
		assert.NoError(err, "Generating public data should not have failed")

		pkBuf1 := new(bytes.Buffer)
		_, err = pk1.WriteTo(pkBuf1)
		assert.NoError(err, "failed to write pk 1 to buffer")

		vkBuf1 := new(bytes.Buffer)
		_, err = vk1.WriteTo(vkBuf1)
		assert.NoError(err, "failed to write vk 1 to buffer")

		proof1, err := plonk.Prove(sparseR1cs1, pk1, &witness1)
		assert.NoError(err, "Proving with good witness should not output an error")

		pfBuf1 := new(bytes.Buffer)
		_, err = proof1.WriteTo(pfBuf1)
		assert.NoError(err, "failed to write proof 1 to buffer")

		var witness2 libgnark.CubicCircuit
		witness2.X.Assign(3)
		witness2.Y.Assign(35)

		kzgSRS2, err := getKzgScheme(sparseR1cs2)
		assert.NoError(err, "Getting KZG scheme should not have failed")

		pk2, vk2, err := plonk.Setup(sparseR1cs2, kzgSRS2)
		assert.NoError(err, "Generating public data should not have failed")

		pkBuf2 := new(bytes.Buffer)
		_, err = pk2.WriteTo(pkBuf2)
		assert.NoError(err, "failed to write pk 2 to buffer")

		vkBuf2 := new(bytes.Buffer)
		_, err = vk2.WriteTo(vkBuf2)
		assert.NoError(err, "failed to write vk 2 to buffer")

		proof2, err := plonk.Prove(sparseR1cs2, pk2, &witness2)
		assert.NoError(err, "Proving with good witness should not output an error")

		pfBuf2 := new(bytes.Buffer)
		_, err = proof2.WriteTo(pfBuf2)
		assert.NoError(err, "failed to write proof 2 to buffer")

		assert.Equal(pkBuf1.Bytes(), pkBuf2.Bytes(), "pks are NOT equal")
		t.Logf("pks of length %d are equal", pkBuf1.Len())

		assert.Equal(vkBuf1.Bytes(), vkBuf2.Bytes(), "vks are NOT equal")
		t.Logf("vks of length %d are equal", vkBuf1.Len())

		assert.NotEqual(pfBuf1.Bytes(), pfBuf2.Bytes(), "proofs are equal")
		t.Logf("proofs of length %d are NOT equal", pfBuf1.Len())
	}

}
