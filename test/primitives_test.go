// +build unit

package test

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/provideapp/privacy/zkp/lib/circuits/gnark"
)

func TestEq(t *testing.T) {
	assert := groth16.NewAssert(t)

	var eqCircuit gnark.EqualCircuit
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &eqCircuit)
	assert.NoError(err)

	{
		var witness gnark.EqualCircuit
		witness.Vals.Val.Assign(250)
		witness.Vals.RelVal.Assign(250)

		assert.ProverSucceeded(r1cs, &witness)
	}

	{
		var witness gnark.EqualCircuit
		witness.Vals.Val.Assign(254)
		witness.Vals.RelVal.Assign(250)

		assert.ProverFailed(r1cs, &witness)
	}
}

func TestNotEq(t *testing.T) {
	assert := groth16.NewAssert(t)

	var eqCircuit gnark.NotEqualCircuit
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &eqCircuit)
	assert.NoError(err)

	{
		var witness gnark.NotEqualCircuit
		witness.Vals.Val.Assign(250)
		witness.Vals.RelVal.Assign(250)

		assert.ProverFailed(r1cs, &witness)
	}

	{
		var witness gnark.NotEqualCircuit
		witness.Vals.Val.Assign(254)
		witness.Vals.RelVal.Assign(250)

		assert.ProverSucceeded(r1cs, &witness)
	}

	{
		var witness gnark.NotEqualCircuit
		witness.Vals.Val.Assign(249)
		witness.Vals.RelVal.Assign(250)

		assert.ProverSucceeded(r1cs, &witness)
	}
}

func TestLessOrEqual(t *testing.T) {
	assert := groth16.NewAssert(t)

	var ltEqCircuit gnark.LessOrEqualCircuit
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &ltEqCircuit)
	assert.NoError(err)

	{
		var witness gnark.LessOrEqualCircuit
		witness.Vals.Val.Assign(250)
		witness.Vals.RelVal.Assign(250)
		assert.ProverSucceeded(r1cs, &witness)
	}

	{
		var witness gnark.LessOrEqualCircuit
		witness.Vals.Val.Assign(120)
		witness.Vals.RelVal.Assign(250)
		assert.ProverSucceeded(r1cs, &witness)
	}

	{
		var witness gnark.LessOrEqualCircuit
		witness.Vals.Val.Assign(350)
		witness.Vals.RelVal.Assign(250)
		assert.ProverFailed(r1cs, &witness)
	}
}

func TestGreaterOrEqual(t *testing.T) {
	assert := groth16.NewAssert(t)

	var ltCircuit gnark.GreaterOrEqualCircuit
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &ltCircuit)
	assert.NoError(err)
	{
		var witness gnark.GreaterOrEqualCircuit
		witness.Vals.Val.Assign(250)
		witness.Vals.RelVal.Assign(250)
		assert.ProverSucceeded(r1cs, &witness)
	}

	{
		var witness gnark.GreaterOrEqualCircuit
		witness.Vals.Val.Assign(250)
		witness.Vals.RelVal.Assign(120)
		assert.ProverSucceeded(r1cs, &witness)
	}

	{
		var witness gnark.GreaterOrEqualCircuit
		witness.Vals.Val.Assign(250)
		witness.Vals.RelVal.Assign(350)
		assert.ProverFailed(r1cs, &witness)
	}
}

func TestLess(t *testing.T) {
	assert := groth16.NewAssert(t)

	var ltCircuit gnark.LessCircuit
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &ltCircuit)
	assert.NoError(err)

	{
		var witness gnark.LessCircuit
		witness.Vals.Val.Assign(250)
		witness.Vals.RelVal.Assign(250)
		assert.ProverFailed(r1cs, &witness)
	}

	{
		var witness gnark.LessCircuit
		witness.Vals.Val.Assign(120)
		witness.Vals.RelVal.Assign(250)
		assert.ProverSucceeded(r1cs, &witness)
	}

	{
		var witness gnark.LessCircuit
		witness.Vals.Val.Assign(350)
		witness.Vals.RelVal.Assign(250)
		assert.ProverFailed(r1cs, &witness)
	}

	{
		var witness gnark.LessCircuit
		witness.Vals.Val.Assign(249)
		witness.Vals.RelVal.Assign(250)
		assert.ProverSucceeded(r1cs, &witness)
	}
}

func TestGreater(t *testing.T) {
	assert := groth16.NewAssert(t)

	var ltCircuit gnark.GreaterCircuit
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &ltCircuit)
	assert.NoError(err)

	{
		var witness gnark.GreaterCircuit
		witness.Vals.Val.Assign(250)
		witness.Vals.RelVal.Assign(250)
		assert.ProverFailed(r1cs, &witness)
	}

	{
		var witness gnark.GreaterCircuit
		witness.Vals.Val.Assign(250)
		witness.Vals.RelVal.Assign(120)
		assert.ProverSucceeded(r1cs, &witness)
	}

	{
		var witness gnark.GreaterCircuit
		witness.Vals.Val.Assign(250)
		witness.Vals.RelVal.Assign(350)
		assert.ProverFailed(r1cs, &witness)
	}

	{
		var witness gnark.GreaterCircuit
		witness.Vals.Val.Assign(250)
		witness.Vals.RelVal.Assign(249)
		assert.ProverSucceeded(r1cs, &witness)
	}
}

func TestProofHash(t *testing.T) {
	assert := groth16.NewAssert(t)

	var pfHashCircuit gnark.ProofHashCircuit
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &pfHashCircuit)
	assert.NoError(err)

	{
		proofString := "9f3aac14a60502ce8a8084d876e9da3ac85191aadc25003d3f81a41eff1f5a389b1177672ca50ee865a9a0563479ea316571d3f3895ab914a4312378f6e89e781dd0447826aebeb42335ec2ab89cd41fea4d797a376d621bf139b5030f873e3487eb40948f4c58dab967ea2e890c722e2ba85d8caa0afdb6301d360d27d966c0"
		proofBytes, err := hex.DecodeString(proofString)
		assert.NoError(err)
		assert.Equal(128, len(proofBytes))

		var publicWitness gnark.ProofHashCircuit
		var i big.Int
		hFunc := mimc.NewMiMC("seed")

		chunks := 6
		chunkSize := fr.Bytes
		proofLen := len(proofBytes)
		for index := 0; index < chunks; index++ {
			var elem fr.Element
			if index*chunkSize < proofLen {
				elem.SetBytes(proofBytes[index*chunkSize : (index+1)*chunkSize])
			}
			b := elem.Bytes()
			hFunc.Write(b[:])
			publicWitness.Proof[index].Assign(elem)
		}
		i.SetBytes(hFunc.Sum(nil))
		fmt.Println(i.String())
		publicWitness.Hash.Assign(i)

		assert.ProverSucceeded(r1cs, &publicWitness)
	}
}

func TestProofEddsa(t *testing.T) {
	assert := groth16.NewAssert(t)

	var pfEddsaCircuit gnark.ProofEddsaCircuit
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &pfEddsaCircuit)
	assert.NoError(err)

	{
		proofString := "9f3aac14a60502ce8a8084d876e9da3ac85191aadc25003d3f81a41eff1f5a389b1177672ca50ee865a9a0563479ea316571d3f3895ab914a4312378f6e89e781dd0447826aebeb42335ec2ab89cd41fea4d797a376d621bf139b5030f873e3487eb40948f4c58dab967ea2e890c722e2ba85d8caa0afdb6301d360d27d966c0"
		proofBytes, err := hex.DecodeString(proofString)
		assert.NoError(err)
		assert.Equal(128, len(proofBytes))

		var publicWitness gnark.ProofEddsaCircuit
		hFunc := mimc.NewMiMC("seed")

		chunks := 6
		chunkSize := fr.Bytes
		for index := 0; index < chunks; index++ {
			var elem fr.Element
			if index*chunkSize < len(proofBytes) {
				elem.SetBytes(proofBytes[index*chunkSize : (index+1)*chunkSize])
			}
			b := elem.Bytes()
			hFunc.Write(b[:])
			publicWitness.Msg[index].Assign(elem)
		}
		hash := hFunc.Sum(nil)

		src := rand.NewSource(0)
		r := rand.New(src)

		privKey, _ := eddsa.GenerateKey(r)
		pubKey := privKey.PublicKey

		sigBytes, err := privKey.Sign(hash, hFunc)
		if err != nil {
			t.Error("failed to sign invoice data")
			return
		}

		verified, err := pubKey.Verify(sigBytes, hash, hFunc)
		if err != nil || !verified {
			t.Error("failed to verify invoice data")
			return
		}

		var point twistededwards.PointAffine
		point.SetBytes(pubKey.Bytes())
		x := point.X.Bytes()
		y := point.Y.Bytes()
		publicWitness.PubKey.A.X.Assign(x[:])
		publicWitness.PubKey.A.Y.Assign(y[:])

		point.SetBytes(sigBytes[:32])
		x2 := point.X.Bytes()
		y2 := point.Y.Bytes()
		publicWitness.Sig.R.X.Assign(x2[:])
		publicWitness.Sig.R.Y.Assign(y2[:])
		publicWitness.Sig.S1.Assign(sigBytes[32:48])
		publicWitness.Sig.S2.Assign(sigBytes[48:])

		assert.ProverSucceeded(r1cs, &publicWitness)
	}
}
