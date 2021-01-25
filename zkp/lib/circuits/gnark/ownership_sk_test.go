package gnark

import (
	"testing"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gurvy"
)

func TestOwnershipSkBN256(t *testing.T) {
	assert := groth16.NewAssert(t)

	var ownershipSkCircuit OwnershipSkCircuit

	r1cs, err := frontend.Compile(gurvy.BN256, &ownershipSkCircuit)
	assert.NoError(err)

	{
		params, err := twistededwards.NewEdCurve(gurvy.BN256)
		assert.NoError(err)

		var witness OwnershipSkCircuit
		witness.Pk.A.X.Assign(42)
		witness.Pk.A.Y.Assign(42)
		witness.Pk.Curve = params
		witness.Sk.Assign(42)

		assert.ProverFailed(r1cs, &witness)
	}

	{
		/*
			var seed [32]byte
			s := []byte("eddsa")
			for i, v := range s {
				seed[i] = v
			}

			// ll 43-45: error eddsa is undefined for New and GetCurveParams when imported
			// refer to https://github.com/ConsenSys/gnark/blob/master/crypto/signature/eddsa/bn256/eddsa.go
			// why is mimc_bn256 defined and eddsa_bn256 undefined
			// prove should be successful with generated eddsa pk,sk
			hFunc := mimc_bn256.NewMiMC("seed")
			pk, sk := eddsa_bn256.New(seed, hFunc)

			params, err := eddsa_bn256.GetCurveParams()
			assert.NoError(err)
		*/

		params, err := twistededwards.NewEdCurve(gurvy.BN256)
		assert.NoError(err)

		var witness OwnershipSkCircuit
		witness.Pk.A.X.Assign(0)
		witness.Pk.A.Y.Assign(1)
		witness.Pk.Curve = params
		witness.Sk.Assign(0)

		assert.ProverSucceeded(r1cs, &witness)
	}

}
