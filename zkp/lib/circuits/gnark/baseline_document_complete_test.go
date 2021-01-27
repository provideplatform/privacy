package gnark

import (
	"testing"

	"github.com/consensys/gnark/backend/groth16"
	mimc_bn256 "github.com/consensys/gnark/crypto/hash/mimc/bn256"
	eddsa_bn256 "github.com/consensys/gnark/crypto/signature/eddsa/bn256"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gurvy"
	fr_bn256 "github.com/consensys/gurvy/bn256/fr"
)

func TestBaselineDocumentComplete(t *testing.T) {
	assert := groth16.NewAssert(t)

	var baselineDocumentComplete BaselineDocumentCompleteCircuit

	r1cs, err := frontend.Compile(gurvy.BN256, &baselineDocumentComplete)
	assert.NoError(err)

	{
		var seed [32]byte
		s := []byte("eddsa")
		for i, v := range s {
			seed[i] = v
		}
		hFunc := mimc_bn256.NewMiMC("seed")
		// FIX: Why is eddsa_bn256 undefined
		pk, sk := eddsa_bn256.New(seed, hFunc)

		params, err := twistededwards.NewEdCurve(gurvy.BN256)
		assert.NoError(err)

		// FIX: Wrong preimage for hash?
		preimage := 35
		hash := "19226210204356004706765360050059680583735587569269469539941275797408975356275"
		var frMsg fr_bn256.Element
		frMsg.SetString(hash)
		hashBin := frMsg.Bytes()
		// FIX: Why is eddsa_bn256 undefined
		signature, err := eddsa_bn256.Sign(hashBin[:], pk, sk)
		assert.NoError(err)

		var witness BaselineDocumentCompleteCircuit
		witness.Doc.PreImage.Assign(preimage)
		witness.Doc.Hash.Assign(hash)

		witness.Pk.A.X.Assign(pk.A.X)
		witness.Pk.A.Y.Assign(pk.A.Y)
		witness.Pk.Curve = params

		witness.Sk = sk

		witness.Sig.R.A.X.Assign(signature.R.X)
		witness.Sig.R.A.Y.Assign(signature.R.Y)
		witness.Sig.S.Assign(signature.S)

		assert.ProverSucceeded(r1cs, &witness)
	}

}
