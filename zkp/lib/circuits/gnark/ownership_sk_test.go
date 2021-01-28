package gnark

import (
	"math/rand"
	"testing"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/crypto/signature"
	eddsabn256 "github.com/consensys/gnark/crypto/signature/eddsa/bn256"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
	edwardsbn256 "github.com/consensys/gurvy/bn256/twistededwards"
)

func TestOwnershipSkBN256(t *testing.T) {
	assert := groth16.NewAssert(t)

	var ownershipSkCircuit OwnershipSkCircuit

	r1cs, err := frontend.Compile(gurvy.BN256, &ownershipSkCircuit)
	assert.NoError(err)

	{
		var witness OwnershipSkCircuit
		witness.Pk.A.X.Assign(42)
		witness.Pk.A.Y.Assign(42)
		witness.Sk.Assign(42)

		assert.ProverFailed(r1cs, &witness)
	}

	{
		// Generate eddsa bn256 sk, pk
		signature.Register(signature.EDDSA_BN256, eddsabn256.GenerateKeyInterfaces)

		src := rand.NewSource(0)
		r := rand.New(src)

		privKey, err := signature.EDDSA_BN256.New(r)
		assert.NoError(err)
		pubKey := privKey.Public()

		// Parse pk, sk
		var pointbn256 edwardsbn256.PointAffine
		pointbn256.SetBytes(pubKey.Bytes()[:32])
		pubkeyAx := pointbn256.X.Bytes()
		pubkeyAy := pointbn256.Y.Bytes()
		pkAx := pubkeyAx[:]
		pkAy := pubkeyAy[:]

		privkeyScalar := privKey.Bytes()[32:64]

		// Check constraints for generate eddsa bn256 sk, pk
		var witness OwnershipSkCircuit
		witness.Pk.A.X.Assign(pkAx)
		witness.Pk.A.Y.Assign(pkAy)
		witness.Sk.Assign(privkeyScalar)

		assert.SolvingSucceeded(r1cs, &witness)
	}

}
