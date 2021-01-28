package gnark

import (
	"math/big"
	"math/rand"
	"testing"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/crypto/hash"
	"github.com/consensys/gnark/crypto/signature"
	eddsabn256 "github.com/consensys/gnark/crypto/signature/eddsa/bn256"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
	edwardsbn256 "github.com/consensys/gurvy/bn256/twistededwards"
)

func TestBaselineDocumentCompleteBN256(t *testing.T) {
	assert := groth16.NewAssert(t)

	var baselineDocumentComplete BaselineDocumentCompleteCircuit

	r1cs, err := frontend.Compile(gurvy.BN256, &baselineDocumentComplete)
	assert.NoError(err)

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

		// Generate signature for hash given pk, sk
		hFunc := hash.MIMC_BN256.New("seed")
		preimage := 35
		hash := "16130099170765464552823636852555369511329944820189892919423002775646948828469"
		var frHash big.Int
		frHash.SetString(hash, 10)
		hashBin := frHash.Bytes()

		signature, err := privKey.Sign(hashBin[:], hFunc)
		assert.NoError(err)

		// Parse signature
		// sigRx, sigRy, sigS
		var sigpointbn256 edwardsbn256.PointAffine
		sigpointbn256.SetBytes(signature[:32])
		signatureRx := sigpointbn256.X.Bytes()
		signatureRy := sigpointbn256.Y.Bytes()
		sigRx := signatureRx[:]
		sigRy := signatureRy[:]

		sigS := signature[32:]

		// Check constraints
		var witness BaselineDocumentCompleteCircuit
		witness.Doc.PreImage.Assign(preimage)
		witness.Doc.Hash.Assign(hash)
		witness.Pk.A.X.Assign(pkAx)
		witness.Pk.A.Y.Assign(pkAy)
		witness.Sk.Assign(privkeyScalar)
		witness.Sig.R.A.X.Assign(sigRx)
		witness.Sig.R.A.Y.Assign(sigRy)
		witness.Sig.S.Assign(sigS)

		assert.SolvingSucceeded(r1cs, &witness)
	}

}
