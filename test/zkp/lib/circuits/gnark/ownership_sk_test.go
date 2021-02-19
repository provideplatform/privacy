package gnark

import (
	"math/rand"
	"testing"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/crypto/signature"

	eddsabls377 "github.com/consensys/gnark/crypto/signature/eddsa/bls377"
	eddsabls381 "github.com/consensys/gnark/crypto/signature/eddsa/bls381"
	eddsabn256 "github.com/consensys/gnark/crypto/signature/eddsa/bn256"
	eddsabw761 "github.com/consensys/gnark/crypto/signature/eddsa/bw761"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
	edwardsbls377 "github.com/consensys/gurvy/bls377/twistededwards"
	edwardsbls381 "github.com/consensys/gurvy/bls381/twistededwards"
	edwardsbn256 "github.com/consensys/gurvy/bn256/twistededwards"
	edwardsbw761 "github.com/consensys/gurvy/bw761/twistededwards"
	libgnark "github.com/provideapp/privacy/zkp/lib/circuits/gnark"
)

func parseKeys(id gurvy.ID, pubKeyBuf []byte, privKeyBuf []byte) ([]byte, []byte, []byte) {
	var pointbn256 edwardsbn256.PointAffine
	var pointbls381 edwardsbls381.PointAffine
	var pointbls377 edwardsbls377.PointAffine
	var pointbw761 edwardsbw761.PointAffine

	switch id {
	case gurvy.BN256:
		pointbn256.SetBytes(pubKeyBuf[:32])
		aX := pointbn256.X.Bytes()
		aY := pointbn256.Y.Bytes()
		scalar := privKeyBuf[32:64]
		return aX[:], aY[:], scalar
	case gurvy.BLS381:
		pointbls381.SetBytes(pubKeyBuf[:32])
		aX := pointbls381.X.Bytes()
		aY := pointbls381.Y.Bytes()
		scalar := privKeyBuf[32:64]
		return aX[:], aY[:], scalar
	case gurvy.BLS377:
		pointbls377.SetBytes(pubKeyBuf[:32])
		aX := pointbls377.X.Bytes()
		aY := pointbls377.Y.Bytes()
		scalar := privKeyBuf[32:64]
		return aX[:], aY[:], scalar
	case gurvy.BW761:
		pointbw761.SetBytes(pubKeyBuf[:48])
		aX := pointbw761.X.Bytes()
		aY := pointbw761.Y.Bytes()
		scalar := privKeyBuf[48:96]
		return aX[:], aY[:], scalar
	default:
		return pubKeyBuf, pubKeyBuf, privKeyBuf
	}
}

func TestOwnershipSk(t *testing.T) {
	assert := groth16.NewAssert(t)

	signature.Register(signature.EDDSA_BN256, eddsabn256.GenerateKeyInterfaces)
	signature.Register(signature.EDDSA_BLS381, eddsabls381.GenerateKeyInterfaces)
	signature.Register(signature.EDDSA_BLS377, eddsabls377.GenerateKeyInterfaces)
	signature.Register(signature.EDDSA_BW761, eddsabw761.GenerateKeyInterfaces)

	confs := map[gurvy.ID]signature.SignatureScheme{
		gurvy.BN256:  signature.EDDSA_BN256,
		gurvy.BLS381: signature.EDDSA_BLS381,
		gurvy.BLS377: signature.EDDSA_BLS377,
		gurvy.BW761:  signature.EDDSA_BW761,
	}

	for id, ss := range confs {
		var ownershipSkCircuit libgnark.OwnershipSkCircuit
		r1cs, err := frontend.Compile(id, &ownershipSkCircuit)
		assert.NoError(err)

		// Correct sk, pk
		{
			// Generate eddsa sk, pk
			src := rand.NewSource(0)
			r := rand.New(src)
			privKey, err := ss.New(r)
			assert.NoError(err)
			pubKey := privKey.Public()

			// Parse sk, pk
			pubkeyAx, pubkeyAy, privkeyScalar := parseKeys(id, pubKey.Bytes(), privKey.Bytes())
			privKeyScalarLength := len(privkeyScalar)
			privKeyScalarUpper := privkeyScalar[:privKeyScalarLength/2]
			privKeyScalarLower := privkeyScalar[privKeyScalarLength/2:]

			var witness libgnark.OwnershipSkCircuit
			witness.Pk.A.X.Assign(pubkeyAx)
			witness.Pk.A.Y.Assign(pubkeyAy)

			witness.Sk.Upper.Assign(privKeyScalarUpper)
			witness.Sk.Lower.Assign(privKeyScalarLower)

			assert.SolvingSucceeded(r1cs, &witness)
			//assert.ProverSucceeded(r1cs, &witness)
		}

		// Incorrect sk, pk
		{
			var witness libgnark.OwnershipSkCircuit
			witness.Pk.A.X.Assign(42) // / these are nonsense values for this circuit
			witness.Pk.A.Y.Assign(42)
			witness.Sk.Upper.Assign(42)
			witness.Sk.Lower.Assign(0)

			assert.SolvingFailed(r1cs, &witness)
			//assert.ProverFailed(r1cs, &witness)
		}

	}
}
