// +build unit

package gnark

import (
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	edwardsbls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/twistededwards"
	eddsabls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/twistededwards/eddsa"
	edwardsbls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards"
	eddsabls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards/eddsa"

	edwardsbls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/twistededwards"
	eddsabls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/twistededwards/eddsa"
	edwardsbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	eddsabn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	edwardsbw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/twistededwards"
	eddsabw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/twistededwards/eddsa"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	libgnark "github.com/provideplatform/privacy/zkp/lib/circuits/gnark"
)

func parseKeys(id ecc.ID, pubKeyBuf []byte, privKeyBuf []byte) ([]byte, []byte, []byte) {
	var pointbn254 edwardsbn254.PointAffine
	var pointbls12381 edwardsbls12381.PointAffine
	var pointbls12377 edwardsbls12377.PointAffine
	var pointbw6761 edwardsbw6761.PointAffine
	var pointbls24315 edwardsbls24315.PointAffine

	switch id {
	case ecc.BN254:
		pointbn254.SetBytes(pubKeyBuf[:32])
		aX := pointbn254.X.Bytes()
		aY := pointbn254.Y.Bytes()
		scalar := privKeyBuf[32:64]
		return aX[:], aY[:], scalar
	case ecc.BLS12_381:
		pointbls12381.SetBytes(pubKeyBuf[:32])
		aX := pointbls12381.X.Bytes()
		aY := pointbls12381.Y.Bytes()
		scalar := privKeyBuf[32:64]
		return aX[:], aY[:], scalar
	case ecc.BLS12_377:
		pointbls12377.SetBytes(pubKeyBuf[:32])
		aX := pointbls12377.X.Bytes()
		aY := pointbls12377.Y.Bytes()
		scalar := privKeyBuf[32:64]
		return aX[:], aY[:], scalar
	case ecc.BW6_761:
		pointbw6761.SetBytes(pubKeyBuf[:48])
		aX := pointbw6761.X.Bytes()
		aY := pointbw6761.Y.Bytes()
		scalar := privKeyBuf[48:96]
		return aX[:], aY[:], scalar
	case ecc.BLS24_315:
		pointbls24315.SetBytes(pubKeyBuf[:32])
		aX := pointbls24315.X.Bytes()
		aY := pointbls24315.Y.Bytes()
		scalar := privKeyBuf[32:64]
		return aX[:], aY[:], scalar
	default:
		return pubKeyBuf, pubKeyBuf, privKeyBuf
	}
}

func TestOwnershipSkGroth16(t *testing.T) {
	assert := groth16.NewAssert(t)

	signature.Register(signature.EDDSA_BN254, eddsabn254.GenerateKeyInterfaces)
	signature.Register(signature.EDDSA_BLS12_381, eddsabls12381.GenerateKeyInterfaces)
	signature.Register(signature.EDDSA_BLS12_377, eddsabls12377.GenerateKeyInterfaces)
	signature.Register(signature.EDDSA_BW6_761, eddsabw6761.GenerateKeyInterfaces)
	signature.Register(signature.EDDSA_BLS24_315, eddsabls24315.GenerateKeyInterfaces)

	type confSig struct {
		h hash.Hash
		s signature.SignatureScheme
	}

	confs := map[ecc.ID]confSig{
		ecc.BN254:     {hash.MIMC_BN254, signature.EDDSA_BN254},
		ecc.BLS12_381: {hash.MIMC_BLS12_381, signature.EDDSA_BLS12_381},
		ecc.BLS12_377: {hash.MIMC_BLS12_377, signature.EDDSA_BLS12_377},
		ecc.BW6_761:   {hash.MIMC_BW6_761, signature.EDDSA_BW6_761},
		ecc.BLS24_315: {hash.MIMC_BLS24_315, signature.EDDSA_BLS24_315},
	}

	for id, ss := range confs {
		var ownershipSkCircuit libgnark.OwnershipSkCircuit
		r1cs, err := frontend.Compile(id, backend.GROTH16, &ownershipSkCircuit)
		assert.NoError(err)

		// Correct sk, pk
		{
			// Generate eddsa sk, pk
			src := rand.NewSource(0)
			r := rand.New(src)
			privKey, err := ss.s.New(r)
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
			witness.Pk.A.X.Assign(42) // these are nonsense values for this circuit
			witness.Pk.A.Y.Assign(42)
			witness.Sk.Upper.Assign(42)
			witness.Sk.Lower.Assign(0)

			assert.SolvingFailed(r1cs, &witness)
			//assert.ProverFailed(r1cs, &witness)
		}

	}
}

func TestOwnershipSkPlonk(t *testing.T) {
	assert := plonk.NewAssert(t)

	signature.Register(signature.EDDSA_BN254, eddsabn254.GenerateKeyInterfaces)
	signature.Register(signature.EDDSA_BLS12_381, eddsabls12381.GenerateKeyInterfaces)
	signature.Register(signature.EDDSA_BLS12_377, eddsabls12377.GenerateKeyInterfaces)
	signature.Register(signature.EDDSA_BW6_761, eddsabw6761.GenerateKeyInterfaces)
	signature.Register(signature.EDDSA_BLS24_315, eddsabls24315.GenerateKeyInterfaces)

	type confSig struct {
		h hash.Hash
		s signature.SignatureScheme
	}

	confs := map[ecc.ID]confSig{
		ecc.BN254:     {hash.MIMC_BN254, signature.EDDSA_BN254},
		ecc.BLS12_381: {hash.MIMC_BLS12_381, signature.EDDSA_BLS12_381},
		ecc.BLS12_377: {hash.MIMC_BLS12_377, signature.EDDSA_BLS12_377},
		ecc.BW6_761:   {hash.MIMC_BW6_761, signature.EDDSA_BW6_761},
		ecc.BLS24_315: {hash.MIMC_BLS24_315, signature.EDDSA_BLS24_315},
	}

	for id, ss := range confs {
		var ownershipSkCircuit libgnark.OwnershipSkCircuit
		r1cs, err := frontend.Compile(id, backend.PLONK, &ownershipSkCircuit)
		assert.NoError(err)

		// Correct sk, pk
		{
			// Generate eddsa sk, pk
			src := rand.NewSource(0)
			r := rand.New(src)
			privKey, err := ss.s.New(r)
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

			pk, vk, err := plonk.Setup(r1cs, getKzgScheme(r1cs))
			assert.NoError(err, "Generating public data should not have failed")

			proof, err := plonk.Prove(r1cs, pk, &witness)
			assert.NoError(err, "Proving with good witness should not output an error")

			err = plonk.Verify(proof, vk, &witness)
			assert.NoError(err, "Verifying correct proof with correct witness should not output an error")
		}

		// Incorrect sk, pk
		{
			var witness libgnark.OwnershipSkCircuit
			witness.Pk.A.X.Assign(42) // these are nonsense values for this circuit
			witness.Pk.A.Y.Assign(42)
			witness.Sk.Upper.Assign(42)
			witness.Sk.Lower.Assign(0)

			pk, _, err := plonk.Setup(r1cs, getKzgScheme(r1cs))
			assert.NoError(err, "Generating public data should not have failed")

			_, err = plonk.Prove(r1cs, pk, &witness)
			assert.Error(err, "Proving with bad witness should output an error")
		}

	}
}
