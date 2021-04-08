// +build unit

package gnark

import (
	"fmt"
	"math/big"
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	edwardsbls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/twistededwards"
	eddsabls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/twistededwards/eddsa"
	edwardsbls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards"
	eddsabls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards/eddsa"
	edwardsbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	eddsabn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	edwardsbw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/twistededwards"
	eddsabw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/twistededwards/eddsa"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	libgnark "github.com/provideapp/privacy/zkp/lib/circuits/gnark"
)

func parseSignature(id ecc.ID, buf []byte) ([]byte, []byte, []byte) {
	var pointbn254 edwardsbn254.PointAffine
	var pointbls12381 edwardsbls12381.PointAffine
	var pointbls12377 edwardsbls12377.PointAffine
	var pointbw6761 edwardsbw6761.PointAffine

	switch id {
	case ecc.BN254:
		pointbn254.SetBytes(buf[:32])
		a, b := parsePoint(id, buf)
		c := buf[32:]
		return a[:], b[:], c
	case ecc.BLS12_381:
		pointbls12381.SetBytes(buf[:32])
		a, b := parsePoint(id, buf)
		c := buf[32:]
		return a[:], b[:], c
	case ecc.BLS12_377:
		pointbls12377.SetBytes(buf[:32])
		a, b := parsePoint(id, buf)
		c := buf[32:]
		return a[:], b[:], c
	case ecc.BW6_761:
		pointbw6761.SetBytes(buf[:48])
		a, b := parsePoint(id, buf)
		c := buf[48:]
		return a[:], b[:], c
	default:
		return buf, buf, buf
	}
}

func parsePoint(id ecc.ID, buf []byte) ([]byte, []byte) {
	var pointbn254 edwardsbn254.PointAffine
	var pointbls12381 edwardsbls12381.PointAffine
	var pointbls12377 edwardsbls12377.PointAffine
	var pointbw6761 edwardsbw6761.PointAffine

	switch id {
	case ecc.BN254:
		pointbn254.SetBytes(buf[:32])
		a := pointbn254.X.Bytes()
		b := pointbn254.Y.Bytes()
		return a[:], b[:]
	case ecc.BLS12_381:
		pointbls12381.SetBytes(buf[:32])
		a := pointbls12381.X.Bytes()
		b := pointbls12381.Y.Bytes()
		return a[:], b[:]
	case ecc.BLS12_377:
		pointbls12377.SetBytes(buf[:32])
		a := pointbls12377.X.Bytes()
		b := pointbls12377.Y.Bytes()
		return a[:], b[:]
	case ecc.BW6_761:
		pointbw6761.SetBytes(buf[:48])
		a := pointbw6761.X.Bytes()
		b := pointbw6761.Y.Bytes()
		return a[:], b[:]
	default:
		return buf, buf
	}
}

func parseSkScalar(id ecc.ID, buf []byte) []byte {
	switch id {
	case ecc.BN254:
		scalar := buf[32:64]
		return scalar
	case ecc.BLS12_381:
		scalar := buf[32:64]
		return scalar
	case ecc.BLS12_377:
		scalar := buf[32:64]
		return scalar
	case ecc.BW6_761:
		scalar := buf[48:96]
		return scalar
	default:
		return buf
	}
}

func TestBaselineDocumentComplete(t *testing.T) {
	assert := groth16.NewAssert(t)

	signature.Register(signature.EDDSA_BN254, eddsabn254.GenerateKeyInterfaces)
	signature.Register(signature.EDDSA_BLS12_381, eddsabls12381.GenerateKeyInterfaces)
	signature.Register(signature.EDDSA_BLS12_377, eddsabls12377.GenerateKeyInterfaces)
	signature.Register(signature.EDDSA_BW6_761, eddsabw6761.GenerateKeyInterfaces)

	type confSig struct {
		h hash.Hash
		s signature.SignatureScheme
	}

	confs := map[ecc.ID]confSig{
		ecc.BN254:     {hash.MIMC_BN254, signature.EDDSA_BN254},
		ecc.BLS12_381: {hash.MIMC_BLS12_381, signature.EDDSA_BLS12_381},
		ecc.BLS12_377: {hash.MIMC_BLS12_377, signature.EDDSA_BLS12_377},
		ecc.BW6_761:   {hash.MIMC_BW6_761, signature.EDDSA_BW6_761},
	}

	for id, conf := range confs {
		var baselineDocumentComplete libgnark.BaselineDocumentCompleteCircuit
		r1cs, err := frontend.Compile(id, backend.GROTH16, &baselineDocumentComplete)
		assert.NoError(err)

		fmt.Println(id)
		// Correct sk, pk, sig, hash, preimage
		{
			// Generate eddsa sk, pk
			src := rand.NewSource(0)
			r := rand.New(src)
			privKey, err := conf.s.New(r)
			assert.NoError(err)
			pubKey := privKey.Public()

			// Parse sk, pk
			pubkeyAx, pubkeyAy := parsePoint(id, pubKey.Bytes())
			privkeyScalar := parseSkScalar(id, privKey.Bytes())
			privKeyScalarLength := len(privkeyScalar)
			privKeyScalarUpper := privkeyScalar[:privKeyScalarLength/2]
			privKeyScalarLower := privkeyScalar[privKeyScalarLength/2:]

			// Generate signature for hash given pk, sk
			hFunc := conf.h.New("seed")
			var preimage big.Int
			preimage.SetString("35", 10)
			hFunc.Write(preimage.Bytes())
			hash := hFunc.Sum(nil)
			fmt.Println(hash)

			sig, err := privKey.Sign(hash, hFunc)
			assert.NoError(err)

			// Parse signature
			sigRx, sigRy, sigS := parseSignature(id, sig)

			var witness libgnark.BaselineDocumentCompleteCircuit
			witness.Doc.PreImage.Assign(preimage)
			witness.Doc.Hash.Assign(hash)
			witness.Pk.A.X.Assign(pubkeyAx)
			witness.Pk.A.Y.Assign(pubkeyAy)
			witness.Sk.Upper.Assign(privKeyScalarUpper)
			witness.Sk.Lower.Assign(privKeyScalarLower)
			witness.Sig.R.A.X.Assign(sigRx)
			witness.Sig.R.A.Y.Assign(sigRy)
			witness.Sig.S.Assign(sigS)

			assert.SolvingSucceeded(r1cs, &witness)
			//assert.ProverSucceeded(r1cs, &witness)
		}
	}
}
