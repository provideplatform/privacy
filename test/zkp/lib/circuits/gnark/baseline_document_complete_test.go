package gnark

import (
	"math/big"
	"math/rand"
	"testing"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/crypto/hash"
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

func parseSignature(id gurvy.ID, buf []byte) ([]byte, []byte, []byte) {
	var pointbn256 edwardsbn256.PointAffine
	var pointbls381 edwardsbls381.PointAffine
	var pointbls377 edwardsbls377.PointAffine
	var pointbw761 edwardsbw761.PointAffine
	switch id {
	case gurvy.BN256:
		pointbn256.SetBytes(buf[:32])
		a, b := parsePoint(id, buf)
		c := buf[32:]
		return a[:], b[:], c
	case gurvy.BLS381:
		pointbls381.SetBytes(buf[:32])
		a, b := parsePoint(id, buf)
		c := buf[32:]
		return a[:], b[:], c
	case gurvy.BLS377:
		pointbls377.SetBytes(buf[:32])
		a, b := parsePoint(id, buf)
		c := buf[32:]
		return a[:], b[:], c
	case gurvy.BW761:
		pointbw761.SetBytes(buf[:48])
		a, b := parsePoint(id, buf)
		c := buf[48:]
		return a[:], b[:], c
	default:
		return buf, buf, buf
	}
}

func parsePoint(id gurvy.ID, buf []byte) ([]byte, []byte) {
	var pointbn256 edwardsbn256.PointAffine
	var pointbls381 edwardsbls381.PointAffine
	var pointbls377 edwardsbls377.PointAffine
	var pointbw761 edwardsbw761.PointAffine
	switch id {
	case gurvy.BN256:
		pointbn256.SetBytes(buf[:32])
		a := pointbn256.X.Bytes()
		b := pointbn256.Y.Bytes()
		return a[:], b[:]
	case gurvy.BLS381:
		pointbls381.SetBytes(buf[:32])
		a := pointbls381.X.Bytes()
		b := pointbls381.Y.Bytes()
		return a[:], b[:]
	case gurvy.BLS377:
		pointbls377.SetBytes(buf[:32])
		a := pointbls377.X.Bytes()
		b := pointbls377.Y.Bytes()
		return a[:], b[:]
	case gurvy.BW761:
		pointbw761.SetBytes(buf[:48])
		a := pointbw761.X.Bytes()
		b := pointbw761.Y.Bytes()
		return a[:], b[:]
	default:
		return buf, buf
	}
}

func parseSkScalar(id gurvy.ID, buf []byte) []byte {
	switch id {
	case gurvy.BN256:
		scalar := buf[32:64]
		return scalar
	case gurvy.BLS381:
		scalar := buf[32:64]
		return scalar
	case gurvy.BLS377:
		scalar := buf[32:64]
		return scalar
	case gurvy.BW761:
		scalar := buf[48:96]
		return scalar
	default:
		return buf
	}
}

func TestBaselineDocumentComplete(t *testing.T) {
	assert := groth16.NewAssert(t)

	signature.Register(signature.EDDSA_BN256, eddsabn256.GenerateKeyInterfaces)
	signature.Register(signature.EDDSA_BLS381, eddsabls381.GenerateKeyInterfaces)
	signature.Register(signature.EDDSA_BLS377, eddsabls377.GenerateKeyInterfaces)
	signature.Register(signature.EDDSA_BW761, eddsabw761.GenerateKeyInterfaces)

	type confSig struct {
		h hash.Hash
		s signature.SignatureScheme
	}

	confs := map[gurvy.ID]confSig{
		gurvy.BN256:  {hash.MIMC_BN256, signature.EDDSA_BN256},
		gurvy.BLS381: {hash.MIMC_BLS381, signature.EDDSA_BLS381},
		gurvy.BLS377: {hash.MIMC_BLS377, signature.EDDSA_BLS377},
		gurvy.BW761:  {hash.MIMC_BW761, signature.EDDSA_BW761},
	}

	for id, conf := range confs {
		var baselineDocumentComplete libgnark.BaselineDocumentCompleteCircuit
		r1cs, err := frontend.Compile(gurvy.BN256, &baselineDocumentComplete)
		assert.NoError(err)

		// Correct sk, pf, sig, hash, preimage
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

			// Generate signature for hash given pk, sk
			hFunc := conf.h.New("seed")
			var preimage big.Int
			preimage.SetString("35", 10)
			hFunc.Write(preimage.Bytes())
			hash := hFunc.Sum(nil)

			sig, err := privKey.Sign(hash, hFunc)
			assert.NoError(err)

			// Parse signature
			sigRx, sigRy, sigS := parseSignature(id, sig)

			var witness libgnark.BaselineDocumentCompleteCircuit
			witness.Doc.PreImage.Assign(preimage)
			witness.Doc.Hash.Assign(hash)
			witness.Pk.A.X.Assign(pubkeyAx)
			witness.Pk.A.Y.Assign(pubkeyAy)
			witness.Sk.Assign(privkeyScalar)
			witness.Sig.R.A.X.Assign(sigRx)
			witness.Sig.R.A.Y.Assign(sigRy)
			witness.Sig.S.Assign(sigS)

			assert.SolvingSucceeded(r1cs, &witness)
			//assert.ProverSucceeded(r1cs, &witness)
		}
	}
}
