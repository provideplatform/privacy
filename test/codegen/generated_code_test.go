package test

import (
	"bytes"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/consensys/gnark/backend/plonk"
)

func TestGenRollupCircuit(t *testing.T) {
	assert := plonk.NewAssert(t)

	var circuit GenRollupCircuit
	r1cs, err := frontend.Compile(ecc.BN254, backend.PLONK, &circuit)
	assert.NoError(err)

	{
		proofs := []string{
			"aa5500ca9af223afdec21989169de5c63938274908f09ee85a233fd1a7396bba89ea271a41a7d38014dfffbdcbe806d0726c5dc4eef7f178ea52de45852697d51f2c74152e1fbbed79ebdfd1235788ea2b1637e6ed49a33a05653133e21a5cfdaa86f1acc9588b17838f8da88a5398cb324b1289aa7759457ddccddf53ee1ca9",
			"9f2becacfe12908f1766b00ed6c7c1d7aa0aa65d2c9651d3aa70b30d25a884aeac1e50a5848f3c2ce9877a690d56801da287224ec2be2e1f26fd73b519fa1b7a19980d9b770a872d03612bd217ea4ff2f6a3bef527997f1eea30098e6772ca8cb033c3f019ce79f794419d2db6039855759e29addc72836fb3a99379e4d5e572",
		}

		var buf bytes.Buffer
		for i := 0; i < len(proofs); i++ {
			digest, _ := mimc.Sum("seed", []byte(proofs[i]))
			buf.Write(digest)
		}

		proofIndex := uint64(0)
		hFunc := mimc.NewMiMC("seed")
		segmentSize := hFunc.Size()
		merkleRoot, proofSet, numLeaves, err := merkletree.BuildReaderProof(&buf, hFunc, segmentSize, proofIndex)
		assert.NoError(err)

		var witness GenRollupCircuit
		proofVerified := merkletree.VerifyProof(hFunc, merkleRoot, proofSet, proofIndex, numLeaves)
		assert.True(proofVerified)
		merkleProofHelper := merkle.GenerateProofHelper(proofSet, proofIndex, numLeaves)

		witness.RootHash.Assign(merkleRoot)
		for i := 0; i < len(proofSet); i++ {
			witness.Proofs[i].Assign(proofSet[i])
			if i < len(proofSet)-1 {
				witness.Helpers[i].Assign(merkleProofHelper[i])
			}
		}

		assert.ProverSucceeded(r1cs, &witness)
	}
}

