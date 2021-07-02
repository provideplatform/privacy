// +build unit

package gnark

import (
	"bytes"
	"encoding/hex"
	"io"
	"math"
	"testing"

	gnark_merkle "github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	gnark_hash "github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/provideplatform/privacy/store/providers/merkletree"
	"github.com/provideplatform/privacy/zkp/lib/circuits/gnark"
)

var curveID = ecc.BN254

func TestBaselineRollupMerkleCircuit(t *testing.T) {
	hFunc := mimc.NewMiMC("seed")

	var dv DocVars
	var buf bytes.Buffer

	// write different vars into the bytes buffer, using the digest to ensure they are of uniform length
	// for gnark's merkle tree reader
	dv.h = gnark_hash.MIMC_BN254
	dv.val = 1234.5678
	dv.text = "test1"
	digest, _ := mimc.Sum("seed", dv.Digest())
	buf.Write(digest)

	dv.val = 102020.35
	dv.text = "test2"
	digest, _ = mimc.Sum("seed", dv.Digest())
	buf.Write(digest)

	dv.val = 145.10
	dv.text = "test3"
	digest, _ = mimc.Sum("seed", dv.Digest())
	buf.Write(digest)

	dv.val = 1110007.78
	dv.text = "test4"
	digest, _ = mimc.Sum("seed", dv.Digest())
	buf.Write(digest)

	segmentSize := dv.Size()
	proofIndex := uint64(0)
	merkleRoot, proofSet, numLeaves, err := gnark_merkle.BuildReaderProof(&buf, hFunc, segmentSize, proofIndex)
	if err != nil {
		t.Errorf("failed to build merkle proof; %s", err.Error())
		return
	}

	proofVerified := gnark_merkle.VerifyProof(hFunc, merkleRoot, proofSet, proofIndex, numLeaves)
	if !proofVerified {
		t.Errorf("failed to verify merkle proof; %s", err.Error())
		return
	}

	var baselineCircuit, publicWitness gnark.BaselineRollupCircuit

	// to compile the circuit, the witnesses must be allocated in the correct sizes
	baselineCircuit.Proofs = make([]frontend.Variable, len(proofSet))
	baselineCircuit.Helpers = make([]frontend.Variable, len(proofSet)-1)
	r1cs, err := frontend.Compile(curveID, backend.GROTH16, &baselineCircuit)
	if err != nil {
		t.Errorf("failed to compile circuit; %s", err.Error())
		return
	}

	merkleProofHelper := merkle.GenerateProofHelper(proofSet, proofIndex, numLeaves)

	publicWitness.Proofs = make([]frontend.Variable, len(proofSet))
	publicWitness.Helpers = make([]frontend.Variable, len(proofSet)-1)
	publicWitness.RootHash.Assign(merkleRoot)
	for i := 0; i < len(proofSet); i++ {
		publicWitness.Proofs[i].Assign(proofSet[i])

		if i < len(proofSet)-1 {
			publicWitness.Helpers[i].Assign(merkleProofHelper[i])
		}
	}

	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		t.Errorf("failed to setup circuit; %s", err.Error())
		return
	}

	// log size of proving key to evaluate requirements of vault
	// size of proving key grows roughly linearly with size of proof set
	provingKeyBuf := new(bytes.Buffer)
	_, err = pk.(io.WriterTo).WriteTo(provingKeyBuf)
	if err != nil {
		t.Errorf("failed to write proving key to bytes buffer; %s", err.Error())
		return
	}

	t.Logf("proving key size in bytes: %d", provingKeyBuf.Len())

	proof, err := groth16.Prove(r1cs, pk, &publicWitness)
	if err != nil {
		t.Errorf("failed to generate proof; %s", err.Error())
		return
	}

	err = groth16.Verify(proof, vk, &publicWitness)
	if err != nil {
		t.Errorf("failed to verify proof; %s", err.Error())
		return
	}

	t.Logf("proof verified")
}

func TestMerkleImplementationsWithPaddedTree(t *testing.T) {
	hFunc := mimc.NewMiMC("seed")

	proofs := []string{
		"aa5500ca9af223afdec21989169de5c63938274908f09ee85a233fd1a7396bba89ea271a41a7d38014dfffbdcbe806d0726c5dc4eef7f178ea52de45852697d51f2c74152e1fbbed79ebdfd1235788ea2b1637e6ed49a33a05653133e21a5cfdaa86f1acc9588b17838f8da88a5398cb324b1289aa7759457ddccddf53ee1ca9",
		"9f2becacfe12908f1766b00ed6c7c1d7aa0aa65d2c9651d3aa70b30d25a884aeac1e50a5848f3c2ce9877a690d56801da287224ec2be2e1f26fd73b519fa1b7a19980d9b770a872d03612bd217ea4ff2f6a3bef527997f1eea30098e6772ca8cb033c3f019ce79f794419d2db6039855759e29addc72836fb3a99379e4d5e572",
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}

	var buf bytes.Buffer
	segmentSize := hFunc.Size()

	// Pad out tree with default hashes if proof count is not a power of two
	// This appears to be due to lack of auto-balancing in our merkle tree
	paddedSize := int(math.Exp2(math.Ceil(math.Log2(float64(len(proofs))))))
	for i := 0; i < len(proofs); i++ {
		hFunc.Reset()
		// mimc Write never returns an error
		hFunc.Write([]byte(proofs[i]))
		sum := hFunc.Sum(nil)
		buf.Write(sum)
	}
	for i := len(proofs); i < paddedSize; i++ {
		empty := make([]byte, segmentSize)
		buf.Write(empty)
	}

	proofIndex := uint64(0)
	merkleRoot, proofSet, numLeaves, err := gnark_merkle.BuildReaderProof(&buf, hFunc, segmentSize, proofIndex)
	if err != nil {
		t.Error("failed to build merkle proof")
		return
	}

	proofVerified := gnark_merkle.VerifyProof(hFunc, merkleRoot, proofSet, proofIndex, numLeaves)
	if !proofVerified {
		t.Error("failed to verify merkle proof")
		return
	}

	t.Log("gnark merkle implementation:")
	t.Logf("root: %s", hex.EncodeToString(merkleRoot))

	t.Log("provide merkle implementation:")
	tr := merkletree.NewMerkleTree(hFunc)

	for i := 0; i < len(proofs); i++ {
		hFunc.Reset()
		// mimc Write never returns an error
		hFunc.Write([]byte(proofs[i]))
		sum := hFunc.Sum(nil)
		index, hash := tr.RawAdd(sum)
		t.Logf("index/hash: %d / %s", index, hash)
	}
	for i := len(proofs); i < paddedSize; i++ {
		empty := make([]byte, segmentSize)
		index, hash := tr.RawAdd(empty)
		t.Logf("index/hash: %d / %s", index, hash)
	}
	root := tr.Recalculate()
	t.Logf("root: %s", root)

	if root != hex.EncodeToString(merkleRoot) {
		t.Error("calculated root for each implementation should match for proof counts which are powers of two")
		return
	}
}
