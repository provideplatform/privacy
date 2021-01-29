// +build integration

package test

import (
	"bytes"
	"encoding/hex"
	"math"
	"math/big"
	"testing"
	"time"

	gnark_merkle "github.com/consensys/gnark/crypto/accumulator/merkletree"
	mimc "github.com/consensys/gnark/crypto/hash/mimc/bn256"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/privacy/store/providers/merkletree"

	privacy "github.com/provideservices/provide-go/api/privacy"
)

func circuitParamsFactory(provider, identifier string) map[string]interface{} {
	return map[string]interface{}{
		"curve":          "BN256",
		"identifier":     identifier,
		"name":           "my 1337 circuit",
		"provider":       provider,
		"proving_scheme": "groth16",
	}
}

func TestCreateCircuitGroth16CubicProofGenerationFailureConstraintNotSatisfied(t *testing.T) {
	testUserID, _ := uuid.NewV4()
	token, _ := userTokenFactory(testUserID)
	params := circuitParamsFactory("gnark", "cubic")

	circuit, err := privacy.CreateCircuit(*token, params)
	if err != nil {
		t.Errorf("failed to create circuit; %s", err.Error())
		return
	}

	t.Logf("created circuit %v", circuit)

	// timeout due to async calls
	time.Sleep(time.Duration(2) * time.Second)

	_, err = privacy.Prove(*token, circuit.ID.String(), map[string]interface{}{
		"witness": map[string]interface{}{
			"X": "3",
			"Y": "9", // this will fail...
		},
	})
	if err == nil {
		t.Error("proof generation should have failed due to unsatisfied constraint")
	}
}

func TestBaselineDocumentProofGenerationFailureConstraintNotSatisfied(t *testing.T) {
	testUserID, _ := uuid.NewV4()
	token, _ := userTokenFactory(testUserID)
	params := circuitParamsFactory("gnark", "baseline_document")

	circuit, err := privacy.CreateCircuit(*token, params)
	if err != nil {
		t.Errorf("failed to create circuit; %s", err.Error())
		return
	}

	t.Logf("created circuit %v", circuit)

	// timeout due to async calls
	time.Sleep(time.Duration(2) * time.Second)

	_, err = privacy.Prove(*token, circuit.ID.String(), map[string]interface{}{
		"witness": map[string]interface{}{
			"PreImage": "3", // these are nonsense values for this circuit
			"Hash":     "9",
		},
	})
	if err == nil {
		t.Error("proof generation should have failed due to unsatisfied constraint")
	}
}

func TestCreateCircuitGroth16Cubic(t *testing.T) {
	testUserID, _ := uuid.NewV4()
	token, _ := userTokenFactory(testUserID)
	params := circuitParamsFactory("gnark", "cubic")

	circuit, err := privacy.CreateCircuit(*token, params)
	if err != nil {
		t.Errorf("failed to create circuit; %s", err.Error())
		return
	}

	t.Logf("created circuit %v", circuit)

	// timeout due to async calls
	time.Sleep(time.Duration(2) * time.Second)

	proof, err := privacy.Prove(*token, circuit.ID.String(), map[string]interface{}{
		"witness": map[string]interface{}{
			"X": "3",
			"Y": "35",
		},
	})
	if err != nil {
		t.Errorf("failed to generate proof; %s", err.Error())
		return
	}

	verification, err := privacy.Verify(*token, circuit.ID.String(), map[string]interface{}{
		"proof": proof.Proof,
		"witness": map[string]interface{}{
			"X": "3",
			"Y": "35",
		},
	})
	if err != nil {
		t.Errorf("failed to verify proof; %s", err.Error())
		return
	}

	t.Logf("proof/verification: %v / %v", proof.Proof, verification.Result)
}

func TestBaselineDocument(t *testing.T) {
	testUserID, _ := uuid.NewV4()
	token, _ := userTokenFactory(testUserID)
	params := circuitParamsFactory("gnark", "baseline_document")

	circuit, err := privacy.CreateCircuit(*token, params)
	if err != nil {
		t.Errorf("failed to create circuit; %s", err.Error())
		return
	}

	t.Logf("created circuit %v", circuit)

	// timeout due to async calls
	time.Sleep(time.Duration(2) * time.Second)

	var dv DocVars
	dv.val = 1234.5678
	dv.text = "test"
	var i big.Int

	preImage := i.SetBytes(dv.Serialize()).String()

	proof, err := privacy.Prove(*token, circuit.ID.String(), map[string]interface{}{
		"witness": map[string]interface{}{
			"PreImage": preImage,
			"Hash":     "20060286978070528279958951500719148627258111740306120210467537499973541529993",
		},
	})
	if err != nil {
		t.Errorf("failed to generate proof; %s", err.Error())
		return
	}

	verification, err := privacy.Verify(*token, circuit.ID.String(), map[string]interface{}{
		"proof": proof.Proof,
		"witness": map[string]interface{}{
			"PreImage": preImage,
			"Hash":     "20060286978070528279958951500719148627258111740306120210467537499973541529993",
		},
	})
	if err != nil {
		t.Errorf("failed to verify proof; %s", err.Error())
		return
	}

	t.Logf("proof/verification: %v / %v", proof.Proof, verification.Result)
}

func TestBaselineRollup(t *testing.T) {
	testUserID, _ := uuid.NewV4()
	token, _ := userTokenFactory(testUserID)
	params := circuitParamsFactory("gnark", "baseline_document")

	circuit, err := privacy.CreateCircuit(*token, params)
	if err != nil {
		t.Errorf("failed to create circuit; %s", err.Error())
		return
	}

	t.Logf("created circuit %v", circuit)

	// timeout due to async calls
	time.Sleep(time.Duration(2) * time.Second)

	var dv DocVars
	dv.val = 1234.5678
	dv.text = "test"
	var i big.Int

	preImage := i.SetBytes(dv.Serialize()).String()

	proof, err := privacy.Prove(*token, circuit.ID.String(), map[string]interface{}{
		"witness": map[string]interface{}{
			"PreImage": preImage,
			"Hash":     "20060286978070528279958951500719148627258111740306120210467537499973541529993",
		},
	})
	if err != nil {
		t.Errorf("failed to generate proof; %s", err.Error())
		return
	}

	verification, err := privacy.Verify(*token, circuit.ID.String(), map[string]interface{}{
		"proof": proof.Proof,
		"witness": map[string]interface{}{
			"PreImage": preImage,
			"Hash":     "20060286978070528279958951500719148627258111740306120210467537499973541529993",
		},
	})
	if err != nil {
		t.Errorf("failed to verify proof; %s", err.Error())
		return
	}

	t.Logf("proof/verification: %v / %v", proof.Proof, verification.Result)

	data := make([]byte, len(*proof.Proof))
	copy(data, []byte(*proof.Proof))

	tree := merkletree.NewMerkleTree(mimc.NewMiMC("seed"))
	index, hash := tree.RawAdd(data)

	t.Logf("added proof to merkle tree at index/hash: %v / %v", index, hash)
}

func TestMerkleImplementations(t *testing.T) {
	hFunc := mimc.NewMiMC("seed")

	proofs := []string{
		"aa5500ca9af223afdec21989169de5c63938274908f09ee85a233fd1a7396bba89ea271a41a7d38014dfffbdcbe806d0726c5dc4eef7f178ea52de45852697d51f2c74152e1fbbed79ebdfd1235788ea2b1637e6ed49a33a05653133e21a5cfdaa86f1acc9588b17838f8da88a5398cb324b1289aa7759457ddccddf53ee1ca9",
		"9f2becacfe12908f1766b00ed6c7c1d7aa0aa65d2c9651d3aa70b30d25a884aeac1e50a5848f3c2ce9877a690d56801da287224ec2be2e1f26fd73b519fa1b7a19980d9b770a872d03612bd217ea4ff2f6a3bef527997f1eea30098e6772ca8cb033c3f019ce79f794419d2db6039855759e29addc72836fb3a99379e4d5e572",
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}

	var buf bytes.Buffer
	segmentSize := hFunc.Size()

	// Pad out tree with default hashes if proof count is not a power of two
	paddedSize := int(math.Exp2(math.Ceil(math.Log2(float64(len(proofs))))))
	for i := 0; i < len(proofs); i++ {
		hFunc.Reset()
		hFunc.Write([]byte(proofs[i]))
		sum := hFunc.Sum(nil)
		buf.Write(sum)
	}
	for i := len(proofs); i < paddedSize; i++ {
		hFunc.Reset()
		hFunc.Write([]byte{})
		sum := hFunc.Sum(nil)
		buf.Write(sum)
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
		hFunc.Write([]byte(proofs[i]))
		sum := hFunc.Sum(nil)
		index, hash := tr.RawAdd(sum)
		t.Logf("index/hash: %d / %s", index, hash)
	}
	for i := len(proofs); i < paddedSize; i++ {
		hFunc.Reset()
		hFunc.Write([]byte{})
		sum := hFunc.Sum(nil)
		index, hash := tr.RawAdd(sum)
		t.Logf("index/hash: %d / %s", index, hash)
	}
	tr.Recalculate()
	root := tr.Root()
	t.Logf("root: %s", root)

	if root != hex.EncodeToString(merkleRoot) {
		t.Error("calculated root for each implementation should match for proof counts which are powers of two")
		return
	}
}
