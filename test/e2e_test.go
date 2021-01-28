// +build integration

package test

import (
	"bytes"
	"encoding/hex"
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

func TestMerkleImplementationsRootHashCalculationMismatch(t *testing.T) {
	hFunc := mimc.NewMiMC("seed")

	proofs := []string{
		"aa5500ca9af223afdec21989169de5c63938274908f09ee85a233fd1a7396bba89ea271a41a7d38014dfffbdcbe806d0726c5dc4eef7f178ea52de45852697d51f2c74152e1fbbed79ebdfd1235788ea2b1637e6ed49a33a05653133e21a5cfdaa86f1acc9588b17838f8da88a5398cb324b1289aa7759457ddccddf53ee1ca9",
		"9f2becacfe12908f1766b00ed6c7c1d7aa0aa65d2c9651d3aa70b30d25a884aeac1e50a5848f3c2ce9877a690d56801da287224ec2be2e1f26fd73b519fa1b7a19980d9b770a872d03612bd217ea4ff2f6a3bef527997f1eea30098e6772ca8cb033c3f019ce79f794419d2db6039855759e29addc72836fb3a99379e4d5e572",
	}

	hashes := make([]byte, hFunc.Size()*len(proofs))
	for i := 0; i < len(proofs); i++ {
		hFunc.Reset()
		hFunc.Write([]byte(proofs[i]))
		sum := hFunc.Sum(nil)
		copy(hashes[i*hFunc.Size():(i+1)*hFunc.Size()], sum)
	}

	var buf bytes.Buffer
	_, err := buf.Write(hashes)
	if err != nil {
		t.Error("failed to write hashes to buffer")
		return
	}
	merkleRoot, proofSet, numLeaves, err := gnark_merkle.BuildReaderProof(&buf, hFunc, hFunc.Size(), 0)
	if err != nil {
		t.Error("failed to build reader proof")
		return
	}

	t.Logf("proofset: %s, %s", hex.EncodeToString(proofSet[0]), hex.EncodeToString(proofSet[1]))
	t.Logf("numLeaves: %d", numLeaves)

	t.Log("gnark merkle implementation:")
	hashString := []string{
		hex.EncodeToString(hashes[:32]),
		hex.EncodeToString(hashes[32:]),
	}
	t.Logf("hashes: %s, %s root: %s", hashString[0], hashString[1], hex.EncodeToString(merkleRoot))

	t.Log("provide merkle implementation:")
	tr := merkletree.NewMerkleTree(hFunc)
	hashMatches := []bool{false, false}

	index, hash := tr.Add([]byte(proofs[0]))
	hashMatches[0] = hash == hashString[0]
	t.Logf("index/hash: %d / %s", index, hash)
	index, hash = tr.Add([]byte(proofs[1]))
	hashMatches[1] = hash == hashString[1]
	t.Logf("index/hash: %d / %s", index, hash)
	// root := tr.Recalculate()
	root := tr.Root()
	t.Logf("root: %s", root)
	t.Logf("hash 0 matches: %v, hash 1 matches: %v, root matches: %v", hashMatches[0], hashMatches[1], root == hex.EncodeToString(merkleRoot))

	if root == hex.EncodeToString(merkleRoot) {
		t.Error("calculated root for each implementation should not match for reasons to be investigated")
		return
	}
}
