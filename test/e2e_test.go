// +build integration

package test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"math"
	"math/big"
	"math/rand"
	"os"
	"strings"
	"testing"
	"time"

	gnark_merkle "github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	mimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	gnark_hash "github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/accumulator/merkle"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/privacy/store/providers/merkletree"
	"github.com/provideplatform/privacy/zkp/lib/circuits/gnark"

	privacy "github.com/provideplatform/provide-go/api/privacy"
)

func waitForAsync() {
	time.Sleep(time.Duration(5) * time.Second)
}

var curveID = ecc.BN254

const testProvingSchemeGroth16 = "groth16"
const testProvingSchemePlonk = "plonk"

func circuitParamsFactory(provider, identifier string, provingScheme string) map[string]interface{} {
	return map[string]interface{}{
		"curve":          strings.ToUpper(curveID.String()),
		"identifier":     identifier,
		"name":           "my 1337 circuit",
		"provider":       provider,
		"proving_scheme": provingScheme,
	}
}

func setBobEnv() {
	os.Setenv("IDENT_API_HOST", "localhost:8084")
	os.Setenv("PRIVACY_API_HOST", "localhost:8083")
}

func setAliceEnv() {
	os.Setenv("IDENT_API_HOST", "localhost:8081")
	os.Setenv("PRIVACY_API_HOST", "localhost:8080")
}

func TestCreateCircuitGroth16CubicProofGenerationFailureConstraintNotSatisfied(t *testing.T) {
	time.Sleep(time.Duration(10) * time.Second)
	testUserID, _ := uuid.NewV4()
	token, _ := userTokenFactory(testUserID)
	params := circuitParamsFactory("gnark", "cubic", testProvingSchemeGroth16)

	circuit, err := privacy.CreateCircuit(*token, params)
	if err != nil {
		t.Errorf("failed to create circuit; %s", err.Error())
		return
	}

	t.Logf("created circuit %v", circuit)

	waitForAsync()

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
	params := circuitParamsFactory("gnark", "mimc", testProvingSchemeGroth16)

	circuit, err := privacy.CreateCircuit(*token, params)
	if err != nil {
		t.Errorf("failed to create circuit; %s", err.Error())
		return
	}

	t.Logf("created circuit %v", circuit)

	waitForAsync()

	_, err = privacy.Prove(*token, circuit.ID.String(), map[string]interface{}{
		"witness": map[string]interface{}{
			"Preimage": "3", // these are nonsense values for this circuit
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
	params := circuitParamsFactory("gnark", "cubic", testProvingSchemeGroth16)

	circuit, err := privacy.CreateCircuit(*token, params)
	if err != nil {
		t.Errorf("failed to create circuit; %s", err.Error())
		return
	}

	t.Logf("created circuit %v", circuit)

	waitForAsync()

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
	params := circuitParamsFactory("gnark", "mimc", testProvingSchemeGroth16)

	circuit, err := privacy.CreateCircuit(*token, params)
	if err != nil {
		t.Errorf("failed to create circuit; %s", err.Error())
		return
	}

	t.Logf("created circuit %v", circuit)

	waitForAsync()

	var dv DocVars
	dv.val = 1234.5678
	dv.text = "test"
	dv.h = gnark_hash.MIMC_BN254
	var i big.Int

	preImage := dv.Digest()
	preImageString := i.SetBytes(preImage).String()

	// mimc Sum merely calls Write which never returns an error
	hash, _ := mimc.Sum("seed", preImage)
	hashString := i.SetBytes(hash).String()

	proof, err := privacy.Prove(*token, circuit.ID.String(), map[string]interface{}{
		"witness": map[string]interface{}{
			"Preimage": preImageString,
			"Hash":     hashString,
		},
	})
	if err != nil {
		t.Errorf("failed to generate proof; %s", err.Error())
		return
	}

	verification, err := privacy.Verify(*token, circuit.ID.String(), map[string]interface{}{
		"proof": proof.Proof,
		"witness": map[string]interface{}{
			"Preimage": preImageString,
			"Hash":     hashString,
		},
	})
	if err != nil {
		t.Errorf("failed to verify proof; %s", err.Error())
		return
	}

	t.Logf("proof/verification: %v / %v", proof.Proof, verification.Result)
}

func TestBaselineRollupMerkleCircuitWithoutPrivacyApi(t *testing.T) {
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
	var provingKeyBuf *bytes.Buffer
	provingKeyBuf = new(bytes.Buffer)
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

func TestProcurement(t *testing.T) {
	testUserID, _ := uuid.NewV4()
	token, _ := userTokenFactory(testUserID)
	params := circuitParamsFactory("gnark", "purchase_order", testProvingSchemeGroth16)

	circuit, err := privacy.CreateCircuit(*token, params)
	if err != nil {
		t.Errorf("failed to create circuit; %s", err.Error())
		return
	}

	t.Logf("created circuit %v", circuit)

	hFunc := mimc.NewMiMC("seed")

	tr := merkletree.NewMerkleTree(hFunc)

	globalPurchaseOrderNumber := []byte("ENTITY-ORDER-NUMBER-20210101-001") // GlobalPONumber from form
	soNumber := []byte("1234567890")
	certificateNumber, err := uuid.FromString("12345678-1234-5678-9abc-123456789abc")
	if err != nil {
		t.Error("failed to convert uuid to bytes")
		return
	}

	// mimc Write never returns an error
	hFunc.Write(globalPurchaseOrderNumber)
	hFunc.Write(soNumber)
	hFunc.Write(certificateNumber.Bytes())

	// preimage is itself a digest due to the field element size limitation of the curve
	preImage := hFunc.Sum(nil)
	var i big.Int

	preImageString := i.SetBytes(preImage).String()

	// mimc Sum merely calls Write which never returns an error
	hash, _ := mimc.Sum("seed", preImage)
	hashString := i.SetBytes(hash).String()

	waitForAsync()

	proof, err := privacy.Prove(*token, circuit.ID.String(), map[string]interface{}{
		"witness": map[string]interface{}{
			"Document.Preimage": preImageString,
			"Document.Hash":     hashString,
		},
	})
	if err != nil {
		t.Errorf("failed to generate proof; %s", err.Error())
		return
	}

	verification, err := privacy.Verify(*token, circuit.ID.String(), map[string]interface{}{
		"proof": proof.Proof,
		"witness": map[string]interface{}{
			"Document.Preimage": preImageString,
			"Document.Hash":     hashString,
		},
	})
	if err != nil {
		t.Errorf("failed to verify proof; %s", err.Error())
		return
	}

	t.Logf("purchase order proof/verification: %v / %v", proof.Proof, verification.Result)

	index, h := tr.RawAdd([]byte(*proof.Proof))
	t.Logf("added purchase order proof to merkle tree, index/hash: %v / %v", index, h)

	storeID := circuit.StoreID
	params = circuitParamsFactory("gnark", "sales_order", testProvingSchemeGroth16)
	params["store_id"] = storeID

	circuit, err = privacy.CreateCircuit(*token, params)
	if err != nil {
		t.Errorf("failed to create circuit; %s", err.Error())
		return
	}

	t.Logf("created circuit %v", circuit)

	globalSalesOrderNumber := []byte("ENTITY-1234567890")
	createdOn := []byte("01/02/2021 04:40 PM UTC")

	hFunc.Reset()
	hFunc.Write(globalPurchaseOrderNumber)
	hFunc.Write(globalSalesOrderNumber)
	hFunc.Write(createdOn)
	hFunc.Write([]byte(*proof.Proof))
	preImage = hFunc.Sum(nil)

	preImageString = i.SetBytes(preImage).String()

	// mimc Sum merely calls Write which never returns an error
	hash, _ = mimc.Sum("seed", preImage)
	hashString = i.SetBytes(hash).String()

	waitForAsync()

	proof, err = privacy.Prove(*token, circuit.ID.String(), map[string]interface{}{
		"witness": map[string]interface{}{
			"Document.Preimage": preImageString,
			"Document.Hash":     hashString,
		},
	})
	if err != nil {
		t.Errorf("failed to generate proof; %s", err.Error())
		return
	}

	verification, err = privacy.Verify(*token, circuit.ID.String(), map[string]interface{}{
		"proof": proof.Proof,
		"witness": map[string]interface{}{
			"Document.Preimage": preImageString,
			"Document.Hash":     hashString,
		},
	})
	if err != nil {
		t.Errorf("failed to verify proof; %s", err.Error())
		return
	}

	t.Logf("sales order proof/verification: %v / %v", proof.Proof, verification.Result)

	index, h = tr.RawAdd([]byte(*proof.Proof))
	t.Logf("added sales order proof to merkle tree, index/hash: %v / %v", index, h)

	params = circuitParamsFactory("gnark", "shipment_notification", testProvingSchemeGroth16)
	params["store_id"] = storeID

	circuit, err = privacy.CreateCircuit(*token, params)
	if err != nil {
		t.Errorf("failed to create circuit; %s", err.Error())
		return
	}

	t.Logf("created circuit %v", circuit)

	globalShipmentNumber := []byte("ENTITY-0000123456")
	soldTo := []byte("56785678")

	hFunc.Reset()
	hFunc.Write(globalPurchaseOrderNumber)
	hFunc.Write(globalShipmentNumber)
	hFunc.Write(soldTo)
	hFunc.Write([]byte(*proof.Proof))
	preImage = hFunc.Sum(nil)

	preImageString = i.SetBytes(preImage).String()

	// mimc Sum merely calls Write which never returns an error
	hash, _ = mimc.Sum("seed", preImage)
	hashString = i.SetBytes(hash).String()

	waitForAsync()

	proof, err = privacy.Prove(*token, circuit.ID.String(), map[string]interface{}{
		"witness": map[string]interface{}{
			"Document.Preimage": preImageString,
			"Document.Hash":     hashString,
		},
	})
	if err != nil {
		t.Errorf("failed to generate proof; %s", err.Error())
		return
	}

	verification, err = privacy.Verify(*token, circuit.ID.String(), map[string]interface{}{
		"proof": proof.Proof,
		"witness": map[string]interface{}{
			"Document.Preimage": preImageString,
			"Document.Hash":     hashString,
		},
	})
	if err != nil {
		t.Errorf("failed to verify proof; %s", err.Error())
		return
	}

	t.Logf("shipment notification proof/verification: %v / %v", proof.Proof, verification.Result)

	index, h = tr.RawAdd([]byte(*proof.Proof))
	t.Logf("added shipment notification proof to merkle tree, index/hash: %v / %v", index, h)

	params = circuitParamsFactory("gnark", "goods_receipt", testProvingSchemeGroth16)
	params["store_id"] = storeID

	circuit, err = privacy.CreateCircuit(*token, params)
	if err != nil {
		t.Errorf("failed to create circuit; %s", err.Error())
		return
	}

	t.Logf("created circuit %v", circuit)

	globalGoodsReceiptNumber := []byte("ENTITY-ORDER-NUMBER-20210101-001-GR")
	createdOn = []byte("01/04/2021 01:40 PM UTC")

	hFunc.Reset()
	hFunc.Write(globalPurchaseOrderNumber)
	hFunc.Write(globalGoodsReceiptNumber)
	hFunc.Write(createdOn)
	hFunc.Write([]byte(*proof.Proof))
	preImage = hFunc.Sum(nil)

	preImageString = i.SetBytes(preImage).String()

	// mimc Sum merely calls Write which never returns an error
	hash, _ = mimc.Sum("seed", preImage)
	hashString = i.SetBytes(hash).String()

	waitForAsync()

	proof, err = privacy.Prove(*token, circuit.ID.String(), map[string]interface{}{
		"witness": map[string]interface{}{
			"Document.Preimage": preImageString,
			"Document.Hash":     hashString,
		},
	})
	if err != nil {
		t.Errorf("failed to generate proof; %s", err.Error())
		return
	}

	verification, err = privacy.Verify(*token, circuit.ID.String(), map[string]interface{}{
		"proof": proof.Proof,
		"witness": map[string]interface{}{
			"Document.Preimage": preImageString,
			"Document.Hash":     hashString,
		},
	})
	if err != nil {
		t.Errorf("failed to verify proof; %s", err.Error())
		return
	}

	t.Logf("goods receipt proof/verification: %v / %v", proof.Proof, verification.Result)

	index, h = tr.RawAdd([]byte(*proof.Proof))
	t.Logf("added goods receipt proof to merkle tree, index/hash: %v / %v", index, h)

	privKey, _ := eddsa.GenerateKey(rand.New(rand.NewSource(time.Now().UnixNano())))
	pubKey := privKey.PublicKey

	var invoiceData big.Int
	invoiceIntStr := "123456789123456789123456789123456789"
	invoiceData.SetString(invoiceIntStr, 10)
	invoiceDataBytes := invoiceData.Bytes()

	sigBytes, err := privKey.Sign(invoiceDataBytes, hFunc)
	if err != nil {
		t.Error("failed to sign invoice data")
		return
	}

	verified, err := pubKey.Verify(sigBytes, invoiceDataBytes, hFunc)
	if err != nil || !verified {
		t.Error("failed to verify invoice data")
		return
	}

	params = circuitParamsFactory("gnark", "invoice", testProvingSchemeGroth16)
	params["store_id"] = storeID

	circuit, err = privacy.CreateCircuit(*token, params)
	if err != nil {
		t.Errorf("failed to create circuit; %s", err.Error())
		return
	}

	t.Logf("created circuit %v", circuit)

	var sig eddsa.Signature
	sig.SetBytes(sigBytes)

	var point twistededwards.PointAffine
	pubKeyBytes := pubKey.Bytes()
	point.SetBytes(pubKeyBytes)
	xKey := point.X.Bytes()
	xKeyString := i.SetBytes(xKey[:]).String()
	yKey := point.Y.Bytes()
	yKeyString := i.SetBytes(yKey[:]).String()

	point.SetBytes(sigBytes)
	xSig := point.X.Bytes()
	xSigString := i.SetBytes(xSig[:]).String()
	ySig := point.Y.Bytes()
	ySigString := i.SetBytes(ySig[:]).String()
	sigLen := len(sigBytes) / 2
	sigS1String := i.SetBytes(sigBytes[sigLen : sigLen+sigLen/2]).String()
	sigS2String := i.SetBytes(sigBytes[sigLen+sigLen/2:]).String()

	// this circuit takes an order of magnitude longer to complete requests due to huge internal params
	waitForAsync()
	waitForAsync()

	proof, err = privacy.Prove(*token, circuit.ID.String(), map[string]interface{}{
		"witness": map[string]interface{}{
			"Msg":        invoiceIntStr,
			"PubKey.A.X": xKeyString,
			"PubKey.A.Y": yKeyString,
			"Sig.R.X":    xSigString,
			"Sig.R.Y":    ySigString,
			"Sig.S1":     sigS1String,
			"Sig.S2":     sigS2String,
		},
	})
	if err != nil {
		t.Errorf("failed to generate proof; %s", err.Error())
		return
	}

	waitForAsync()
	waitForAsync()
	waitForAsync()
	waitForAsync()

	verification, err = privacy.Verify(*token, circuit.ID.String(), map[string]interface{}{
		"proof": proof.Proof,
		"witness": map[string]interface{}{
			"Msg":        invoiceIntStr,
			"PubKey.A.X": xKeyString,
			"PubKey.A.Y": yKeyString,
			"Sig.R.X":    xSigString,
			"Sig.R.Y":    ySigString,
			"Sig.S1":     sigS1String,
			"Sig.S2":     sigS2String,
		},
	})
	if err != nil {
		t.Errorf("failed to verify proof; %s", err.Error())
		return
	}

	t.Logf("invoice proof/verification: %v / %v", proof.Proof, verification.Result)

	index, h = tr.RawAdd([]byte(*proof.Proof))
	t.Logf("added invoice proof to merkle tree, index/hash: %v / %v", index, h)

	root := tr.Recalculate()
	t.Logf("calculated root: %s", root)

	hashIndex := uint64(0)
	store, err := privacy.GetStoreValue(*token, circuit.ID.String(), hashIndex)
	if err != nil {
		t.Errorf("failed to get store value; %s", err.Error())
		return
	}
	t.Logf("store value index %v: %s, store root: %s", hashIndex, *store.Value, *store.Root)

	if root != *store.Root {
		t.Error("root mismatch with merkle store")
		return
	}
}

func TestProofVerifyMerkle(t *testing.T) {
	testUserID, _ := uuid.NewV4()
	token, _ := userTokenFactory(testUserID)
	params := circuitParamsFactory("gnark", "purchase_order", testProvingSchemeGroth16)

	circuit, err := privacy.CreateCircuit(*token, params)
	if err != nil {
		t.Errorf("failed to create circuit; %s", err.Error())
		return
	}

	t.Logf("created circuit %v", circuit)

	hFunc := mimc.NewMiMC("seed")

	tr := merkletree.NewMerkleTree(hFunc)

	globalPurchaseOrderNumber := []byte("ENTITY-ORDER-NUMBER-20210101-001") // GlobalPONumber from form
	soNumber := []byte("1234567890")
	certificateNumber, err := uuid.FromString("12345678-1234-5678-9abc-123456789abc")
	if err != nil {
		t.Error("failed to convert uuid to bytes")
		return
	}

	// mimc Write never returns an error
	hFunc.Write(globalPurchaseOrderNumber)
	hFunc.Write(soNumber)
	hFunc.Write(certificateNumber.Bytes())

	// preimage is itself a digest due to the field element size limitation of the curve
	preImage := hFunc.Sum(nil)
	var i big.Int

	preImageString := i.SetBytes(preImage).String()

	// mimc Sum merely calls Write which never returns an error
	hash, _ := mimc.Sum("seed", preImage)
	hashString := i.SetBytes(hash).String()

	waitForAsync()

	proof, err := privacy.Prove(*token, circuit.ID.String(), map[string]interface{}{
		"witness": map[string]interface{}{
			"Document.Preimage": preImageString,
			"Document.Hash":     hashString,
		},
	})
	if err != nil {
		t.Errorf("failed to generate proof; %s", err.Error())
		return
	}

	verification, err := privacy.Verify(*token, circuit.ID.String(), map[string]interface{}{
		"proof": proof.Proof,
		"witness": map[string]interface{}{
			"Document.Preimage": preImageString,
			"Document.Hash":     hashString,
		},
		"store": false,
	})
	if err != nil {
		t.Errorf("failed to verify proof; %s", err.Error())
		return
	}

	t.Logf("purchase order proof/verification: %v / %v", proof.Proof, verification.Result)

	index, h := tr.RawAdd([]byte(*proof.Proof))
	t.Logf("added purchase order proof to merkle tree, index/hash: %v / %v", index, h)

	root := tr.Recalculate()
	t.Logf("calculated root: %s", root)

	hashIndex := uint64(0)
	store, err := privacy.GetStoreValue(*token, circuit.ID.String(), hashIndex)
	if err != nil {
		t.Errorf("failed to get store value; %s", err.Error())
		return
	}
	t.Logf("store value index %v: %s, store root: %s", hashIndex, *store.Value, *store.Root)

	hashFromTree, err := tr.HashAt(hashIndex)
	if err != nil {
		t.Errorf("failed to get hash 0 from merkle tree")
		return
	}

	if hashFromTree != *store.Value {
		t.Errorf("hash mismatch with merkle store")
		return
	}

	if root != *store.Root {
		t.Error("root mismatch with merkle store")
		return
	}
}

func TestDuplicateProofVerifyMerkle(t *testing.T) {
	testUserID, _ := uuid.NewV4()
	token, _ := userTokenFactory(testUserID)
	params := circuitParamsFactory("gnark", "purchase_order", testProvingSchemeGroth16)

	circuit, err := privacy.CreateCircuit(*token, params)
	if err != nil {
		t.Errorf("failed to create circuit; %s", err.Error())
		return
	}

	t.Logf("created circuit %v", circuit)

	hFunc := mimc.NewMiMC("seed")

	tr := merkletree.NewMerkleTree(hFunc)

	globalPurchaseOrderNumber := []byte("ENTITY-ORDER-NUMBER-20210101-001") // GlobalPONumber from form
	soNumber := []byte("1234567890")
	certificateNumber, err := uuid.FromString("12345678-1234-5678-9abc-123456789abc")
	if err != nil {
		t.Error("failed to convert uuid to bytes")
		return
	}

	// mimc Write never returns an error
	hFunc.Write(globalPurchaseOrderNumber)
	hFunc.Write(soNumber)
	hFunc.Write(certificateNumber.Bytes())

	// preimage is itself a digest due to the field element size limitation of the curve
	preImage := hFunc.Sum(nil)
	var i big.Int

	preImageString := i.SetBytes(preImage).String()

	// mimc Sum merely calls Write which never returns an error
	hash, _ := mimc.Sum("seed", preImage)
	hashString := i.SetBytes(hash).String()

	waitForAsync()

	proof, err := privacy.Prove(*token, circuit.ID.String(), map[string]interface{}{
		"witness": map[string]interface{}{
			"Document.Preimage": preImageString,
			"Document.Hash":     hashString,
		},
	})
	if err != nil {
		t.Errorf("failed to generate proof; %s", err.Error())
		return
	}

	verification, err := privacy.Verify(*token, circuit.ID.String(), map[string]interface{}{
		"proof": proof.Proof,
		"witness": map[string]interface{}{
			"Document.Preimage": preImageString,
			"Document.Hash":     hashString,
		},
		"store": true,
	})
	if err != nil {
		t.Errorf("failed to verify proof; %s", err.Error())
		return
	}

	t.Logf("purchase order proof/verification: %v / %v", proof.Proof, verification.Result)

	index, h := tr.RawAdd([]byte(*proof.Proof))
	t.Logf("added purchase order proof to merkle tree, index/hash: %v / %v", index, h)
	index, h = tr.RawAdd([]byte(*proof.Proof))
	t.Logf("added duplicate purchase order proof to merkle tree, index/hash: %v / %v", index, h)

	root := tr.Recalculate()
	t.Logf("calculated root: %s", root)

	hashIndex := uint64(0)
	store, err := privacy.GetStoreValue(*token, circuit.ID.String(), hashIndex)
	if err != nil {
		t.Errorf("failed to get store value; %s", err.Error())
		return
	}
	t.Logf("store value index %v: %s, store root: %s", hashIndex, *store.Value, *store.Root)

	hashFromTree, err := tr.HashAt(hashIndex)
	if err != nil {
		t.Errorf("failed to get hash 0 from merkle tree")
		return
	}

	if hashFromTree != *store.Value {
		t.Errorf("hash mismatch with merkle store")
		return
	}

	if root != *store.Root {
		t.Error("root mismatch with merkle store")
		return
	}

	store, err = privacy.GetStoreValue(*token, circuit.ID.String(), hashIndex)
	if err != nil {
		t.Errorf("failed to get store value; %s", err.Error())
		return
	}
	t.Logf("duplicate store value index %v: %s, store root: %s", hashIndex, *store.Value, *store.Root)

	if hashFromTree != *store.Value {
		t.Errorf("hash mismatch with merkle store")
		return
	}

	if root != *store.Root {
		t.Error("root mismatch with merkle store")
		return
	}
}

func TestTwoPartyProofVerification(t *testing.T) {
	setAliceEnv()
	aliceUserID, _ := uuid.NewV4()
	aliceToken, _ := userTokenFactory(aliceUserID)
	params := circuitParamsFactory("gnark", "purchase_order", testProvingSchemeGroth16)

	aliceCircuit, err := privacy.CreateCircuit(*aliceToken, params)
	if err != nil {
		t.Errorf("failed to create circuit; %s", err.Error())
		return
	}

	t.Logf("created alice's circuit %v", aliceCircuit)

	waitForAsync()

	aliceCircuit, err = privacy.GetCircuitDetails(*aliceToken, aliceCircuit.ID.String())
	if err != nil {
		t.Errorf("failed to get circuit details; %s", err.Error())
		return
	}

	hFunc := mimc.NewMiMC("seed")

	globalPurchaseOrderNumber := []byte("ENTITY-ORDER-NUMBER-20210101-001") // GlobalPONumber from form
	soNumber := []byte("1234567890")
	certificateNumber, err := uuid.FromString("12345678-1234-5678-9abc-123456789abc")
	if err != nil {
		t.Error("failed to convert uuid to bytes")
		return
	}

	// mimc Write never returns an error
	hFunc.Write(globalPurchaseOrderNumber)
	hFunc.Write(soNumber)
	hFunc.Write(certificateNumber.Bytes())

	// preimage is itself a digest due to the field element size limitation of the curve
	preImage := hFunc.Sum(nil)
	var i big.Int

	preImageString := i.SetBytes(preImage).String()

	// mimc Sum merely calls Write which never returns an error
	hash, _ := mimc.Sum("seed", preImage)
	hashString := i.SetBytes(hash).String()

	waitForAsync()

	proof, err := privacy.Prove(*aliceToken, aliceCircuit.ID.String(), map[string]interface{}{
		"witness": map[string]interface{}{
			"Document.Preimage": preImageString,
			"Document.Hash":     hashString,
		},
	})
	if err != nil {
		t.Errorf("failed to generate proof; %s", err.Error())
		return
	}

	t.Logf("alice's proof: %v", proof.Proof)

	hashIndex := uint64(0)
	aliceStore, err := privacy.GetStoreValue(*aliceToken, aliceCircuit.ID.String(), hashIndex)
	if err != nil {
		t.Errorf("failed to get store value; %s", err.Error())
		return
	}
	t.Logf("alice's store value index %v: %s, store root: %s", hashIndex, *aliceStore.Value, *aliceStore.Root)

	setBobEnv()
	bobUserID, _ := uuid.NewV4()
	bobToken, _ := userTokenFactory(bobUserID)

	bobParams := circuitParamsFactory(*aliceCircuit.Provider, *aliceCircuit.Identifier, testProvingSchemeGroth16)
	bobParams["artifacts"] = aliceCircuit.Artifacts
	bobParams["verifier_contract"] = aliceCircuit.VerifierContract

	bobCircuit, err := privacy.CreateCircuit(*bobToken, bobParams)
	if err != nil {
		t.Errorf("failed to create circuit; %s", err.Error())
		return
	}

	t.Logf("created bob's circuit")

	waitForAsync()

	verification, err := privacy.Verify(*bobToken, bobCircuit.ID.String(), map[string]interface{}{
		"proof": proof.Proof,
		"witness": map[string]interface{}{
			"Document.Preimage": preImageString,
			"Document.Hash":     hashString,
		},
		"store": true,
	})
	if err != nil {
		t.Errorf("failed to verify proof; %s", err.Error())
		return
	}

	t.Logf("bob's verification: %v", verification.Result)

	bobStore, err := privacy.GetStoreValue(*bobToken, bobCircuit.ID.String(), hashIndex)
	if err != nil {
		t.Errorf("failed to get store value; %s", err.Error())
		return
	}
	t.Logf("bob's store value index %v: %s, store root: %s", hashIndex, *bobStore.Value, *bobStore.Root)

	if *bobStore.Value != *aliceStore.Value {
		t.Errorf("hash mismatch")
		return
	}

	if *bobStore.Root != *aliceStore.Root {
		t.Error("root mismatch")
		return
	}
}

type STAGE uint16

const (
	PURCHASE STAGE = iota
	SALES
	SHIPMENT
	GOODS
	INVOICE
)

func getProcurementWitness(stage STAGE, hFunc hash.Hash, proofString string, creditRating string) (string, map[string]interface{}) {
	var i big.Int

	certificateNumber, _ := uuid.FromString("12345678-1234-5678-9abc-123456789abc")
	createdOn := []byte("01/02/2021 04:40 PM UTC")
	globalGoodsReceiptNumber := []byte("ENTITY-ORDER-NUMBER-20210101-001-GR")
	globalPurchaseOrderNumber := []byte("ENTITY-ORDER-NUMBER-20210101-001") // GlobalPONumber from form
	globalSalesOrderNumber := []byte("ENTITY-1234567890")
	globalShipmentNumber := []byte("ENTITY-0000123456")
	goodsReceiptCreatedOn := []byte("01/04/2021 01:40 PM UTC")
	soldTo := []byte("56785678")
	soNumber := []byte("1234567890")

	identifier := ""
	hFunc.Reset()

	switch stage {
	case PURCHASE:
		// mimc Write never returns an error
		hFunc.Write(globalPurchaseOrderNumber)
		hFunc.Write(soNumber)
		hFunc.Write(certificateNumber.Bytes())
		identifier = "purchase_order"
	case SALES:
		hFunc.Write(globalPurchaseOrderNumber)
		hFunc.Write(globalSalesOrderNumber)
		hFunc.Write(createdOn)
		identifier = "sales_order"
	case SHIPMENT:
		hFunc.Write(globalPurchaseOrderNumber)
		hFunc.Write(globalShipmentNumber)
		hFunc.Write(soldTo)
		identifier = "shipment_notification"
	case GOODS:
		hFunc.Write(globalPurchaseOrderNumber)
		hFunc.Write(globalGoodsReceiptNumber)
		hFunc.Write(goodsReceiptCreatedOn)
		identifier = "goods_receipt"
	case INVOICE:
		privKey, _ := eddsa.GenerateKey(rand.New(rand.NewSource(time.Now().UnixNano())))
		pubKey := privKey.PublicKey

		var invoiceData big.Int
		invoiceIntStr := "123456789123456789123456789123456789"
		invoiceData.SetString(invoiceIntStr, 10)
		invoiceDataBytes := invoiceData.Bytes()

		sigBytes, err := privKey.Sign(invoiceDataBytes, hFunc)
		if err != nil {
			return "", nil
		}

		verified, err := pubKey.Verify(sigBytes, invoiceDataBytes, hFunc)
		if err != nil || !verified {
			return "", nil
		}

		var sig eddsa.Signature
		sig.SetBytes(sigBytes)

		var point twistededwards.PointAffine
		pubKeyBytes := pubKey.Bytes()
		point.SetBytes(pubKeyBytes)
		xKey := point.X.Bytes()
		xKeyString := i.SetBytes(xKey[:]).String()
		yKey := point.Y.Bytes()
		yKeyString := i.SetBytes(yKey[:]).String()

		point.SetBytes(sigBytes)
		xSig := point.X.Bytes()
		xSigString := i.SetBytes(xSig[:]).String()
		ySig := point.Y.Bytes()
		ySigString := i.SetBytes(ySig[:]).String()
		sigLen := len(sigBytes) / 2
		sigS1String := i.SetBytes(sigBytes[sigLen : sigLen+sigLen/2]).String()
		sigS2String := i.SetBytes(sigBytes[sigLen+sigLen/2:]).String()

		return "invoice", map[string]interface{}{
			"Msg":        invoiceIntStr,
			"PubKey.A.X": xKeyString,
			"PubKey.A.Y": yKeyString,
			"Sig.R.X":    xSigString,
			"Sig.R.Y":    ySigString,
			"Sig.S1":     sigS1String,
			"Sig.S2":     sigS2String,
		}
	}

	hFunc.Write([]byte(proofString))
	hFunc.Write([]byte(creditRating))
	preImage := hFunc.Sum(nil)
	preImageString := i.SetBytes(preImage).String()

	// mimc Sum merely calls Write which never returns an error
	hash, _ := mimc.Sum("seed", preImage)
	hashString := i.SetBytes(hash).String()

	return identifier, map[string]interface{}{
		"Document.Preimage": preImageString,
		"Document.Hash":     hashString,
	}
}

func TestTwoPartyProcurement(t *testing.T) {
	setAliceEnv()
	aliceUserID, _ := uuid.NewV4()
	aliceToken, _ := userTokenFactory(aliceUserID)
	setBobEnv()
	bobUserID, _ := uuid.NewV4()
	bobToken, _ := userTokenFactory(bobUserID)

	hFunc := mimc.NewMiMC("seed")
	tr := merkletree.NewMerkleTree(hFunc)
	var aliceCircuit, bobCircuit *privacy.Circuit
	var aliceStore *privacy.StoreValueResponse
	var err error

	proofString := ""
	hashIndex := uint64(0)

	for stage := PURCHASE; stage <= INVOICE; stage++ {
		setAliceEnv()

		identifier, witness := getProcurementWitness(stage, hFunc, proofString, "")
		aliceParams := circuitParamsFactory("gnark", identifier, testProvingSchemeGroth16)
		if aliceCircuit != nil && aliceCircuit.StoreID != nil {
			aliceParams["store_id"] = aliceCircuit.StoreID
		}
		aliceCircuit, err = privacy.CreateCircuit(*aliceToken, aliceParams)
		if err != nil {
			t.Errorf("failed to create alice's %s circuit; %s", identifier, err.Error())
			return
		}

		t.Logf("created alice's %s circuit %v", identifier, aliceCircuit)

		waitForAsync()
		if stage == INVOICE {
			waitForAsync()
		}

		aliceCircuit, err = privacy.GetCircuitDetails(*aliceToken, aliceCircuit.ID.String())
		if err != nil {
			t.Errorf("failed to get circuit details; %s", err.Error())
			return
		}

		if stage == INVOICE {
			waitForAsync()
			waitForAsync()
			waitForAsync()
			waitForAsync()
		}

		proof, err := privacy.Prove(*aliceToken, aliceCircuit.ID.String(), map[string]interface{}{
			"witness": witness,
		})
		if err != nil {
			t.Errorf("failed to generate proof; %s", err.Error())
			return
		}

		t.Logf("alice's proof: %v", proof.Proof)

		aliceStore, err = privacy.GetStoreValue(*aliceToken, aliceCircuit.ID.String(), hashIndex)
		if err != nil {
			t.Errorf("failed to get store value; %s", err.Error())
			return
		}
		t.Logf("alice's store value index %v: %s, store root: %s", hashIndex, *aliceStore.Value, *aliceStore.Root)

		setBobEnv()

		bobParams := circuitParamsFactory(*aliceCircuit.Provider, *aliceCircuit.Identifier, testProvingSchemeGroth16)
		if bobCircuit != nil && bobCircuit.StoreID != nil {
			bobParams["store_id"] = bobCircuit.StoreID
		}
		bobParams["artifacts"] = aliceCircuit.Artifacts
		bobParams["verifier_contract"] = aliceCircuit.VerifierContract

		bobCircuit, err = privacy.CreateCircuit(*bobToken, bobParams)
		if err != nil {
			t.Errorf("failed to create circuit; %s", err.Error())
			return
		}

		t.Logf("created bob's %s circuit", identifier)

		waitForAsync()
		if stage == INVOICE {
			waitForAsync()
			waitForAsync()
			waitForAsync()
		}

		verification, err := privacy.Verify(*bobToken, bobCircuit.ID.String(), map[string]interface{}{
			"proof":   proof.Proof,
			"witness": witness,
			"store":   true,
		})
		if err != nil {
			t.Errorf("failed to verify proof; %s", err.Error())
			return
		}

		t.Logf("bob's verification: %v", verification.Result)

		bobStore, err := privacy.GetStoreValue(*bobToken, bobCircuit.ID.String(), hashIndex)
		if err != nil {
			t.Errorf("failed to get store value; %s", err.Error())
			return
		}
		t.Logf("bob's store value index %v: %s, store root: %s", hashIndex, *bobStore.Value, *bobStore.Root)
		hashIndex++

		if *bobStore.Value != *aliceStore.Value {
			t.Errorf("hash mismatch")
			return
		}

		if *bobStore.Root != *aliceStore.Root {
			t.Error("root mismatch")
			return
		}

		proofString = *proof.Proof
		index, h := tr.RawAdd([]byte(proofString))
		t.Logf("added %s proof to merkle tree, index/hash: %v / %v", identifier, index, h)
	}

	root := tr.Recalculate()
	t.Logf("calculated root: %s", root)

	if root != *aliceStore.Root {
		t.Error("root mismatch with merkle store")
		return
	}
}

func TestTwoPartyProcurementIterated(t *testing.T) {
	setAliceEnv()
	provideUserID, _ := uuid.NewV4()
	provideToken, _ := userTokenFactory(provideUserID)
	setBobEnv()
	financierUserID, _ := uuid.NewV4()
	financierToken, _ := userTokenFactory(financierUserID)

	hFunc := mimc.NewMiMC("seed")
	tr := merkletree.NewMerkleTree(hFunc)
	var provideCircuit, financierCircuit *privacy.Circuit
	var provideStore, financierStore *privacy.StoreValueResponse
	var err error

	proofString := ""
	creditRating := "AAA"
	hashIndex := uint64(0)
	var buf bytes.Buffer

	const repeat = 3
	for i := 0; i < repeat; i++ {
		for stage := PURCHASE; stage <= INVOICE; stage++ {
			setAliceEnv()

			identifier, witness := getProcurementWitness(stage, hFunc, proofString, creditRating)
			provideParams := circuitParamsFactory("gnark", identifier, testProvingSchemeGroth16)
			if provideCircuit != nil && provideCircuit.StoreID != nil {
				provideParams["store_id"] = provideCircuit.StoreID
			}
			provideCircuit, err = privacy.CreateCircuit(*provideToken, provideParams)
			if err != nil {
				t.Errorf("failed to create provide's %s circuit; %s", identifier, err.Error())
				return
			}

			t.Logf("created provide's %s circuit %v", identifier, provideCircuit)

			waitForAsync()
			if stage == INVOICE {
				waitForAsync()
			}

			provideCircuit, err = privacy.GetCircuitDetails(*provideToken, provideCircuit.ID.String())
			if err != nil {
				t.Errorf("failed to get circuit details; %s", err.Error())
				return
			}

			if stage == INVOICE {
				waitForAsync()
				waitForAsync()
				waitForAsync()
				waitForAsync()
			}

			proof, err := privacy.Prove(*provideToken, provideCircuit.ID.String(), map[string]interface{}{
				"witness": witness,
			})
			if err != nil {
				t.Errorf("failed to generate proof; %s", err.Error())
				return
			}

			t.Logf("provide's proof: %v", proof.Proof)

			provideStore, err = privacy.GetStoreValue(*provideToken, provideCircuit.ID.String(), hashIndex)
			if err != nil {
				t.Errorf("failed to get store value; %s", err.Error())
				return
			}
			t.Logf("provide's store value index %v: %s, store root: %s", hashIndex, *provideStore.Value, *provideStore.Root)

			setBobEnv()

			financierParams := circuitParamsFactory(*provideCircuit.Provider, *provideCircuit.Identifier, testProvingSchemeGroth16)
			if financierCircuit != nil && financierCircuit.StoreID != nil {
				financierParams["store_id"] = financierCircuit.StoreID
			}
			financierParams["artifacts"] = provideCircuit.Artifacts
			financierParams["verifier_contract"] = provideCircuit.VerifierContract

			financierCircuit, err = privacy.CreateCircuit(*financierToken, financierParams)
			if err != nil {
				t.Errorf("failed to create circuit; %s", err.Error())
				return
			}

			t.Logf("created financier's %s circuit", identifier)

			waitForAsync()
			if stage == INVOICE {
				waitForAsync()
				waitForAsync()
				waitForAsync()
			}

			verification, err := privacy.Verify(*financierToken, financierCircuit.ID.String(), map[string]interface{}{
				"proof":   proof.Proof,
				"witness": witness,
				"store":   true,
			})
			if err != nil {
				t.Errorf("failed to verify proof; %s", err.Error())
				return
			}

			t.Logf("financier's verification: %v", verification.Result)

			financierStore, err = privacy.GetStoreValue(*financierToken, financierCircuit.ID.String(), hashIndex)
			if err != nil {
				t.Errorf("failed to get store value; %s", err.Error())
				return
			}
			t.Logf("financier's store value index %v: %s, store root: %s", hashIndex, *financierStore.Value, *financierStore.Root)
			hashIndex++

			if *financierStore.Value != *provideStore.Value {
				t.Errorf("hash mismatch")
				return
			}

			if *financierStore.Root != *provideStore.Root {
				t.Error("root mismatch")
				return
			}

			proofString = *proof.Proof
			proofHash, _ := mimc.Sum("seed", []byte(proofString))
			buf.Write(proofHash)
			index, h := tr.RawAdd([]byte(proofString))
			t.Logf("added %s proof to merkle tree, index/hash: %v / %v", identifier, index, h)
		}
	}

	root := tr.Recalculate()
	t.Logf("calculated root: %s", root)

	if root != *provideStore.Root {
		t.Error("root mismatch with merkle store")
		return
	}

	privKey, _ := eddsa.GenerateKey(rand.New(rand.NewSource(time.Now().UnixNano())))
	pubKey := privKey.PublicKey

	var financierRootData big.Int
	financierRootData.SetString(*financierStore.Root, 16)
	financierRootDataBytes := financierRootData.Bytes()

	sigBytes, err := privKey.Sign(financierRootDataBytes, hFunc)
	if err != nil {
		t.Error("failed to sign financier root data")
		return
	}

	verified, err := pubKey.Verify(sigBytes, financierRootDataBytes, hFunc)
	if err != nil || !verified {
		t.Error("failed to verify financier root data")
		return
	}

	var sig eddsa.Signature
	sig.SetBytes(sigBytes)

	var i big.Int
	var point twistededwards.PointAffine
	pubKeyBytes := pubKey.Bytes()
	point.SetBytes(pubKeyBytes)
	xKey := point.X.Bytes()
	xKeyString := i.SetBytes(xKey[:]).String()
	yKey := point.Y.Bytes()
	yKeyString := i.SetBytes(yKey[:]).String()

	point.SetBytes(sigBytes)
	xSig := point.X.Bytes()
	xSigString := i.SetBytes(xSig[:]).String()
	ySig := point.Y.Bytes()
	ySigString := i.SetBytes(ySig[:]).String()
	sigLen := len(sigBytes) / 2
	sigS1String := i.SetBytes(sigBytes[sigLen : sigLen+sigLen/2]).String()
	sigS2String := i.SetBytes(sigBytes[sigLen+sigLen/2:]).String()

	// this circuit takes an order of magnitude longer to complete requests due to huge internal params
	waitForAsync()
	waitForAsync()

	proof, err := privacy.Prove(*financierToken, financierCircuit.ID.String(), map[string]interface{}{
		"witness": map[string]interface{}{
			"Msg":        financierRootData.String(),
			"PubKey.A.X": xKeyString,
			"PubKey.A.Y": yKeyString,
			"Sig.R.X":    xSigString,
			"Sig.R.Y":    ySigString,
			"Sig.S1":     sigS1String,
			"Sig.S2":     sigS2String,
		},
	})
	if err != nil {
		t.Errorf("failed to generate proof; %s", err.Error())
		return
	}

	waitForAsync()
	waitForAsync()
	waitForAsync()
	waitForAsync()

	verification, err := privacy.Verify(*financierToken, financierCircuit.ID.String(), map[string]interface{}{
		"proof": proof.Proof,
		"witness": map[string]interface{}{
			"Msg":        financierRootData.String(),
			"PubKey.A.X": xKeyString,
			"PubKey.A.Y": yKeyString,
			"Sig.R.X":    xSigString,
			"Sig.R.Y":    ySigString,
			"Sig.S1":     sigS1String,
			"Sig.S2":     sigS2String,
		},
	})
	if err != nil {
		t.Errorf("failed to verify proof; %s", err.Error())
		return
	}

	t.Logf("financier root signature proof/verification: %v / %v", proof.Proof, verification.Result)
}

func TestProofEddsaWithApi(t *testing.T) {
	hFunc := mimc.NewMiMC("seed")
	financierUserID, _ := uuid.NewV4()
	financierToken, _ := userTokenFactory(financierUserID)
	identifier := "proof_eddsa"

	financierParams := circuitParamsFactory("gnark", identifier, testProvingSchemeGroth16)
	financierCircuit, err := privacy.CreateCircuit(*financierToken, financierParams)
	if err != nil {
		t.Errorf("failed to create financier's %s circuit; %s", identifier, err.Error())
		return
	}

	t.Logf("created financier's %s circuit %v", identifier, financierCircuit)

	waitForAsync()
	waitForAsync()

	proofString := "9f3aac14a60502ce8a8084d876e9da3ac85191aadc25003d3f81a41eff1f5a389b1177672ca50ee865a9a0563479ea316571d3f3895ab914a4312378f6e89e781dd0447826aebeb42335ec2ab89cd41fea4d797a376d621bf139b5030f873e3487eb40948f4c58dab967ea2e890c722e2ba85d8caa0afdb6301d360d27d966c0"
	proofBytes, err := hex.DecodeString(proofString)
	if err != nil {
		t.Errorf("failed to decode proof string")
	}

	chunks := 6
	chunkSize := fr.Bytes
	witness := map[string]interface{}{}
	for index := 0; index < chunks; index++ {
		var elem fr.Element
		if index*chunkSize < len(proofBytes) {
			elem.SetBytes(proofBytes[index*chunkSize : (index+1)*chunkSize])
		}
		b := elem.Bytes()
		hFunc.Write(b[:])
		msgStr := fmt.Sprintf("Msg[%d]", index)
		witness[msgStr] = elem.String()
	}
	hash := hFunc.Sum(nil)

	src := rand.NewSource(0)
	r := rand.New(src)

	privKey, _ := eddsa.GenerateKey(r)
	pubKey := privKey.PublicKey

	sigBytes, err := privKey.Sign(hash, hFunc)
	if err != nil {
		t.Error("failed to sign invoice data")
		return
	}

	verified, err := pubKey.Verify(sigBytes, hash, hFunc)
	if err != nil || !verified {
		t.Error("failed to verify invoice data")
		return
	}

	var sig eddsa.Signature
	var i big.Int
	var point twistededwards.PointAffine

	sig.SetBytes(sigBytes)
	pubKeyBytes := pubKey.Bytes()
	point.SetBytes(pubKeyBytes)
	xKey := point.X.Bytes()
	xKeyString := i.SetBytes(xKey[:]).String()
	yKey := point.Y.Bytes()
	yKeyString := i.SetBytes(yKey[:]).String()

	point.SetBytes(sigBytes)
	xSig := point.X.Bytes()
	xSigString := i.SetBytes(xSig[:]).String()
	ySig := point.Y.Bytes()
	ySigString := i.SetBytes(ySig[:]).String()
	sigLen := len(sigBytes) / 2
	sigS1String := i.SetBytes(sigBytes[sigLen : sigLen+sigLen/2]).String()
	sigS2String := i.SetBytes(sigBytes[sigLen+sigLen/2:]).String()

	witness["PubKey.A.X"] = xKeyString
	witness["PubKey.A.Y"] = yKeyString
	witness["Sig.R.X"] = xSigString
	witness["Sig.R.Y"] = ySigString
	witness["Sig.S1"] = sigS1String
	witness["Sig.S2"] = sigS2String

	proof, err := privacy.Prove(*financierToken, financierCircuit.ID.String(), map[string]interface{}{
		"witness": witness,
	})
	if err != nil {
		t.Errorf("failed to generate proof; %s", err.Error())
		return
	}

	t.Logf("generated proof for financier's %s circuit", identifier)

	waitForAsync()
	waitForAsync()
	waitForAsync()
	waitForAsync()

	verification, err := privacy.Verify(*financierToken, financierCircuit.ID.String(), map[string]interface{}{
		"proof":   proof.Proof,
		"witness": witness,
	})
	if err != nil {
		t.Errorf("failed to verify proof; %s", err.Error())
		return
	}

	t.Logf("financier root signature proof/verification: %v / %v", proof.Proof, verification.Result)
}
