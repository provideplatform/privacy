// +build integration

package test

import (
	"bytes"
	"encoding/hex"
	"io"
	"math"
	"math/big"
	"math/rand"
	"testing"
	"time"

	"github.com/consensys/gnark/backend/groth16"
	gnark_merkle "github.com/consensys/gnark/crypto/accumulator/merkletree"
	mimc "github.com/consensys/gnark/crypto/hash/mimc/bn256"
	eddsa "github.com/consensys/gnark/crypto/signature/eddsa/bn256"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/consensys/gurvy"
	"github.com/consensys/gurvy/bn256/twistededwards"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/privacy/store/providers/merkletree"
	"github.com/provideapp/privacy/zkp/lib/circuits/gnark"

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

	preImage := i.SetBytes(dv.Digest()).String()

	proof, err := privacy.Prove(*token, circuit.ID.String(), map[string]interface{}{
		"witness": map[string]interface{}{
			"PreImage": preImage,
			"Hash":     "4511120069326357802246315184921336344580039746739647562931138731310930627466",
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
			"Hash":     "4511120069326357802246315184921336344580039746739647562931138731310930627466",
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
	r1cs, err := frontend.Compile(gurvy.BN256, &baselineCircuit)
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
	tr.Recalculate()
	root := tr.Root()
	t.Logf("root: %s", root)

	if root != hex.EncodeToString(merkleRoot) {
		t.Error("calculated root for each implementation should match for proof counts which are powers of two")
		return
	}
}

func TestProcurement(t *testing.T) {
	testUserID, _ := uuid.NewV4()
	token, _ := userTokenFactory(testUserID)
	params := circuitParamsFactory("gnark", "purchase_order")

	circuit, err := privacy.CreateCircuit(*token, params)
	if err != nil {
		t.Errorf("failed to create circuit; %s", err.Error())
		return
	}

	t.Logf("created circuit %v", circuit)

	hFunc := mimc.NewMiMC("seed")

	// var merkleBuf bytes.Buffer

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

	// timeout due to async calls
	time.Sleep(time.Duration(2) * time.Second)

	proof, err := privacy.Prove(*token, circuit.ID.String(), map[string]interface{}{
		"witness": map[string]interface{}{
			"Document.PreImage": preImageString,
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
			"Document.PreImage": preImageString,
			"Document.Hash":     hashString,
		},
	})
	if err != nil {
		t.Errorf("failed to verify proof; %s", err.Error())
		return
	}

	t.Logf("purchase order proof/verification: %v / %v", proof.Proof, verification.Result)

	// bytes.Buffer.Write() may panic, but never returns an error
	// merkleBuf.Write(preImage)

	params = circuitParamsFactory("gnark", "sales_order")

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

	// timeout due to async calls
	time.Sleep(time.Duration(2) * time.Second)

	proof, err = privacy.Prove(*token, circuit.ID.String(), map[string]interface{}{
		"witness": map[string]interface{}{
			"Document.PreImage": preImageString,
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
			"Document.PreImage": preImageString,
			"Document.Hash":     hashString,
		},
	})
	if err != nil {
		t.Errorf("failed to verify proof; %s", err.Error())
		return
	}

	t.Logf("sales order proof/verification: %v / %v", proof.Proof, verification.Result)

	// // bytes.Buffer.Write() may panic, but never returns an error
	// merkleBuf.Write(preImage)

	params = circuitParamsFactory("gnark", "shipment_notification")

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

	// timeout due to async calls
	time.Sleep(time.Duration(2) * time.Second)

	proof, err = privacy.Prove(*token, circuit.ID.String(), map[string]interface{}{
		"witness": map[string]interface{}{
			"Document.PreImage": preImageString,
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
			"Document.PreImage": preImageString,
			"Document.Hash":     hashString,
		},
	})
	if err != nil {
		t.Errorf("failed to verify proof; %s", err.Error())
		return
	}

	t.Logf("shipment notification proof/verification: %v / %v", proof.Proof, verification.Result)

	// // bytes.Buffer.Write() may panic, but never returns an error
	// merkleBuf.Write(preImage)

	params = circuitParamsFactory("gnark", "goods_receipt")

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

	// timeout due to async calls
	time.Sleep(time.Duration(2) * time.Second)

	proof, err = privacy.Prove(*token, circuit.ID.String(), map[string]interface{}{
		"witness": map[string]interface{}{
			"Document.PreImage": preImageString,
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
			"Document.PreImage": preImageString,
			"Document.Hash":     hashString,
		},
	})
	if err != nil {
		t.Errorf("failed to verify proof; %s", err.Error())
		return
	}

	t.Logf("goods receipt proof/verification: %v / %v", proof.Proof, verification.Result)

	// // bytes.Buffer.Write() may panic, but never returns an error
	// merkleBuf.Write(preImage)

	src := rand.NewSource(0)
	r := rand.New(src)

	privKey, _ := eddsa.GenerateKey(r)
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

	params = circuitParamsFactory("gnark", "invoice")

	circuit, err = privacy.CreateCircuit(*token, params)
	if err != nil {
		t.Errorf("failed to create circuit; %s", err.Error())
		return
	}

	t.Logf("created circuit %v", circuit)

	var sig eddsa.Signature
	sig.SetBytes(sigBytes)

	var point twistededwards.PointAffine
	point.SetBytes(pubKey.Bytes())
	xKey := point.X.Bytes()
	xKeyString := i.SetBytes(xKey[:]).String()
	yKey := point.Y.Bytes()
	yKeyString := i.SetBytes(yKey[:]).String()

	point.SetBytes(sigBytes)
	xSig := point.X.Bytes()
	xSigString := i.SetBytes(xSig[:]).String()
	ySig := point.Y.Bytes()
	ySigString := i.SetBytes(ySig[:]).String()
	sigSString := i.SetBytes(sigBytes[32:]).String()

	// timeout due to async calls
	time.Sleep(time.Duration(2) * time.Second)

	proof, err = privacy.Prove(*token, circuit.ID.String(), map[string]interface{}{
		"witness": map[string]interface{}{
			"Msg":        invoiceIntStr,
			"PubKey.A.X": xKeyString,
			"PubKey.A.Y": yKeyString,
			"Sig.R.A.X":  xSigString,
			"Sig.R.A.Y":  ySigString,
			"Sig.S":      sigSString,
		},
	})
	if err != nil {
		t.Errorf("failed to generate proof; %s", err.Error())
		return
	}

	verification, err = privacy.Verify(*token, circuit.ID.String(), map[string]interface{}{
		"proof": proof.Proof,
		"witness": map[string]interface{}{
			"Msg":        invoiceIntStr,
			"PubKey.A.X": xKeyString,
			"PubKey.A.Y": yKeyString,
			"Sig.R.A.X":  xSigString,
			"Sig.R.A.Y":  ySigString,
			"Sig.S":      sigSString,
		},
	})
	if err != nil {
		t.Errorf("failed to verify proof; %s", err.Error())
		return
	}

	t.Logf("invoice proof/verification: %v / %v", proof.Proof, verification.Result)

	// segmentSize := hFunc.Size()
	// proofIndex := uint64(0)
	// merkleRoot, proofSet, numLeaves, err := gnark_merkle.BuildReaderProof(&merkleBuf, hFunc, segmentSize, proofIndex)
	// if err != nil {
	// 	t.Errorf("failed to build merkle proof; %s", err.Error())
	// 	return
	// }

	// proofVerified := gnark_merkle.VerifyProof(hFunc, merkleRoot, proofSet, proofIndex, numLeaves)
	// if !proofVerified {
	// 	t.Errorf("failed to verify merkle proof; %s", err.Error())
	// 	return
	// }

	// var baselineCircuit, publicWitness gnark.BaselineRollupCircuit

	// // to compile the circuit, the witnesses must be allocated in the correct sizes
	// baselineCircuit.Proofs = make([]frontend.Variable, len(proofSet))
	// baselineCircuit.Helpers = make([]frontend.Variable, len(proofSet)-1)
	// r1cs, err = frontend.Compile(gurvy.BN256, &baselineCircuit)
	// if err != nil {
	// 	t.Errorf("failed to compile circuit; %s", err.Error())
	// 	return
	// }

	// merkleProofHelper := merkle.GenerateProofHelper(proofSet, proofIndex, numLeaves)

	// publicWitness.Proofs = make([]frontend.Variable, len(proofSet))
	// publicWitness.Helpers = make([]frontend.Variable, len(proofSet)-1)
	// publicWitness.RootHash.Assign(merkleRoot)
	// for i := 0; i < len(proofSet); i++ {
	// 	publicWitness.Proofs[i].Assign(proofSet[i])

	// 	if i < len(proofSet)-1 {
	// 		publicWitness.Helpers[i].Assign(merkleProofHelper[i])
	// 	}
	// }
	// // assert.ProverSucceeded(r1cs, &publicWitness)
}

func TestProcurementWithSubdividedWitnesses(t *testing.T) {
	testUserID, _ := uuid.NewV4()
	token, _ := userTokenFactory(testUserID)
	params := circuitParamsFactory("gnark", "baseline_document")

	circuit, err := privacy.CreateCircuit(*token, params)
	if err != nil {
		t.Errorf("failed to create circuit; %s", err.Error())
		return
	}

	t.Logf("created circuit %v", circuit)

	hFunc := mimc.NewMiMC("seed")

	var merkleBuf bytes.Buffer

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

	// timeout due to async calls
	time.Sleep(time.Duration(2) * time.Second)

	proof, err := privacy.Prove(*token, circuit.ID.String(), map[string]interface{}{
		"witness": map[string]interface{}{
			"PreImage": preImageString,
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
			"PreImage": preImageString,
			"Hash":     hashString,
		},
	})
	if err != nil {
		t.Errorf("failed to verify proof; %s", err.Error())
		return
	}

	t.Logf("purchase order proof/verification: %v / %v", proof.Proof, verification.Result)

	// bytes.Buffer.Write() may panic, but never returns an error
	merkleBuf.Write(preImage)

	params = circuitParamsFactory("gnark", "baseline_document")

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

	// timeout due to async calls
	time.Sleep(time.Duration(2) * time.Second)

	proof, err = privacy.Prove(*token, circuit.ID.String(), map[string]interface{}{
		"witness": map[string]interface{}{
			"PreImage": preImageString,
			"Hash":     hashString,
		},
	})
	if err != nil {
		t.Errorf("failed to generate proof; %s", err.Error())
		return
	}

	verification, err = privacy.Verify(*token, circuit.ID.String(), map[string]interface{}{
		"proof": proof.Proof,
		"witness": map[string]interface{}{
			"PreImage": preImageString,
			"Hash":     hashString,
		},
	})
	if err != nil {
		t.Errorf("failed to verify proof; %s", err.Error())
		return
	}

	t.Logf("sales order proof/verification: %v / %v", proof.Proof, verification.Result)

	// bytes.Buffer.Write() may panic, but never returns an error
	merkleBuf.Write(preImage)

	params = circuitParamsFactory("gnark", "baseline_document")

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

	// timeout due to async calls
	time.Sleep(time.Duration(2) * time.Second)

	proof, err = privacy.Prove(*token, circuit.ID.String(), map[string]interface{}{
		"witness": map[string]interface{}{
			"PreImage": preImageString,
			"Hash":     hashString,
		},
	})
	if err != nil {
		t.Errorf("failed to generate proof; %s", err.Error())
		return
	}

	verification, err = privacy.Verify(*token, circuit.ID.String(), map[string]interface{}{
		"proof": proof.Proof,
		"witness": map[string]interface{}{
			"PreImage": preImageString,
			"Hash":     hashString,
		},
	})
	if err != nil {
		t.Errorf("failed to verify proof; %s", err.Error())
		return
	}

	t.Logf("shipment notification proof/verification: %v / %v", proof.Proof, verification.Result)

	// bytes.Buffer.Write() may panic, but never returns an error
	merkleBuf.Write(preImage)

	params = circuitParamsFactory("gnark", "baseline_document")

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

	// timeout due to async calls
	time.Sleep(time.Duration(2) * time.Second)

	proof, err = privacy.Prove(*token, circuit.ID.String(), map[string]interface{}{
		"witness": map[string]interface{}{
			"PreImage": preImageString,
			"Hash":     hashString,
		},
	})
	if err != nil {
		t.Errorf("failed to generate proof; %s", err.Error())
		return
	}

	verification, err = privacy.Verify(*token, circuit.ID.String(), map[string]interface{}{
		"proof": proof.Proof,
		"witness": map[string]interface{}{
			"PreImage": preImageString,
			"Hash":     hashString,
		},
	})
	if err != nil {
		t.Errorf("failed to verify proof; %s", err.Error())
		return
	}

	t.Logf("goods receipt proof/verification: %v / %v", proof.Proof, verification.Result)

	// bytes.Buffer.Write() may panic, but never returns an error
	merkleBuf.Write(preImage)

	src := rand.NewSource(0)
	r := rand.New(src)

	privKey, _ := eddsa.GenerateKey(r)
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

	params = circuitParamsFactory("gnark", "invoice_sub")

	circuit, err = privacy.CreateCircuit(*token, params)
	if err != nil {
		t.Errorf("failed to create circuit; %s", err.Error())
		return
	}

	t.Logf("created circuit %v", circuit)

	var sig eddsa.Signature
	sig.SetBytes(sigBytes)

	var point twistededwards.PointAffine
	point.SetBytes(pubKey.Bytes())
	xKey := point.X.Bytes()
	xKeyString := i.SetBytes(xKey[:]).String()
	yKey := point.Y.Bytes()
	yKeyString := i.SetBytes(yKey[:]).String()

	point.SetBytes(sigBytes)
	xSig := point.X.Bytes()
	xSigString := i.SetBytes(xSig[:]).String()
	ySig := point.Y.Bytes()
	ySigString := i.SetBytes(ySig[:]).String()
	sigSString := i.SetBytes(sigBytes[32:]).String()

	// timeout due to async calls
	time.Sleep(time.Duration(2) * time.Second)

	proof, err = privacy.Prove(*token, circuit.ID.String(), map[string]interface{}{
		"witness": map[string]interface{}{
			"Msg":      invoiceIntStr,
			"PubKeyAX": xKeyString,
			"PubKeyAY": yKeyString,
			"SigRAX":   xSigString,
			"SigRAY":   ySigString,
			"SigS":     sigSString,
		},
	})
	if err != nil {
		t.Errorf("failed to generate proof; %s", err.Error())
		return
	}

	verification, err = privacy.Verify(*token, circuit.ID.String(), map[string]interface{}{
		"proof": proof.Proof,
		"witness": map[string]interface{}{
			"Msg":      invoiceIntStr,
			"PubKeyAX": xKeyString,
			"PubKeyAY": yKeyString,
			"SigRAX":   xSigString,
			"SigRAY":   ySigString,
			"SigS":     sigSString,
		},
	})
	if err != nil {
		t.Errorf("failed to verify proof; %s", err.Error())
		return
	}

	t.Logf("invoice proof/verification: %v / %v", proof.Proof, verification.Result)

	segmentSize := hFunc.Size()
	proofIndex := uint64(0)
	merkleRoot, proofSet, numLeaves, err := gnark_merkle.BuildReaderProof(&merkleBuf, hFunc, segmentSize, proofIndex)
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
	r1cs, err := frontend.Compile(gurvy.BN256, &baselineCircuit)
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

	merkleProof, err := groth16.Prove(r1cs, pk, &publicWitness)
	if err != nil {
		t.Errorf("failed to generate proof; %s", err.Error())
		return
	}

	err = groth16.Verify(merkleProof, vk, &publicWitness)
	if err != nil {
		t.Errorf("failed to verify proof; %s", err.Error())
		return
	}

	t.Logf("merkle circuit verified")

	store, err := privacy.GetStoreValue(*token, circuit.ID.String(), 0)
	if err != nil {
		t.Errorf("failed to get store value; %s", err.Error())
		return
	}
	t.Logf("store value: %s", *store.Value)

	// get root hash from store and verify it matches our root
}
