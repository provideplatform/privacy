/*
 * Copyright 2017-2022 Provide Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// +build integration

package test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"math/big"
	"math/rand"

	"os"
	"testing"
	"time"

	"github.com/consensys/gnark/std/accumulator/merkle"

	"github.com/consensys/gnark-crypto/ecc"

	gnark_merkle "github.com/consensys/gnark-crypto/accumulator/merkletree"
	mimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/privacy/store/providers/merkletree"

	"github.com/provideplatform/provide-go/api/privacy"
)

const requireProverTimeout = time.Minute * 5
const requireProverTickerInterval = time.Second * 5
const requireProverSleepInterval = time.Millisecond * 500

func init() {
	time.Sleep(time.Second * 20)
}

var curveID = ecc.BN254

const testProvingSchemeGroth16 = "groth16"
const testProvingSchemePlonk = "plonk"

func setBobEnv() {
	os.Setenv("IDENT_API_HOST", "localhost:8084")
	os.Setenv("PRIVACY_API_HOST", "localhost:8083")
}

func setAliceEnv() {
	os.Setenv("IDENT_API_HOST", "localhost:8081")
	os.Setenv("PRIVACY_API_HOST", "localhost:8080")
}

func TestProcureToPayWorkflowGroth16(t *testing.T) {
	hFunc := mimc.NewMiMC("seed")
	tree := merkletree.NewMerkleTree(hFunc)

	testUserID, _ := uuid.NewV4()
	token, _ := userTokenFactory(testUserID)

	provers, err := createProcureToPayWorkflow(token, testProvingSchemeGroth16)
	if err != nil {
		t.Errorf("failed to create procure to pay workflow provers%s", err.Error())
		return
	}

	for _, prover := range provers {
		t.Logf("deployed prover %s with id %s", *prover.Name, prover.ID)
	}

	requireProvers(token, provers)

	purchaseOrderProver := provers[0]
	salesOrderProver := provers[1]
	shipmentNotificationProver := provers[2]
	goodsReceiptProver := provers[3]
	invoiceProver := provers[4]

	tt := []struct {
		proverIndex uint64
		prover      *privacy.Prover
		prevProver  *privacy.Prover
		payload      map[string]interface{}
	}{
		{0, purchaseOrderProver, nil, map[string]interface{}{"value": 11111111, "hello": "world1"}},
		{1, salesOrderProver, purchaseOrderProver, map[string]interface{}{"value": 22222222, "hello": "world2"}},
		{2, shipmentNotificationProver, salesOrderProver, map[string]interface{}{"value": 33333333, "hello": "world3"}},
		{3, goodsReceiptProver, shipmentNotificationProver, map[string]interface{}{"value": 44444444, "hello": "world4"}},
		{4, invoiceProver, goodsReceiptProver, map[string]interface{}{"value": 55555555, "hello": "world5"}},
	}

	for i, tc := range tt {
		_, err = testProverLifecycle(t, tree, hFunc, token, tc.proverIndex, tc.prover, tc.prevProver, tc.payload)
		if err != nil {
			t.Errorf("failed to test prover %d; %s", i, err.Error())
			return
		}
	}
}

func TestProverReuse(t *testing.T) {
	hFunc := mimc.NewMiMC("seed")

	testUserID, _ := uuid.NewV4()
	token, _ := userTokenFactory(testUserID)

	prover, err := privacy.CreateProver(
		*token,
		proverParamsFactory(
			"BN254",
			"PO",
			"purchase_order",
			testProvingSchemeGroth16,
			nil,
			nil,
		),
	)
	if err != nil {
		t.Errorf("failed to deploy prover; %s", err.Error())
		return
	}

	payload := map[string]interface{}{
		"value": 11111111,
		"hello": "world1",
	}

	raw, _ := json.Marshal(payload)

	hFunc.Reset()
	hFunc.Write(raw)

	var i big.Int

	// preimage is itself a digest due to the field element size limitation of the curve
	preImage := hFunc.Sum(nil)
	preImageString := i.SetBytes(preImage).String()

	hash, _ := mimc.Sum("seed", preImage)
	hashString := i.SetBytes(hash).String()

	witness := map[string]interface{}{
		"Document.Preimage": preImageString,
		"Document.Hash":     hashString,
	}

	t.Logf("proving witness Document.Hash: %s, Document.PreImage: %s", hashString, preImageString)

	time.Sleep(time.Duration(5) * time.Second)

	proof, err := privacy.Prove(*token, prover.ID.String(), map[string]interface{}{
		"witness": witness,
	})
	if err != nil {
		t.Errorf("failed to generate proof; %s", err.Error())
		return
	}

	note := map[string]interface{}{
		"proof": proof.Proof,
		"witness": map[string]interface{}{
			"Document.Hash": hashString,
		},
	}

	verification, err := privacy.Verify(*token, prover.ID.String(), note)
	if err != nil {
		t.Errorf("failed to verify proof; %s", err.Error())
		return
	}

	t.Logf("%s proof/verification: %s / %v", *prover.Name, *proof.Proof, verification.Result)

	proverIndex := uint64(0)
	resp, err := privacy.GetNoteValue(*token, prover.ID.String(), proverIndex)
	if err != nil {
		t.Errorf("failed to fetch note value; %s", err.Error())
	}

	noteValue, err := base64.StdEncoding.DecodeString(*resp.Value)
	if err != nil {
		t.Errorf("failed to base64 decode note value; %s", err.Error())
		return
	}
	t.Logf("retrieved %d-byte note value: %s; root: %s", len(noteValue), string(noteValue), *resp.Root)

	t.Log("proving using new witness and same prover")

	payload = map[string]interface{}{
		"value": 22222222,
		"hello": "world2",
	}

	raw, _ = json.Marshal(payload)

	hFunc.Reset()
	hFunc.Write(raw)

	// preimage is itself a digest due to the field element size limitation of the curve
	preImage = hFunc.Sum(nil)
	preImageString = i.SetBytes(preImage).String()

	hash, _ = mimc.Sum("seed", preImage)
	hashString = i.SetBytes(hash).String()

	witness = map[string]interface{}{
		"Document.Preimage": preImageString,
		"Document.Hash":     hashString,
	}

	t.Logf("proving witness Document.Hash: %s, Document.PreImage: %s", hashString, preImageString)

	proof, err = privacy.Prove(*token, prover.ID.String(), map[string]interface{}{
		"witness": witness,
	})
	if err != nil {
		t.Errorf("failed to generate proof; %s", err.Error())
		return
	}

	note = map[string]interface{}{
		"proof": proof.Proof,
		"witness": map[string]interface{}{
			"Document.Hash": hashString,
		},
	}

	verification, err = privacy.Verify(*token, prover.ID.String(), note)
	if err != nil {
		t.Errorf("failed to verify proof; %s", err.Error())
		return
	}

	t.Logf("%s proof/verification: %s / %v", *prover.Name, *proof.Proof, verification.Result)

	proverIndex++
	resp, err = privacy.GetNoteValue(*token, prover.ID.String(), proverIndex)
	if err != nil {
		t.Errorf("failed to fetch note value; %s", err.Error())
	}

	noteValue, err = base64.StdEncoding.DecodeString(*resp.Value)
	if err != nil {
		t.Errorf("failed to base64 decode note value; %s", err.Error())
		return
	}
	t.Logf("retrieved %d-byte note value: %s; root: %s", len(noteValue), string(noteValue), *resp.Root)

	t.Log("attempting retrieval of original note")

	proverIndex--
	resp, err = privacy.GetNoteValue(*token, prover.ID.String(), proverIndex)
	if err != nil {
		t.Errorf("failed to fetch note value; %s", err.Error())
	}

	noteValue, err = base64.StdEncoding.DecodeString(*resp.Value)
	if err != nil {
		t.Errorf("failed to base64 decode note value; %s", err.Error())
		return
	}
	t.Logf("retrieved %d-byte note value: %s; root: %s", len(noteValue), string(noteValue), *resp.Root)
}

func TestProcureToPayWorkflowRollupGroth16(t *testing.T) {
	hFunc := mimc.NewMiMC("seed")
	tree := merkletree.NewMerkleTree(hFunc)

	testUserID, _ := uuid.NewV4()
	token, _ := userTokenFactory(testUserID)

	provers := make([]*privacy.Prover, 0)
	notes := make([][]byte, 0)

	workflowCount := 1

	for workflowIndex := 0; workflowIndex < workflowCount; workflowIndex++ {

		t.Logf("procuring workflow %d", workflowIndex)

		workflowProvers err := createProcureToPayWorkflow(token, testProvingSchemeGroth16)
		if err != nil {
			t.Errorf("failed to create procure to pay workflow provers%s", err.Error())
			return
		}

		for _, prover := range workflowProvers{
			t.Logf("deployed prover %s with id %s", *prover.Name, prover.ID)
		}

		requireProverstoken, workflowPProvers

		var firstPrevProver *privacy.Prover
		if workflowIndex == 0 {
			firstPrevProver = nil
		} else {
			firstPrevProver = provers[len(provers)-1]
		}

		provers = append(provers, workflowProvers:]...)

		purchaseOrderProver := provers[workflowIndex*5]
		salesOrderProver := provers[workflowIndex*5+1]
		shipmentNotificationProver := provers[workflowIndex*5+2]
		goodsReceiptProver := provers[workflowIndex*5+3]
		invoiceProver := provers[workflowIndex*5+4]

		tt := []struct {
			proverIndex uint64
			prover      *privacy.Prover
			prevProver  *privacy.Prover
			payload      map[string]interface{}
		}{
			{uint64(0), purchaseOrderProver, firstPrevProver, map[string]interface{}{"value": 11111111, "hello": "world1"}},
			{uint64(1), salesOrderProver, purchaseOrderProver, map[string]interface{}{"value": 22222222, "hello": "world2"}},
			{uint64(2), shipmentNotificationProver, salesOrderProver, map[string]interface{}{"value": 33333333, "hello": "world3"}},
			{uint64(3), goodsReceiptProver, shipmentNotificationProver, map[string]interface{}{"value": 44444444, "hello": "world4"}},
			{uint64(4), invoiceProver, goodsReceiptProver, map[string]interface{}{"value": 55555555, "hello": "world5"}},
		}

		for i, tc := range tt {
			nullifiedNote, err := testProverLifecycle(t, tree, hFunc, token, tc.proverIndex, tc.prover, tc.prevProver, tc.payload)
			if err != nil {
				t.Errorf("failed to test prover %d; %s", workflowIndex*5+i, err.Error())
				return
			}

			if len(nullifiedNote) > 0 {
				notes = append(notes, nullifiedNote)
			}
		}

	}

	t.Logf("successfully deployed %d provers, stored %d notes", len(provers), len(notes))

	buf := new(bytes.Buffer)
	segmentSize := mimc.BlockSize

	for _, n := range notes {
		digest, _ := mimc.Sum("seed", n)
		buf.Write(digest)
	}

	proofIndex := uint64(0)
	merkleRoot, proofSet, numLeaves, err := gnark_merkle.BuildReaderProof(buf, hFunc, segmentSize, proofIndex)

	proofVerified := gnark_merkle.VerifyProof(hFunc, merkleRoot, proofSet, proofIndex, numLeaves)
	if !proofVerified {
		t.Errorf("failed to verify merkle proof; %s", err.Error())
		return
	}

	params := proverParamsFactory(
		"BN254",
		"Rollup",
		"baseline_rollup",
		testProvingSchemeGroth16,
		nil,
		nil,
	)

	proofCount := new(big.Int).SetInt64(int64(len(proofSet)))
	helperCount := new(big.Int).SetInt64(int64(len(proofSet) - 1))
	params["variables"] = map[string]interface{}{
		"Proofs_count":  proofCount.String(),
		"Helpers_count": helperCount.String(),
	}

	rollupProver, err := privacy.CreateProver(*token, params)
	if err != nil {
		t.Errorf("failed to deploy rollup prover; %s", err.Error())
		return
	}

	t.Logf("deployed prover %s with id %s", *rollupProver.Name, rollupProver.ID)

	merkleProofHelper := merkle.GenerateProofHelper(proofSet, proofIndex, numLeaves)

	var i big.Int
	witness := map[string]interface{}{
		"RootHash":      i.SetBytes(merkleRoot).String(),
		"Proofs_count":  proofCount.String(),
		"Helpers_count": helperCount.String(),
	}

	for index := 0; index < len(proofSet); index++ {
		elemStr := fmt.Sprintf("Proofs[%d]", index)
		witness[elemStr] = i.SetBytes(proofSet[index]).String()

		if index < len(proofSet)-1 {
			elemStr := fmt.Sprintf("Helpers[%d]", index)
			witness[elemStr] = i.SetInt64(int64(merkleProofHelper[index])).String()
		}
	}

	time.Sleep(time.Second * 5)

	rollupProof, err := privacy.Prove(*token, rollupProver.ID.String(), map[string]interface{}{
		"witness": witness,
	})
	if err != nil {
		t.Errorf("failed to generate proof; %s", err.Error())
		return
	}

	publicWitness := map[string]interface{}{
		"proof": rollupProof.Proof,
		"witness": map[string]interface{}{
			"RootHash":      i.SetBytes(merkleRoot).String(),
			"Proofs_count":  proofCount.String(),
			"Helpers_count": helperCount.String(),
		},
	}

	verification, err := privacy.Verify(*token, rollupProver.ID.String(), publicWitness)
	if err != nil {
		t.Errorf("failed to verify proof; %s", err.Error())
		return
	}

	t.Logf("%s proof/verification: %s / %v", *rollupProver.Name, *rollupProof.Proof, verification.Result)
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
