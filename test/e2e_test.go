// +build integration

package test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"

	"os"
	"testing"
	"time"

	"github.com/consensys/gnark/std/accumulator/merkle"

	"github.com/consensys/gnark-crypto/ecc"

	gnark_merkle "github.com/consensys/gnark-crypto/accumulator/merkletree"
	mimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/privacy/ceremony"
	"github.com/provideplatform/privacy/common"
	"github.com/provideplatform/privacy/store/providers/merkletree"

	"github.com/provideplatform/provide-go/api/privacy"
)

const requireCircuitTimeout = time.Minute * 5
const requireCircuitTickerInterval = time.Second * 5
const requireCircuitSleepInterval = time.Millisecond * 500

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
	token, err := userTokenFactory(testUserID)
	if err != nil {
		t.Errorf("failed to create user token; %s", err.Error())
		return
	}

	circuits, err := createProcureToPayWorkflow(token, testProvingSchemeGroth16)
	if err != nil {
		t.Errorf("failed to create procure to pay workflow circuits; %s", err.Error())
		return
	}

	for _, circuit := range circuits {
		t.Logf("deployed circuit %s with id %s", *circuit.Name, circuit.ID)
	}

	requireCircuits(token, circuits)

	purchaseOrderCircuit := circuits[0]
	salesOrderCircuit := circuits[1]
	shipmentNotificationCircuit := circuits[2]
	goodsReceiptCircuit := circuits[3]
	invoiceCircuit := circuits[4]

	tt := []struct {
		circuitIndex uint64
		circuit      *privacy.Circuit
		prevCircuit  *privacy.Circuit
		payload      map[string]interface{}
	}{
		{0, purchaseOrderCircuit, nil, map[string]interface{}{"value": 11111111, "hello": "world1"}},
		{1, salesOrderCircuit, purchaseOrderCircuit, map[string]interface{}{"value": 22222222, "hello": "world2"}},
		{2, shipmentNotificationCircuit, salesOrderCircuit, map[string]interface{}{"value": 33333333, "hello": "world3"}},
		{3, goodsReceiptCircuit, shipmentNotificationCircuit, map[string]interface{}{"value": 44444444, "hello": "world4"}},
		{4, invoiceCircuit, goodsReceiptCircuit, map[string]interface{}{"value": 55555555, "hello": "world5"}},
	}

	for i, tc := range tt {
		_, err = testCircuitLifecycle(t, tree, hFunc, token, tc.circuitIndex, tc.circuit, tc.prevCircuit, tc.payload)
		if err != nil {
			t.Errorf("failed to test circuit %d; %s", i, err.Error())
			return
		}
	}
}

func TestCircuitReuse(t *testing.T) {
	hFunc := mimc.NewMiMC("seed")

	testUserID, _ := uuid.NewV4()
	token, err := userTokenFactory(testUserID)
	if err != nil {
		t.Errorf("failed to create user token; %s", err.Error())
		return
	}

	circuit, err := privacy.CreateCircuit(
		*token,
		circuitParamsFactory(
			"BN254",
			"PO",
			"purchase_order",
			testProvingSchemeGroth16,
			nil,
			nil,
		),
	)
	if err != nil {
		t.Errorf("failed to deploy circuit; %s", err.Error())
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

	proof, err := privacy.Prove(*token, circuit.ID.String(), map[string]interface{}{
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

	verification, err := privacy.Verify(*token, circuit.ID.String(), note)
	if err != nil {
		t.Errorf("failed to verify proof; %s", err.Error())
		return
	}

	t.Logf("%s proof/verification: %s / %v", *circuit.Name, *proof.Proof, verification.Result)

	circuitIndex := uint64(0)
	resp, err := privacy.GetNoteValue(*token, circuit.ID.String(), circuitIndex)
	if err != nil {
		t.Errorf("failed to fetch note value; %s", err.Error())
	}

	noteValue, err := base64.StdEncoding.DecodeString(*resp.Value)
	if err != nil {
		t.Errorf("failed to base64 decode note value; %s", err.Error())
		return
	}
	t.Logf("retrieved %d-byte note value: %s; root: %s", len(noteValue), string(noteValue), *resp.Root)

	t.Log("proving using new witness and same circuit")

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

	proof, err = privacy.Prove(*token, circuit.ID.String(), map[string]interface{}{
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

	verification, err = privacy.Verify(*token, circuit.ID.String(), note)
	if err != nil {
		t.Errorf("failed to verify proof; %s", err.Error())
		return
	}

	t.Logf("%s proof/verification: %s / %v", *circuit.Name, *proof.Proof, verification.Result)

	circuitIndex++
	resp, err = privacy.GetNoteValue(*token, circuit.ID.String(), circuitIndex)
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

	circuitIndex--
	resp, err = privacy.GetNoteValue(*token, circuit.ID.String(), circuitIndex)
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
	token, err := userTokenFactory(testUserID)
	if err != nil {
		t.Errorf("failed to create user token; %s", err.Error())
		return
	}

	circuits := make([]*privacy.Circuit, 0)
	notes := make([][]byte, 0)

	workflowCount := 1

	for workflowIndex := 0; workflowIndex < workflowCount; workflowIndex++ {

		t.Logf("procuring workflow %d", workflowIndex)

		workflowCircuits, err := createProcureToPayWorkflow(token, testProvingSchemeGroth16)
		if err != nil {
			t.Errorf("failed to create procure to pay workflow circuits; %s", err.Error())
			return
		}

		for _, circuit := range workflowCircuits {
			t.Logf("deployed circuit %s with id %s", *circuit.Name, circuit.ID)
		}

		requireCircuits(token, workflowCircuits)

		var firstPrevCircuit *privacy.Circuit
		if workflowIndex == 0 {
			firstPrevCircuit = nil
		} else {
			firstPrevCircuit = circuits[len(circuits)-1]
		}

		circuits = append(circuits, workflowCircuits[:]...)

		purchaseOrderCircuit := circuits[workflowIndex*5]
		salesOrderCircuit := circuits[workflowIndex*5+1]
		shipmentNotificationCircuit := circuits[workflowIndex*5+2]
		goodsReceiptCircuit := circuits[workflowIndex*5+3]
		invoiceCircuit := circuits[workflowIndex*5+4]

		tt := []struct {
			circuitIndex uint64
			circuit      *privacy.Circuit
			prevCircuit  *privacy.Circuit
			payload      map[string]interface{}
		}{
			{uint64(0), purchaseOrderCircuit, firstPrevCircuit, map[string]interface{}{"value": 11111111, "hello": "world1"}},
			{uint64(1), salesOrderCircuit, purchaseOrderCircuit, map[string]interface{}{"value": 22222222, "hello": "world2"}},
			{uint64(2), shipmentNotificationCircuit, salesOrderCircuit, map[string]interface{}{"value": 33333333, "hello": "world3"}},
			{uint64(3), goodsReceiptCircuit, shipmentNotificationCircuit, map[string]interface{}{"value": 44444444, "hello": "world4"}},
			{uint64(4), invoiceCircuit, goodsReceiptCircuit, map[string]interface{}{"value": 55555555, "hello": "world5"}},
		}

		for i, tc := range tt {
			nullifiedNote, err := testCircuitLifecycle(t, tree, hFunc, token, tc.circuitIndex, tc.circuit, tc.prevCircuit, tc.payload)
			if err != nil {
				t.Errorf("failed to test circuit %d; %s", workflowIndex*5+i, err.Error())
				return
			}

			if len(nullifiedNote) > 0 {
				notes = append(notes, nullifiedNote)
			}
		}

	}

	t.Logf("successfully deployed %d circuits, stored %d notes", len(circuits), len(notes))

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

	params := circuitParamsFactory(
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

	rollupCircuit, err := privacy.CreateCircuit(*token, params)
	if err != nil {
		t.Errorf("failed to deploy rollup circuit; %s", err.Error())
		return
	}

	t.Logf("deployed circuit %s with id %s", *rollupCircuit.Name, rollupCircuit.ID)

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

	rollupProof, err := privacy.Prove(*token, rollupCircuit.ID.String(), map[string]interface{}{
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

	verification, err := privacy.Verify(*token, rollupCircuit.ID.String(), publicWitness)
	if err != nil {
		t.Errorf("failed to verify proof; %s", err.Error())
		return
	}

	t.Logf("%s proof/verification: %s / %v", *rollupCircuit.Name, *rollupProof.Proof, verification.Result)
}

func setupTestMPCs(t *testing.T, mpcs *[]*ceremony.Ceremony, parties []string, blockID uint64) error {
	for i := 0; i < len(parties); i++ {
		mpc := &ceremony.Ceremony{}

		mpc.CeremonyFactory(parties, &ceremony.CeremonyConfig{
			Block: &blockID,
		})

		err := mpc.GetEntropyFromBeacon()
		if err != nil {
			return fmt.Errorf("unable to get entropy; %s", err.Error())
		}

		*mpcs = append(*mpcs, mpc)
	}

	t.Logf("created %d MPCs", len(*mpcs))
	return nil
}

// TODO: replace with actual entropy receipt
func addPartiesToTestMPCs(t *testing.T, mpcs []*ceremony.Ceremony) error {
	partyCount := len(mpcs)
	for i := 0; i < partyCount; i++ {
		entropy, err := common.RandomBytes(mpcs[i].Config.WordSize)
		if err != nil {
			return fmt.Errorf("unable to generate entropy for mpc ceremony; %s", err.Error())
		}

		for j := 0; j < partyCount; j++ {
			err = mpcs[j].SubmitEntropy(mpcs[i].Parties[i], entropy)
			if err != nil {
				return fmt.Errorf("unable to submit entropy; %s", err.Error())
			}
		}
	}

	return nil
}

func validateEntropy(t *testing.T, mpcs []*ceremony.Ceremony) error {
	for i := 1; i < len(mpcs); i++ {
		if !mpcs[i-1].CompareEntropy(mpcs[i]) {
			return fmt.Errorf("entropy from mpc %d does not match mpc %d", i-1, i)
		}
	}

	return nil
}

func TestCeremonySRSGeneration(t *testing.T) {
	mpcs := make([]*ceremony.Ceremony, 0)

	// TODO: retrieve block ID properly
	blockID := uint64(123456)
	const partyCount = 5
	parties := make([]string, 0)

	i := new(big.Int)
	for party := int64(0); party < int64(partyCount); party++ {
		i.SetInt64(party)
		parties = append(parties, i.String())
	}

	err := setupTestMPCs(t, &mpcs, parties, blockID)
	if err != nil {
		t.Errorf("error setting up test MPCs; %s", err.Error())
		return
	}

	t.Logf("set up %d MPCs", len(mpcs))

	err = addPartiesToTestMPCs(t, mpcs[:])
	if err != nil {
		t.Errorf("error adding parties to test MPCs; %s", err.Error())
		return
	}

	err = validateEntropy(t, mpcs[:])
	if err != nil {
		t.Errorf("error validating entropy for test MPCs; %s", err.Error())
		return
	}

	t.Log("all calculated entropy values are valid")

	t.Log("all calculated entropy values are valid")

	err = mpcs[0].StoreEntropy()
	if err != nil {
		t.Errorf("failed to store entropy in vault; %s", err.Error())
		return
	}

	t.Logf("stored entropy in vault")

	testUserID, _ := uuid.NewV4()
	token, _ := userTokenFactory(testUserID)

	params := circuitParamsFactory(
		"BN254",
		"PO",
		"purchase_order",
		"plonk",
		nil,
		nil,
	)

	params["entropy_id"] = entropySecretID.String()

	circuit, err := privacy.CreateCircuit(*token, params)
	if err != nil {
		t.Errorf("failed to deploy circuit; %s", err.Error())
		return
	}

	t.Logf("created circuit id: %s", circuit.ID.String())
}
