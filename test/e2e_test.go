// +build integration

package test

import (
	"math/big"
	"testing"
	"time"

	uuid "github.com/kthomas/go.uuid"

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
