// +build integration

package test

import (
	"testing"

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

	_, err = privacy.Prove(*token, circuit.ID.String(), map[string]interface{}{
		"witness": map[string]interface{}{
			"x": "3",
			"Y": "9", // this will fail...
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

	proof, err := privacy.Prove(*token, circuit.ID.String(), map[string]interface{}{
		"witness": map[string]interface{}{
			"x": "3",
			"Y": "9", // this will fail...
		},
	})
	if err != nil {
		t.Errorf("failed to generate proof; %s", err.Error())
		return
	}

	verification, err := privacy.Verify(*token, circuit.ID.String(), map[string]interface{}{
		"proof":   "FIXME",
		"witness": "FIXME",
	})
	if err != nil {
		t.Errorf("failed to verify proof; %s", err.Error())
		return
	}

	t.Logf("proof/verification: %v / %v", proof.Proof, verification.Result)
}
