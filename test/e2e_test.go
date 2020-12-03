// +build integration

package test

import (
	"testing"

	privacy "github.com/provideservices/provide-go/api/privacy"
)

func circuitParamsFactory() map[string]interface{} {
	return map[string]interface{}{
		"hello": "world",
	}
}

func TestCreateCircuit(t *testing.T) {
	token := ""
	params := circuitParamsFactory()

	circuit, err := privacy.CreateCircuit(token, params)
	if err != nil {
		t.Errorf("failed to create circuit; %s", err.Error())
		return
	}

	t.Logf("created circuit %v", circuit)
}
