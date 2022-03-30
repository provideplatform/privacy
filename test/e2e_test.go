//go:build integration
// +build integration

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

package test

import (
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/provide-go/api/privacy"
)

const requireProverTimeout = time.Minute * 5
const requireProverTickerInterval = time.Second * 5
const requireProverSleepInterval = time.Millisecond * 500

var curveID = ecc.BN254

const testProvingSchemeGroth16 = "groth16"
const testProvingSchemePlonk = "plonk"

func TestPreimageHashProver(t *testing.T) {
	var preimageHashProver *privacy.Prover //*gnark.PreimageHashCircuit
	var err error

	userID, _ := uuid.NewV4()
	token, err := userTokenFactory(userID)
	if err != nil {
		t.Errorf("failed to initialize and authenticate user; %s", err.Error())
	}

	for _, provingScheme := range []string{
		testProvingSchemeGroth16,
		// TODO: add "plonk"
	} {
		t.Logf("initializing preimage prover for proving scheme: %s", provingScheme) // preimage knowledge prover
		preimageHashProver, err = createPreimageHashProver(token, provingScheme)
		if err != nil {
			t.Errorf("failed to initialize preimage prover for proving scheme: %s; %s", provingScheme, err.Error())
			return
		}
		t.Logf("initialized preimage prover for proving scheme: %s; prover id: %s", provingScheme, preimageHashProver.ID)
	}

	requireProvers(token, []*privacy.Prover{preimageHashProver})
}
