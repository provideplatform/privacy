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
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	gnarkhash "github.com/consensys/gnark-crypto/hash"

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

	hash := gnarkhash.MIMC_BLS12_377.New()
	var i big.Int

	payload := map[string]interface{}{
		"value": 22222222,
		"hello": "world2",
	}
	raw, _ := json.Marshal(payload)
	hash.Reset()
	hash.Write(raw)

	// preimage is itself a digest due to the field element size limitation of the curve
	preImage := hash.Sum(nil)
	preImageStr := i.SetBytes(preImage).String()

	_hash := gnarkhash.MIMC_BLS12_377.New()
	_hash.Write(preImage)
	hashStr := i.SetBytes(_hash.Sum(nil)).String()

	proof, err := privacy.Prove(*token, preimageHashProver.ID.String(), map[string]interface{}{
		"witness": map[string]interface{}{
			"Preimage": preImageStr,
			"Hash":     hashStr,
		}, // HACK!!! this will soon be replaced by a circuit-specific witness factory...
	})
	if err != nil {
		t.Errorf("failed to generate proof; %s", err.Error())
	}

	t.Logf("generated zero-knowledge proof %s", *proof.Proof)
}
