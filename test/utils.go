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
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"testing"
	"time"

	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/privacy/common"
	"github.com/provideplatform/privacy/store/providers/merkletree"
	provide "github.com/provideplatform/provide-go/api/ident"
	"github.com/provideplatform/provide-go/api/privacy"

	vault "github.com/provideplatform/provide-go/api/vault"
	util "github.com/provideplatform/provide-go/common/util"

	newmerkletree "github.com/providenetwork/merkletree"
)

func getUserToken(email, password string) (*provide.Token, error) {
	authResponse, err := provide.Authenticate(email, password)
	if err != nil {
		return nil, fmt.Errorf("error authenticating user; %s", err.Error())
	}

	return authResponse.Token, nil
}

func getUserTokenByTestId(testID uuid.UUID) (*provide.Token, error) {
	user, err := userFactory(
		"privacy"+testID.String(),
		"user "+testID.String(),
		"privacy.user"+testID.String()+"@email.com",
		"secretpassword!!!",
	)
	if err != nil {
		return nil, fmt.Errorf("error creating user; %s", err.Error())
	}

	authResponse, err := provide.Authenticate(user.Email, "secretpassword!!!")
	if err != nil {
		return nil, fmt.Errorf("error authenticating user; %s", err.Error())
	}

	return authResponse.Token, nil
}

func userFactory(firstName, lastName, email, password string) (*provide.User, error) {
	return provide.CreateUser("", map[string]interface{}{
		"first_name": firstName,
		"last_name":  lastName,
		"email":      email,
		"password":   password,
	})
}

func userTokenFactory(testID uuid.UUID) (*string, error) {
	token, err := getUserTokenByTestId(testID)
	if err != nil {
		return nil, fmt.Errorf("error generating token; %s", err.Error())
	}

	return token.AccessToken, nil
}

func createProcureToPayWorkflow(token *string, provingScheme string) ([]*privacy.Prover, error) {
	provers := make([]*privacy.Prover, 0)

	prover, err := privacy.CreateProver(
		*token,
		proverParamsFactory(
			"BN254",
			"PO",
			"purchase_order",
			provingScheme,
			nil,
			nil,
		),
	)
	if err != nil {
		common.Log.Debugf("failed to deploy prover; %s", err.Error())
		return nil, err
	}
	provers = append(provers, prover)

	prover, err = privacy.CreateProver(
		*token,
		proverParamsFactory(
			"BN254",
			"SO",
			"sales_order",
			provingScheme,
			common.StringOrNil(prover.NoteStoreID.String()),
			common.StringOrNil(prover.NullifierStoreID.String()),
		),
	)
	if err != nil {
		common.Log.Debugf("failed to deploy prover; %s", err.Error())
		return nil, err
	}
	provers = append(provers, prover)

	prover, err = privacy.CreateProver(
		*token,
		proverParamsFactory(
			"BN254",
			"SN",
			"shipment_notification",
			provingScheme,
			common.StringOrNil(prover.NoteStoreID.String()),
			common.StringOrNil(prover.NullifierStoreID.String()),
		),
	)
	if err != nil {
		common.Log.Debugf("failed to deploy prover; %s", err.Error())
		return nil, err
	}
	provers = append(provers, prover)

	prover, err = privacy.CreateProver(
		*token,
		proverParamsFactory(
			"BN254",
			"GR",
			"goods_receipt",
			provingScheme,
			common.StringOrNil(prover.NoteStoreID.String()),
			common.StringOrNil(prover.NullifierStoreID.String()),
		),
	)
	if err != nil {
		common.Log.Debugf("failed to deploy prover; %s", err.Error())
		return nil, err
	}
	provers = append(provers, prover)

	prover, err = privacy.CreateProver(
		*token,
		proverParamsFactory(
			"BN254",
			"Invoice",
			"invoice",
			provingScheme,
			common.StringOrNil(prover.NoteStoreID.String()),
			common.StringOrNil(prover.NullifierStoreID.String()),
		),
	)
	if err != nil {
		common.Log.Debugf("failed to deploy prover; %s", err.Error())
		return nil, err
	}
	provers = append(provers, prover)

	return provers, nil
}

func requireProvers(token *string, provers []*privacy.Prover) error {
	startTime := time.Now()
	timer := time.NewTicker(requireProverTickerInterval)
	defer timer.Stop()

	deployStates := make([]bool, len(provers))

	for {
		select {
		case <-timer.C:
			for i, prover := range provers {
				if !deployStates[i] {
					prover, err := privacy.GetProverDetails(*token, prover.ID.String())
					if err != nil {
						common.Log.Debugf("failed to fetch prover details; %s", err.Error())
						break
					}

					if prover.Status != nil && *prover.Status == "provisioned" {
						common.Log.Debugf("provisioned workflow prover: %s", prover.ID)

						// var _prover *prover.Prover
						// dbconf.DatabaseConnection().Where("id = ?", preimageHashProver.ID).Find(&_prover)
						if prover.ProvingKeyID == nil {
							common.Log.Errorf("prover response contained nil proving key id for proving scheme: %s; prover id: %s", *prover.ProvingScheme, prover.ID.String())
						} else if prover.VerifyingKeyID == nil {
							common.Log.Errorf("prover response contained nil verifying key id for proving scheme: %s; prover id: %s", *prover.ProvingScheme, prover.ID.String())
						} else {
							common.Log.Debugf("proving key id: %s", prover.ProvingKeyID.String())
							common.Log.Debugf("verifying key id: %s", prover.VerifyingKeyID.String())

							// if prover.VerifierContract != nil {
							// if source, sourceOk := prover.VerifierContract["source"].(string); sourceOk {
							// contractRaw, _ := json.MarshalIndent(source, "", "  ")
							// src := strings.TrimSpace(strings.ReplaceAll(source, "\\n", "\n"))
							// common.Log.Debugf("verifier contract: %s", src)
							// contractName := fmt.Sprintf("%s Verifier", *prover.Name)
							// DeployContract([]byte(contractName), []byte(src))
							// }
							// }

							deployStates[i] = true
						}
					}
				}
			}

			x := 0
			for i := range provers {
				if deployStates[i] {
					x++
				}
			}
			if x == len(provers) {
				return nil
			}
		default:
			if startTime.Add(requireProverTimeout).Before(time.Now()) {
				msg := fmt.Sprintf("failed to provision %d workstep prover(s)", len(provers))
				common.Log.Warning(msg)
				return errors.New(msg)
			} else {
				time.Sleep(requireProverSleepInterval)
			}
		}
	}
}

func getNullifier(
	t *testing.T,
	token *string,
	nullifiedIndex uint64,
	prover *privacy.Prover,
) ([]byte, error) {
	resp, err := privacy.GetNoteValue(*token, prover.ID.String(), nullifiedIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch nullified note value; %s", err.Error())
	}

	nullifiedNote, err := base64.StdEncoding.DecodeString(*resp.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode nullified note value; %s", err.Error())
	}
	t.Logf("retrieved %d-byte nullified note value: %s; root: %s", len(nullifiedNote), string(nullifiedNote), *resp.Root)

	nullifierTreeKey, err := base64.StdEncoding.DecodeString(*resp.NullifierKey)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode nullifier tree key; %s", err.Error())
	}
	t.Logf("retrieved nullifier tree key: %s", hex.EncodeToString(nullifierTreeKey))

	resp, err = privacy.GetNullifierValue(*token, prover.ID.String(), hex.EncodeToString(nullifierTreeKey))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch nullified note from nullifier tree; %s", err.Error())
	}
	if len(*resp.Value) == 0 {
		return nil, fmt.Errorf("failed to fetch nullified note from nullifier tree; key does not exist in tree")
	}

	nullifiedValue, err := base64.StdEncoding.DecodeString(*resp.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode nullified note value; %s", err.Error())
	}
	t.Logf("retrieved %d-byte nullified note value: %s; root: %s", len(nullifiedValue), hex.EncodeToString(nullifiedValue), *resp.Root)

	return nullifiedValue, nil
}

func testProverLifecycle(
	t *testing.T,
	tree merkletree.MerkleTree,
	hFunc hash.Hash,
	token *string,
	proverIndex uint64,
	prover *privacy.Prover,
	prevProver *privacy.Prover,
	payload map[string]interface{},
) ([]byte, error) {
	raw, _ := json.Marshal(payload)

	hFunc.Reset()
	hFunc.Write(raw)

	var i big.Int

	// preimage is itself a digest due to the field element size limitation of the curve
	preImage := hFunc.Sum(nil)
	preImageString := i.SetBytes(preImage).String()

	// hash := mimc.NewMiMC()
	hashString := i.SetBytes(preImage).String()

	witness := map[string]interface{}{
		"Document.Preimage": preImageString,
		"Document.Hash":     hashString,
	}

	t.Logf("proving witness Document.Hash: %s, Document.PreImage: %s", hashString, preImageString)

	proof, err := privacy.Prove(*token, prover.ID.String(), map[string]interface{}{
		"witness": witness,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate proof; %s", err.Error())
	}

	note := map[string]interface{}{
		"proof": proof.Proof,
		"witness": map[string]interface{}{
			"Document.Hash": hashString,
		},
	}

	verification, err := privacy.Verify(*token, prover.ID.String(), note)
	if err != nil {
		return nil, fmt.Errorf("failed to verify proof; %s", err.Error())
	}

	t.Logf("%s proof/verification: %s / %v", *prover.Name, *proof.Proof, verification.Result)

	// noteRaw, _ := json.Marshal(note)
	// index, h := tree.RawAdd(noteRaw)
	// t.Logf("added %s note to merkle tree, index/hash: %v / %v", *prover.Name, index, h)

	// note state
	resp, err := privacy.GetNoteValue(*token, prover.ID.String(), proverIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch note value; %s", err.Error())
	}

	noteValue, err := base64.StdEncoding.DecodeString(*resp.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode note value; %s", err.Error())
	}
	t.Logf("retrieved %d-byte note value: %s at index %d; root: %s", len(noteValue), string(noteValue), proverIndex, *resp.Root)

	if proverIndex > 0 && prevProver != nil {
		return getNullifier(t, token, proverIndex-1, prevProver)
	}

	return []byte{}, nil
}

func proverParamsFactory(curve, name, identifier, provingScheme string, noteStoreID, nullifierStoreID *string) map[string]interface{} {
	params := map[string]interface{}{
		"curve":          curve,
		"identifier":     identifier,
		"name":           name,
		"provider":       "gnark",
		"proving_scheme": provingScheme,
	}

	if noteStoreID != nil {
		params["note_store_id"] = noteStoreID
	}

	if nullifierStoreID != nil {
		params["nullifier_store_id"] = nullifierStoreID
	}

	return params
}

func encryptNote(vaultID, keyID, note string) ([]byte, error) {
	encryptresp, err := vault.Encrypt(
		util.DefaultVaultAccessJWT,
		vaultID,
		keyID,
		note,
	)
	if err != nil {
		return nil, err
	}

	data, err := hex.DecodeString(encryptresp.Data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

type treeContent struct {
	hash  hash.Hash
	value []byte
}

// CalculateHash returns the hash of the underlying value using the configured hash function
func (tc *treeContent) CalculateHash() ([]byte, error) {
	if tc.hash == nil {
		return nil, errors.New("tree content requires configured hash function")
	}
	tc.hash.Reset()
	tc.hash.Write(tc.value)
	return tc.hash.Sum(nil), nil
}

// Equals returns true if the given content matches the underlying value
func (tc *treeContent) Equals(other newmerkletree.Content) (bool, error) {
	h0, err := tc.CalculateHash()
	if err != nil {
		return false, err
	}

	h1, err := other.CalculateHash()
	if err != nil {
		return false, err
	}

	return bytes.Equal(h0, h1), nil
}

func contentFactory(val []byte, hash hash.Hash) *treeContent {
	return &treeContent{
		hash:  hash,
		value: val,
	}
}
