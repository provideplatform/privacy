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

package prover

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/jinzhu/gorm"
	dbconf "github.com/kthomas/go-db-config"
	natsutil "github.com/kthomas/go-natsutil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/privacy/common"
	"github.com/provideplatform/privacy/state"
	storage "github.com/provideplatform/privacy/store"
	storeprovider "github.com/provideplatform/privacy/store/providers"
	zkp "github.com/provideplatform/privacy/zkp/providers"
	provide "github.com/provideplatform/provide-go/api"
	vault "github.com/provideplatform/provide-go/api/vault"
	util "github.com/provideplatform/provide-go/common/util"
)

const proverProvingSchemeGroth16 = "groth16"
const proverProvingSchemePlonk = "plonk"

const proverStatusFailed = "failed"
const proverStatusCompiling = "compiling"
const proverStatusCompiled = "compiled"
const proverStatusPendingSetup = "pending_setup"
const proverStatusRunningSetup = "running_setup"
const proverStatusDeployingArtifacts = "deploying_artifacts" // optional -- if i.e. verifier contract should be deployed to blockchain
const proverStatusProvisioned = "provisioned"

const proverVaultTypePrivacyProvingKey = "privacy_proving_key"
const proverVaultTypePrivacyVerifyingKey = "privacy_verifying_key"
const proverVaultTypePrivacySRS = "privacy_srs"

// Prover model
type Prover struct {
	provide.Model

	// Artifacts, i.e., r1cs, ABI, etc
	ABI    []byte `json:"abi,omitempty"`
	Binary []byte `gorm:"column:bin" json:"-"`

	// Vault and the vault secret identifiers for the encryption/decryption key and proving/verifying keys, SRS
	VaultID         *uuid.UUID `json:"vault_id"`
	EncryptionKeyID *uuid.UUID `json:"encryption_key_id"`
	ProvingKeyID    *uuid.UUID `json:"proving_key_id"`
	VerifyingKeyID  *uuid.UUID `json:"verifying_key_id"`

	// Associations
	ApplicationID  *uuid.UUID `sql:"type:uuid" json:"-"`
	OrganizationID *uuid.UUID `sql:"type:uuid" json:"-"`
	UserID         *uuid.UUID `sql:"type:uuid" json:"-"`

	Name          *string `json:"name"`
	Description   *string `json:"description"`
	Identifier    *string `json:"identifier"`
	Provider      *string `json:"provider"`
	ProvingScheme *string `json:"proving_scheme"`
	Curve         *string `json:"curve"`

	Status *string `sql:"not null;default:'init'" json:"status"`

	// SRS (structured reference string) is protocol-specific and may be nil depending on the proving scheme
	StructuredReferenceStringID *uuid.UUID `gorm:"column:srs_id" json:"srs_id,omitempty"`

	// encrypted notes storage
	NoteStoreID *uuid.UUID `sql:"type:uuid" json:"note_store_id"`
	noteStore   *storage.Store

	// storage for hashed proofs (nullifiers)
	NullifierStoreID *uuid.UUID `sql:"type:uuid" json:"nullifier_store_id"`
	nullifierStore   *storage.Store

	// ephemeral fields
	srs          []byte
	provingKey   []byte
	verifyingKey []byte

	// artifacts
	Artifacts map[string]interface{} `sql:"-" json:"artifacts,omitempty"`

	// state
	State *state.State `sql:"-" json:"state,omitempty"`

	// optional on-chain artifact (i.e., verifier contract)
	VerifierContract         map[string]interface{} `sql:"-" json:"verifier_contract,omitempty"`
	verifierContractABI      []byte
	verifierContractArtifact []byte
	verifierContractSource   []byte

	// mutex
	mutex sync.Mutex
}

func (c *Prover) proverProviderFactory() zkp.ZKSnarkProverProvider {
	if c.Provider == nil {
		common.Log.Warning("failed to initialize prover provider; no provider defined")
		return nil
	}

	switch *c.Provider {
	case zkp.ZKSnarkProverProviderGnark:
		return zkp.InitGnarkProverProvider(c.Curve, c.ProvingScheme)
	case zkp.ZKSnarkProverProviderZoKrates:
		return nil // not implemented
	default:
		common.Log.Warningf("failed to initialize prover provider; unknown provider: %s", *c.Provider)
	}

	return nil
}

// Create a prover
func (c *Prover) Create(variables interface{}) bool {
	if !c.validate() {
		return false
	}

	db := dbconf.DatabaseConnection()
	isImport := c.Artifacts != nil

	if !c.importArtifacts(db) && !c.compile(db, variables) {
		return false
	}

	if db.NewRecord(c) || isImport {
		result := db.Create(&c)
		rowsAffected := result.RowsAffected
		errors := result.GetErrors()
		if len(errors) > 0 {
			for _, err := range errors {
				c.Errors = append(c.Errors, &provide.Error{
					Message: common.StringOrNil(err.Error()),
				})
			}
		}
		if !db.NewRecord(c) {
			success := rowsAffected > 0
			if success {
				common.Log.Debugf("initialized %s %s %s prover: %s", *c.Provider, *c.ProvingScheme, *c.Identifier, c.ID)

				if c.NoteStoreID == nil || c.NullifierStoreID == nil {
					err := c.initStorage()
					if err != nil {
						common.Log.Warning(err.Error())
						c.updateStatus(db, proverStatusFailed, common.StringOrNil(err.Error()))
						c.Errors = append(c.Errors, &provide.Error{
							Message: common.StringOrNil(err.Error()),
						})
						return false
					}
				} else {
					if c.NoteStoreID != nil {
						c.noteStore = storage.Find(*c.NoteStoreID)
					}

					if c.NullifierStoreID != nil {
						c.nullifierStore = storage.Find(*c.NullifierStoreID)
					}
				}

				if c.srsRequired() {
					if c.srs == nil || len(c.srs) == 0 {
						c.Errors = append(c.Errors, &provide.Error{
							Message: common.StringOrNil(fmt.Sprintf("failed to setup %s prover with identifier %s; required SRS was not present", *c.ProvingScheme, *c.Identifier)),
						})
						return false
					}

					if !c.persistSRS() {
						c.Errors = append(c.Errors, &provide.Error{
							Message: common.StringOrNil(fmt.Sprintf("failed to setup %s prover with identifier %s; SRS not persisted", *c.ProvingScheme, *c.Identifier)),
						})
						return false
					}
				}

				if c.setupRequired() {
					c.updateStatus(db, proverStatusPendingSetup, nil)

					payload, _ := json.Marshal(map[string]interface{}{
						"prover_id": c.ID.String(),
					})
					natsutil.NatsJetstreamPublish(natsCreatedProverSetupSubject, payload)
				} else if isImport {
					c.updateStatus(db, proverStatusProvisioned, nil)
				}
			}

			return success
		}
	}

	return false
}

// NoteStoreHeight returns the underlying note store height
func (c *Prover) NoteStoreHeight() (*int, error) {
	if c.noteStore == nil && c.NoteStoreID != nil {
		c.noteStore = storage.Find(*c.NoteStoreID)
	}

	if c.noteStore == nil {
		return nil, fmt.Errorf("failed to resolve note store height for prover %s", c.ID)
	}

	height := c.noteStore.Height()
	return &height, nil
}

// NullifierStoreHeight returns the underlying nullifier store height
func (c *Prover) NullifierStoreHeight() (*int, error) {
	if c.nullifierStore == nil && c.NullifierStoreID != nil {
		c.nullifierStore = storage.Find(*c.NullifierStoreID)
	}

	if c.nullifierStore == nil {
		return nil, fmt.Errorf("failed to resolve nullifier store height for prover %s", c.ID)
	}

	height := c.nullifierStore.Height()
	return &height, nil
}

// NoteStoreRoot returns the underlying note store root
func (c *Prover) NoteStoreRoot() (*string, error) {
	if c.noteStore == nil && c.NoteStoreID != nil {
		c.noteStore = storage.Find(*c.NoteStoreID)
	}

	if c.noteStore == nil {
		return nil, fmt.Errorf("failed to resolve note store root for prover %s", c.ID)
	}

	return c.noteStore.Root()
}

// NoteValueAt returns the decrypted note and key for nullified note from the underlying note storage provider
func (c *Prover) NoteValueAt(index uint64) ([]byte, []byte, error) {
	if c.noteStore == nil && c.NoteStoreID != nil {
		c.noteStore = storage.Find(*c.NoteStoreID)
	}

	if c.noteStore == nil {
		return nil, nil, fmt.Errorf("failed to resolve note store value for index %d for prover %s", index, c.ID)
	}

	val, err := c.noteStore.ValueAt(new(big.Int).SetUint64(index).Bytes())
	if err != nil {
		return nil, nil, err
	}

	resp, err := vault.Decrypt(
		util.DefaultVaultAccessJWT,
		c.VaultID.String(),
		c.EncryptionKeyID.String(),
		map[string]interface{}{
			"data": hex.EncodeToString(val),
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve note store value for index %d for prover %s; failed to decrypt note; %s", index, c.ID, err.Error())
	}

	if c.nullifierStore == nil && c.NullifierStoreID != nil {
		c.nullifierStore = storage.Find(*c.NullifierStoreID)
	}

	var key []byte
	if c.nullifierStore != nil {
		key, err = c.nullifierStore.CalculateKey(string(val))
		if err != nil {
			return nil, nil, err
		}
	}

	return []byte(resp.Data), key, nil
}

// NullifierStoreRoot returns the underlying nullifier store root
func (c *Prover) NullifierStoreRoot() (*string, error) {
	if c.nullifierStore == nil && c.NullifierStoreID != nil {
		c.nullifierStore = storage.Find(*c.NullifierStoreID)
	}

	if c.nullifierStore == nil {
		return nil, fmt.Errorf("failed to resolve nullifier store root for prover %s", c.ID)
	}

	return c.nullifierStore.Root()
}

// NullifierValueAt returns the hashed note from the underlying nullifier proof storage provider
func (c *Prover) NullifierValueAt(key []byte) ([]byte, error) {
	if c.nullifierStore == nil && c.NullifierStoreID != nil {
		c.nullifierStore = storage.Find(*c.NullifierStoreID)
	}

	if c.nullifierStore == nil {
		return nil, fmt.Errorf("failed to resolve proof store value for key %s for prover %s", string(key), c.ID)
	}

	return c.nullifierStore.ValueAt(key)
}

// Prove generates a proof for the given witness
func (c *Prover) Prove(witness map[string]interface{}) (*string, error) {
	err := c.enrich()
	if err != nil {
		common.Log.Warningf("enrich failed for proving prover %s; %s", c.ID, err.Error())
	}

	provider := c.proverProviderFactory()
	if provider == nil {
		return nil, fmt.Errorf("failed to resolve prover provider")
	}

	witval, err := provider.WitnessFactory(*c.Identifier, *c.Curve, witness, false)
	if err != nil {
		common.Log.Warningf("failed to read serialized witness for prover %s; %s", c.ID, err.Error())
		return nil, err
	}

	proof, err := provider.Prove(c.Binary, c.provingKey, witval, c.srs)
	if err != nil {
		common.Log.Warningf("failed to generate proof for prover %s; %s", c.ID, err.Error())
		return nil, err
	}

	buf := new(bytes.Buffer)
	_, err = proof.(io.WriterTo).WriteTo(buf)
	if err != nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to marshal binary proof for prover %s with identifier %s; %s", c.ID, *c.Identifier, err.Error())),
		})
		return nil, err
	}

	_proof := common.StringOrNil(hex.EncodeToString(buf.Bytes()))
	common.Log.Debugf("generated proof for prover %s with identifier %s: %s", c.ID, *c.Identifier, *_proof)

	err = c.updateState(*_proof, witness)
	if err != nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to update state for prover %s with identifier %s; %s", c.ID, *c.Identifier, err.Error())),
		})
		return nil, err
	}

	return _proof, nil
}

// Verify a proof to be verifiable for the given witness
func (c *Prover) Verify(proof string, witness map[string]interface{}, store bool) (bool, error) {
	err := c.enrich()
	if err != nil {
		common.Log.Warningf("enrich failed for verifying prover %s with identifier %s; %s", c.ID, *c.Identifier, err.Error())
	}

	provider := c.proverProviderFactory()
	if provider == nil {
		return false, fmt.Errorf("failed to resolve prover provider")
	}

	var _proof []byte

	_proof, err = hex.DecodeString(proof)
	if err != nil {
		common.Log.Debugf("failed to decode proof as hex for verification of prover %s; %s", c.ID, err.Error())
		_proof = []byte(proof)
	}

	witval, err := provider.WitnessFactory(*c.Identifier, *c.Curve, witness, true)
	if err != nil {
		common.Log.Warningf("failed to read serialized witness for prover %s; %s", c.ID, err.Error())
		return false, err
	}

	err = provider.Verify(_proof, c.verifyingKey, witval, c.srs)
	if err != nil {
		common.Log.Debugf("failed to verify witness for prover %s; proof: %s; %s", c.ID, proof, err.Error())
		return false, err
	}

	if store {
		err = c.updateState(string(_proof), witness)
		if err != nil {
			c.Errors = append(c.Errors, &provide.Error{
				Message: common.StringOrNil(fmt.Sprintf("failed to update state for prover %s with identifier %s; %s", c.ID, *c.Identifier, err.Error())),
			})
			return false, err
		}
	}

	common.Log.Debugf("witness verified for prover %s; proof: %s", c.ID, proof)
	return true, nil
}

// compile attempts to compile the prover
func (c *Prover) compile(db *gorm.DB, variables interface{}) bool {
	c.updateStatus(db, proverStatusCompiling, nil)

	provider := c.proverProviderFactory()
	if provider == nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil("failed to resolve prover provider"),
		})
		return false
	}

	var artifacts interface{}
	var err error

	if c.Identifier != nil {
		prover := provider.ProverFactory(*c.Identifier)

		if prover != nil {
			artifacts, err = provider.Compile(prover, variables)
			if err != nil {
				c.Errors = append(c.Errors, &provide.Error{
					Message: common.StringOrNil(fmt.Sprintf("failed to compile prover with identifier %s; %s", *c.Identifier, err.Error())),
				})
				return false
			}
		} else {
			c.Errors = append(c.Errors, &provide.Error{
				Message: common.StringOrNil(fmt.Sprintf("failed to resolve prover %s for provider: %s", *c.Identifier, *c.Provider)),
			})
			return false
		}
	}

	buf := new(bytes.Buffer)
	_, err = artifacts.(io.WriterTo).WriteTo(buf)
	if err != nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to marshal binary artifacts for prover with identifier %s; %s", *c.Identifier, err.Error())),
		})
		return false
	}
	c.Binary = buf.Bytes()

	c.updateStatus(db, proverStatusCompiled, nil)
	return len(c.Errors) == 0
}

// canExportVerifier returns true if the prover instance supports exporting a verifier smart contract
func (c *Prover) canExportVerifier() bool {
	return c.VerifierContract == nil && strings.ToLower(*c.ProvingScheme) == proverProvingSchemeGroth16 && strings.ToLower(*c.Curve) == ecc.BN254.String()
}

// enrich the prover
func (c *Prover) enrich() error {
	if (c.provingKey == nil || len(c.provingKey) == 0) && c.ProvingKeyID != nil {
		secret, err := vault.FetchSecret(
			util.DefaultVaultAccessJWT,
			c.VaultID.String(),
			c.ProvingKeyID.String(),
			map[string]interface{}{},
		)
		if err != nil {
			return err
		}
		c.provingKey, err = hex.DecodeString(*secret.Value)
		if err != nil {
			common.Log.Warningf("failed to decode proving key secret from hex; %s", err.Error())
			return err
		}
	}

	if (c.provingKey == nil || len(c.provingKey) == 0) && c.ProvingKeyID != nil {
		secret, err := vault.FetchSecret(
			util.DefaultVaultAccessJWT,
			c.VaultID.String(),
			c.ProvingKeyID.String(),
			map[string]interface{}{},
		)
		if err != nil {
			return err
		}
		c.provingKey, err = hex.DecodeString(*secret.Value)
		if err != nil {
			common.Log.Warningf("failed to decode proving key secret from hex; %s", err.Error())
			return err
		}
	}

	if (c.verifyingKey == nil || len(c.verifyingKey) == 0) && c.VerifyingKeyID != nil {
		secret, err := vault.FetchSecret(
			util.DefaultVaultAccessJWT,
			c.VaultID.String(),
			c.VerifyingKeyID.String(),
			map[string]interface{}{},
		)
		if err != nil {
			return err
		}
		c.verifyingKey, err = hex.DecodeString(*secret.Value)
		if err != nil {
			common.Log.Warningf("failed to decode verifying key secret from hex; %s", err.Error())
			return err
		}
	}

	if (c.srs == nil || len(c.srs) == 0) && c.StructuredReferenceStringID != nil {
		secret, err := vault.FetchSecret(
			util.DefaultVaultAccessJWT,
			c.VaultID.String(),
			c.StructuredReferenceStringID.String(),
			map[string]interface{}{},
		)
		if err != nil {
			return err
		}
		c.srs, err = hex.DecodeString(*secret.Value)
		if err != nil {
			common.Log.Warningf("failed to decode SRS secret from hex; %s", err.Error())
			return err
		}
	}

	if c.Artifacts == nil {
		c.Artifacts = map[string]interface{}{
			"binary":        hex.EncodeToString(c.Binary),
			"proving_key":   hex.EncodeToString(c.provingKey),
			"verifying_key": hex.EncodeToString(c.verifyingKey),
		}

		if c.srs != nil && len(c.srs) > 0 {
			c.Artifacts["srs"] = hex.EncodeToString(c.srs)
		}
	}

	if c.noteStore == nil && c.NoteStoreID != nil {
		c.noteStore = storage.Find(*c.NoteStoreID)
	}

	if c.nullifierStore == nil && c.NullifierStoreID != nil {
		c.nullifierStore = storage.Find(*c.NullifierStoreID)
	}

	if c.canExportVerifier() {
		err := c.exportVerifier()
		if err != nil {
			common.Log.Debugf("failed to export verifier contract for prover %s; %s", c.ID, err.Error())
		} else if c.verifierContractSource != nil && len(c.verifierContractSource) > 0 {
			c.VerifierContract = map[string]interface{}{
				"source": string(c.verifierContractSource),
			}
		}
	}

	// epoch := uint64(0) // FIXME-- resolve latest epoch
	// c.exportState(epoch)

	return nil
}

// // exportState exports the state of the prover at the given epoch
// func (c *Prover) exportState(epoch uint64) (*state.State, error) {
// 	noteState, _ := c.noteStore.StateAt(epoch)
// 	nullifiedState, _ := c.nullifierStore.StateAt(epoch) // spent

// 	common.Log.Debugf("resolved note and nullified state; %s; %s", noteState, nullifiedState)
// 	return nullifiedState, nil
// }

func (c *Prover) exportVerifier() error {
	provider := c.proverProviderFactory()
	if provider == nil {
		return fmt.Errorf("failed to resolve prover provider")
	}

	verifierContract, err := provider.ExportVerifier(string(c.verifyingKey))
	if err != nil {
		return err
	}

	c.verifierContractSource = verifierContract.([]byte)
	return nil
}

// importArtifacts attempts to import the prover from existing artifacts
func (c *Prover) importArtifacts(db *gorm.DB) bool {
	if c.Artifacts == nil {
		common.Log.Tracef("short-provering the creation of prover %s from binary artifacts", c.ID)
		return false
	}

	var err error

	if binary, binaryOk := c.Artifacts["binary"].(string); binaryOk {
		c.Binary, err = hex.DecodeString(binary)
		if err != nil {
			c.Errors = append(c.Errors, &provide.Error{
				Message: common.StringOrNil(fmt.Sprintf("failed to import binary artifact for prover %s; %s", c.ID, err.Error())),
			})
			return false
		}
	}

	if provingKey, provingKeyOk := c.Artifacts["proving_key"].(string); provingKeyOk {
		c.provingKey, err = hex.DecodeString(provingKey)
		if err != nil {
			c.Errors = append(c.Errors, &provide.Error{
				Message: common.StringOrNil(fmt.Sprintf("failed to import proving key for prover %s; %s", c.ID, err.Error())),
			})
			return false
		}
	}

	if verifyingKey, verifyingKeyOk := c.Artifacts["verifying_key"].(string); verifyingKeyOk {
		c.verifyingKey, err = hex.DecodeString(verifyingKey)
		if err != nil {
			c.Errors = append(c.Errors, &provide.Error{
				Message: common.StringOrNil(fmt.Sprintf("failed to import verifying key for prover %s; %s", c.ID, err.Error())),
			})
			return false
		}
	}

	if srs, srsOk := c.Artifacts["srs"].(string); srsOk {
		c.srs, err = hex.DecodeString(srs)
		if err != nil {
			c.Errors = append(c.Errors, &provide.Error{
				Message: common.StringOrNil(fmt.Sprintf("failed to import SRS for prover %s; %s", c.ID, err.Error())),
			})
			return false
		}
	}

	if !c.generateEncryptionKey() {
		return false
	}

	if !c.persistKeys() {
		return false
	}

	if c.srs != nil && len(c.srs) > 0 && !c.persistSRS() {
		return false
	}

	return len(c.Errors) == 0
}

// initStorage attempts to initialize storage for notes (dense) and nullifiers (sparse)
// for the prover instance; no-op for each store type if it has already been initialized
func (c *Prover) initStorage() error {
	if c.NoteStoreID == nil {
		err := c.initNoteStorage()
		if err != nil {
			return err
		}
	}

	if c.NullifierStoreID == nil {
		return c.initNullifierStorage()
	}

	return nil
}

// initNoteStorage initializes dense merkle tree storage for the prover instance
func (c *Prover) initNoteStorage() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.NoteStoreID != nil {
		return fmt.Errorf("failed to initialize notes storage provider for prover %s; notes store has already been initialized", c.ID)
	}

	common.Log.Debugf("attempting to initialize notes storage for prover %s", c.ID)

	store := &storage.Store{
		Name:     common.StringOrNil(fmt.Sprintf("notes merkle tree storage for prover %s", c.ID)),
		Provider: common.StringOrNil(storeprovider.StoreProviderDenseMerkleTree),
		Curve:    common.StringOrNil(*c.Curve),
	}

	if store.Create() {
		common.Log.Debugf("initialized notes storage for prover with identifier %s", c.ID)
		c.NoteStoreID = &store.ID
		c.noteStore = store
	} else {
		return fmt.Errorf("failed to initialize notes storage provider for prover %s; store not persisted", c.ID)
	}

	return nil
}

// initNullifierStorage initializes sparse merkle tree storage for hashed proofs for the prover instance
func (c *Prover) initNullifierStorage() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.NullifierStoreID != nil {
		return fmt.Errorf("failed to initialize proof storage provider for prover %s; store has already been initialized", c.ID)
	}

	common.Log.Debugf("attempting to initialize proof storage for prover %s", c.ID)

	store := &storage.Store{
		Name:     common.StringOrNil(fmt.Sprintf("nullifiers merkle tree storage for prover %s", c.ID)),
		Provider: common.StringOrNil(storeprovider.StoreProviderSparseMerkleTree),
		Curve:    common.StringOrNil(*c.Curve),
	}

	if store.Create() {
		common.Log.Debugf("initialized proof storage for prover with identifier %s", c.ID)
		c.NullifierStoreID = &store.ID
		c.nullifierStore = store
	} else {
		return fmt.Errorf("failed to initialize proof storage provider for prover %s; store not persisted", c.ID)
	}

	return nil
}

// generateEncryptionKey attempts to generate an AES-256-GCM symmetric key for encrypting
// notes and persist the key id on the prover instance
func (c *Prover) generateEncryptionKey() bool {
	key, err := vault.CreateKey(
		util.DefaultVaultAccessJWT,
		c.VaultID.String(),
		map[string]interface{}{
			"name":        fmt.Sprintf("%s prover note encryption key", *c.Name),
			"description": fmt.Sprintf("%s prover key for encrypted note storage", *c.Name),
			"spec":        "AES-256-GCM",
			"type":        "symmetric",
			"usage":       "encrypt/decrypt",
		},
	)
	if err != nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to generate symmetric key material for encrypted notes storage for prover %s in vault %s; %s", *c.Identifier, c.VaultID.String(), err.Error())),
		})
		return false
	}

	c.EncryptionKeyID = &key.ID
	return c.EncryptionKeyID != nil
}

// persistKeys attempts to persist the proving and verifying keys as secrets
// in the configured vault instance
func (c *Prover) persistKeys() bool {
	secret, err := vault.CreateSecret(
		util.DefaultVaultAccessJWT,
		c.VaultID.String(),
		map[string]interface{}{
			"description": fmt.Sprintf("%s prover %s proving key", *c.Name, *c.ProvingScheme),
			"name":        fmt.Sprintf("%s prover proving key", *c.Name),
			"type":        proverVaultTypePrivacyProvingKey,
			"value":       hex.EncodeToString(c.provingKey),
		},
	)
	if err != nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to store proving key for prover %s in vault %s; %s", *c.Identifier, c.VaultID.String(), err.Error())),
		})
		return false
	}
	c.ProvingKeyID = &secret.ID

	secret, err = vault.CreateSecret(
		util.DefaultVaultAccessJWT,
		c.VaultID.String(),
		map[string]interface{}{
			"description": fmt.Sprintf("%s prover %s verifying key", *c.Name, *c.ProvingScheme),
			"name":        fmt.Sprintf("%s prover verifying key", *c.Name),
			"type":        proverVaultTypePrivacyVerifyingKey,
			"value":       hex.EncodeToString(c.verifyingKey),
		},
	)
	if err != nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to store verifying key for prover %s in vault %s; %s", *c.Identifier, c.VaultID.String(), err.Error())),
		})
		return false
	}
	c.VerifyingKeyID = &secret.ID

	return c.ProvingKeyID != nil && c.VerifyingKeyID != nil
}

// persistSRS attempts to persist the prover SRS as a secret in the configured vault instance
func (c *Prover) persistSRS() bool {
	secret, err := vault.CreateSecret(
		util.DefaultVaultAccessJWT,
		c.VaultID.String(),
		map[string]interface{}{
			"description": fmt.Sprintf("%s prover %s SRS", *c.Name, *c.ProvingScheme),
			"name":        fmt.Sprintf("%s prover SRS", *c.Name),
			"type":        proverVaultTypePrivacySRS,
			"value":       hex.EncodeToString(c.srs),
		},
	)
	if err != nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to store SRS for prover %s in vault %s; %s", *c.Identifier, c.VaultID.String(), err.Error())),
		})
		return false
	}
	c.StructuredReferenceStringID = &secret.ID
	return c.StructuredReferenceStringID != nil
}

func (c *Prover) setupRequired() bool {
	return c.ProvingScheme != nil && (*c.ProvingScheme == proverProvingSchemeGroth16 || *c.ProvingScheme == proverProvingSchemePlonk) && c.Status != nil && (*c.Status == proverStatusCompiled || *c.Status == proverStatusPendingSetup)
}

// setup attempts to setup the prover
func (c *Prover) setup(db *gorm.DB) bool {
	if !c.setupRequired() {
		common.Log.Warningf("attempted to setup prover for which setup is not required")
		return false
	}

	c.updateStatus(db, proverStatusRunningSetup, nil)

	if c.Binary == nil || len(c.Binary) == 0 {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to setup prover with identifier %s; no compiled artifacts", *c.Identifier)),
		})
		common.Log.Warningf("failed to setup prover with identifier %s; no compiled artifacts", *c.Identifier)
		return false
	}

	provider := c.proverProviderFactory()
	if provider == nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil("failed to resolve prover provider"),
		})
		return false
	}

	if c.srsRequired() && (c.srs == nil || len(c.srs) == 0) {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to acquire srs before setup for prover with identifier %s", *c.Identifier)),
		})
		common.Log.Warningf("failed to acquire srs before Setup for prover with identifier %s", *c.Identifier)
		return false
	}
	pk, vk, err := provider.Setup(c.Binary, c.srs)

	if err != nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("error during setup of verifier and proving keys for prover with identifier %s; %s", *c.Identifier, err.Error())),
		})
		common.Log.Warningf("error during setup of verifier and proving keys for prover with identifier %s; %s", *c.Identifier, err.Error())
		return false
	} else if vk == nil || pk == nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to setup verifier and proving keys for prover with identifier %s", *c.Identifier)),
		})
		common.Log.Warningf("failed to setup verifier and proving keys for prover with identifier %s", *c.Identifier)
		return false
	}

	pkBuf := new(bytes.Buffer)
	_, err = pk.(io.WriterTo).WriteTo(pkBuf)
	if err != nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to marshal binary proving key for prover with identifier %s; %s", *c.Identifier, err.Error())),
		})
		common.Log.Warningf("failed to marshal binary proving key for prover with identifier %s; %s", *c.Identifier, err.Error())
		return false
	}
	c.provingKey = pkBuf.Bytes()

	vkBuf := new(bytes.Buffer)
	_, err = vk.(io.WriterTo).WriteTo(vkBuf)
	if err != nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to marshal binary verifying key for prover with identifier %s; %s", *c.Identifier, err.Error())),
		})
		common.Log.Warningf("failed to marshal binary verifying key for prover with identifier %s; %s", *c.Identifier, err.Error())
		return false
	}
	c.verifyingKey = vkBuf.Bytes()

	if len(c.Errors) != 0 {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("errors found while setting up prover with identifier %s", *c.Identifier)),
		})
		common.Log.Warningf("errors found while setting up prover with identifier %s", *c.Identifier)
		return false
	}

	if !c.generateEncryptionKey() {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to persist encryption key for prover with identifier %s", *c.Identifier)),
		})
		common.Log.Warningf("failed to persist encryption key for prover with identifier %s", *c.Identifier)
		return false
	}

	if !c.persistKeys() {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to persist proving and verifying keys for prover with identifier %s", *c.Identifier)),
		})
		common.Log.Warningf("failed to persist proving and verifying keys for prover with identifier %s", *c.Identifier)
		return false
	}

	err = c.enrich()
	if err != nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to enrich prover with identifier %s; %s", *c.Identifier, err.Error())),
		})
		common.Log.Warningf("failed to enrich prover with identifier %s; %s", *c.Identifier, err.Error())
		return false
	}

	err = c.updateStatus(db, proverStatusProvisioned, nil)
	if err != nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to update status of prover with identifier %s; %s", *c.Identifier, err.Error())),
		})
		common.Log.Warningf("failed to update status of prover with identifier %s; %s", *c.Identifier, err.Error())
		return false
	}

	return true
}

func (c *Prover) srsRequired() bool {
	return c.ProvingScheme != nil && *c.ProvingScheme == proverProvingSchemePlonk
}

// updateStatus updates the prover status and optional description
func (c *Prover) updateStatus(db *gorm.DB, status string, description *string) error {
	// FIXME-- use distributed lock here
	c.Status = common.StringOrNil(status)
	c.Description = description
	if !db.NewRecord(&c) {
		result := db.Save(&c)
		errors := result.GetErrors()
		if len(errors) > 0 {
			for _, err := range errors {
				c.Errors = append(c.Errors, &provide.Error{
					Message: common.StringOrNil(err.Error()),
				})
			}
			return errors[0]
		}
	}
	return nil
}

// TODO-- add object, witness
func (c *Prover) updateState(proof string, witness map[string]interface{}) error {
	var note []byte

	// FIXME -- adopt proper Note structure
	note, _ = json.Marshal(map[string]interface{}{
		"proof":   proof,
		"witness": witness,
	})

	var data []byte
	var nullifiedNote []byte

	nullifierExists := false
	nullifiedIndex := -1

	if c.noteStore != nil {
		resp, err := vault.Encrypt(
			util.DefaultVaultAccessJWT,
			c.VaultID.String(),
			c.EncryptionKeyID.String(),
			string(note),
		)
		if err != nil {
			common.Log.Warningf("failed to update state; failed to encrypt note for prover %s; %s", c.ID, err.Error())
			return err
		}

		data, err = hex.DecodeString(resp.Data)
		if err != nil {
			common.Log.Warningf("failed to update state; failed to encrypt note for prover %s; %s", c.ID, err.Error())
			return err
		}

		nullifiedIndex, err = c.noteStore.Size()
		if err != nil {
			common.Log.Warningf("failed to get size of note store for prover %s; %s", c.ID, err.Error())
			return err
		}

		nullifiedIndex--

		if nullifiedIndex >= 0 && c.nullifierStore != nil {
			nullifiedNote, err = c.noteStore.ValueAt(new(big.Int).SetUint64(uint64(nullifiedIndex)).Bytes())
			if err != nil {
				common.Log.Warningf("failed to update state; note not inserted for prover %s; failed to check double-spend; %s", c.ID, err.Error())
				return err
			}

			nullifierExists, err = c.nullifierStore.Contains(string(nullifiedNote))
			if err != nil {
				common.Log.Warningf("failed to update state; unable to determine if nullifier exists for prover %s; %s", c.ID, err.Error())
				return err
			}

			if nullifierExists {
				err := fmt.Errorf("attempt to double-spend %d-byte note for prover %s", len(note), c.ID)
				common.Log.Warning(err.Error())
				return err
			}
		}

		_, err = c.noteStore.Insert(string(data))
		if err != nil {
			common.Log.Warningf("failed to update state; note not inserted for prover %s; %s", c.ID, err.Error())
			return err
		}

		_, err = c.dispatchNotification(natsProverNotificationNoteDeposit)
		if err != nil {
			common.Log.Warningf("failed to dispatch %s notification for prover %s; %s", natsProverNotificationNoteDeposit, c.ID, err.Error())
		}

		common.Log.Debugf("inserted %d-byte note for prover %s", len(note), c.ID)
	}

	if nullifiedIndex >= 0 && c.nullifierStore != nil {
		common.Log.Debugf("state update nullified previous note at index %d", nullifiedIndex)

		root, err := c.nullifierStore.Insert(string(nullifiedNote))
		if err != nil {
			common.Log.Warningf("failed to insert nullifier for prover %s; %s", c.ID, err.Error())
			return err
		} else {
			nullifierExists, err = c.nullifierStore.Contains(string(nullifiedNote))
			if err != nil {
				common.Log.Warningf("failed to update state; unable to determine if nullifier exists for prover %s; %s", c.ID, err.Error())
				return err
			}

			if !nullifierExists {
				err := fmt.Errorf("inserted nullifier for prover %s resulted in internal inconsistency for %d-byte note", c.ID, len(note))
				common.Log.Warning(err.Error())
				return err
			}

			_, err = c.dispatchNotification(natsProverNotificationNoteNullified)
			if err != nil {
				common.Log.Warningf("failed to dispatch %s notification for prover %s; %s", natsProverNotificationNoteNullified, c.ID, err.Error())
			}

			common.Log.Debugf("inserted %d-byte nullifier for prover %s: root: %s", len(data), c.ID, hex.EncodeToString(root))
		}
	}

	return nil
}

// exited returns true if the prover, or its logical parent, has exited
// a prover can exit iff !exited()
func (c *Prover) exited() bool {

	return false
}

// exit the given prover by nullifying its final valid state
//
// 1. Set all values in the note object to zero and encrypt. This will always lead to the same string and thus nullifier index for the note and nullifier tree for a given prover.
// 2. Check if the last index value is the value to ensure that the note tree has not already been exited. If yes, then error out, if no continue
// 3. Check if the nullifier tree has that entry too. If yes, then error out, if no continue
// 4. Update the note store
// 5. Update the nullifier tree. This seals both note and nullifier trees to further changes.
//
// TODO: add function to check if a workflow has been exited by checking to see if the last note is the exit note and if it has been nullified in the SMT
func (c *Prover) exit() error {
	var err error
	// TODO: check to ensure an exit is possible...

	_, err = c.dispatchNotification(natsProverNotificationExit)
	if err != nil {
		common.Log.Warningf("failed to dispatch %s notification for prover %s; %s", natsProverNotificationExit, c.ID, err.Error())
	}

	return nil
}

// validate the prover params
func (c *Prover) validate() bool {
	c.Errors = make([]*provide.Error, 0)

	if c.Curve == nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil("prover curve id required"),
		})
	}

	if c.Provider == nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil("prover provider required"),
		})
	}

	if c.ProvingScheme == nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil("prover proving scheme required"),
		})
	}

	if c.Identifier == nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil("prover identifier required"),
		})
	}

	if c.VaultID == nil {
		if common.DefaultVault != nil {
			c.VaultID = &common.DefaultVault.ID
		}

		if c.VaultID == nil {
			c.Errors = append(c.Errors, &provide.Error{
				Message: common.StringOrNil("vault id required"),
			})
		}
	}

	return len(c.Errors) == 0
}
