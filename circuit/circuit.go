package circuit

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
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

	kzgbls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/kzg"
	kzgbls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/kzg"
	kzgbls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr/kzg"
	kzgbn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
	kzgbw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/kzg"
)

const circuitProvingSchemeGroth16 = "groth16"
const circuitProvingSchemePlonk = "plonk"

const circuitStatusFailed = "failed"
const circuitStatusInit = "init"
const circuitStatusCompiling = "compiling"
const circuitStatusCompiled = "compiled"
const circuitStatusPendingSetup = "pending_setup"
const circuitStatusRunningSetup = "running_setup"
const circuitStatusDeployingArtifacts = "deploying_artifacts" // optional -- if i.e. verifier contract should be deployed to blockchain
const circuitStatusProvisioned = "provisioned"

// Circuit model
type Circuit struct {
	provide.Model

	// Artifacts, i.e., r1cs, ABI, etc
	ABI      []byte `json:"abi,omitempty"`
	Binary   []byte `gorm:"column:bin" json:"-"`
	SRSAlpha []byte `sql:"-" json:"-"`

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

func (c *Circuit) circuitProviderFactory() zkp.ZKSnarkCircuitProvider {
	if c.Provider == nil {
		common.Log.Warning("failed to initialize circuit provider; no provider defined")
		return nil
	}

	switch *c.Provider {
	case zkp.ZKSnarkCircuitProviderGnark:
		return zkp.InitGnarkCircuitProvider(c.Curve, c.ProvingScheme)
	case zkp.ZKSnarkCircuitProviderZoKrates:
		return nil // not implemented
	default:
		common.Log.Warningf("failed to initialize circuit provider; unknown provider: %s", *c.Provider)
	}

	return nil
}

func getKzgScheme(r1cs frontend.CompiledConstraintSystem, alpha *big.Int) kzg.SRS {
	nbConstraints := r1cs.GetNbConstraints()
	internal, secret, public := r1cs.GetNbVariables()
	nbVariables := internal + secret + public
	var s, size int
	if nbConstraints > nbVariables {
		s = nbConstraints
	} else {
		s = nbVariables
	}
	size = common.NextPowerOfTwo(s)

	switch r1cs.CurveID() {
	case ecc.BN254:
		return kzgbn254.NewSRS(size, alpha)
	case ecc.BLS12_381:
		return kzgbls12381.NewSRS(size, alpha)
	case ecc.BLS12_377:
		return kzgbls12377.NewSRS(size, alpha)
	case ecc.BW6_761:
		return kzgbw6761.NewSRS(size*2, alpha)
	case ecc.BLS24_315:
		return kzgbls24315.NewSRS(size, alpha)
	default:
		return nil
	}
}

// generateSRS generates a KZG SRS for testing and will be replaced with proper MPC ceremony
func (c *Circuit) generateSRS() error {
	var r1cs frontend.CompiledConstraintSystem

	switch *c.ProvingScheme {
	case circuitProvingSchemeGroth16:
		r1cs = groth16.NewCS(common.GnarkCurveIDFactory(c.Curve))
	case circuitProvingSchemePlonk:
		r1cs = plonk.NewCS(common.GnarkCurveIDFactory(c.Curve))
	default:
		return fmt.Errorf("invalid proving scheme %s", *c.ProvingScheme)
	}

	_, err := r1cs.ReadFrom(bytes.NewReader(c.Binary))
	if err != nil {
		return fmt.Errorf("failed to read r1cs for circuit with identifier %s; %s", *c.Identifier, err.Error())
	}

	alpha := new(big.Int).SetBytes(c.SRSAlpha)
	srs := getKzgScheme(r1cs, alpha)
	buf := new(bytes.Buffer)
	_, err = srs.WriteTo(buf)
	if err != nil {
		return fmt.Errorf("failed to write srs for circuit with identifier %s; %s", *c.Identifier, err.Error())
	}

	c.srs = buf.Bytes()

	return nil
}

// Create a circuit
func (c *Circuit) Create() bool {
	if !c.validate() {
		return false
	}

	db := dbconf.DatabaseConnection()
	isImport := c.Artifacts != nil

	if !c.importArtifacts(db) && !c.compile(db) {
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
				common.Log.Debugf("initialized %s %s %s circuit: %s", *c.Provider, *c.ProvingScheme, *c.Identifier, c.ID)

				if c.NoteStoreID == nil || c.NullifierStoreID == nil {
					err := c.initStorage()
					if err != nil {
						common.Log.Warning(err.Error())
						c.updateStatus(db, circuitStatusFailed, common.StringOrNil(err.Error()))
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
					if c.SRSAlpha != nil && (c.srs == nil || len(c.srs) == 0) {
						err := c.generateSRS()
						if err != nil {
							c.Errors = append(c.Errors, &provide.Error{
								Message: common.StringOrNil(fmt.Sprintf("failed to setup %s circuit with identifier %s; required alpha for SRS was not present", *c.ProvingScheme, *c.Identifier)),
							})
							return false
						}
					}

					if c.srs == nil || len(c.srs) == 0 {
						c.Errors = append(c.Errors, &provide.Error{
							Message: common.StringOrNil(fmt.Sprintf("failed to setup %s circuit with identifier %s; required SRS was not present", *c.ProvingScheme, *c.Identifier)),
						})
						return false
					}

					if !c.persistSRS() {
						c.Errors = append(c.Errors, &provide.Error{
							Message: common.StringOrNil(fmt.Sprintf("failed to setup %s circuit with identifier %s; SRS not persisted", *c.ProvingScheme, *c.Identifier)),
						})
						return false
					}
				}

				if c.setupRequired() {
					c.updateStatus(db, circuitStatusPendingSetup, nil)

					payload, _ := json.Marshal(map[string]interface{}{
						"circuit_id": c.ID.String(),
					})
					natsutil.NatsStreamingPublish(natsCreatedCircuitSetupSubject, payload)
				} else if isImport {
					c.updateStatus(db, circuitStatusProvisioned, nil)
				}
			}

			return success
		}
	}

	return false
}

// NoteStoreHeight returns the underlying note store height
func (c *Circuit) NoteStoreHeight() (*int, error) {
	if c.noteStore == nil && c.NoteStoreID != nil {
		c.noteStore = storage.Find(*c.NoteStoreID)
	}

	if c.noteStore == nil {
		return nil, fmt.Errorf("failed to resolve note store height for circuit %s", c.ID)
	}

	height := c.noteStore.Height()
	return &height, nil
}

// NullifierStoreHeight returns the underlying nullifier store height
func (c *Circuit) NullifierStoreHeight() (*int, error) {
	if c.nullifierStore == nil && c.NullifierStoreID != nil {
		c.nullifierStore = storage.Find(*c.NullifierStoreID)
	}

	if c.nullifierStore == nil {
		return nil, fmt.Errorf("failed to resolve nullifier store height for circuit %s", c.ID)
	}

	height := c.nullifierStore.Height()
	return &height, nil
}

// NoteValueAt returns the decrypted note from the underlying note storage provider
func (c *Circuit) NoteValueAt(key []byte) ([]byte, error) {
	if c.noteStore == nil && c.NoteStoreID != nil {
		c.noteStore = storage.Find(*c.NoteStoreID)
	}

	if c.noteStore == nil {
		return nil, fmt.Errorf("failed to resolve note store value for key %s for circuit %s", key, c.ID)
	}

	val, err := c.noteStore.ValueAt(key)
	if err != nil {
		return nil, err
	}

	// rawval, err := base64.RawStdEncoding.DecodeString(*val)
	// if err != nil {
	// 	return nil, err
	// }

	// *val = string(rawval)
	return val, nil
}

// NullifierStoreRoot returns the underlying nullifier store root
func (c *Circuit) NullifierStoreRoot() (*string, error) {
	if c.nullifierStore == nil && c.NullifierStoreID != nil {
		c.nullifierStore = storage.Find(*c.NullifierStoreID)
	}

	if c.nullifierStore == nil {
		return nil, fmt.Errorf("failed to resolve store root for circuit %s", c.ID)
	}

	return c.nullifierStore.Root()
}

// NullifierValueAt returns the hashed proof from the underlying nullifier proof storage provider
func (c *Circuit) NullifierValueAt(key []byte) ([]byte, error) {
	if c.nullifierStore == nil && c.NullifierStoreID != nil {
		c.nullifierStore = storage.Find(*c.NullifierStoreID)
	}

	if c.nullifierStore == nil {
		return nil, fmt.Errorf("failed to resolve proof store value for key %s for circuit %s", string(key), c.ID)
	}

	return c.nullifierStore.ValueAt(key)
}

// Prove generates a proof for the given witness
func (c *Circuit) Prove(witness map[string]interface{}) (*string, error) {
	c.enrich()

	provider := c.circuitProviderFactory()
	if provider == nil {
		return nil, fmt.Errorf("failed to resolve circuit provider")
	}

	witval, err := provider.WitnessFactory(*c.Identifier, *c.Curve, witness)
	if err != nil {
		common.Log.Warningf("failed to read serialize witness; %s", err.Error())
		return nil, err
	}

	proof, err := provider.Prove(c.Binary, c.provingKey, witval, c.srs)
	if err != nil {
		common.Log.Warningf("failed to generate proof; %s", err.Error())
		return nil, err
	}

	buf := new(bytes.Buffer)
	_, err = proof.(io.WriterTo).WriteTo(buf)
	if err != nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to marshal binary proof for circuit with identifier %s; %s", *c.Identifier, err.Error())),
		})
		return nil, err
	}

	_proof := common.StringOrNil(buf.String())
	common.Log.Debugf("generated proof for circuit with identifier %s: %s", *c.Identifier, hex.EncodeToString(buf.Bytes()))

	err = c.updateState(*_proof, witness)
	if err != nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to update state for circuit with identifier %s; %s", *c.Identifier, err.Error())),
		})
		return nil, err
	}

	*_proof = hex.EncodeToString([]byte(*_proof))
	return _proof, nil
}

// Verify a proof to be verifiable for the given witness
func (c *Circuit) Verify(proof string, witness map[string]interface{}, store bool) (bool, error) {
	c.enrich()

	provider := c.circuitProviderFactory()
	if provider == nil {
		return false, fmt.Errorf("failed to resolve circuit provider")
	}

	var _proof []byte
	var err error

	_proof, err = hex.DecodeString(proof)
	if err != nil {
		common.Log.Debugf("failed to decode proof as hex; %s", err.Error())
		_proof = []byte(proof)
	}

	witval, err := provider.WitnessFactory(*c.Identifier, *c.Curve, witness)
	if err != nil {
		common.Log.Warningf("failed to read serialize witness; %s", err.Error())
		return false, err
	}

	err = provider.Verify(_proof, c.verifyingKey, witval, c.srs)
	if err != nil {
		return false, err
	}

	if store {
		err = c.updateState(string(_proof), witness)
		if err != nil {
			c.Errors = append(c.Errors, &provide.Error{
				Message: common.StringOrNil(fmt.Sprintf("failed to update state for circuit with identifier %s; %s", *c.Identifier, err.Error())),
			})
			return false, err
		}
	}

	common.Log.Debugf("circuit witness %s verified for proof: %s", witness, proof)
	return true, nil
}

// compile attempts to compile the circuit
func (c *Circuit) compile(db *gorm.DB) bool {
	c.updateStatus(db, circuitStatusCompiling, nil)

	provider := c.circuitProviderFactory()
	if provider == nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil("failed to resolve circuit provider"),
		})
		return false
	}

	var artifacts interface{}
	var err error

	if c.Identifier != nil {
		circuit := provider.CircuitFactory(*c.Identifier)

		if circuit != nil {
			artifacts, err = provider.Compile(circuit)
			if err != nil {
				c.Errors = append(c.Errors, &provide.Error{
					Message: common.StringOrNil(fmt.Sprintf("failed to compile circuit with identifier %s; %s", *c.Identifier, err.Error())),
				})
				return false
			}
		} else {
			c.Errors = append(c.Errors, &provide.Error{
				Message: common.StringOrNil(fmt.Sprintf("failed to resolve circuit for provider: %s", *c.Provider)),
			})
			return false
		}
	}

	buf := new(bytes.Buffer)
	_, err = artifacts.(io.WriterTo).WriteTo(buf)
	if err != nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to marshal binary artifacts for circuit with identifier %s; %s", *c.Identifier, err.Error())),
		})
		return false
	}
	c.Binary = buf.Bytes()

	c.updateStatus(db, circuitStatusCompiled, nil)
	return len(c.Errors) == 0
}

// canExportVerifier returns true if the circuit instance supports exporting a verifier smart contract
func (c *Circuit) canExportVerifier() bool {
	return c.VerifierContract == nil && *c.ProvingScheme == circuitProvingSchemeGroth16 && *c.Curve == ecc.BN254.String()
}

// enrich the circuit
func (c *Circuit) enrich() error {
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
			common.Log.Debugf("failed to export verifier contract for circuit; %s", err.Error())
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

// // exportState exports the state of the circuit at the given epoch
// func (c *Circuit) exportState(epoch uint64) (*state.State, error) {
// 	noteState, _ := c.noteStore.StateAt(epoch)
// 	nullifiedState, _ := c.nullifierStore.StateAt(epoch) // spent

// 	common.Log.Debugf("resolved note and nullified state; %s; %s", noteState, nullifiedState)
// 	return nullifiedState, nil
// }

func (c *Circuit) exportVerifier() error {
	provider := c.circuitProviderFactory()
	if provider == nil {
		return fmt.Errorf("failed to resolve circuit provider")
	}

	verifierContract, err := provider.ExportVerifier(string(c.verifyingKey))
	if err != nil {
		return err
	}

	c.verifierContractSource = verifierContract.([]byte)
	return nil
}

// importArtifacts attempts to import the circuit from existing artifacts
func (c *Circuit) importArtifacts(db *gorm.DB) bool {
	if c.Artifacts == nil {
		common.Log.Tracef("short-circuiting the creation of circuit %s from binary artifacts", *c.Identifier)
		return false
	}

	var err error

	if binary, binaryOk := c.Artifacts["binary"].(string); binaryOk {
		c.Binary, err = hex.DecodeString(binary)
		if err != nil {
			c.Errors = append(c.Errors, &provide.Error{
				Message: common.StringOrNil(fmt.Sprintf("failed to import binary artifact for circuit %s; %s", *c.Identifier, err.Error())),
			})
			return false
		}
	}

	if provingKey, provingKeyOk := c.Artifacts["proving_key"].(string); provingKeyOk {
		c.provingKey, err = hex.DecodeString(provingKey)
		if err != nil {
			c.Errors = append(c.Errors, &provide.Error{
				Message: common.StringOrNil(fmt.Sprintf("failed to import proving key for circuit %s; %s", *c.Identifier, err.Error())),
			})
			return false
		}
	}

	if verifyingKey, verifyingKeyOk := c.Artifacts["verifying_key"].(string); verifyingKeyOk {
		c.verifyingKey, err = hex.DecodeString(verifyingKey)
		if err != nil {
			c.Errors = append(c.Errors, &provide.Error{
				Message: common.StringOrNil(fmt.Sprintf("failed to import verifying key for circuit %s; %s", *c.Identifier, err.Error())),
			})
			return false
		}
	}

	if srs, srsOk := c.Artifacts["srs"].(string); srsOk {
		c.srs, err = hex.DecodeString(srs)
		if err != nil {
			c.Errors = append(c.Errors, &provide.Error{
				Message: common.StringOrNil(fmt.Sprintf("failed to import SRS for circuit %s; %s", *c.Identifier, err.Error())),
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

// initStorage attempts to initialize storage for notes (dense) and hashed proofs (sparse)
// for the circuit instance; no-op for each store type if it has already been initialized
func (c *Circuit) initStorage() error {
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

// initNoteStorage initializes dense merkle tree storage for the circuit instance
func (c *Circuit) initNoteStorage() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.NoteStoreID != nil {
		return fmt.Errorf("failed to initialize notes storage provider for circuit %s; notes store has already been initialized", c.ID)
	}

	common.Log.Debugf("attempting to initialize notes storage for circuit %s", c.ID)

	store := &storage.Store{
		Name:     common.StringOrNil(fmt.Sprintf("dense merkle tree notes storage for circuit %s", c.ID)),
		Provider: common.StringOrNil(storeprovider.StoreProviderMerkleTree),
		Curve:    common.StringOrNil(*c.Curve),
	}

	if store.Create() {
		common.Log.Debugf("initialized notes storage for circuit with identifier %s", c.ID)
		c.NoteStoreID = &store.ID
		c.noteStore = store
	} else {
		return fmt.Errorf("failed to initialize notes storage provider for circuit %s; store not persisted", c.ID)
	}

	return nil
}

// initNullifierStorage initializes sparse merkle tree storage for hashed proofs for the circuit instance
func (c *Circuit) initNullifierStorage() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.NullifierStoreID != nil {
		return fmt.Errorf("failed to initialize proof storage provider for circuit %s; store has already been initialized", c.ID)
	}

	common.Log.Debugf("attempting to initialize proof storage for circuit %s", c.ID)

	store := &storage.Store{
		Name:     common.StringOrNil(fmt.Sprintf("merkle tree proof storage for circuit %s", c.ID)),
		Provider: common.StringOrNil(storeprovider.StoreProviderSparseMerkleTree),
		Curve:    common.StringOrNil(*c.Curve),
	}

	if store.Create() {
		common.Log.Debugf("initialized proof storage for circuit with identifier %s", c.ID)
		c.NullifierStoreID = &store.ID
		c.nullifierStore = store
	} else {
		return fmt.Errorf("failed to initialize proof storage provider for circuit %s; store not persisted", c.ID)
	}

	return nil
}

// generateEncryptionKey attempts to generate an AES-256-GCM symmetric key for encrypting
// notes and persist the key id on the circuit instance
func (c *Circuit) generateEncryptionKey() bool {
	key, err := vault.CreateKey(
		util.DefaultVaultAccessJWT,
		c.VaultID.String(),
		map[string]interface{}{
			"name":        fmt.Sprintf("%s circuit note encryption key", *c.Name),
			"description": fmt.Sprintf("%s circuit key for encrypted note storage", *c.Name),
			"spec":        "AES-256-GCM",
			"type":        "symmetric",
			"usage":       "encrypt/decrypt",
		},
	)
	if err != nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to generate symmetric key material for encrypted notes storage for circuit %s in vault %s; %s", *c.Identifier, c.VaultID.String(), err.Error())),
		})
		return false
	}

	c.EncryptionKeyID = &key.ID
	return c.EncryptionKeyID != nil
}

// persistKeys attempts to persist the proving and verifying keys as secrets
// in the configured vault instance
func (c *Circuit) persistKeys() bool {
	secret, err := vault.CreateSecret(
		util.DefaultVaultAccessJWT,
		c.VaultID.String(),
		hex.EncodeToString(c.provingKey),
		fmt.Sprintf("%s circuit proving key", *c.Name),
		fmt.Sprintf("%s circuit %s proving key", *c.Name, *c.ProvingScheme),
		fmt.Sprintf("%s proving key", *c.ProvingScheme),
	)
	if err != nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to store proving key for circuit %s in vault %s; %s", *c.Identifier, c.VaultID.String(), err.Error())),
		})
		return false
	}
	c.ProvingKeyID = &secret.ID

	secret, err = vault.CreateSecret(
		util.DefaultVaultAccessJWT,
		c.VaultID.String(),
		hex.EncodeToString(c.verifyingKey),
		fmt.Sprintf("%s circuit verifying key", *c.Name),
		fmt.Sprintf("%s circuit %s verifying key", *c.Name, *c.ProvingScheme),
		fmt.Sprintf("%s verifying key", *c.ProvingScheme),
	)
	if err != nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to store verifying key for circuit %s in vault %s; %s", *c.Identifier, c.VaultID.String(), err.Error())),
		})
		return false
	}
	c.VerifyingKeyID = &secret.ID

	return c.ProvingKeyID != nil && c.VerifyingKeyID != nil
}

// persistSRS attempts to persist the circuit SRS as a secret in the configured vault instance
func (c *Circuit) persistSRS() bool {
	secret, err := vault.CreateSecret(
		util.DefaultVaultAccessJWT,
		c.VaultID.String(),
		hex.EncodeToString(c.srs),
		fmt.Sprintf("%s circuit SRS", *c.Name),
		fmt.Sprintf("%s circuit %s SRS", *c.Name, *c.ProvingScheme),
		fmt.Sprintf("%s SRS", *c.ProvingScheme),
	)
	if err != nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to store SRS for circuit %s in vault %s; %s", *c.Identifier, c.VaultID.String(), err.Error())),
		})
		return false
	}
	c.StructuredReferenceStringID = &secret.ID
	return c.StructuredReferenceStringID != nil
}

func (c *Circuit) setupRequired() bool {
	return c.ProvingScheme != nil && (*c.ProvingScheme == circuitProvingSchemeGroth16 || *c.ProvingScheme == circuitProvingSchemePlonk) && c.Status != nil && (*c.Status == circuitStatusCompiled || *c.Status == circuitStatusPendingSetup)
}

// setup attempts to setup the circuit
func (c *Circuit) setup(db *gorm.DB) bool {
	if !c.setupRequired() {
		common.Log.Warningf("attempted to setup circuit for which setup is not required")
		return false
	}

	c.updateStatus(db, circuitStatusRunningSetup, nil)

	if c.Binary == nil || len(c.Binary) == 0 {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to setup circuit with identifier %s; no compiled artifacts", *c.Identifier)),
		})
		common.Log.Warningf("failed to setup circuit with identifier %s; no compiled artifacts", *c.Identifier)
		return false
	}

	provider := c.circuitProviderFactory()
	if provider == nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil("failed to resolve circuit provider"),
		})
		return false
	}

	if c.srsRequired() && (c.srs == nil || len(c.srs) == 0) {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to acquire srs before setup for circuit with identifier %s", *c.Identifier)),
		})
		common.Log.Warningf("failed to acquire srs before Setup for circuit with identifier %s", *c.Identifier)
		return false
	}
	pk, vk, err := provider.Setup(c.Binary, c.srs)

	if err != nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("error during setup of verifier and proving keys for circuit with identifier %s; %s", *c.Identifier, err.Error())),
		})
		common.Log.Warningf("error during setup of verifier and proving keys for circuit with identifier %s; %s", *c.Identifier, err.Error())
		return false
	} else if vk == nil || pk == nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to setup verifier and proving keys for circuit with identifier %s", *c.Identifier)),
		})
		common.Log.Warningf("failed to setup verifier and proving keys for circuit with identifier %s", *c.Identifier)
		return false
	}

	pkBuf := new(bytes.Buffer)
	_, err = pk.(io.WriterTo).WriteTo(pkBuf)
	if err != nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to marshal binary proving key for circuit with identifier %s; %s", *c.Identifier, err.Error())),
		})
		common.Log.Warningf("failed to marshal binary proving key for circuit with identifier %s; %s", *c.Identifier, err.Error())
		return false
	}
	c.provingKey = pkBuf.Bytes()

	vkBuf := new(bytes.Buffer)
	_, err = vk.(io.WriterTo).WriteTo(vkBuf)
	if err != nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to marshal binary verifying key for circuit with identifier %s; %s", *c.Identifier, err.Error())),
		})
		common.Log.Warningf("failed to marshal binary verifying key for circuit with identifier %s; %s", *c.Identifier, err.Error())
		return false
	}
	c.verifyingKey = vkBuf.Bytes()

	if len(c.Errors) != 0 {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("errors found while setting up circuit with identifier %s", *c.Identifier)),
		})
		common.Log.Warningf("errors found while setting up circuit with identifier %s", *c.Identifier)
		return false
	}

	if !c.generateEncryptionKey() {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to persist encryption key for circuit with identifier %s", *c.Identifier)),
		})
		common.Log.Warningf("failed to persist encryption key for circuit with identifier %s", *c.Identifier)
		return false
	}

	if !c.persistKeys() {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to persist proving and verifying keys for circuit with identifier %s", *c.Identifier)),
		})
		common.Log.Warningf("failed to persist proving and verifying keys for circuit with identifier %s", *c.Identifier)
		return false
	}

	err = c.enrich()
	if err != nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to enrich circuit with identifier %s; %s", *c.Identifier, err.Error())),
		})
		common.Log.Warningf("failed to enrich circuit with identifier %s; %s", *c.Identifier, err.Error())
		return false
	}

	err = c.updateStatus(db, circuitStatusProvisioned, nil)
	if err != nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to update status of circuit with identifier %s; %s", *c.Identifier, err.Error())),
		})
		common.Log.Warningf("failed to update status of circuit with identifier %s; %s", *c.Identifier, err.Error())
		return false
	}

	return true
}

func (c *Circuit) srsRequired() bool {
	return c.ProvingScheme != nil && *c.ProvingScheme == circuitProvingSchemePlonk
}

// updateStatus updates the circuit status and optional description
func (c *Circuit) updateStatus(db *gorm.DB, status string, description *string) error {
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
func (c *Circuit) updateState(proof string, witness map[string]interface{}) error {
	var root []byte

	if c.noteStore != nil {
		// FIXME -- adopt proper Note structure
		note, _ := json.Marshal(map[string]interface{}{
			"proof":   proof,
			"witness": witness,
		})

		encryptresp, err := vault.Encrypt(
			util.DefaultVaultAccessJWT,
			c.VaultID.String(),
			c.EncryptionKeyID.String(),
			string(note),
		)
		if err != nil {
			common.Log.Warningf("failed to update state; failed to encrypt note for circuit %s; %s", c.ID, err.Error())
			return err
		}

		root, err = c.noteStore.Insert(encryptresp.Data)
		if err != nil {
			common.Log.Warningf("failed to update state; note not inserted for circuit %s; %s", c.ID, err.Error())
			return err
		} else {
			common.Log.Debugf("inserted %d-byte note for circuit %s; root: %s", len(note), c.ID, hex.EncodeToString(root))
		}
	}

	if c.nullifierStore != nil {
		if c.State == nil {
			// TODO-- audit this for when the first note has not yet been spent
			common.Log.Debugf("no notes spent for circuit %s; initializing sparse nullifier tree with %d-byte state root", c.ID, len(root))
			_, err := c.nullifierStore.Insert("")
			if err != nil {
				common.Log.Warningf("failed to insert nullifier proof for circuit %s; %s", c.ID, err.Error())
				return err
			}
			common.Log.Debugf("initialized sparse nullifier tree with %d-byte state root for circuit %s", len(root), c.ID)
			c.State = &state.State{}
		}

		root, err := c.nullifierStore.Insert(proof)
		if err != nil {
			common.Log.Warningf("failed to insert nullifier proof for circuit %s; %s", c.ID, err.Error())
			return err
		} else {
			common.Log.Debugf("inserted nullifier proof for circuit %s: %s; root: %s", c.ID, hex.EncodeToString([]byte(proof)), hex.EncodeToString(root))
			if !c.nullifierStore.Contains(proof) {
				err := fmt.Errorf("inserted nullifier proof for circuit %s resulted in internal inconsistency for proof: %s", c.ID, hex.EncodeToString([]byte(proof)))
				common.Log.Warning(err.Error())
				return err
			}
		}
	}

	return nil
}

// validate the circuit params
func (c *Circuit) validate() bool {
	c.Errors = make([]*provide.Error, 0)

	if c.Curve == nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil("circuit curve id required"),
		})
	}

	if c.Provider == nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil("circuit provider required"),
		})
	}

	if c.ProvingScheme == nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil("circuit proving scheme required"),
		})
	}

	if c.Identifier == nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil("circuit identifier required"),
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
