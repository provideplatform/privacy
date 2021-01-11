package circuit

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"github.com/jinzhu/gorm"
	dbconf "github.com/kthomas/go-db-config"
	natsutil "github.com/kthomas/go-natsutil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/privacy/common"
	"github.com/provideapp/privacy/zkp/lib/circuits/gnark"
	zkp "github.com/provideapp/privacy/zkp/providers"
	provide "github.com/provideservices/provide-go/api"
	vault "github.com/provideservices/provide-go/api/vault"
	util "github.com/provideservices/provide-go/common/util"
)

const circuitProvingSchemeGroth16 = "groth16"

const circuitStatusFailed = "failed"
const circuitStatusInit = "init"
const circuitStatusCompiling = "compiling"
const circuitStatusCompiled = "compiled"
const circuitStatusPendingSetup = "pending_setup"
const circuitStatusRunningSetup = "running_setup"
const circuitStatusDeployingArtifacts = "deploying_artifacts" // optional -- if i.e. verifier contract should be deployed to blockchain
const circuitStatusProvisioned = "provisioned"

// Policy -- TODO? currently the following policy items are configured directly on the Circuit
type Policy struct {
	// configuration of the curve + Input/Outputs; preprocessing or processing; interactive/noninteractive, etc.
	// MIME type (aka file format)
	// ConstraintSystem *string `json:"constraint_system"`
	// Curve *string `json:"curve"`
	// ABI (i.e., inputs, outputs etc)
}

// Circuit model
type Circuit struct {
	provide.Model

	// Artifacts, i.e., r1cs, ABI, etc
	ABI       []byte `json:"abi,omitempty"`
	Artifacts []byte `json:"-"`

	// Vault and the vault secret identifiers for the proving/verifying keys
	VaultID        *uuid.UUID `json:"vault_id"`
	ProvingKeyID   *uuid.UUID `json:"proving_key_id"`
	VerifyingKeyID *uuid.UUID `json:"verifying_key_id"`

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
	Source        *string `json:"source"`

	Status *string `sql:"not null;default:'init'" json:"status"`

	// Policy *CircuitPolicy `json:""`
	// Seed -- entropy for uniqueness within the setup

	// ephemeral fields
	provingKey   []byte
	verifyingKey []byte

	// optional on-chain artifact (i.e., verifier contract)
	verifierContractArtifact []byte
}

func (c *Circuit) circuitProviderFactory() zkp.ZKSnarkCircuitProvider {
	if c.Provider == nil {
		common.Log.Warning("failed to initialize zk circuit provider; no provider defined")
		return nil
	}

	switch *c.Provider {
	case zkp.ZKSnarkCircuitProviderGnark:
		return zkp.InitGnarkCircuitProvider(c.Curve)
	case zkp.ZKSnarkCircuitProviderZoKrates:
		return nil // not implemented
	default:
		common.Log.Warningf("failed to initialize zk circuit provider; unknown provider: %s", *c.Provider)
	}

	return nil
}

// Create a circuit
func (c *Circuit) Create() bool {
	if !c.validate() {
		return false
	}

	db := dbconf.DatabaseConnection()

	if !c.compile(db) {
		return false
	}

	if db.NewRecord(c) {
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

				if c.setupRequired() {
					c.updateStatus(db, circuitStatusPendingSetup, nil)

					payload, _ := json.Marshal(map[string]interface{}{
						"circuit_id": c.ID.String(),
					})
					natsutil.NatsStreamingPublish(natsCircuitSetupSubject, payload)
				}
			}

			return success
		}
	}

	return false
}

// Prove generates a proof for the given witness
func (c *Circuit) Prove(witness map[string]interface{}) (*string, error) {
	c.enrich()
	var _proof *string

	provider := c.circuitProviderFactory()
	if provider == nil {
		return nil, fmt.Errorf("failed to resolve circuit provider")
	}

	proof, err := provider.Prove(c.Artifacts, c.provingKey, witness)
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

	_proof = common.StringOrNil(hex.EncodeToString(buf.Bytes()))
	common.Log.Debugf("generated proof for circuit with identifier %s: %s", *c.Identifier, *_proof)
	return _proof, nil
}

// Verify a proof to be verifiable for the given witness
func (c *Circuit) Verify(proof string, witness map[string]interface{}) (bool, error) {
	c.enrich()

	provider := c.circuitProviderFactory()
	if provider == nil {
		return false, fmt.Errorf("failed to resolve circuit provider")
	}

	var _proof []byte
	var err error

	_proof, err = hex.DecodeString(proof)
	if err != nil {
		common.Log.Tracef("failed to decode proof as hex; %s", err.Error())
		_proof = []byte(proof)
	}

	err = provider.Verify(_proof, c.verifyingKey, witness)
	if err != nil {
		return false, err
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

	var buf *bytes.Buffer
	var artifacts interface{} // TODO: accept r1cs -- in addition to -- the "identifier" of the circuit??
	var err error

	if c.Identifier != nil {
		switch *c.Identifier {
		case zkp.GnarkCircuitIdentifierCubic:
			var circuit gnark.CubicCircuit
			artifacts, err = provider.Compile(&circuit)
			if err != nil {
				c.Errors = append(c.Errors, &provide.Error{
					Message: common.StringOrNil(fmt.Sprintf("failed to compile circuit with identifier %s; %s", *c.Identifier, err.Error())),
				})
				return false
			}
			break
		default:
			c.Errors = append(c.Errors, &provide.Error{
				Message: common.StringOrNil(fmt.Sprintf("failed to resolve circuit for provider: %s", *c.Provider)),
			})
			return false
		}
	}

	buf = new(bytes.Buffer)
	_, err = artifacts.(io.WriterTo).WriteTo(buf)
	if err != nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to marshal binary artifacts for circuit with identifier %s; %s", *c.Identifier, err.Error())),
		})
		return false
	}
	c.Artifacts = buf.Bytes()

	c.updateStatus(db, circuitStatusCompiled, nil)
	return len(c.Errors) == 0
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

	return nil
}

func (c *Circuit) setupRequired() bool {
	return c.ProvingScheme != nil && *c.ProvingScheme == circuitProvingSchemeGroth16 && c.Status != nil && (*c.Status == circuitStatusCompiled || *c.Status == circuitStatusPendingSetup)
}

// setup attempts to setup the circuit
func (c *Circuit) setup(db *gorm.DB) bool {
	if !c.setupRequired() {
		common.Log.Warningf("attempted to setup circuit for which setup is not required")
		return false
	}

	c.updateStatus(db, circuitStatusRunningSetup, nil)

	if c.Artifacts == nil || len(c.Artifacts) == 0 {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to setup circuit with identifier %s; no compiled artifacts", *c.Identifier)),
		})
		return false
	}

	provider := c.circuitProviderFactory()
	if provider == nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil("failed to resolve circuit provider"),
		})
		return false
	}

	var buf *bytes.Buffer

	pk, vk, err := provider.Setup(c.Artifacts)
	if err != nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to setup verifier and proving keys for circuit with identifier %s; %s", *c.Identifier, err.Error())),
		})
		return false
	} else if vk == nil || pk == nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to setup verifier and proving keys for circuit with identifier %s", *c.Identifier)),
		})
		return false
	}

	buf = new(bytes.Buffer)
	_, err = pk.(io.WriterTo).WriteTo(buf)
	if err != nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to marshal binary proving key for circuit with identifier %s; %s", *c.Identifier, err.Error())),
		})
		return false
	}
	c.provingKey = buf.Bytes()

	buf = new(bytes.Buffer)
	_, err = vk.(io.WriterTo).WriteTo(buf)
	if err != nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to marshal binary verifying key for circuit with identifier %s; %s", *c.Identifier, err.Error())),
		})
		return false
	}
	c.verifyingKey = buf.Bytes()

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

	success := len(c.Errors) == 0
	if success {
		if c.verifierContractArtifact != nil && len(c.verifierContractArtifact) != 0 {
			common.Log.Warningf("verifier contract deployment not yet supported")
			c.updateStatus(db, circuitStatusFailed, common.StringOrNil("verifier contract deployment not yet supported"))
			return false
		}
		c.updateStatus(db, circuitStatusProvisioned, nil)
	}

	return success
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

// validate the circuit params
func (c *Circuit) validate() bool {
	c.Errors = make([]*provide.Error, 0)

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
