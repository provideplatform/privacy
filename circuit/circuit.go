package circuit

import (
	"fmt"

	"github.com/provideapp/privacy/zkp/lib/circuits/gnark"

	"github.com/fxamacker/cbor/v2"
	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/privacy/common"
	zkp "github.com/provideapp/privacy/zkp/providers"
	provide "github.com/provideservices/provide-go/api"
	vault "github.com/provideservices/provide-go/api/vault"
	util "github.com/provideservices/provide-go/common/util"
)

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
	ABI       []byte `json:"abi"`
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
	ProvingSystem *string `json:"proving_system"`
	Curve         *string `json:"curve"`

	// Policy *CircuitPolicy `json:""`
	// Seed -- entropy for uniqueness within the setup

	// ephemeral fields
	provingKey   []byte
	verifyingKey []byte
}

func (c *Circuit) circuitProviderFactory() zkp.ZKSnarkCircuitProvider {
	if c.Provider == nil {
		common.Log.Warning("failed to initialize zk circuit provider; no provider defined")
		return nil
	}

	switch *c.Provider {
	case zkp.ZKSnarkCircuitProviderGnark:
		return zkp.InitGnarkCircuitProvider()
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

	var artifacts interface{} // TODO: accept r1cs -- in addition to -- the "identifier" of the circuit??
	var err error

	provider := c.circuitProviderFactory()
	if provider == nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil("failed to resolve circuit provider"),
		})
		return false
	}

	if c.Identifier != nil && *c.Identifier == zkp.GnarkCircuitIdentifierCubic {
		var circuit gnark.CubicCircuit
		artifacts, err = provider.Compile(&circuit)
		if err != nil {
			c.Errors = append(c.Errors, &provide.Error{
				Message: common.StringOrNil(fmt.Sprintf("failed to compile circuit with identifier %s; %s", *c.Identifier, err.Error())),
			})
			return false
		}
	}

	c.Artifacts, err = cbor.Marshal(artifacts)
	if err != nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to marshal binary artifacts for circuit with identifier %s; %s", *c.Identifier, err.Error())),
		})
		return false
	}

	vk, pk := provider.Setup(artifacts)
	if vk == nil || pk == nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to setup verifier and proving keys for circuit with identifier %s", *c.Identifier)),
		})
		return false
	}

	c.provingKey, err = cbor.Marshal(pk)
	if err != nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to marshal binary proving key for circuit with identifier %s; %s", *c.Identifier, err.Error())),
		})
		return false
	}

	c.verifyingKey, err = cbor.Marshal(vk)
	if err != nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to marshal binary verifying key for circuit with identifier %s; %s", *c.Identifier, err.Error())),
		})
		return false
	}

	secret, err := vault.CreateSecret(
		util.DefaultVaultAccessJWT,
		c.VaultID.String(),
		string(c.provingKey),
		fmt.Sprintf("%s circuit proving key", *c.Name),
		fmt.Sprintf("%s circuit %s proving key", *c.Name, *c.ProvingSystem),
		fmt.Sprintf("%s proving key", *c.ProvingSystem),
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
		string(c.verifyingKey),
		fmt.Sprintf("%s circuit verifying key", *c.Name),
		fmt.Sprintf("%s circuit %s verifying key", *c.Name, *c.ProvingSystem),
		fmt.Sprintf("%s verifying key", *c.ProvingSystem),
	)
	if err != nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to store verifying key for circuit %s in vault %s; %s", *c.Identifier, c.VaultID.String(), err.Error())),
		})
		return false
	}
	c.VerifyingKeyID = &secret.ID

	common.Log.Debugf("compiled circuit: %v", c)
	common.Log.Debugf("verifying/provingkeys: %v, %v", vk, pk)

	db := dbconf.DatabaseConnection()
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
			return success
		}
	}

	return false
}

// Prove generates a proof for the given witness
func (c *Circuit) Prove(witness string) (*string, error) {
	c.enrich()

	provider := c.circuitProviderFactory()
	if provider == nil {
		return nil, fmt.Errorf("failed to resolve circuit provider")
	}

	proof, err := provider.Prove(c.Artifacts, c.provingKey, witness)
	if err != nil {
		common.Log.Warningf("failed to generate proof; %s", err.Error())
		return nil, err
	}

	proofStr := proof.(string)

	common.Log.Debugf("proof generated %s", proofStr)
	return &proofStr, nil
}

// Verify a circuit
func (c *Circuit) Verify(proof, witness string) (bool, error) {
	c.enrich()

	provider := c.circuitProviderFactory()
	if provider == nil {
		return false, fmt.Errorf("failed to resolve circuit provider")
	}

	err := provider.Verify(c.Artifacts, c.verifyingKey, witness)
	if err != nil {
		return false, err
	}

	common.Log.Debugf("circuit witness %s verified for proof: %s", witness, proof)
	return true, nil
}

// enrich the circuit
func (c *Circuit) enrich() error {
	if c.provingKey == nil && c.ProvingKeyID != nil {
		secret, err := vault.FetchSecret(
			util.DefaultVaultAccessJWT,
			c.VaultID.String(),
			c.ProvingKeyID.String(),
			map[string]interface{}{},
		)
		if err != nil {
			return err
		}
		c.provingKey = []byte(*secret.Value)
	}

	if c.verifyingKey == nil && c.VerifyingKeyID != nil {
		secret, err := vault.FetchSecret(
			util.DefaultVaultAccessJWT,
			c.VaultID.String(),
			c.VerifyingKeyID.String(),
			map[string]interface{}{},
		)
		if err != nil {
			return err
		}
		c.verifyingKey = []byte(*secret.Value)
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
