package circuit

import (
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/privacy/common"
	zkp "github.com/provideapp/privacy/zkp/providers"
	provide "github.com/provideservices/provide-go/api"
)

// Policy WIP
type Policy struct {
	// TODO
	// configuration of the curve + Input/Outputs; preprocessing or processing; interactive/noninteractive, etc.
	// MIME type (aka file format)
	// ConstraintSystem *string `json:"constraint_system"`
	// Curve *string `json:"curve"`
	// Inputs
	// Outputs
}

// Circuit model
type Circuit struct {
	*provide.Model

	// Associations
	ApplicationID  *uuid.UUID `sql:"type:uuid" json:"-"`
	OrganizationID *uuid.UUID `sql:"type:uuid" json:"-"`
	// UserID         *uuid.UUID `sql:"type:uuid" json:"-"`

	Name             *string `json:"name"`
	Description      *string `json:"description"`
	Identifier       *string `json:"identifier"`
	Provider         *string `json:"provider"`
	Type             *string `json:"type"`
	Curve            *string `json:"curve"`
	ConstraintSystem *string `json:"constraint_system"`

	// Policy *CircuitPolicy `json:""`
	// Seed -- entropy for uniqueness within the setup

	// ephemeral fields
	bin []byte
}

func circuitProviderFactory() zkp.ZKSnarkCircuitProvider {
	return zkp.InitGnarkCircuitProvider()
}

func (c *Circuit) circuitProviderFactory() zkp.ZKSnarkCircuitProvider {
	if c.Provider == nil {
		common.Log.Warning("failed to initialize zk circuit provider; no provider defined")
		return nil
	}

	switch *c.Provider {
	case zkp.ZKSnarkCircuitProviderGnark:
		return zkp.InitGnarkCircuitProvider()
	default:
		common.Log.Warningf("failed to initialize zk circuit provider; unknown provider: %s", *c.Provider)
	}

	return nil
}

// Create a circuit
func (c *Circuit) Create() bool {
	// TODO: accept r1cs -- OR -- the "identifier" of the circuit
	var provider zkp.ZKSnarkCircuitProvider

	if c.Identifier != nil && *c.Identifier == zkp.GnarkCircuitIdentifierCubic {
		provider.Compile()
	}

	// FIXME... parameterize -- provider.Compile()
	artifacts, err := provider.Compile("")
	if err != nil {
		common.Log.Warningf("failed to compile circuit; %s", err.Error())
		return false
	}

	common.Log.Debugf("compiled circuit %s", artifacts)

	return false
}
