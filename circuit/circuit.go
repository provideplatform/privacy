package circuit

import (
	provide "github.com/provideservices/provide-go/api"
)

// Circuit model
type Circuit struct {
	*provide.Model

	// Associations
	// ApplicationID  *uuid.UUID `sql:"type:uuid" json:"-"`
	// OrganizationID *uuid.UUID `sql:"type:uuid" json:"-"`
	// UserID         *uuid.UUID `sql:"type:uuid" json:"-"`

	Name             *string `json:"name"`
	Description      *string `json:"description"`
	Type             *string `json:"type"`
	Curve            *string `json:"curve"`
	ConstraintSystem *string `json:"constraint_system"`

	// ephemeral fields
	ABI interface{}
	bin []byte
}
