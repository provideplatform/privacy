package state

import uuid "github.com/kthomas/go.uuid"

// State is the account state which can only be changed as a result of a valid transaction
// (i.e., successful Workstep execution) by way of a StateClaim.
type State struct {
	ID        uuid.UUID  `json:"id"`
	AccountID *uuid.UUID `json:"account_id"`
	Address   *string    `json:"address"` // FIXME... int type this address
	ProverID  *uuid.UUID `json:"prover_id"`
	Epoch     uint64     `json:"epoch"`
	Nonce     uint64     `json:"nonce"`

	StateClaims []*StateClaim
}

// StateClaim is the representation of a valid state as claimed by a workgroup participant
type StateClaim struct {
	Cardinality uint64   `json:"cardinality"`
	Path        []string `json:"path"`
	Root        *string  `json:"root"`
	Values      []string `json:"values"` // list of hashed proofs corresponding to the values at index and each sibling path
}
