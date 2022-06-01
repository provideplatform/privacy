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
