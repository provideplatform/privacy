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

package dmt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"

	"github.com/providenetwork/merkletree"
)

// treeContent represents an arbitrary value and the hash function configured
// for use with a dense merkle tree instance
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
func (tc *treeContent) Equals(other merkletree.Content) (bool, error) {
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

func (tc *treeContent) MarshalJSON() ([]byte, error) {
	if tc.value == nil || len(tc.value) == 0 {
		return nil, errors.New("failed to marshal content with nil value")
	}

	val := base64.RawStdEncoding.EncodeToString(tc.value)
	return []byte(fmt.Sprintf("{\"value\": \"%s\"}", val)), nil
}

func (tc *treeContent) UnmarshalJSON(raw []byte) error {
	var params map[string]interface{}
	err := json.Unmarshal(raw, &params)
	if err != nil {
		return err
	}

	val, ok := params["value"].(string)
	if !ok {
		return errors.New("failed to unmarshal content with nil value")
	}

	tc.value, err = base64.RawStdEncoding.DecodeString(val)
	if err != nil {
		return err
	}

	return nil
}
