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

package providers

import (
	"github.com/provideplatform/provide-go/api/vault"
)

type BLS struct {
	Signatures []string
}

func (b *BLS) AggregateSignatures(token *string) (*vault.BLSAggregateRequestResponse, error) {
	resp, err := vault.AggregateSignatures(token, map[string]interface{}{
		"signatures": b.Signatures,
	})
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (b *BLS) VerifyAggregateSignatures(token *string, params map[string]interface{}) (bool, error) {
	resp, err := vault.VerifyAggregateSignatures(token, params)
	if err != nil {
		return false, err
	}

	return resp.Verified, nil
}
