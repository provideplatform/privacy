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

package common

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
	"strings"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
)

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))

// ECDSASignature for ECDSA signature marshaling
type ECDSASignature struct {
	R, S *big.Int
}

// PanicIfEmpty panics if the given string is empty
func PanicIfEmpty(val string, msg string) {
	if val == "" {
		panic(msg)
	}
}

// StringOrNil returns the given string or nil when empty
func StringOrNil(str string) *string {
	if str == "" {
		return nil
	}
	return &str
}

// RandomString generates a random string of the given length
func RandomString(length int) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

// SHA256 is a convenience method to return the sha256 hash of the given input
func SHA256(str string) string {
	digest := sha256.New()
	digest.Write([]byte(str))
	return hex.EncodeToString(digest.Sum(nil))
}

// RandomBytes generates a cryptographically random byte array
func RandomBytes(length int) ([]byte, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return nil, fmt.Errorf("error generating random bytes %s", err.Error())
	}
	return b, nil
}

// GnarkCurveIDFactory returns an ecc curve id corresponding to the input name
func GnarkCurveIDFactory(curveID *string) ecc.ID {
	if curveID == nil {
		return ecc.UNKNOWN
	}

	switch strings.ToLower(*curveID) {
	case ecc.BLS12_377.String():
		return ecc.BLS12_377
	case ecc.BLS12_381.String():
		return ecc.BLS12_381
	case ecc.BN254.String():
		return ecc.BN254
	case ecc.BW6_761.String():
		return ecc.BW6_761
	case ecc.BLS24_315.String():
		return ecc.BLS24_315
	default:
		return ecc.UNKNOWN
	}
}

const gnarkProvingSchemeGroth16 = "groth16"
const gnarkProvingSchemePlonk = "plonk"

func GnarkProvingSchemeFactory(provingScheme *string) backend.ID {
	if provingScheme == nil {
		return backend.UNKNOWN
	}

	switch strings.ToLower(*provingScheme) {
	case gnarkProvingSchemeGroth16:
		return backend.GROTH16
	case gnarkProvingSchemePlonk:
		return backend.PLONK
	default:
		return backend.UNKNOWN
	}
}

// NextPowerOfTwo returns the next power of two greater than or equal to the input number
func NextPowerOfTwo(_n int) int {
	n := uint64(_n)
	p := uint64(1)
	if (n & (n - 1)) == 0 {
		return _n
	}
	for p < n {
		p <<= 1
	}
	return int(p)
}
