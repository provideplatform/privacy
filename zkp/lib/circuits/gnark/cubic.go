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

package gnark

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

// CubicProver defines a simple prover
// x**3 + x + 5 == y
type CubicProver struct {
	// struct tags on a variable is optional
	// default uses variable name and secret visibility.
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

// Define declares the prover constraints
// x**3 + x + 5 == y
func (prover *CubicProver) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	x3 := cs.Mul(prover.X, prover.X, prover.X)
	cs.AssertIsEqual(prover.Y, cs.Add(x3, prover.X, 5))
	return nil
}
