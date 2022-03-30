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

// // MimcProver defines a pre-image knowledge proof
// // mimc(secret preImage) = public hash
// type MimcProver struct {
// 	// struct tag on a variable is optional
// 	// default uses variable name and secret visibility.
// 	Preimage frontend.Variable
// 	Hash     frontend.Variable `gnark:",public"`
// }

// // Define declares the prover's constraints
// // Hash = mimc(Preimage)
// func (prover *MimcProver) Define(curveID ecc.ID, cs *cs.ConstraintSystem) error {
// 	// hash function
// 	mimc, _ := mimc.NewMiMC("seed", curveID)

// 	// specify constraints
// 	// mimc(preImage) == hash
// 	cs.AssertIsEqual(prover.Hash, mimc.Hash(cs, prover.Preimage))

// 	return nil
// }
