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

// // RelationProver defines generic relation R between Val and RelVal
// type RelationProver struct {
// 	Val    frontend.Variable `gnark:",public"`
// 	RelVal frontend.Variable
// }

// // EqualProver defines an equality verification prover
// type EqualProver struct {
// 	Vals RelationProver
// }

// // Define declares the prover constraints
// func (prover *EqualProver) Define(curveID ecc.ID, cs *cs.ConstraintSystem) error {
// 	cs.AssertIsLessOrEqual(prover.Vals.Val, prover.Vals.RelVal)
// 	cs.AssertIsLessOrEqual(prover.Vals.RelVal, prover.Vals.Val) // AssertIsEqual having trouble with this prover, this is a workaround
// 	//diff := cs.Sub(prover.Vals.Val, prover.Vals.RelVal)
// 	//diffIsZero := cs.IsZero(diff, curveID)
// 	//cs.AssertIsEqual(diffIsZero, cs.Constant(1))
// 	return nil
// }

// // NotEqualProver defines an inequality verification prover
// type NotEqualProver struct {
// 	Vals RelationProver
// }

// // Define declares the prover constraints
// func (prover *NotEqualProver) Define(curveID ecc.ID, cs *cs.ConstraintSystem) error {
// 	diff := cs.Sub(prover.Vals.Val, prover.Vals.RelVal)
// 	diffIsZero := cs.IsZero(diff, curveID)
// 	cs.AssertIsEqual(diffIsZero, cs.Constant(0))
// 	return nil
// }

// // LessOrEqualProver defines a <= verification prover
// type LessOrEqualProver struct {
// 	Vals RelationProver
// }

// // Define declares the prover constraints
// func (prover *LessOrEqualProver) Define(curveID ecc.ID, cs *cs.ConstraintSystem) error {
// 	cs.AssertIsLessOrEqual(prover.Vals.Val, prover.Vals.RelVal)
// 	return nil
// }

// // GreaterOrEqualProver defines a >= verification prover
// type GreaterOrEqualProver struct {
// 	Vals RelationProver
// }

// // Define declares the prover constraints
// func (prover *GreaterOrEqualProver) Define(curveID ecc.ID, cs *cs.ConstraintSystem) error {
// 	cs.AssertIsLessOrEqual(prover.Vals.RelVal, prover.Vals.Val)
// 	return nil
// }

// // LessProver defines a < verification prover
// type LessProver struct {
// 	Vals RelationProver
// }

// // Define declares the prover constraints
// func (prover *LessProver) Define(curveID ecc.ID, cs *cs.ConstraintSystem) error {
// 	cs.AssertIsLessOrEqual(prover.Vals.Val, cs.Sub(prover.Vals.RelVal, 1))
// 	return nil
// }

// // GreaterProver defines a > verification prover
// type GreaterProver struct {
// 	Vals RelationProver
// }

// // Define declares the prover constraints
// func (prover *GreaterProver) Define(curveID ecc.ID, cs *cs.ConstraintSystem) error {
// 	cs.AssertIsLessOrEqual(prover.Vals.RelVal, cs.Sub(prover.Vals.Val, 1))
// 	return nil
// }

// // ProofHashProver defines hash(Proof[]) == Hash
// type ProofHashProver struct {
// 	Proof [6]frontend.Variable
// 	Hash  frontend.Variable `gnark:",public"`
// }

// // Define declares the prover constraints
// func (prover *ProofHashProver) Define(curveID ecc.ID, cs *cs.ConstraintSystem) error {
// 	hFunc, err := mimc.NewMiMC("seed", curveID)
// 	if err != nil {
// 		return err
// 	}

// 	hash := hFunc.Hash(cs, prover.Proof[:]...)
// 	cs.AssertIsEqual(hash, prover.Hash)

// 	return nil
// }

// // ProofEddsaProver defines eddsa.Verify(hash(Msg[])) of PubKey and Sig
// type ProofEddsaProver struct {
// 	Msg    [32]frontend.Variable
// 	PubKey eddsa.PublicKey `gnark:",public"`
// 	Sig    eddsa.Signature `gnark:",public"`
// }

// // Define declares the ProofEddsaProver prover constraints
// func (prover *ProofEddsaProver) Define(curveID ecc.ID, cs *cs.ConstraintSystem) error {
// 	curve, err := twistededwards.NewEdCurve(curveID)
// 	if err != nil {
// 		return err
// 	}
// 	prover.PubKey.Curve = curve

// 	hFunc, err := mimc.NewMiMC("seed", curveID)
// 	if err != nil {
// 		return err
// 	}

// 	hash := hFunc.Hash(cs, prover.Msg[:]...)
// 	eddsa.Verify(cs, prover.Sig, hash, prover.PubKey)

// 	return nil
// }
