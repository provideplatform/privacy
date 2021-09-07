package gnark

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
)

// RelationCircuit defines generic relation R between Val and RelVal
type RelationCircuit struct {
	Val    frontend.Variable `gnark:",public"`
	RelVal frontend.Variable
}

// EqualCircuit defines an equality verification circuit
type EqualCircuit struct {
	Vals RelationCircuit
}

// Define declares the circuit constraints
func (circuit *EqualCircuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	cs.AssertIsLessOrEqual(circuit.Vals.Val, circuit.Vals.RelVal)
	cs.AssertIsLessOrEqual(circuit.Vals.RelVal, circuit.Vals.Val) // AssertIsEqual having trouble with this circuit, this is a workaround
	//diff := cs.Sub(circuit.Vals.Val, circuit.Vals.RelVal)
	//diffIsZero := cs.IsZero(diff)
	//cs.AssertIsEqual(diffIsZero, cs.Constant(1))
	return nil
}

// NotEqualCircuit defines an inequality verification circuit
type NotEqualCircuit struct {
	Vals RelationCircuit
}

// Define declares the circuit constraints
func (circuit *NotEqualCircuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	diff := cs.Sub(circuit.Vals.Val, circuit.Vals.RelVal)
	diffIsZero := cs.IsZero(diff)
	cs.AssertIsEqual(diffIsZero, cs.Constant(0))
	return nil
}

// LessOrEqualCircuit defines a <= verification circuit
type LessOrEqualCircuit struct {
	Vals RelationCircuit
}

// Define declares the circuit constraints
func (circuit *LessOrEqualCircuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	cs.AssertIsLessOrEqual(circuit.Vals.Val, circuit.Vals.RelVal)
	return nil
}

// GreaterOrEqualCircuit defines a >= verification circuit
type GreaterOrEqualCircuit struct {
	Vals RelationCircuit
}

// Define declares the circuit constraints
func (circuit *GreaterOrEqualCircuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	cs.AssertIsLessOrEqual(circuit.Vals.RelVal, circuit.Vals.Val)
	return nil
}

// LessCircuit defines a < verification circuit
type LessCircuit struct {
	Vals RelationCircuit
}

// Define declares the circuit constraints
func (circuit *LessCircuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	cs.AssertIsLessOrEqual(circuit.Vals.Val, cs.Sub(circuit.Vals.RelVal, 1))
	return nil
}

// GreaterCircuit defines a > verification circuit
type GreaterCircuit struct {
	Vals RelationCircuit
}

// Define declares the circuit constraints
func (circuit *GreaterCircuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	cs.AssertIsLessOrEqual(circuit.Vals.RelVal, cs.Sub(circuit.Vals.Val, 1))
	return nil
}

// ProofHashCircuit defines hash(Proof[]) == Hash
type ProofHashCircuit struct {
	Proof [6]frontend.Variable
	Hash  frontend.Variable `gnark:",public"`
}

// Define declares the circuit constraints
func (circuit *ProofHashCircuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	hFunc, err := mimc.NewMiMC("seed", curveID, cs)
	if err != nil {
		return err
	}

	hFunc.Write(circuit.Proof[:]...)
	cs.AssertIsEqual(hFunc.Sum(), circuit.Hash)

	return nil
}

// ProofEddsaCircuit defines eddsa.Verify(hash(Msg[])) of PubKey and Sig
type ProofEddsaCircuit struct {
	Msg    [32]frontend.Variable
	PubKey eddsa.PublicKey `gnark:",public"`
	Sig    eddsa.Signature `gnark:",public"`
}

// Define declares the ProofEddsaCircuit circuit constraints
func (circuit *ProofEddsaCircuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	curve, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}
	circuit.PubKey.Curve = curve

	hFunc, err := mimc.NewMiMC("seed", curveID, cs)
	if err != nil {
		return err
	}

	hFunc.Write(circuit.Msg[:]...)
	eddsa.Verify(cs, circuit.Sig, hFunc.Sum(), circuit.PubKey)

	return nil
}
