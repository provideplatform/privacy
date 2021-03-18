package gnark

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
	"github.com/consensys/gurvy"
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
func (circuit *EqualCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	cs.AssertIsLessOrEqual(circuit.Vals.Val, circuit.Vals.RelVal)
	cs.AssertIsLessOrEqual(circuit.Vals.RelVal, circuit.Vals.Val) // AssertIsEqual having trouble with this circuit, this is a workaround
	//diff := cs.Sub(circuit.Vals.Val, circuit.Vals.RelVal)
	//diffIsZero := cs.IsZero(diff, curveID)
	//cs.AssertIsEqual(diffIsZero, cs.Constant(1))
	return nil
}

// NotEqualCircuit defines an inequality verification circuit
type NotEqualCircuit struct {
	Vals RelationCircuit
}

// Define declares the circuit constraints
func (circuit *NotEqualCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	diff := cs.Sub(circuit.Vals.Val, circuit.Vals.RelVal)
	diffIsZero := cs.IsZero(diff, curveID)
	cs.AssertIsEqual(diffIsZero, cs.Constant(0))
	return nil
}

// LessOrEqualCircuit defines a <= verification circuit
type LessOrEqualCircuit struct {
	Vals RelationCircuit
}

// Define declares the circuit constraints
func (circuit *LessOrEqualCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	cs.AssertIsLessOrEqual(circuit.Vals.Val, circuit.Vals.RelVal)
	return nil
}

// GreaterOrEqualCircuit defines a >= verification circuit
type GreaterOrEqualCircuit struct {
	Vals RelationCircuit
}

// Define declares the circuit constraints
func (circuit *GreaterOrEqualCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	cs.AssertIsLessOrEqual(circuit.Vals.RelVal, circuit.Vals.Val)
	return nil
}

// LessCircuit defines a < verification circuit
type LessCircuit struct {
	Vals RelationCircuit
}

// Define declares the circuit constraints
func (circuit *LessCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	cs.AssertIsLessOrEqual(circuit.Vals.Val, cs.Sub(circuit.Vals.RelVal, 1))
	return nil
}

// GreaterCircuit defines a > verification circuit
type GreaterCircuit struct {
	Vals RelationCircuit
}

// Define declares the circuit constraints
func (circuit *GreaterCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	cs.AssertIsLessOrEqual(circuit.Vals.RelVal, cs.Sub(circuit.Vals.Val, 1))
	return nil
}

// ProofHashCircuit defines hash(Proof[]) == Hash
type ProofHashCircuit struct {
	Proof [16]frontend.Variable
	Hash  frontend.Variable `gnark:",public"`
}

// Define declares the circuit constraints
func (circuit *ProofHashCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	hFunc, err := mimc.NewMiMC("seed", curveID)
	if err != nil {
		return err
	}

	hash := hFunc.Hash(cs, circuit.Proof[0], circuit.Proof[1], circuit.Proof[2], circuit.Proof[3], circuit.Proof[4], circuit.Proof[5], circuit.Proof[6], circuit.Proof[7], circuit.Proof[8], circuit.Proof[9], circuit.Proof[10], circuit.Proof[11], circuit.Proof[12], circuit.Proof[13], circuit.Proof[14], circuit.Proof[15])
	cs.AssertIsEqual(hash, circuit.Hash)

	return nil
}

// ProofEddsaCircuit defines eddsa.Verify(hash(Msg[])) of PubKey and Sig
type ProofEddsaCircuit struct {
	Msg    [16]frontend.Variable
	PubKey eddsa.PublicKey `gnark:",public"`
	Sig    eddsa.Signature `gnark:",public"`
}

// Define declares the ProofEddsaCircuit circuit constraints
func (circuit *ProofEddsaCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	curve, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}
	circuit.PubKey.Curve = curve

	hFunc, err := mimc.NewMiMC("seed", curveID)
	if err != nil {
		return err
	}

	hash := hFunc.Hash(cs, circuit.Msg[0], circuit.Msg[1], circuit.Msg[2], circuit.Msg[3], circuit.Msg[4], circuit.Msg[5], circuit.Msg[6], circuit.Msg[7], circuit.Msg[8], circuit.Msg[9], circuit.Msg[10], circuit.Msg[11], circuit.Msg[12], circuit.Msg[13], circuit.Msg[14], circuit.Msg[15])
	eddsa.Verify(cs, circuit.Sig, hash, circuit.PubKey)

	return nil
}
