package gnark

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
)

// EqualCircuit defines an equality verification circuit
type EqualCircuit struct {
	Val   frontend.Variable `gnark:",public"`
	EqVal frontend.Variable
}

// Define declares the circuit constraints
func (circuit *EqualCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	cs.AssertIsLessOrEqual(circuit.Val, circuit.EqVal)
	cs.AssertIsLessOrEqual(circuit.EqVal, circuit.Val) // AssertIsEqual having trouble with this circuit, this is a workaround
	return nil
}

// NotEqualCircuit defines an inequality verification circuit
type NotEqualCircuit struct {
	Val      frontend.Variable `gnark:",public"`
	NotEqVal frontend.Variable
}

// Define declares the circuit constraints
func (circuit *NotEqualCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	diff := cs.Sub(circuit.Val, circuit.NotEqVal)
	diffIsZero := cs.IsZero(diff, curveID)
	cs.AssertIsEqual(diffIsZero, cs.Constant(0))
	return nil
}

// LessOrEqualCircuit defines a <= verification circuit
type LessOrEqualCircuit struct {
	Val         frontend.Variable `gnark:",public"`
	LessOrEqVal frontend.Variable
}

// Define declares the circuit constraints
func (circuit *LessOrEqualCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	cs.AssertIsLessOrEqual(circuit.Val, circuit.LessOrEqVal)
	return nil
}

// GreaterOrEqualCircuit defines a >= verification circuit
type GreaterOrEqualCircuit struct {
	Val            frontend.Variable `gnark:",public"`
	GreaterOrEqVal frontend.Variable
}

// Define declares the circuit constraints
func (circuit *GreaterOrEqualCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	cs.AssertIsLessOrEqual(circuit.GreaterOrEqVal, circuit.Val)
	return nil
}

// LessOrEqualCircuit defines a < verification circuit
type LessCircuit struct {
	Val     frontend.Variable `gnark:",public"`
	LessVal frontend.Variable
}

// Define declares the circuit constraints
func (circuit *LessCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	cs.AssertIsLessOrEqual(circuit.Val, cs.Sub(circuit.LessVal, 1))
	return nil
}

// GreaterCircuit defines a > verification circuit
type GreaterCircuit struct {
	Val        frontend.Variable `gnark:",public"`
	GreaterVal frontend.Variable
}

// Define declares the circuit constraints
func (circuit *GreaterCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	cs.AssertIsLessOrEqual(circuit.GreaterVal, cs.Sub(circuit.Val, 1))
	return nil
}
