// +build unit

package test

import (
	"testing"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
	"github.com/provideapp/privacy/zkp/lib/circuits/gnark"
)

func TestEq(t *testing.T) {
	assert := groth16.NewAssert(t)

	var eqCircuit gnark.EqualCircuit
	r1cs, err := frontend.Compile(gurvy.BN256, &eqCircuit)
	assert.NoError(err)

	{
		var witness gnark.EqualCircuit
		witness.Val.Assign(250)
		witness.EqVal.Assign(250)

		assert.ProverSucceeded(r1cs, &witness)
	}

	{
		var witness gnark.EqualCircuit
		witness.Val.Assign(254)
		witness.EqVal.Assign(250)

		assert.ProverFailed(r1cs, &witness)
	}
}

func TestNotEq(t *testing.T) {
	assert := groth16.NewAssert(t)

	var eqCircuit gnark.NotEqualCircuit
	r1cs, err := frontend.Compile(gurvy.BN256, &eqCircuit)
	assert.NoError(err)

	{
		var witness gnark.NotEqualCircuit
		witness.Val.Assign(250)
		witness.NotEqVal.Assign(250)

		assert.ProverFailed(r1cs, &witness)
	}

	{
		var witness gnark.NotEqualCircuit
		witness.Val.Assign(254)
		witness.NotEqVal.Assign(250)

		assert.ProverSucceeded(r1cs, &witness)
	}

	{
		var witness gnark.NotEqualCircuit
		witness.Val.Assign(249)
		witness.NotEqVal.Assign(250)

		assert.ProverSucceeded(r1cs, &witness)
	}
}

func TestLessOrEqual(t *testing.T) {
	assert := groth16.NewAssert(t)

	var ltEqCircuit gnark.LessOrEqualCircuit
	r1cs, err := frontend.Compile(gurvy.BN256, &ltEqCircuit)
	assert.NoError(err)

	{
		var witness gnark.LessOrEqualCircuit
		witness.Val.Assign(250)
		witness.LessOrEqVal.Assign(250)
		assert.ProverSucceeded(r1cs, &witness)
	}

	{
		var witness gnark.LessOrEqualCircuit
		witness.Val.Assign(120)
		witness.LessOrEqVal.Assign(250)
		assert.ProverSucceeded(r1cs, &witness)
	}

	{
		var witness gnark.LessOrEqualCircuit
		witness.Val.Assign(350)
		witness.LessOrEqVal.Assign(250)
		assert.ProverFailed(r1cs, &witness)
	}
}

func TestGreaterOrEqual(t *testing.T) {
	assert := groth16.NewAssert(t)

	var ltCircuit gnark.GreaterOrEqualCircuit
	r1cs, err := frontend.Compile(gurvy.BN256, &ltCircuit)
	assert.NoError(err)
	{
		var witness gnark.GreaterOrEqualCircuit
		witness.Val.Assign(250)
		witness.GreaterOrEqVal.Assign(250)
		assert.ProverSucceeded(r1cs, &witness)
	}

	{
		var witness gnark.GreaterOrEqualCircuit
		witness.Val.Assign(250)
		witness.GreaterOrEqVal.Assign(120)
		assert.ProverSucceeded(r1cs, &witness)
	}

	{
		var witness gnark.GreaterOrEqualCircuit
		witness.Val.Assign(250)
		witness.GreaterOrEqVal.Assign(350)
		assert.ProverFailed(r1cs, &witness)
	}
}

func TestLess(t *testing.T) {
	assert := groth16.NewAssert(t)

	var ltCircuit gnark.LessCircuit
	r1cs, err := frontend.Compile(gurvy.BN256, &ltCircuit)
	assert.NoError(err)

	{
		var witness gnark.LessCircuit
		witness.Val.Assign(250)
		witness.LessVal.Assign(250)
		assert.ProverFailed(r1cs, &witness)
	}

	{
		var witness gnark.LessCircuit
		witness.Val.Assign(120)
		witness.LessVal.Assign(250)
		assert.ProverSucceeded(r1cs, &witness)
	}

	{
		var witness gnark.LessCircuit
		witness.Val.Assign(350)
		witness.LessVal.Assign(250)
		assert.ProverFailed(r1cs, &witness)
	}

	{
		var witness gnark.LessCircuit
		witness.Val.Assign(249)
		witness.LessVal.Assign(250)
		assert.ProverSucceeded(r1cs, &witness)
	}
}

func TestGreater(t *testing.T) {
	assert := groth16.NewAssert(t)

	var ltCircuit gnark.GreaterCircuit
	r1cs, err := frontend.Compile(gurvy.BN256, &ltCircuit)
	assert.NoError(err)

	{
		var witness gnark.GreaterCircuit
		witness.Val.Assign(250)
		witness.GreaterVal.Assign(250)
		assert.ProverFailed(r1cs, &witness)
	}

	{
		var witness gnark.GreaterCircuit
		witness.Val.Assign(250)
		witness.GreaterVal.Assign(120)
		assert.ProverSucceeded(r1cs, &witness)
	}

	{
		var witness gnark.GreaterCircuit
		witness.Val.Assign(250)
		witness.GreaterVal.Assign(350)
		assert.ProverFailed(r1cs, &witness)
	}

	{
		var witness gnark.GreaterCircuit
		witness.Val.Assign(250)
		witness.GreaterVal.Assign(249)
		assert.ProverSucceeded(r1cs, &witness)
	}
}
