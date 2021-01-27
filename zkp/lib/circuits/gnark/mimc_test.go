package gnark

import (
	"testing"

	"github.com/consensys/gurvy"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

func TestPreimage(t *testing.T) {
	assert := groth16.NewAssert(t)

	var mimcCircuit MimcCircuit

	r1cs, err := frontend.Compile(gurvy.BN256, &mimcCircuit)
	assert.NoError(err)

	{
		var witness MimcCircuit
		witness.Hash.Assign(42)
		witness.PreImage.Assign(42)
		assert.ProverFailed(r1cs, &witness)
	}

	{
		var witness MimcCircuit
		witness.PreImage.Assign(35)
		witness.Hash.Assign("19226210204356004706765360050059680583735587569269469539941275797408975356275")
		assert.ProverSucceeded(r1cs, &witness)
	}

}
