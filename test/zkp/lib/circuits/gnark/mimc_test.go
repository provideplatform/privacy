package gnark

import (
	"testing"

	"github.com/consensys/gurvy"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	libgnark "github.com/provideapp/privacy/zkp/lib/circuits/gnark"
)

func TestPreimage(t *testing.T) {
	assert := groth16.NewAssert(t)

	var mimcCircuit libgnark.MimcCircuit

	r1cs, err := frontend.Compile(gurvy.BN256, &mimcCircuit)
	assert.NoError(err)

	{
		var witness libgnark.MimcCircuit
		witness.Hash.Assign(42)
		witness.PreImage.Assign(42)
		assert.ProverFailed(r1cs, &witness)
	}

	{
		var witness libgnark.MimcCircuit
		witness.PreImage.Assign(35)
		witness.Hash.Assign("16130099170765464552823636852555369511329944820189892919423002775646948828469")
		assert.ProverSucceeded(r1cs, &witness)
	}

}
