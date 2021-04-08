// +build unit

package gnark

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	libgnark "github.com/provideapp/privacy/zkp/lib/circuits/gnark"
)

func TestPreimage(t *testing.T) {
	assert := groth16.NewAssert(t)

	confs := map[ecc.ID]hash.Hash{
		ecc.BN254:     hash.MIMC_BN254,
		ecc.BLS12_381: hash.MIMC_BLS12_381,
		ecc.BLS12_377: hash.MIMC_BLS12_377,
		ecc.BW6_761:   hash.MIMC_BW6_761,
	}

	for id, h := range confs {
		var mimcCircuit libgnark.MimcCircuit
		r1cs, err := frontend.Compile(id, backend.GROTH16, &mimcCircuit)
		assert.NoError(err)

		{
			hFunc := h.New("seed")
			var preimage big.Int
			preimage.SetString("35", 10)
			hFunc.Write(preimage.Bytes())
			hash := hFunc.Sum(nil)

			var witness libgnark.MimcCircuit
			witness.PreImage.Assign(preimage)
			witness.Hash.Assign(hash)

			assert.SolvingSucceeded(r1cs, &witness)
			//assert.ProverSucceeded(r1cs, &witness)
		}

		{
			var witness libgnark.MimcCircuit
			witness.Hash.Assign(42) // these are nonsense values for this circuit
			witness.PreImage.Assign(42)

			assert.SolvingFailed(r1cs, &witness)
			//assert.ProverFailed(r1cs, &witness)
		}
	}
}
