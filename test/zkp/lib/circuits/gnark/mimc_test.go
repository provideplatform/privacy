// +build unit

package gnark

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	libgnark "github.com/provideplatform/privacy/zkp/lib/circuits/gnark"
)

func TestPreimageGroth16(t *testing.T) {
	assert := groth16.NewAssert(t)

	confs := map[ecc.ID]hash.Hash{
		ecc.BN254:     hash.MIMC_BN254,
		ecc.BLS12_381: hash.MIMC_BLS12_381,
		ecc.BLS12_377: hash.MIMC_BLS12_377,
		ecc.BW6_761:   hash.MIMC_BW6_761,
		ecc.BLS24_315: hash.MIMC_BLS24_315,
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
			witness.Preimage.Assign(preimage)
			witness.Hash.Assign(hash)

			assert.SolvingSucceeded(r1cs, &witness)
			//assert.ProverSucceeded(r1cs, &witness)
		}

		{
			var witness libgnark.MimcCircuit
			witness.Hash.Assign(42) // these are nonsense values for this circuit
			witness.Preimage.Assign(42)

			assert.SolvingFailed(r1cs, &witness)
			//assert.ProverFailed(r1cs, &witness)
		}
	}
}

func TestPreimagePlonk(t *testing.T) {
	assert := plonk.NewAssert(t)

	confs := map[ecc.ID]hash.Hash{
		ecc.BN254:     hash.MIMC_BN254,
		ecc.BLS12_381: hash.MIMC_BLS12_381,
		ecc.BLS12_377: hash.MIMC_BLS12_377,
		ecc.BW6_761:   hash.MIMC_BW6_761,
		ecc.BLS24_315: hash.MIMC_BLS24_315,
	}

	for id, h := range confs {
		var mimcCircuit libgnark.MimcCircuit
		r1cs, err := frontend.Compile(id, backend.PLONK, &mimcCircuit)
		assert.NoError(err)

		{
			hFunc := h.New("seed")
			var preimage big.Int
			preimage.SetString("35", 10)
			hFunc.Write(preimage.Bytes())
			hash := hFunc.Sum(nil)

			var witness, publicWitness libgnark.MimcCircuit
			witness.Preimage.Assign(preimage)
			witness.Hash.Assign(hash)

			pk, vk, err := plonk.Setup(r1cs, getKzgScheme(r1cs))
			assert.NoError(err, "Generating public data should not have failed")

			proof, err := plonk.Prove(r1cs, pk, &witness)
			assert.NoError(err, "Proving with good witness should not output an error")

			publicWitness.Hash.Assign(hash)
			err = plonk.Verify(proof, vk, &publicWitness)
			assert.NoError(err, "Verifying correct proof with correct witness should not output an error")
		}

		{
			var witness libgnark.MimcCircuit
			witness.Hash.Assign(42) // these are nonsense values for this circuit
			witness.Preimage.Assign(42)

			pk, _, err := plonk.Setup(r1cs, getKzgScheme(r1cs))
			assert.NoError(err, "Generating public data should not have failed")

			_, err = plonk.Prove(r1cs, pk, &witness)
			assert.Error(err, "Proving with bad witness should output an error")
		}
	}
}
