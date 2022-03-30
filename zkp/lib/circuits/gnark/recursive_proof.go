package gnark

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/groth16_bls12377"
	"github.com/consensys/gnark/std/hash/mimc"
)

// const recursiveProofCurve = ecc.BW6_761

type RecursiveProofCircuit struct {
	Preimage     frontend.Variable
	PreimageHash frontend.Variable `gnark:",public"`

	Hash         frontend.Variable `gnark:",public"`
	Proof        groth16_bls12377.Proof
	VerifyingKey groth16_bls12377.VerifyingKey
}

// Define recursive proof circuit logic
func (prover *RecursiveProofCircuit) Define(api frontend.API) error {
	// verify the recursive proof
	publicInput := []frontend.Variable{prover.Hash}
	groth16_bls12377.Verify(
		api,
		prover.VerifyingKey,
		prover.Proof,
		publicInput,
	)

	// preimage hash proof
	mimc, _ := mimc.NewMiMC(api)
	mimc.Write(prover.Preimage)
	api.AssertIsEqual(prover.PreimageHash, mimc.Sum())

	return nil
}

// verifyingKeyFactory initializes the given verifying key on curve BLS12_377
// func (prover *RecursiveProofCircuit) verifyingKeyFactory() groth16_bls12377.VerifyingKey {
// 	// buf := make([]byte, 0)
// 	// i, err := hex.Decode(prover.VerifyingKey, buf)
// 	// if err != nil {
// 	// 	common.Log.Warningf("failed to decode verifying key; %s", err.Error())
// 	// }

// 	_vk, _ := prover.VerifyingKey.([]byte)
// 	// common.Log.Debugf("read %d-byte witness-supplied verifying key", i)

// 	vk := groth16.NewVerifyingKey(ecc.BLS12_377)
// 	vk.UnsafeReadFrom(bytes.NewReader(_vk))

// 	var verifyingKey groth16_bls12377.VerifyingKey
// 	verifyingKey.Assign(vk)
// 	return verifyingKey
// }
