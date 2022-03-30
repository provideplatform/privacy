//go:build integration
// +build integration

package test

import (
	"github.com/provideplatform/privacy/common"
	"github.com/provideplatform/provide-go/api/privacy"
)

func createPreimageHashProver(token *string, provingScheme string) (*privacy.Prover, error) {
	prover, err := privacy.CreateProver(
		*token,
		proverParamsFactory(
			"BLS12_377",
			"General Consistency",
			"preimage_hash",
			provingScheme,
			nil,
			nil,
		),
	)
	if err != nil {
		common.Log.Debugf("failed to deploy prover; %s", err.Error())
		return nil, err
	}

	return prover, err
}

func createRecursiveProofProver(token *string, provingScheme string) (*privacy.Prover, error) {
	params := proverParamsFactory(
		"BW6_761",
		"General Consistency (Recursive)",
		"recursive_proof",
		provingScheme,
		nil,
		nil,
	)
	params["variables"] = map[string]interface{}{
		"VerifyingKey": "a0aa589fd1bab91d4c3bffc82ebd1b3333ebc5acca0987875dd31743de450c89a81207b12d32790e956faad8a8fbfaeba01c6ff09e0a18d18f33c0b18ed6132e899630e2c5886dec111792208149cb2fbfa64d1750de211853f314353e9e5b1ba0caf8db86543378c2a911d614f24f80b9e722bacf39263f672bdb323988b85a2dc3e91098660a0583804f59c32ee51000e53c4cfb913ea35bc4290b5f56f594969c135517e027de42b1e0e754eef15542d791165539cae85ac799cddc8c323da053a4833f978c5a9dfd6621049bc5864200059a05c67ed23cd2b6b87421268b66a912094ef9af603347f0436bcb43fa00b83b69c824c67cc845c80e8cff793ad0714ee3de6642275ff8d89b11285998e0fb548425058ebc3ec9e6dc1bf54b07a17dc5a22b3ae5f5e168ebf3a67f10ff2ee1663fd5caafdb345ed2fc51a9facc4d69ee6c7524a5c0846e3e59a2426c52a19c7d19938ff7c41ff814ad8fcf9d3ef0ea9fd8920656834297c70f8588acd6ee81ef49575a1b426608797607ee4dfa00a9459e266f7e1073043201f57d860624e80c10bc3ab9174700b4d7c95f0e95529cafa7601d175ff49c0c35af33399900000002813134a97abcf96dd48583f48e45611d53fb39cc2f21350c737453783dfef21a4d081dff1f3631133312795e3a8dee6280605d5d0592c43d3daf632a88a40b1c351b7d99a48989d0e3f1d6e17b0b5098c8e167de466c2ffdef21ddcf9bf90d55",
	}
	prover, err := privacy.CreateProver(
		*token,
		params,
	)
	if err != nil {
		common.Log.Debugf("failed to deploy prover; %s", err.Error())
		return nil, err
	}

	return prover, err
}
