// +build ceremony

package test

import (
	"fmt"
	"math/big"
	"testing"

	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/privacy/ceremony"
	"github.com/provideplatform/privacy/common"
	"github.com/provideplatform/provide-go/api/privacy"
	"github.com/provideplatform/provide-go/common/util"
)

func setupTestMPCs(t *testing.T, mpcs *[]*ceremony.Ceremony, parties []string, blockID uint64) error {
	for i := 0; i < len(parties); i++ {
		mpc := ceremony.CeremonyFactory(parties, &ceremony.CeremonyConfig{
			Block:           &blockID,
			ExpectedEntropy: 32 * (len(parties) + 1),
			WordSize:        32,
		})

		err := mpc.GetEntropyFromBeacon(blockID)
		if err != nil {
			return fmt.Errorf("unable to get entropy; %s", err.Error())
		}

		err = mpc.GenerateEntropy()
		if err != nil {
			return fmt.Errorf("unable to generate entropy; %s", err.Error())
		}

		err = mpc.SubmitEntropy()
		if err != nil {
			return fmt.Errorf("unable to submit entropy; %s", err.Error())
		}

		*mpcs = append(*mpcs, mpc)
	}

	t.Logf("created %d MPCs", len(*mpcs))
	return nil
}

// TODO: replace with actual entropy receipt
func addPartiesToTestMPCs(t *testing.T, mpcs []*ceremony.Ceremony) error {
	partyCount := len(mpcs)
	for i := 0; i < partyCount; i++ {
		for j := 0; j < partyCount; j++ {
			mpcs[i].AddParty(j, mpcs[j])
		}
	}

	return nil
}

func validateEntropy(t *testing.T, mpcs []*ceremony.Ceremony) error {
	for i := 1; i < len(mpcs); i++ {
		if !mpcs[i-1].CompareEntropy(mpcs[i]) {
			return fmt.Errorf("entropy from mpc %d does not match mpc %d", i-1, i)
		}
	}

	return nil
}

func circuitParamsFactory(curve, name, identifier, provingScheme string, noteStoreID, nullifierStoreID *string) map[string]interface{} {
	params := map[string]interface{}{
		"curve":          curve,
		"identifier":     identifier,
		"name":           name,
		"provider":       "gnark",
		"proving_scheme": provingScheme,
	}

	if noteStoreID != nil {
		params["note_store_id"] = noteStoreID
	}

	if nullifierStoreID != nil {
		params["nullifier_store_id"] = nullifierStoreID
	}

	return params
}

func TestCeremonySRSGeneration(t *testing.T) {
	mpcs := make([]*ceremony.Ceremony, 0)

	// TODO: retrieve block ID properly
	blockID := uint64(123456)
	const partyCount = 5
	parties := make([]string, 0)

	i := new(big.Int)
	for party := int64(0); party < int64(partyCount); party++ {
		i.SetInt64(party)
		parties = append(parties, i.String())
	}

	err := setupTestMPCs(t, &mpcs, parties, blockID)
	if err != nil {
		t.Errorf("error setting up test MPCs; %s", err.Error())
		return
	}

	t.Logf("set up %d MPCs", len(mpcs))

	err = addPartiesToTestMPCs(t, mpcs[:])
	if err != nil {
		t.Errorf("error adding parties to test MPCs; %s", err.Error())
		return
	}

	err = validateEntropy(t, mpcs[:])
	if err != nil {
		t.Errorf("error validating entropy for test MPCs; %s", err.Error())
		return
	}

	t.Log("all calculated entropy values are valid")

	newVault, err := vaultFactory(util.DefaultVaultAccessJWT, "mpc vault", "contains entropy for mpc")
	if err != nil {
		t.Errorf("failed to create vault for ceremony test; %s", err.Error())
		return
	}

	entropySecretID, err := mpcs[0].StoreEntropy(
		common.StringOrNil(util.DefaultVaultAccessJWT),
		common.StringOrNil(newVault.ID.String()),
		common.StringOrNil("mpc entropy"),
		common.StringOrNil("entropy for mpc"),
		common.StringOrNil("entropy"),
	)
	if err != nil {
		t.Errorf("failed to store entropy in vault; %s", err.Error())
		return
	}

	t.Logf("stored entropy in vault; secret id: %s", entropySecretID.String())

	testUserID, _ := uuid.NewV4()
	token, _ := userTokenFactory(testUserID)

	params := circuitParamsFactory(
		"BN254",
		"PO",
		"purchase_order",
		"plonk",
		nil,
		nil,
	)

	params["entropy_id"] = entropySecretID.String()
	params["vault_id"] = newVault.ID.String()

	circuit, err := privacy.CreateCircuit(*token, params)
	if err != nil {
		t.Errorf("failed to deploy circuit; %s", err.Error())
		return
	}

	t.Logf("created circuit id: %s", circuit.ID.String())
}
