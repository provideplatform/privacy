// +build ceremony

package test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/provideplatform/privacy/ceremony"
)

func setupTestMPCs(t *testing.T, mpcs *[]*ceremony.Ceremony, parties []string, blockID uint64) error {
	for i := 0; i < len(parties); i++ {
		mpc := ceremony.CeremonyFactory(parties, &ceremony.CeremonyConfig{
			Block:           &blockID,
			ExpectedEntropy: 32 * (len(parties) + 1),
			WordSize:        32,
		})

		err := mpc.GetEntropy(blockID)
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
}
