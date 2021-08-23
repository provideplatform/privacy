// +build ceremony

package test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/provideplatform/privacy/ceremony"
)

func setupTestMPCs(t *testing.T, mpcs *[]*ceremony.Ceremony, partyCount, blockID int) error {
	for i := 0; i < partyCount; i++ {
		mpc := ceremony.NewCeremony(i)

		err := mpc.GetEntropy(blockID)
		if err != nil {
			return fmt.Errorf("unable to get entropy; %s", err.Error())
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

func addPartiesToTestMPCs(t *testing.T, mpcs []*ceremony.Ceremony) error {
	partyCount := len(mpcs)
	for i := 0; i < partyCount; i++ {
		for j := 0; j < partyCount; j++ {
			if i == j {
				continue
			}
			mpcs[i].AddParty(mpcs[j])
		}
	}

	return nil
}

func validateSRS(t *testing.T, mpcs []*ceremony.Ceremony) error {
	// TODO: get correct size for SRS from circuit API?
	sizeForSRS := uint64(500)

	srs, err := mpcs[0].GenerateSRS(sizeForSRS, ecc.BN254)
	if err != nil {
		return fmt.Errorf("error generating initial SRS; %s", err.Error())
	}

	srsBuf := new(bytes.Buffer)
	_, err = srs.WriteTo(srsBuf)
	if err != nil {
		return fmt.Errorf("error writing initial SRS to bytes buffer; %s", err.Error())
	}

	for _, mpc := range mpcs {
		testSRS, err := mpc.GenerateSRS(sizeForSRS, ecc.BN254)
		if err != nil {
			return fmt.Errorf("error generating test SRS; %s", err.Error())
		}

		testSRSBuf := new(bytes.Buffer)
		_, err = testSRS.WriteTo(testSRSBuf)
		if err != nil {
			return fmt.Errorf("error writing test SRS to bytes buffer; %s", err.Error())
		}

		if !bytes.Equal(srsBuf.Bytes(), testSRSBuf.Bytes()) {
			return fmt.Errorf("test SRS does not match initial SRS")
		}
	}

	return nil
}

func TestCeremonySRSGeneration(t *testing.T) {
	mpcs := make([]*ceremony.Ceremony, 0)

	// TODO: retrieve block ID properly
	blockID := 123456
	const partyCount = 5

	err := setupTestMPCs(t, &mpcs, partyCount, blockID)
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

	err = validateSRS(t, mpcs[:])
	if err != nil {
		t.Errorf("error validating SRS for test MPCs; %s", err.Error())
		return
	}

	t.Log("all generated SRS are valid")
}
