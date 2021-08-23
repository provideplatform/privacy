package ceremony

import (
	"fmt"
	"math/big"

	"github.com/provideplatform/privacy/common"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/kzg"

	kzgbls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/kzg"
	kzgbls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/kzg"
	kzgbls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr/kzg"
	kzgbn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
	kzgbw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/kzg"
)

// Ceremony model
type Ceremony struct {
	BlockID            int
	entropy            big.Int
	needsEntropyUpdate bool
	partyEntropy       map[int]big.Int
	PartyID            int
}

func (c *Ceremony) AddParty(other *Ceremony) {
	c.partyEntropy[other.PartyID] = other.entropy
}

func (c *Ceremony) calculateAlpha() *big.Int {
	alpha := new(big.Int)

	for _, entropy := range c.partyEntropy {
		alpha.Add(alpha, &entropy)
	}
	return alpha
}

func (c *Ceremony) GenerateSRS(size uint64, curveID ecc.ID) (kzg.SRS, error) {
	alpha := c.calculateAlpha()

	switch curveID {
	case ecc.BN254:
		return kzgbn254.NewSRS(ecc.NextPowerOfTwo(size)+3, alpha)
	case ecc.BLS12_381:
		return kzgbls12381.NewSRS(ecc.NextPowerOfTwo(size)+3, alpha)
	case ecc.BLS12_377:
		return kzgbls12377.NewSRS(ecc.NextPowerOfTwo(size)+3, alpha)
	case ecc.BW6_761:
		return kzgbw6761.NewSRS(ecc.NextPowerOfTwo(size)+3, alpha)
	case ecc.BLS24_315:
		return kzgbls24315.NewSRS(ecc.NextPowerOfTwo(size)+3, alpha)
	default:
		return nil, fmt.Errorf("invalid curve id")
	}
}

func (c *Ceremony) GetEntropy(blockID int) error {
	if !c.needsEntropyUpdate {
		return fmt.Errorf("entropy already retrieved, %v", c.needsEntropyUpdate)
	}

	// TODO: get beacon entropy by blockID
	entropy, err := common.RandomBytes(32)
	if err != nil {
		return fmt.Errorf("unable to retrieve entropy for mpc ceremony; %s", err.Error())
	}

	c.entropy.SetBytes(entropy)
	c.partyEntropy[c.PartyID] = c.entropy
	c.needsEntropyUpdate = false
	return nil
}

func NewCeremony(partyID int) *Ceremony {
	return &Ceremony{
		PartyID:            partyID,
		needsEntropyUpdate: true,
		partyEntropy:       make(map[int]big.Int),
	}
}

func (c *Ceremony) SubmitEntropy() error {
	// TODO: broadcast entropy to other parties
	return nil
}
