package ceremony

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/jinzhu/gorm"
	provide "github.com/provideplatform/provide-go/api"

	dbconf "github.com/kthomas/go-db-config"
	natsutil "github.com/kthomas/go-natsutil"
	"github.com/provideplatform/privacy/common"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/kzg"

	kzgbls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/kzg"
	kzgbls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/kzg"
	kzgbls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr/kzg"
	kzgbn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
	kzgbw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/kzg"
)

const defaultWordSize = 32

// CeremonyConfig
type CeremonyConfig struct {
	Block           *uint64 `json:"block"`            // number of block being used for entropy
	ExpectedEntropy int     `json:"expected_entropy"` // expected number of bytes of entropy from all parties and any random beacon as required
	Index           int     `json:"index"`            // index of party's entropy
	WordSize        int     `json:"word_size"`
}

// Ceremony model
type Ceremony struct {
	provide.Model

	Config  CeremonyConfig `json:"config"`
	Parties [][]byte       `json:"parties"`
	Status  *string        `json:"status"`
	entropy []byte         `json:"-"`
}

// Create a ceremony
func (c *Ceremony) AddParty(other *Ceremony) error {
	// TODO: receive entropy from other parties
	if c.Config.WordSize != other.Config.WordSize {
		return fmt.Errorf("other word size %d does not match expected word size %d", other.Config.WordSize, c.Config.WordSize)
	}
	copy(c.entropy[other.Config.Index*other.Config.WordSize:], other.entropy[other.Config.Index*other.Config.WordSize:(other.Config.Index+1)*other.Config.WordSize])
	return nil
}

// calculateAlpha value from entropy
func (c *Ceremony) calculateAlpha() (*big.Int, error) {
	alpha := new(big.Int)

	// TODO: need to check ready condition of entropy
	alpha.SetBytes(c.entropy)
	return alpha, nil
}

// CeremonyFactory creates a new Ceremony object
func CeremonyFactory(parties [][]byte, config *CeremonyConfig) *Ceremony {
	ceremony := &Ceremony{
		Parties: parties,
		Config:  *config,
	}

	if ceremony.Config.WordSize <= 0 {
		ceremony.Config.WordSize = defaultWordSize
	}

	if ceremony.Config.ExpectedEntropy <= 0 {
		ceremony.Config.ExpectedEntropy = ceremony.Config.WordSize * (len(parties) + 1)
	}

	ceremony.entropy = make([]byte, ceremony.Config.ExpectedEntropy)

	return ceremony
}

func (c *Ceremony) Create(variables interface{}) bool {
	if !c.validate() {
		return false
	}

	db := dbconf.DatabaseConnection()

	if db.NewRecord(c) {
		result := db.Create(&c)
		rowsAffected := result.RowsAffected
		errors := result.GetErrors()
		if len(errors) > 0 {
			for _, err := range errors {
				c.Errors = append(c.Errors, &provide.Error{
					Message: common.StringOrNil(err.Error()),
				})
			}
		}
		if !db.NewRecord(c) {
			success := rowsAffected > 0
			if success {
				c.updateStatus(db, ceremonyStatusPending, nil)

				payload, _ := json.Marshal(map[string]interface{}{
					"ceremony_id": c.ID.String(),
				})
				natsutil.NatsStreamingPublish(natsCeremonyPendingSubject, payload)
				c.updateStatus(db, ceremonyStatusCreated, nil)
			}

			return success
		}
	}

	return false
}

// enrich the ceremony
func (c *Ceremony) enrich() error {
	return nil
}

// GenerateEntropy generates entropy at party index
func (c *Ceremony) GenerateEntropy() error {
	entropy, err := common.RandomBytes(c.Config.WordSize)
	if err != nil {
		return fmt.Errorf("unable to generate entropy for mpc ceremony; %s", err.Error())
	}

	// insert block entropy at party index
	copy(c.entropy[c.Config.Index*c.Config.WordSize:], entropy)
	return nil
}

// GenerateSRS from constraint size and entropy-seeded alpha value
func (c *Ceremony) GenerateSRS(size uint64, curveID ecc.ID) (kzg.SRS, error) {
	alpha, err := c.calculateAlpha()
	if err != nil {
		return nil, fmt.Errorf("unable to calculate alpha value; %s", err.Error())
	}

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

// GetEntropy gets the requested entropy by block number
func (c *Ceremony) GetEntropy(block uint64) error {

	// TODO: get beacon entropy by block number, this will be same for all parties
	entropy := []byte("test block entropy blahblahblah.")

	// insert block entropy at end
	copy(c.entropy[len(c.entropy)-c.Config.WordSize:], entropy)
	return nil
}

// SubmitEntropy broadcasts entropy to other parties
func (c *Ceremony) SubmitEntropy() error {
	// TODO: broadcast entropy to other parties
	return nil
}

// updateStatus updates the circuit status and optional description
func (c *Ceremony) updateStatus(db *gorm.DB, status string, description *string) error {
	// FIXME-- use distributed lock here
	c.Status = common.StringOrNil(status)
	// c.Description = description
	if !db.NewRecord(&c) {
		result := db.Save(&c)
		errors := result.GetErrors()
		if len(errors) > 0 {
			for _, err := range errors {
				c.Errors = append(c.Errors, &provide.Error{
					Message: common.StringOrNil(err.Error()),
				})
			}
			return errors[0]
		}
	}
	return nil
}

func (c *Ceremony) validate() bool {
	c.Errors = make([]*provide.Error, 0)

	return len(c.Errors) == 0
}
