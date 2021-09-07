package ceremony

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/jinzhu/gorm"
	provide "github.com/provideplatform/provide-go/api"
	"github.com/provideplatform/provide-go/api/vault"

	dbconf "github.com/kthomas/go-db-config"
	natsutil "github.com/kthomas/go-natsutil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/privacy/common"
)

const defaultWordSize = 32

// const ceremonyStatusComplete = "complete"
// const ceremonyStatusCreated = "created"
// const ceremonyStatusFailed = "failed"
// const ceremonyStatusInit = "init"
const ceremonyStatusPending = "pending"

// CeremonyConfig
type CeremonyConfig struct {
	Block           *uint64 `json:"block"`            // number of block being used for entropy
	ExpectedEntropy int     `json:"expected_entropy"` // expected number of bytes of entropy from all parties and any random beacon as required
	WordSize        int     `json:"word_size"`
}

// Ceremony model
type Ceremony struct {
	provide.Model

	Config     CeremonyConfig `json:"config"`
	Parties    []string       `json:"parties"`
	Status     *string        `json:"status"`
	entropy    []byte         `json:"-"`
	ownEntropy []byte         `json:"-"`
}

// AddParty creates a ceremony
func (c *Ceremony) AddParty(index int, other *Ceremony) error {
	// TODO: receive entropy from other parties
	if c.Config.WordSize != other.Config.WordSize {
		return fmt.Errorf("other word size %d does not match expected word size %d", other.Config.WordSize, c.Config.WordSize)
	}

	if len(other.ownEntropy) == 0 || bytes.Equal(other.ownEntropy, make([]byte, other.Config.WordSize)) {
		return fmt.Errorf("other party ceremony has uninitialized entropy value")
	}

	copy(c.entropy[index*c.Config.WordSize:], other.ownEntropy)
	return nil
}

// CeremonyFactory creates a new Ceremony object
func CeremonyFactory(parties []string, config *CeremonyConfig) *Ceremony {
	ceremony := &Ceremony{
		Parties: parties,
		Config:  *config,
	}

	sort.Strings(ceremony.Parties)

	if ceremony.Config.WordSize <= 0 {
		ceremony.Config.WordSize = defaultWordSize
	}

	if ceremony.Config.ExpectedEntropy <= 0 {
		ceremony.Config.ExpectedEntropy = ceremony.Config.WordSize * (len(parties) + 1)
	}

	ceremony.entropy = make([]byte, ceremony.Config.ExpectedEntropy)

	return ceremony
}

// CompareEntropy compares entropy value to that of other Ceremony
func (c *Ceremony) CompareEntropy(other *Ceremony) bool {
	return bytes.Equal(c.entropy, other.entropy)
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
				payload, _ := json.Marshal(map[string]interface{}{
					"ceremony_id": c.ID.String(),
				})
				natsutil.NatsStreamingPublish(natsCeremonyPendingSubject, payload)
				c.updateStatus(db, ceremonyStatusPending, nil)
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

	c.ownEntropy = entropy

	return nil
}

// GetEntropyFromBeacon gets the requested entropy by block number
func (c *Ceremony) GetEntropyFromBeacon(block uint64) error {

	// TODO: get beacon entropy by block number, this will be same for all parties
	entropy := []byte("test block entropy blahblahblah.")

	// insert block entropy at end
	copy(c.entropy[len(c.entropy)-c.Config.WordSize:], entropy)
	return nil
}

// StoreEntropy stores entropy in vault
func (c *Ceremony) StoreEntropy(token, vaultID, name, description, secretType *string) (*uuid.UUID, error) {
	// TODO: make sure entropy value has no uninitialized/all-zero words

	secret, err := vault.CreateSecret(
		*token,
		*vaultID,
		hex.EncodeToString(c.entropy),
		*name,
		*description,
		*secretType,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to store entropy for ceremony %s in vault %s; %s", c.ID.String(), *vaultID, err.Error())
	}
	return &secret.ID, nil
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
