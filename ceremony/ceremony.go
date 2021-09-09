package ceremony

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	"github.com/jinzhu/gorm"
	provide "github.com/provideplatform/provide-go/api"
	"github.com/provideplatform/provide-go/api/vault"
	util "github.com/provideplatform/provide-go/common/util"

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
	Block    *uint64 `json:"block"` // number of block being used for entropy
	WordSize int     `json:"word_size"`
}

// Ceremony model
type Ceremony struct {
	provide.Model

	Config  CeremonyConfig `json:"config"`
	Parties []string       `json:"parties"`
	Status  *string        `json:"status"`

	Entropy []byte `json:"-"`

	VaultID              *uuid.UUID `json:"vault_id"`
	EntropyVaultSecretID *uuid.UUID `json:"entropy_vault_secret_id"`

	// Associations
	ApplicationID  *uuid.UUID `sql:"type:uuid" json:"-"`
	OrganizationID *uuid.UUID `sql:"type:uuid" json:"-"`
	UserID         *uuid.UUID `sql:"type:uuid" json:"-"`

	mutex sync.Mutex
}

// CeremonyFactory creates a new Ceremony object
func (c *Ceremony) CeremonyFactory(parties []string, config *CeremonyConfig) {
	c.Parties = parties
	c.Config = *config

	// TODO: validate no duplicate parties
	sort.Strings(c.Parties)

	if c.Config.WordSize <= 0 {
		c.Config.WordSize = defaultWordSize
	}

	c.Entropy = make([]byte, c.Config.WordSize*(len(parties)+1))
}

// CompareEntropy compares entropy value to that of other Ceremony
func (c *Ceremony) CompareEntropy(other *Ceremony) bool {
	return bytes.Equal(c.Entropy, other.Entropy)
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
				natsutil.NatsJetstreamPublish(natsCeremonyPendingSubject, payload)
				c.updateStatus(db, ceremonyStatusPending, nil)
			}

			return success
		}
	}

	return false
}

// enrich the ceremony
func (c *Ceremony) enrich() error {
	if c.VaultID == nil {
		if common.DefaultVault != nil {
			c.VaultID = &common.DefaultVault.ID
		}

		if c.VaultID == nil {
			return fmt.Errorf("vault id required")
		}
	}

	if (c.Entropy == nil || len(c.Entropy) == 0) && c.EntropyVaultSecretID != nil {
		secret, err := vault.FetchSecret(
			util.DefaultVaultAccessJWT,
			c.VaultID.String(),
			c.EntropyVaultSecretID.String(),
			map[string]interface{}{},
		)
		if err != nil {
			return err
		}
		c.Entropy, err = hex.DecodeString(*secret.Value)
		if err != nil {
			common.Log.Warningf("failed to decode entropy secret from hex; %s", err.Error())
			return err
		}
	}

	return nil
}

// GetEntropyFromBeacon gets the requested entropy by block number
func (c *Ceremony) GetEntropyFromBeacon() error {

	// TODO: get beacon entropy by block number, this will be same for all parties
	entropy := []byte("test block entropy blahblahblah.")

	// insert block entropy at end
	copy(c.Entropy[len(c.Entropy)-c.Config.WordSize:], entropy)
	return nil
}

// StoreEntropy stores entropy in vault
func (c *Ceremony) StoreEntropy() error {
	// TODO: make sure entropy value has no uninitialized/all-zero words

	if c.VaultID == nil {
		if common.DefaultVault != nil {
			c.VaultID = &common.DefaultVault.ID
		}

		if c.VaultID == nil {
			return fmt.Errorf("vault id required")
		}
	}

	secret, err := vault.CreateSecret(
		util.DefaultVaultAccessJWT,
		c.VaultID.String(),
		hex.EncodeToString(c.Entropy),
		"mpc entropy",
		"entropy for multiparty computation ceremony",
		"entropy",
	)
	if err != nil {
		return fmt.Errorf("failed to store entropy for ceremony %s in vault %s; %s", c.ID.String(), c.VaultID.String(), err.Error())
	}

	c.EntropyVaultSecretID = &secret.ID

	return nil
}

// SubmitEntropy broadcasts entropy to other parties
func (c *Ceremony) SubmitEntropy(party string, entropy []byte) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	err := c.enrich()
	if err != nil {
		return fmt.Errorf("failed to enrich entropy; %s", err.Error())
	}

	// TODO: receive entropy from other parties
	if c.Config.WordSize != len(entropy) {
		return fmt.Errorf("entropy size %d does not match expected word size %d", len(entropy), c.Config.WordSize)
	}

	index := -1
	for i, p := range c.Parties {
		if p == party {
			index = i
			break
		}
	}

	if index == -1 {
		return fmt.Errorf("invalid party %s", party)
	}

	copy(c.Entropy[index*c.Config.WordSize:], entropy)
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
