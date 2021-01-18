package store

import (
	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/privacy/common"
	proofstorage "github.com/provideapp/privacy/store/providers"
	provide "github.com/provideservices/provide-go/api"
)

// Store model
type Store struct {
	provide.Model

	CircuitID *uuid.UUID `sql:"not null" json:"circuit_id"`

	Name        *string `json:"name"`
	Description *string `json:"description"`
	Provider    *string `json:"provider"`
}

func (s *Store) storeProviderFactory() proofstorage.StoreProvider {
	if s.Provider == nil {
		common.Log.Warning("failed to initialize store provider; no provider defined")
		return nil
	}

	switch *s.Provider {
	case proofstorage.StoreProviderMerkleTree:
		return proofstorage.InitMerkleTreeStoreProvider(s.ID)
	default:
		common.Log.Warningf("failed to initialize store provider; unknown provider: %s", *s.Provider)
	}

	return nil
}

// Create a store
func (s *Store) Create() bool {
	if !s.validate() {
		return false
	}

	db := dbconf.DatabaseConnection()

	if db.NewRecord(s) {
		result := db.Create(&s)
		rowsAffected := result.RowsAffected
		errors := result.GetErrors()
		if len(errors) > 0 {
			for _, err := range errors {
				s.Errors = append(s.Errors, &provide.Error{
					Message: common.StringOrNil(err.Error()),
				})
			}
		}
		if !db.NewRecord(s) {
			success := rowsAffected > 0
			if success {
				common.Log.Debugf("initialized %s store: %s", *s.Provider, s.ID)
			}

			return success
		}
	}

	return false
}

// validate the store params
func (s *Store) validate() bool {
	s.Errors = make([]*provide.Error, 0)

	if s.Provider == nil {
		s.Errors = append(s.Errors, &provide.Error{
			Message: common.StringOrNil("store provider required"),
		})
	}

	return len(s.Errors) == 0
}
