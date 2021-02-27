package store

import (
	"fmt"

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

// Find loads a store by id
func Find(storeID uuid.UUID) *Store {
	store := &Store{}
	db := dbconf.DatabaseConnection()
	db.Where("id = ?", storeID).Find(&store)
	if store == nil || store.ID == uuid.Nil {
		return nil
	}
	return store
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

// Contains returns true if the given proof exists in the store
func (s *Store) Contains(proof string) bool {
	provider := s.storeProviderFactory()
	if provider != nil {
		return provider.Contains(proof)
	}
	return false
}

// Insert a proof into the state of the configured storage provider
func (s *Store) Insert(proof string) (*int, error) {
	provider := s.storeProviderFactory()
	if provider != nil {
		idx, _ := provider.Add([]byte(proof)) // FIXME-- should this be hex.DecodeString? RawAdd? return the hash?
		return &idx, nil
	}
	return nil, fmt.Errorf("failed to insert proof in store %s", s.ID)
}

// Recalculate the underlying state of the configured storage provider
// (i.e., the root in the case of a merkle tree provider)
func (s *Store) Recalculate() (*string, error) {
	provider := s.storeProviderFactory()
	if provider != nil {
		root := provider.Recalculate()
		return &root, nil

	}
	return nil, fmt.Errorf("failed to recalculate store %s", s.ID)
}

// Root returns the store root
func (s *Store) Root() (*string, error) {
	provider := s.storeProviderFactory()
	if provider != nil {
		root, err := provider.Root()
		if err != nil {
			return nil, fmt.Errorf("failed to resolve root in store %s; %s", s.ID, err.Error())
		}
		return &root, nil
	}
	return nil, fmt.Errorf("failed to resolve root in store %s", s.ID)
}

// ValueAt returns the store representation of value at the given index
func (s *Store) ValueAt(index int) (*string, error) {
	provider := s.storeProviderFactory()
	if provider != nil {
		val, err := provider.HashAt(index)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve value at index %d in store %s; %s", index, s.ID, err.Error())
		}
		return &val, nil
	}
	return nil, fmt.Errorf("failed to resolve value at index %d in store %s", index, s.ID)
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
