package store

import (
	"fmt"

	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/privacy/common"
	proofstorage "github.com/provideplatform/privacy/store/providers"
	provide "github.com/provideplatform/provide-go/api"
)

// Store model
type Store struct {
	provide.Model

	Name        *string `json:"name"`
	Description *string `json:"description"`
	Provider    *string `json:"provider"`
	Curve       *string `json:"curve"`
}

func (s *Store) storeProviderFactory() proofstorage.StoreProvider {
	if s.Provider == nil {
		common.Log.Warning("failed to initialize store provider; no provider defined")
		return nil
	}

	switch *s.Provider {
	case proofstorage.StoreProviderMerkleTree:
		return proofstorage.InitMerkleTreeStoreProvider(s.ID, s.Curve)
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

// Contains returns true if the given hash exists in the store
func (s *Store) Contains(val string) bool {
	provider := s.storeProviderFactory()
	if provider != nil {
		return provider.Contains(val)
	}
	return false
}

// Insert a proof into the state of the configured storage provider
func (s *Store) Insert(val string) (*int, error) {
	provider := s.storeProviderFactory()
	if provider != nil {
		idx, _ := provider.Add([]byte(val))
		return &idx, nil
	}
	return nil, fmt.Errorf("failed to insert proof in store %s", s.ID)
}

// Length returns the number of stored nodes
func (s *Store) Length() int {
	provider := s.storeProviderFactory()
	if provider != nil {
		return provider.Length()
	}
	return 0
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
		return root, nil
	}
	return nil, fmt.Errorf("failed to resolve root in store %s", s.ID)
}

// ValueAt returns the store representation of value at the given index
func (s *Store) ValueAt(index uint64) (*string, error) {
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
