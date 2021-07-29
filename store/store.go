package store

import (
	"fmt"

	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/privacy/common"
	"github.com/provideplatform/privacy/state"
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

func (s *Store) storeProviderFactory() (proofstorage.StoreProvider, error) {
	if s.Provider == nil {
		return nil, fmt.Errorf("failed to initialize provider in store %s; no provider defined", s.ID)
	}

	switch *s.Provider {
	case proofstorage.StoreProviderDenseMerkleTree:
		return proofstorage.InitDenseMerkleTreeStoreProvider(s.ID, s.Curve)
	case proofstorage.StoreProviderSparseMerkleTree:
		return proofstorage.InitSparseMerkleTreeStoreProvider(s.ID, s.Curve)
	default:
		return nil, fmt.Errorf("failed to initialize store provider; unknown provider: %s", *s.Provider)
	}

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

// Contains returns true if the given value exists in the store
func (s *Store) Contains(val string) bool {
	provider, err := s.storeProviderFactory()
	if err != nil {
		common.Log.Warningf("failed to check value existence in store %s; %s", s.ID, err.Error())
		return false
	}

	return provider.Contains(val)
}

// Insert a value into the state of the configured storage provider
func (s *Store) Insert(val string) (root []byte, err error) {
	provider, err := s.storeProviderFactory()
	if err != nil {
		return nil, fmt.Errorf("failed to insert value in store %s; %s", s.ID, err.Error())
	}

	root, err = provider.Insert(val)
	if err != nil {
		return nil, fmt.Errorf("failed to insert value in store %s; %s", s.ID, err.Error())
	}
	return root, nil
}

// Height returns the height of the underlying store
func (s *Store) Height() int {
	provider, err := s.storeProviderFactory()
	if err != nil {
		common.Log.Warningf("failed to get height in store %s; %s", s.ID, err.Error())
		return 0
	}

	return provider.Height()
}

// Root returns the store root
func (s *Store) Root() (*string, error) {
	provider, err := s.storeProviderFactory()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve root in store %s; %s", s.ID, err.Error())
	}

	root, err := provider.Root()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve root in store %s; %s", s.ID, err.Error())
	}
	return root, nil

}

// State returns the state at the given epoch
func (s *Store) StateAt(epoch uint64) (*state.State, error) {
	claims := make([]*state.StateClaim, 0)

	// FIXME
	root, err := s.Root() // impl RootAt()
	if err != nil {
		return nil, err
	}

	claims = append(claims, &state.StateClaim{
		Cardinality: uint64(1),
		Path:        []string{},
		Root:        root,
		Values:      []string{},
	})

	// FIXME!!!
	state := &state.State{
		// ID        uuid.UUID  `json:"id"`
		// AccountID *uuid.UUID `json:"account_id"`
		// Address   *string    `json:"address"` // FIXME... int type this address
		Epoch:       epoch,
		StateClaims: claims,
	}

	return state, nil
}

// ValueAt returns the store representation for the given key
func (s *Store) ValueAt(key []byte) ([]byte, error) {
	provider, err := s.storeProviderFactory()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve value for key %s in store %s; %s", string(key), s.ID, err.Error())
	}

	val, err := provider.Get(key)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve value for key %s in store %s; %s", string(key), s.ID, err.Error())
	}
	return val, nil

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
