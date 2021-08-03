// +build integration-deprecated

package test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"time"

	uuid "github.com/kthomas/go.uuid"
	provide "github.com/provideplatform/provide-go/api/ident"

	"github.com/consensys/gnark-crypto/ecc"
	kzgbls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/kzg"
	kzgbls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/kzg"
	kzgbls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr/kzg"
	kzgbn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
	kzgbw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/kzg"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/frontend"

	vault "github.com/provideplatform/provide-go/api/vault"
	util "github.com/provideplatform/provide-go/common/util"

	newmerkletree "github.com/providenetwork/merkletree"
)

const requireCircuitTimeout = time.Minute * 5
const requireCircuitTickerInterval = time.Second * 5
const requireCircuitSleepInterval = time.Millisecond * 500

func getUserToken(email, password string) (*provide.Token, error) {
	authResponse, err := provide.Authenticate(email, password)
	if err != nil {
		return nil, fmt.Errorf("error authenticating user; %s", err.Error())
	}

	return authResponse.Token, nil
}

func getUserTokenByTestId(testID uuid.UUID) (*provide.Token, error) {
	user, _ := userFactory(
		"privacy"+testID.String(),
		"user "+testID.String(),
		"privacy.user"+testID.String()+"@email.com",
		"secretpassword!!!",
	)
	authResponse, err := provide.Authenticate(user.Email, "secretpassword!!!")
	if err != nil {
		return nil, fmt.Errorf("error authenticating user. Error: %s", err.Error())
	}

	return authResponse.Token, nil
}

func userFactory(firstName, lastName, email, password string) (*provide.User, error) {
	return provide.CreateUser("", map[string]interface{}{
		"first_name": firstName,
		"last_name":  lastName,
		"email":      email,
		"password":   password,
	})
}

func userTokenFactory(testID uuid.UUID) (*string, error) {
	token, err := getUserTokenByTestId(testID)
	if err != nil {
		return nil, fmt.Errorf("error generating token; %s", err.Error())
	}

	return token.AccessToken, nil
}

// getKzgSchemeForTest resolves the Kate-Zaverucha-Goldberg (KZG) constant-sized polynomial
// commitment scheme for the given r1cs, using constant (insecure) alpha
func getKzgSchemeForTest(r1cs frontend.CompiledConstraintSystem) (kzg.SRS, error) {
	nbConstraints := r1cs.GetNbConstraints()
	internal, secret, public := r1cs.GetNbVariables()
	nbVariables := internal + secret + public

	var s int
	var size uint64
	if nbConstraints > nbVariables {
		s = nbConstraints
	} else {
		s = nbVariables
	}

	size = ecc.NextPowerOfTwo(uint64(s))
	alpha := new(big.Int).SetUint64(42)

	switch r1cs.CurveID() {
	case ecc.BN254:
		return kzgbn254.NewSRS(size+3, alpha)
	case ecc.BLS12_381:
		return kzgbls12381.NewSRS(size+3, alpha)
	case ecc.BLS12_377:
		return kzgbls12377.NewSRS(size+3, alpha)
	case ecc.BW6_761:
		return kzgbw6761.NewSRS(size*2+3, alpha)
	case ecc.BLS24_315:
		return kzgbls24315.NewSRS(size+3, alpha)
	default:
		return nil, fmt.Errorf("invalid curve id")
	}
}

// generateSRSForTest generates a KZG SRS for testing and will be replaced with proper MPC ceremony
func generateSRSForTest(r1cs frontend.CompiledConstraintSystem) []byte {
	srs, err := getKzgSchemeForTest(r1cs)
	if err != nil {
		return nil
	}
	buf := new(bytes.Buffer)
	_, err = srs.WriteTo(buf)
	if err != nil {
		return nil
	}
	return buf.Bytes()
}

func circuitParamsFactory(curve, name, identifier, provingScheme string, noteStoreID, nullifierStoreID *string) map[string]interface{} {
	params := map[string]interface{}{
		"curve":          curve,
		"identifier":     identifier,
		"name":           name,
		"provider":       "gnark",
		"proving_scheme": provingScheme,
	}

	if noteStoreID != nil {
		params["note_store_id"] = noteStoreID
	}

	if nullifierStoreID != nil {
		params["nullifier_store_id"] = nullifierStoreID
	}

	return params
}

func encryptNote(vaultID, keyID, note string) ([]byte, error) {
	encryptresp, err := vault.Encrypt(
		util.DefaultVaultAccessJWT,
		vaultID,
		keyID,
		note,
	)
	if err != nil {
		return nil, err
	}

	data, err := hex.DecodeString(encryptresp.Data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

type treeContent struct {
	hash  hash.Hash
	value []byte
}

// CalculateHash returns the hash of the underlying value using the configured hash function
func (tc *treeContent) CalculateHash() ([]byte, error) {
	if tc.hash == nil {
		return nil, errors.New("tree content requires configured hash function")
	}
	tc.hash.Reset()
	tc.hash.Write(tc.value)
	return tc.hash.Sum(nil), nil
}

// Equals returns true if the given content matches the underlying value
func (tc *treeContent) Equals(other newmerkletree.Content) (bool, error) {
	h0, err := tc.CalculateHash()
	if err != nil {
		return false, err
	}

	h1, err := other.CalculateHash()
	if err != nil {
		return false, err
	}

	return bytes.Equal(h0, h1), nil
}

func contentFactory(val []byte, hash hash.Hash) *treeContent {
	return &treeContent{
		hash:  hash,
		value: val,
	}
}
