// +build integration

package test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"testing"
	"time"

	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/privacy/common"
	"github.com/provideplatform/privacy/store/providers/merkletree"
	provide "github.com/provideplatform/provide-go/api/ident"
	"github.com/provideplatform/provide-go/api/privacy"

	"github.com/consensys/gnark-crypto/ecc"
	kzgbls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/kzg"
	kzgbls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/kzg"
	kzgbls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr/kzg"
	kzgbn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	kzgbw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/kzg"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/frontend"

	vault "github.com/provideplatform/provide-go/api/vault"
	util "github.com/provideplatform/provide-go/common/util"

	newmerkletree "github.com/providenetwork/merkletree"
)

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

func createProcureToPayWorkflow(token *string, provingScheme string) ([]*privacy.Circuit, error) {
	circuits := make([]*privacy.Circuit, 0)

	circuit, err := privacy.CreateCircuit(
		*token,
		circuitParamsFactory(
			"BN254",
			"PO",
			"purchase_order",
			provingScheme,
			nil,
			nil,
		),
	)
	if err != nil {
		common.Log.Debugf("failed to deploy circuit; %s", err.Error())
		return nil, err
	}
	circuits = append(circuits, circuit)

	circuit, err = privacy.CreateCircuit(
		*token,
		circuitParamsFactory(
			"BN254",
			"SO",
			"sales_order",
			provingScheme,
			common.StringOrNil(circuit.NoteStoreID.String()),
			common.StringOrNil(circuit.NullifierStoreID.String()),
		),
	)
	if err != nil {
		common.Log.Debugf("failed to deploy circuit; %s", err.Error())
		return nil, err
	}
	circuits = append(circuits, circuit)

	circuit, err = privacy.CreateCircuit(
		*token,
		circuitParamsFactory(
			"BN254",
			"SN",
			"shipment_notification",
			provingScheme,
			common.StringOrNil(circuit.NoteStoreID.String()),
			common.StringOrNil(circuit.NullifierStoreID.String()),
		),
	)
	if err != nil {
		common.Log.Debugf("failed to deploy circuit; %s", err.Error())
		return nil, err
	}
	circuits = append(circuits, circuit)

	circuit, err = privacy.CreateCircuit(
		*token,
		circuitParamsFactory(
			"BN254",
			"GR",
			"goods_receipt",
			provingScheme,
			common.StringOrNil(circuit.NoteStoreID.String()),
			common.StringOrNil(circuit.NullifierStoreID.String()),
		),
	)
	if err != nil {
		common.Log.Debugf("failed to deploy circuit; %s", err.Error())
		return nil, err
	}
	circuits = append(circuits, circuit)

	circuit, err = privacy.CreateCircuit(
		*token,
		circuitParamsFactory(
			"BN254",
			"Invoice",
			"invoice",
			provingScheme,
			common.StringOrNil(circuit.NoteStoreID.String()),
			common.StringOrNil(circuit.NullifierStoreID.String()),
		),
	)
	if err != nil {
		common.Log.Debugf("failed to deploy circuit; %s", err.Error())
		return nil, err
	}
	circuits = append(circuits, circuit)

	return circuits, nil
}

func requireCircuits(token *string, circuits []*privacy.Circuit) error {
	startTime := time.Now()
	timer := time.NewTicker(requireCircuitTickerInterval)
	defer timer.Stop()

	deployStates := make([]bool, len(circuits))

	for {
		select {
		case <-timer.C:
			for i, circuit := range circuits {
				if !deployStates[i] {
					circuit, err := privacy.GetCircuitDetails(*token, circuit.ID.String())
					if err != nil {
						common.Log.Debugf("failed to fetch circuit details; %s", err.Error())
						break
					}
					if circuit.Status != nil && *circuit.Status == "provisioned" {
						common.Log.Debugf("provisioned workflow circuit: %s", circuit.ID)
						// if circuit.VerifierContract != nil {
						// if source, sourceOk := circuit.VerifierContract["source"].(string); sourceOk {
						// contractRaw, _ := json.MarshalIndent(source, "", "  ")
						// src := strings.TrimSpace(strings.ReplaceAll(source, "\\n", "\n"))
						// common.Log.Debugf("verifier contract: %s", src)
						// contractName := fmt.Sprintf("%s Verifier", *circuit.Name)
						// DeployContract([]byte(contractName), []byte(src))
						// }
						// }

						deployStates[i] = true
					}
				}
			}

			x := 0
			for i := range circuits {
				if deployStates[i] {
					x++
				}
			}
			if x == len(circuits) {
				return nil
			}
		default:
			if startTime.Add(requireCircuitTimeout).Before(time.Now()) {
				msg := fmt.Sprintf("failed to provision %d workstep circuit(s)", len(circuits))
				common.Log.Warning(msg)
				return errors.New(msg)
			} else {
				time.Sleep(requireCircuitSleepInterval)
			}
		}
	}
}

func testCircuitLifecycle(
	t *testing.T,
	tree merkletree.MerkleTree,
	hFunc hash.Hash,
	token *string,
	circuitIndex uint64,
	circuit *privacy.Circuit,
	prevCircuit *privacy.Circuit,
	payload map[string]interface{},
) error {
	raw, _ := json.Marshal(payload)

	hFunc.Reset()
	hFunc.Write(raw)

	var i big.Int

	// preimage is itself a digest due to the field element size limitation of the curve
	preImage := hFunc.Sum(nil)
	preImageString := i.SetBytes(preImage).String()

	hash, _ := mimc.Sum("seed", preImage)
	hashString := i.SetBytes(hash).String()

	witness := map[string]interface{}{
		"Document.Preimage": preImageString,
		"Document.Hash":     hashString,
	}

	t.Logf("proving witness Document.Hash: %s, Document.PreImage: %s", hashString, preImageString)

	proof, err := privacy.Prove(*token, circuit.ID.String(), map[string]interface{}{
		"witness": witness,
	})
	if err != nil {
		return fmt.Errorf("failed to generate proof; %s", err.Error())
	}

	note := map[string]interface{}{
		"proof": proof.Proof,
		"witness": map[string]interface{}{
			"Document.Hash": hashString,
		},
	}

	verification, err := privacy.Verify(*token, circuit.ID.String(), note)
	if err != nil {
		return fmt.Errorf("failed to verify proof; %s", err.Error())
	}

	t.Logf("%s proof/verification: %s / %v", *circuit.Name, *proof.Proof, verification.Result)

	// noteRaw, _ := json.Marshal(note)
	// index, h := tree.RawAdd(noteRaw)
	// t.Logf("added %s note to merkle tree, index/hash: %v / %v", *circuit.Name, index, h)

	// note state
	resp, err := privacy.GetNoteValue(*token, circuit.ID.String(), circuitIndex)
	if err != nil {
		return fmt.Errorf("failed to fetch note value; %s", err.Error())
	}

	noteValue, err := base64.StdEncoding.DecodeString(*resp.Value)
	if err != nil {
		return fmt.Errorf("failed to base64 decode note value; %s", err.Error())
	}
	t.Logf("retrieved %d-byte note value: %s at index %d; root: %s", len(*resp.Value), string(*resp.Value), circuitIndex, *resp.Root)

	if circuitIndex > 0 && prevCircuit != nil {
		nullifiedIndex := circuitIndex - 1

		resp, err := privacy.GetNoteValue(*token, prevCircuit.ID.String(), nullifiedIndex)
		if err != nil {
			return fmt.Errorf("failed to fetch nullified note value; %s", err.Error())
		}

		nullifiedNote, err := base64.StdEncoding.DecodeString(*resp.Value)
		if err != nil {
			return fmt.Errorf("failed to base64 decode nullified note value; %s", err.Error())
		}
		t.Logf("retrieved %d-byte nullified note value: %s; root: %s", len(noteValue), string(noteValue), *resp.Root)

		hFunc.Reset()
		hFunc.Write(nullifiedNote)
		nullifierTreeKey := hFunc.Sum(nil)
		t.Logf("nullifier key: %s", hex.EncodeToString(nullifierTreeKey))
		resp, err = privacy.GetNullifierValue(*token, prevCircuit.ID.String(), hex.EncodeToString(nullifierTreeKey))
		if err != nil {
			return fmt.Errorf("failed to fetch nullified note from nullifier tree; %s", err.Error())
		}

		nullifiedValue, err := base64.StdEncoding.DecodeString(*resp.Value)
		if err != nil {
			return fmt.Errorf("failed to base64 decode nullified note value; %s", err.Error())
		}
		t.Logf("retrieved %d-byte nullified note value: %s; root: %s", len(nullifiedValue), string(nullifiedValue), *resp.Root)
	}

	return nil
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
