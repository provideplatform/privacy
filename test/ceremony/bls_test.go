// +build bls

package test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/provideplatform/privacy/ceremony/providers"
	"github.com/provideplatform/privacy/common"
	provide "github.com/provideplatform/provide-go/api/ident"
	"github.com/provideplatform/provide-go/api/vault"

	uuid "github.com/kthomas/go.uuid"
)

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

func vaultFactory(token, name, desc string) (*vault.Vault, error) {
	resp, err := vault.CreateVault(token, map[string]interface{}{
		"name":        name,
		"description": desc,
	})
	if err != nil {
		return nil, err
	}
	vlt := &vault.Vault{}
	respRaw, err := json.Marshal(resp)
	if err != nil {
		return nil, err
	}
	json.Unmarshal(respRaw, &vlt)
	return vlt, nil
}

func createKeyAndSignMessage(t *testing.T, token, vaultID *string, keyParams map[string]interface{}, msg string) (string, string, error) {
	resp, err := vault.CreateKey(
		*token,
		*vaultID,
		keyParams,
	)

	if err != nil {
		return "", "", fmt.Errorf("failed to create key error; %s", err.Error())
	}

	key := &vault.Key{}
	respRaw, err := json.Marshal(resp)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshall key data; %s", err.Error())
	}
	json.Unmarshal(respRaw, &key)
	t.Logf("key generated. %s", key.ID)

	t.Logf("public key received: %s", *key.PublicKey)

	sigResp, err := vault.SignMessage(
		*token,
		*vaultID,
		key.ID.String(),
		msg,
		nil,
	)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign message; %s", err.Error())
	}

	return *sigResp.Signature, *key.PublicKey, nil
}

func TestBlsCreateAndVerifyAggregateSignatures(t *testing.T) {
	var blsProvider providers.BLS

	testUserID, _ := uuid.NewV4()
	token, _ := userTokenFactory(testUserID)

	newVault, err := vaultFactory(*token, "bls key vault", "so many bls keys within")
	if err != nil {
		t.Errorf("failed to create default vaults for privacy instance; %s", err.Error())
		return
	}

	const numKeys = 10

	var keys [numKeys]string
	var msgs [numKeys]string

	blsProvider.Signatures = make([]string, 0)

	keyType := "asymmetric"
	keyUsage := "sign/verify"
	keySpec := "BLS12-381"
	keyName := "bls signature key"
	keyDesc := "fascinating description"

	for i := 0; i < numKeys; i++ {
		msgBytes, _ := common.RandomBytes(32)
		msg := hex.EncodeToString(msgBytes)
		msgs[i] = msg

		signature, key, err := createKeyAndSignMessage(
			t,
			token,
			common.StringOrNil(newVault.ID.String()),
			map[string]interface{}{
				"type":        keyType,
				"usage":       keyUsage,
				"spec":        keySpec,
				"name":        keyName,
				"description": keyDesc,
			},
			msg,
		)
		if err != nil {
			t.Errorf("failed to create key and sign message; %s", err.Error())
			return
		}

		keys[i] = key
		blsProvider.Signatures = append(blsProvider.Signatures, signature)
		t.Logf("signature returned: %s", signature)
	}

	aggResp, err := blsProvider.AggregateSignatures(token)
	if err != nil {
		t.Errorf("failed to aggregate signatures; %s", err.Error())
		return
	}

	t.Logf("response: %+v", *aggResp.AggregateSignature)

	verified, err := blsProvider.VerifyAggregateSignatures(token, map[string]interface{}{
		"messages":    msgs,
		"public_keys": keys,
		"signature":   *aggResp.AggregateSignature,
	})
	if err != nil {
		t.Errorf("failed to verify signature; %s", err.Error())
		return
	}

	if !verified {
		t.Error("invalid signature")
		return
	}

	t.Logf("signature verified: %v", verified)
}
