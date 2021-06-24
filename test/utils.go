// +build integration

package test

import (
	"fmt"

	uuid "github.com/kthomas/go.uuid"
	provide "github.com/provideplatform/provide-go/api/ident"
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

	return token.Token, nil
}
