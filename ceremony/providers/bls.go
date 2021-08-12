package providers

import (
	"github.com/provideplatform/provide-go/api/vault"
)

type BLS struct {
	Signatures []string
}

func (b *BLS) AggregateSignatures(token *string) (*vault.BLSAggregateRequestResponse, error) {
	resp, err := vault.AggregateSignatures(token, map[string]interface{}{
		"signatures": b.Signatures,
	})
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (b *BLS) VerifyAggregateSignatures(token *string, params map[string]interface{}) (bool, error) {
	resp, err := vault.VerifyAggregateSignatures(token, params)
	if err != nil {
		return false, err
	}

	return resp.Verified, nil
}
