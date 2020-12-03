package providers

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"

	"github.com/provideapp/privacy/common"
)

// GnarkCircuitProvider interacts with the go-native gnark package
type GnarkCircuitProvider struct {
	ZKSnarkCircuitProvider
}

// InitGnarkCircuitProvider initializes and configures a new GnarkCircuitProvider instance
func InitGnarkCircuitProvider() *GnarkCircuitProvider {
	return &GnarkCircuitProvider{}
}

// Compile the circuit...
func Compile(circuit *frontend.Circuit) (interface{}, error) {
	curveID := gurvy.BN256 // FIXME

	r1cs, err := frontend.Compile(curveID, *circuit)
	if err != nil {
		common.Log.Warningf("failed to compile circuit to r1cs using gnark; %s", err.Error())
		return nil, err
	}

	common.Log.Debugf("compiled r1cs: %s", r1cs)

	// use circuit...
	return nil, nil
}

// ComputeWitness computes a witness for the given inputs
func ComputeWitness(artifacts map[string]interface{}, args ...interface{}) (interface{}, error) {
	return nil, nil
}

// ExportVerifier exports the verifier contract, if supported; returns nil if the `Verify` method should be called
func ExportVerifier(verifyingKey string) (interface{}, error) {
	return nil, nil
}

// GenerateProof generates a proof
func GenerateProof(circuit interface{}, witness, provingKey string) (interface{}, error) {
	return nil, nil
}

// Setup runs the trusted setup
func Setup(circuit interface{}) (interface{}, error) {
	return nil, nil
}
