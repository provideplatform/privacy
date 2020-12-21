package providers

import (
	"fmt"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/r1cs"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
	"github.com/fxamacker/cbor/v2"
	"github.com/provideapp/privacy/common"
)

const defaultCurveID = gurvy.BN256

// GnarkCircuitProvider interacts with the go-native gnark package
type GnarkCircuitProvider struct{}

// InitGnarkCircuitProvider initializes and configures a new GnarkCircuitProvider instance
func InitGnarkCircuitProvider() *GnarkCircuitProvider {
	return &GnarkCircuitProvider{}
}

// Compile the circuit...
func (p *GnarkCircuitProvider) Compile(argv ...interface{}) (interface{}, error) {
	var curveID gurvy.ID
	var circuit frontend.Circuit

	if len(argv) == 2 {
		curveID = argv[0].(gurvy.ID)
		circuit = argv[1].(frontend.Circuit)
	} else if len(argv) == 1 {
		curveID = defaultCurveID
		circuit = argv[0].(frontend.Circuit)
	}

	r1cs, err := frontend.Compile(curveID, circuit)
	if err != nil {
		common.Log.Warningf("failed to compile circuit to r1cs using gnark; %s", err.Error())
		return nil, err
	}

	common.Log.Debugf("compiled r1cs circuit: %s", r1cs)
	return r1cs, err
}

// ComputeWitness computes a witness for the given inputs
func (p *GnarkCircuitProvider) ComputeWitness(artifacts map[string]interface{}, argv ...interface{}) (interface{}, error) {
	return nil, fmt.Errorf("gnark does not not implement ComputeWitness()")
}

// ExportVerifier exports the verifier contract, if supported; returns nil if the `Verify` method should be called
func (p *GnarkCircuitProvider) ExportVerifier(verifyingKey string) (interface{}, error) {
	return nil, fmt.Errorf("gnark does not not implement ExportVerifier()")
}

// GenerateProof generates a proof
func (p *GnarkCircuitProvider) GenerateProof(circuit interface{}, witness, provingKey string) (interface{}, error) {
	return nil, fmt.Errorf("gnark does not not implement GenerateProof()")
}

// Setup runs the trusted setup
func (p *GnarkCircuitProvider) Setup(circuit interface{}) (interface{}, interface{}) {
	return groth16.Setup(circuit.(r1cs.R1CS))
}

// Prove generates a proof
func (p *GnarkCircuitProvider) Prove(circuit, provingKey []byte, witness string) (interface{}, error) {
	var err error

	var circuitR1CS r1cs.R1CS
	err = cbor.Unmarshal(circuit, &circuitR1CS)
	if err != nil {
		return nil, err
	}

	var pk groth16.ProvingKey
	err = cbor.Unmarshal(provingKey, &pk)
	if err != nil {
		return nil, err
	}

	return groth16.Prove(circuitR1CS, pk, witness)
}

// Verify the given proof and witness
func (p *GnarkCircuitProvider) Verify(proof, verifyingKey []byte, witness string) error {
	var err error

	var prf groth16.Proof
	err = cbor.Unmarshal(proof, &prf)
	if err != nil {
		return err
	}

	var vk groth16.VerifyingKey
	err = cbor.Unmarshal(verifyingKey, &vk)
	if err != nil {
		return err
	}
	return groth16.Verify(prf, vk, witness)
}
