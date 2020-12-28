package providers

import (
	"bytes"
	"fmt"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/r1cs"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
	"github.com/provideapp/privacy/common"
)

const defaultCurveID = gurvy.BN256

// GnarkCircuitProvider interacts with the go-native gnark package
type GnarkCircuitProvider struct{}

// InitGnarkCircuitProvider initializes and configures a new GnarkCircuitProvider instance
func InitGnarkCircuitProvider() *GnarkCircuitProvider {
	return &GnarkCircuitProvider{}
}

func (p *GnarkCircuitProvider) decodeR1CS(curveID gurvy.ID, encodedR1CS []byte) (r1cs.R1CS, error) {
	decodedR1CS := r1cs.New(curveID)
	_, err := decodedR1CS.ReadFrom(bytes.NewReader(encodedR1CS))
	if err != nil {
		common.Log.Warningf("unable to decode R1CS; failed to decode curve id; %s", err.Error())
		return nil, err
	}

	return decodedR1CS, nil
}

func (p *GnarkCircuitProvider) decodeProvingKey(curveID gurvy.ID, pk []byte) (groth16.ProvingKey, error) {
	provingKey := groth16.NewProvingKey(curveID)
	_, err := provingKey.ReadFrom(bytes.NewReader(pk))
	if err != nil {
		return nil, fmt.Errorf("unable to decode proving key; %s", err.Error())
	}

	return provingKey, nil
}

func (p *GnarkCircuitProvider) decodeVerifyingKey(curveID gurvy.ID, vk []byte) (groth16.VerifyingKey, error) {
	verifyingKey := groth16.NewVerifyingKey(curveID)
	_, err := verifyingKey.ReadFrom(bytes.NewReader(vk))
	if err != nil {
		return nil, fmt.Errorf("unable to decode verifying key; %s", err.Error())
	}

	return verifyingKey, nil
}

func (p *GnarkCircuitProvider) decodeProof(curveID gurvy.ID, proof []byte) (groth16.Proof, error) {
	prf := groth16.NewProof(curveID)
	_, err := prf.ReadFrom(bytes.NewReader(proof))
	if err != nil {
		return nil, fmt.Errorf("unable to decode proof; %s", err.Error())
	}

	return prf, nil
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
func (p *GnarkCircuitProvider) Setup(circuit interface{}) (interface{}, interface{}, error) {
	return groth16.Setup(circuit.(r1cs.R1CS))
}

// Prove generates a proof
func (p *GnarkCircuitProvider) Prove(circuit, provingKey []byte, witness string) (interface{}, error) {
	var err error

	r1cs, err := p.decodeR1CS(defaultCurveID, circuit)
	if err != nil {
		return nil, err
	}

	pk, err := p.decodeProvingKey(defaultCurveID, provingKey)
	if err != nil {
		return nil, err
	}
	common.Log.Debugf("proving Key %s", pk)

	return groth16.Prove(r1cs, pk, witness)
}

// Verify the given proof and witness
func (p *GnarkCircuitProvider) Verify(proof, verifyingKey []byte, witness string) error {
	var err error

	prf, err := p.decodeProof(defaultCurveID, proof)
	if err != nil {
		return err
	}

	vk, err := p.decodeVerifyingKey(defaultCurveID, verifyingKey)
	if err != nil {
		return err
	}

	return groth16.Verify(prf, vk, witness)
}
