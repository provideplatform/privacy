package providers

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/provideapp/privacy/common"
	"github.com/provideapp/privacy/zkp/lib/circuits/gnark"
)

// GnarkCircuitProvider interacts with the go-native gnark package
type GnarkCircuitProvider struct {
	curveID ecc.ID
}

// InitGnarkCircuitProvider initializes and configures a new GnarkCircuitProvider instance
func InitGnarkCircuitProvider(curveID *string) *GnarkCircuitProvider {
	return &GnarkCircuitProvider{
		curveID: curveIDFactory(curveID),
	}
}

// CircuitFactory returns a library circuit by name
func (p *GnarkCircuitProvider) CircuitFactory(identifier string) interface{} {
	switch identifier {
	case GnarkCircuitIdentifierCubic:
		return &gnark.CubicCircuit{}
	case GnarkCircuitIdentifierMimc:
		return &gnark.MimcCircuit{}
	case GnarkCircuitIdentifierBaselineRollup:
		return &gnark.BaselineRollupCircuit{}
	case GnarkCircuitIdentifierPurchaseOrderCircuit:
		return &gnark.PurchaseOrderCircuit{}
	case GnarkCircuitIdentifierSalesOrderCircuit:
		return &gnark.SalesOrderCircuit{}
	case GnarkCircuitIdentifierShipmentNotificationCircuit:
		return &gnark.ShipmentNotificationCircuit{}
	case GnarkCircuitIdentifierGoodsReceiptCircuit:
		return &gnark.GoodsReceiptCircuit{}
	case GnarkCircuitIdentifierInvoiceCircuit:
		return &gnark.InvoiceCircuit{}
	default:
		return nil
	}
}

// WitnessFactory generates a valid witness for the given circuit identifier, curve and named inputs
func (p *GnarkCircuitProvider) WitnessFactory(identifier string, curve string, inputs interface{}) (interface{}, error) {
	w := p.CircuitFactory(identifier)
	if w == nil {
		return nil, fmt.Errorf("failed to serialize witness; %s circuit not resolved", identifier)
	}

	var buf *bytes.Buffer

	if witmap, witmapOk := inputs.(map[string]interface{}); witmapOk {
		witval := reflect.Indirect(reflect.ValueOf(w))
		for k := range witmap {
			field := witval
			// handle variables in nested structs
			for _, f := range strings.Split(k, ".") {
				field = field.FieldByName(f)
			}
			if !field.CanSet() {
				return nil, fmt.Errorf("failed to serialize witness; field %s does not exist on %s circuit", k, identifier)
			}

			v := frontend.Variable{}
			v.Assign(witmap[k])
			field.Set(reflect.ValueOf(v))
		}

		buf = new(bytes.Buffer)
		_, err := witness.WriteFullTo(buf, curveIDFactory(&curve), w.(frontend.Circuit))
		if err != nil {
			common.Log.Warningf("failed to serialize witness for %s circuit; %s", identifier, err.Error())
			return nil, err
		}

		return w, nil
	}

	return nil, fmt.Errorf("failed to serialize witness for %s circuit", identifier)
}

func curveIDFactory(curveID *string) ecc.ID {
	if curveID == nil {
		common.Log.Warning("no curve id provided")
		return ecc.UNKNOWN
	}

	switch strings.ToLower(*curveID) {
	case ecc.BLS12_377.String():
		return ecc.BLS12_377
	case ecc.BLS12_381.String():
		return ecc.BLS12_381
	case ecc.BN254.String():
		return ecc.BN254
	case ecc.BW6_761.String():
		return ecc.BW6_761
	default:
		common.Log.Warningf("failed to resolve elliptic curve; unknown curve: %s", *curveID)

	}

	return ecc.UNKNOWN
}

func (p *GnarkCircuitProvider) decodeR1CS(encodedR1CS []byte) (frontend.CompiledConstraintSystem, error) {
	decodedR1CS := groth16.NewCS(p.curveID)
	_, err := decodedR1CS.ReadFrom(bytes.NewReader(encodedR1CS))
	if err != nil {
		common.Log.Warningf("unable to decode R1CS; %s", err.Error())
		return nil, err
	}

	return decodedR1CS, nil
}

func (p *GnarkCircuitProvider) decodeProvingKey(pk []byte) (groth16.ProvingKey, error) {
	provingKey := groth16.NewProvingKey(p.curveID)
	n, err := provingKey.ReadFrom(bytes.NewReader(pk))
	common.Log.Debugf("read %d bytes during attempted proving key deserialization", n)
	if err != nil {
		return nil, fmt.Errorf("unable to decode proving key; %s", err.Error())
	}

	return provingKey, nil
}

func (p *GnarkCircuitProvider) decodeVerifyingKey(vk []byte) (groth16.VerifyingKey, error) {
	verifyingKey := groth16.NewVerifyingKey(p.curveID)
	n, err := verifyingKey.ReadFrom(bytes.NewReader(vk))
	common.Log.Debugf("read %d bytes during attempted verifying key deserialization", n)
	if err != nil {
		return nil, fmt.Errorf("unable to decode verifying key; %s", err.Error())
	}

	return verifyingKey, nil
}

func (p *GnarkCircuitProvider) decodeProof(proof []byte) (groth16.Proof, error) {
	prf := groth16.NewProof(p.curveID)
	_, err := prf.ReadFrom(bytes.NewReader(proof))
	if err != nil {
		common.Log.Warningf("unable to decode proof; %s", err.Error()) // HACK?
		// return nil, fmt.Errorf("unable to decode proof; %s", err.Error())
	}

	return prf, nil
}

// Compile the circuit...
func (p *GnarkCircuitProvider) Compile(argv ...interface{}) (interface{}, error) {
	circuit := argv[0].(frontend.Circuit)
	r1cs, err := frontend.Compile(p.curveID, backend.GROTH16, circuit)
	if err != nil {
		common.Log.Warningf("failed to compile circuit to r1cs using gnark; %s", err.Error())
		return nil, err
	}

	return r1cs, err
}

// ComputeWitness computes a witness for the given inputs
func (p *GnarkCircuitProvider) ComputeWitness(artifacts interface{}, argv ...interface{}) (interface{}, error) {
	return nil, fmt.Errorf("gnark does not not implement ComputeWitness()")
}

// ExportVerifier exports the verifier contract, if supported; returns nil if the `Verify` method should be called
func (p *GnarkCircuitProvider) ExportVerifier(verifyingKey string) (interface{}, error) {
	vk, err := p.decodeVerifyingKey([]byte(verifyingKey))
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	err = vk.ExportSolidity(buf)
	if err != nil {
		common.Log.Warningf("failed to export verifier contract for using gnark; %s", err.Error())
		return nil, err
	}

	return buf.Bytes(), nil
}

// GenerateProof generates a proof
func (p *GnarkCircuitProvider) GenerateProof(circuit interface{}, witness interface{}, provingKey string) (interface{}, error) {
	return nil, fmt.Errorf("gnark does not not implement GenerateProof()")
}

// Setup runs the trusted setup
func (p *GnarkCircuitProvider) Setup(circuit interface{}) (interface{}, interface{}, error) {
	r1cs, err := p.decodeR1CS(circuit.([]byte))
	if err != nil {
		return nil, nil, err
	}

	return groth16.Setup(r1cs)
}

// Prove generates a proof
func (p *GnarkCircuitProvider) Prove(circuit, provingKey []byte, witness interface{}) (interface{}, error) {
	var err error

	r1cs, err := p.decodeR1CS(circuit)
	if err != nil {
		return nil, err
	}

	pk, err := p.decodeProvingKey(provingKey)
	if err != nil {
		return nil, err
	}

	return groth16.Prove(r1cs, pk, witness.(frontend.Circuit))
}

// Verify the given proof and witness
func (p *GnarkCircuitProvider) Verify(proof, verifyingKey []byte, witness interface{}) error {
	var err error

	prf, err := p.decodeProof(proof)
	if err != nil {
		return err
	}

	vk, err := p.decodeVerifyingKey(verifyingKey)
	if err != nil {
		return err
	}

	return groth16.Verify(prf, vk, witness.(frontend.Circuit))
}
