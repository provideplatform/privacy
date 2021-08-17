package providers

import (
	"bytes"
	"fmt"
	"math/big"
	"reflect"
	"strconv"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/provideplatform/privacy/common"
	"github.com/provideplatform/privacy/zkp/lib/circuits/gnark"
)

// GnarkCircuitProvider interacts with the go-native gnark package
type GnarkCircuitProvider struct {
	curveID         ecc.ID
	provingSchemeID backend.ID
	circuitLibrary  map[string]interface{}
}

// InitGnarkCircuitProvider initializes and configures a new GnarkCircuitProvider instance
func InitGnarkCircuitProvider(curveID *string, provingScheme *string) *GnarkCircuitProvider {
	return &GnarkCircuitProvider{
		curveID:         common.GnarkCurveIDFactory(curveID),
		provingSchemeID: common.GnarkProvingSchemeFactory(provingScheme),
		circuitLibrary: map[string]interface{}{
			GnarkCircuitIdentifierCubic:                       &gnark.CubicCircuit{},
			GnarkCircuitIdentifierMimc:                        &gnark.MimcCircuit{},
			GnarkCircuitIdentifierBaselineRollup:              &gnark.BaselineRollupCircuit{},
			GnarkCircuitIdentifierPurchaseOrderCircuit:        &gnark.PurchaseOrderCircuit{},
			GnarkCircuitIdentifierSalesOrderCircuit:           &gnark.SalesOrderCircuit{},
			GnarkCircuitIdentifierShipmentNotificationCircuit: &gnark.ShipmentNotificationCircuit{},
			GnarkCircuitIdentifierGoodsReceiptCircuit:         &gnark.GoodsReceiptCircuit{},
			GnarkCircuitIdentifierInvoiceCircuit:              &gnark.InvoiceCircuit{},
			GnarkCircuitIdentifierProofHashCircuit:            &gnark.ProofHashCircuit{},
			GnarkCircuitIdentifierProofEddsaCircuit:           &gnark.ProofEddsaCircuit{},
		},
	}
}

// CircuitFactory returns a library circuit by name
func (p *GnarkCircuitProvider) CircuitFactory(identifier string) interface{} {
	id := strings.ToLower(identifier)
	circuit, circuitOk := p.circuitLibrary[id]
	if circuitOk {
		return circuit
	}

	return nil
}

// AddCircuit adds a gnark circuit to the library
func (p *GnarkCircuitProvider) AddCircuit(identifier string, circuit interface{}) error {
	c, cOk := circuit.(frontend.Circuit)
	if !cOk {
		return fmt.Errorf("invalid gnark circuit type %T; expected frontend.Circuit", circuit)
	}

	id := strings.ToLower(identifier)
	p.circuitLibrary[id] = c

	return nil
}

// allocateVariablesForCircuit allocates slices for the given circuit if needed
// inputs should be of the form map[string]interface{}{"CircuitMemberName_count": "3"}
func allocateVariablesForCircuit(circuit frontend.Circuit, inputs map[string]interface{}) error {
	witval := reflect.Indirect(reflect.ValueOf(circuit))

	for k := range inputs {
		if !strings.Contains(k, "_count") {
			continue
		}

		field := witval
		// handle variables in nested structs
		var f string
		k = strings.Split(k, "_")[0]
		for _, f = range strings.Split(k, ".") {
			field = field.FieldByName(strings.Split(f, "[")[0])
		}

		if field.Kind() == reflect.Slice && field.Len() == 0 {
			countString, countStringOk := inputs[k+"_count"]
			if !countStringOk {
				continue
			}
			countInt, countIntOk := new(big.Int).SetString(countString.(string), 10)
			if !countIntOk {
				continue
			}
			count := int(countInt.Int64())

			t := reflect.TypeOf(frontend.Variable{})
			slice := reflect.MakeSlice(reflect.SliceOf(t), count, count)
			field.Set(slice)
		}
	}

	return nil
}

// WitnessFactory generates a valid witness for the given circuit identifier, curve and named inputs
func (p *GnarkCircuitProvider) WitnessFactory(identifier string, curve string, inputs interface{}, isPublic bool) (interface{}, error) {
	w := p.CircuitFactory(identifier)
	if w == nil {
		return nil, fmt.Errorf("failed to serialize witness; %s circuit not resolved", identifier)
	}

	err := allocateVariablesForCircuit(w.(frontend.Circuit), inputs.(map[string]interface{}))
	if err != nil {
		return nil, fmt.Errorf("failed to serialize witness; %s", err.Error())
	}

	if witmap, witmapOk := inputs.(map[string]interface{}); witmapOk {
		witval := reflect.Indirect(reflect.ValueOf(w))
		for k := range witmap {
			if strings.Contains(k, "_count") {
				continue
			}

			field := witval
			// handle variables in nested structs
			var f string
			for _, f = range strings.Split(k, ".") {
				field = field.FieldByName(strings.Split(f, "[")[0])
			}
			if !field.CanSet() {
				return nil, fmt.Errorf("failed to serialize witness; field %s does not exist on %s circuit", k, identifier)
			}
			if (field.Kind() == reflect.Array || field.Kind() == reflect.Slice) && strings.Contains(f, "[") {
				indexStr := strings.Split(f, "[")[1]
				indexStr = strings.TrimRight(indexStr, "]")
				index, err := strconv.Atoi(indexStr)
				if err != nil {
					return nil, fmt.Errorf("failed to serialize witness; unable to extract index from witness on %s circuit", identifier)
				}
				if index >= field.Len() {
					return nil, fmt.Errorf("failed to serialize witness; invalid index %d for field %s on %s circuit", index, k, identifier)
				}
				field = field.Index(index)
			}

			v := frontend.Variable{}
			v.Assign(witmap[k])
			field.Set(reflect.ValueOf(v))
		}

		buf := new(bytes.Buffer)
		var errWrite error
		if isPublic {
			_, errWrite = witness.WritePublicTo(buf, common.GnarkCurveIDFactory(&curve), w.(frontend.Circuit))
		} else {
			_, errWrite = witness.WriteFullTo(buf, common.GnarkCurveIDFactory(&curve), w.(frontend.Circuit))
		}
		if errWrite != nil {
			common.Log.Warningf("failed to serialize witness for %s circuit; %s", identifier, errWrite.Error())
			return nil, errWrite
		}

		return w, nil
	}

	return nil, fmt.Errorf("failed to serialize witness for %s circuit", identifier)
}

func (p *GnarkCircuitProvider) decodeR1CS(encodedR1CS []byte) (frontend.CompiledConstraintSystem, error) {
	var decodedR1CS frontend.CompiledConstraintSystem

	switch p.provingSchemeID {
	case backend.GROTH16:
		decodedR1CS = groth16.NewCS(p.curveID)
	case backend.PLONK:
		decodedR1CS = plonk.NewCS(p.curveID)
	default:
		return nil, fmt.Errorf("invalid proving scheme in decodeR1CS")
	}

	_, err := decodedR1CS.ReadFrom(bytes.NewReader(encodedR1CS))
	if err != nil {
		common.Log.Warningf("unable to decode R1CS; %s", err.Error())
		return nil, err
	}

	return decodedR1CS, nil
}

func (p *GnarkCircuitProvider) decodeProvingKey(pk []byte) (interface{}, error) {
	var n int64
	var err error
	var provingKey interface{}

	switch p.provingSchemeID {
	case backend.GROTH16:
		provingKey = groth16.NewProvingKey(p.curveID)
		n, err = provingKey.(groth16.ProvingKey).ReadFrom(bytes.NewReader(pk))
		if err != nil {
			return nil, fmt.Errorf("unable to decode proving key; %s", err.Error())
		}
	case backend.PLONK:
		provingKey = plonk.NewProvingKey(p.curveID)
		n, err = provingKey.(plonk.ProvingKey).ReadFrom(bytes.NewReader(pk))
		if err != nil {
			return nil, fmt.Errorf("unable to decode proving key; %s", err.Error())
		}
	default:
		return nil, fmt.Errorf("invalid proving scheme in decodeProvingKey")
	}

	common.Log.Debugf("read %d bytes during attempted proving key deserialization", n)

	return provingKey, nil
}

func (p *GnarkCircuitProvider) decodeVerifyingKey(vk []byte) (interface{}, error) {
	var n int64
	var err error
	var verifyingKey interface{}

	switch p.provingSchemeID {
	case backend.GROTH16:
		verifyingKey = groth16.NewVerifyingKey(p.curveID)
		n, err = verifyingKey.(groth16.VerifyingKey).ReadFrom(bytes.NewReader(vk))
		if err != nil {
			return nil, fmt.Errorf("unable to decode verifying key; %s", err.Error())
		}
	case backend.PLONK:
		verifyingKey = plonk.NewVerifyingKey(p.curveID)
		n, err = verifyingKey.(plonk.VerifyingKey).ReadFrom(bytes.NewReader(vk))
		if err != nil {
			return nil, fmt.Errorf("unable to decode verifying key; %s", err.Error())
		}
	default:
		return nil, fmt.Errorf("invalid proving scheme in decodeVerifyingKeyy")
	}

	common.Log.Debugf("read %d bytes during attempted verifying key deserialization", n)

	return verifyingKey, nil
}

func (p *GnarkCircuitProvider) decodeProof(proof []byte) (interface{}, error) {
	var err error
	var prf interface{}

	switch p.provingSchemeID {
	case backend.GROTH16:
		prf = groth16.NewProof(p.curveID)
		_, err = prf.(groth16.Proof).ReadFrom(bytes.NewReader(proof))
	case backend.PLONK:
		if p.curveID != ecc.BN254 {
			return nil, fmt.Errorf("unsupported plonk curve")
		}
		prf = plonk.NewProof(p.curveID)
		_, err = prf.(plonk.Proof).ReadFrom(bytes.NewReader(proof))
	default:
		return nil, fmt.Errorf("invalid proving scheme in decodeR1CS")
	}

	if err != nil {
		common.Log.Warningf("unable to decode proof; %s", err.Error())
		return nil, err
	}

	return prf, nil
}

// Compile the circuit...
func (p *GnarkCircuitProvider) Compile(argv ...interface{}) (interface{}, error) {
	circuit := argv[0].(frontend.Circuit)
	if len(argv) > 1 {
		inputs, ok := argv[1].(map[string]interface{})

		if ok {
			err := allocateVariablesForCircuit(circuit, inputs)
			if err != nil {
				common.Log.Warningf("failed to compile circuit to r1cs using gnark; %s", err.Error())
				return nil, err
			}
		}
	}
	r1cs, err := frontend.Compile(p.curveID, p.provingSchemeID, circuit)
	if err != nil {
		common.Log.Warningf("failed to compile circuit to r1cs using gnark; %s", err.Error())
		return nil, err
	}

	return r1cs, err
}

// ComputeWitness computes a witness for the given inputs
func (p *GnarkCircuitProvider) ComputeWitness(artifacts interface{}, argv ...interface{}) (interface{}, error) {
	return nil, fmt.Errorf("gnark does not implement ComputeWitness()")
}

// ExportVerifier exports the verifier contract, if supported; returns nil if the `Verify` method should be called
func (p *GnarkCircuitProvider) ExportVerifier(verifyingKey string) (interface{}, error) {
	if p.provingSchemeID != backend.GROTH16 {
		return nil, fmt.Errorf("export verifier not supported for proving scheme %s", p.provingSchemeID.String())
	}
	vk, err := p.decodeVerifyingKey([]byte(verifyingKey))
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	err = vk.(groth16.VerifyingKey).ExportSolidity(buf)
	if err != nil {
		common.Log.Warningf("failed to export verifier contract for using gnark; %s", err.Error())
		return nil, err
	}

	return buf.Bytes(), nil
}

// GenerateProof generates a proof
func (p *GnarkCircuitProvider) GenerateProof(circuit interface{}, witness interface{}, provingKey string) (interface{}, error) {
	return nil, fmt.Errorf("gnark does not implement GenerateProof()")
}

// Setup runs the circuit setup; if srs is non-nil, it is intended to be
// the input from a MPC process
func (p *GnarkCircuitProvider) Setup(circuit interface{}, srs []byte) (interface{}, interface{}, error) {
	r1cs, err := p.decodeR1CS(circuit.([]byte))
	if err != nil {
		return nil, nil, err
	}

	switch p.provingSchemeID {
	case backend.GROTH16:
		return groth16.Setup(r1cs)
	case backend.PLONK:
		kzgsrs := kzg.NewSRS(p.curveID)
		kzgsrs.ReadFrom(bytes.NewReader(srs))
		return plonk.Setup(r1cs, kzgsrs)
	}

	return nil, nil, fmt.Errorf("invalid proving scheme for Setup")
}

// Prove generates a proof
func (p *GnarkCircuitProvider) Prove(circuit, provingKey []byte, witness interface{}, srs []byte) (interface{}, error) {
	var err error

	r1cs, err := p.decodeR1CS(circuit)
	if err != nil {
		return nil, err
	}

	pk, err := p.decodeProvingKey(provingKey)
	if err != nil {
		return nil, err
	}

	switch p.provingSchemeID {
	case backend.GROTH16:
		return groth16.Prove(r1cs, pk.(groth16.ProvingKey), witness.(frontend.Circuit))
	case backend.PLONK:
		kzgsrs := kzg.NewSRS(p.curveID)
		kzgsrs.ReadFrom(bytes.NewReader(srs))
		err := pk.(plonk.ProvingKey).InitKZG(kzgsrs)
		if err != nil {
			return nil, err
		}
		return plonk.Prove(r1cs, pk.(plonk.ProvingKey), witness.(frontend.Circuit))
	}

	return nil, fmt.Errorf("invalid proving scheme for Prove")
}

// Verify the given proof and witness
func (p *GnarkCircuitProvider) Verify(proof, verifyingKey []byte, witness interface{}, srs []byte) error {
	var err error

	prf, err := p.decodeProof(proof)
	if err != nil {
		return err
	}

	vk, err := p.decodeVerifyingKey(verifyingKey)
	if err != nil {
		return err
	}

	switch p.provingSchemeID {
	case backend.GROTH16:
		return groth16.Verify(prf.(groth16.Proof), vk.(groth16.VerifyingKey), witness.(frontend.Circuit))
	case backend.PLONK:
		kzgsrs := kzg.NewSRS(p.curveID)
		kzgsrs.ReadFrom(bytes.NewReader(srs))
		err := vk.(plonk.VerifyingKey).InitKZG(kzgsrs)
		if err != nil {
			return err
		}
		return plonk.Verify(prf.(plonk.Proof), vk.(plonk.VerifyingKey), witness.(frontend.Circuit))
	}

	return fmt.Errorf("invalid proving scheme for Verify")
}
