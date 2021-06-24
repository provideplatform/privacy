package providers

import (
	"bytes"
	"fmt"
	"math/big"
	"math/rand"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/provideplatform/privacy/common"
	"github.com/provideplatform/privacy/zkp/lib/circuits/gnark"

	kzgbls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/kzg"
	kzgbls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/kzg"
	kzgbls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr/kzg"
	kzgbn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
	kzgbw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/kzg"
)

const providersProvingSchemeGroth16 = "groth16"
const providersProvingSchemePlonk = "plonk"

// GnarkCircuitProvider interacts with the go-native gnark package
type GnarkCircuitProvider struct {
	curveID         ecc.ID
	provingSchemeID backend.ID
}

// InitGnarkCircuitProvider initializes and configures a new GnarkCircuitProvider instance
func InitGnarkCircuitProvider(curveID *string, provingScheme *string) *GnarkCircuitProvider {
	return &GnarkCircuitProvider{
		curveID:         curveIDFactory(curveID),
		provingSchemeID: provingSchemeFactory(provingScheme),
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
	case GnarkCircuitIdentifierProofHashCircuit:
		return &gnark.ProofHashCircuit{}
	case GnarkCircuitIdentifierProofEddsaCircuit:
		return &gnark.ProofEddsaCircuit{}
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
			var f string
			for _, f = range strings.Split(k, ".") {
				field = field.FieldByName(strings.Split(f, "[")[0])
			}
			if !field.CanSet() {
				return nil, fmt.Errorf("failed to serialize witness; field %s does not exist on %s circuit", k, identifier)
			}
			if field.Kind() == reflect.Array && strings.Contains(f, "[") {
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
	case ecc.BLS24_315.String():
		return ecc.BLS24_315
	default:
		common.Log.Warningf("failed to resolve elliptic curve; unknown curve: %s", *curveID)

	}

	return ecc.UNKNOWN
}

func provingSchemeFactory(provingScheme *string) backend.ID {
	if provingScheme == nil {
		common.Log.Warning("no proving scheme provided")
		return backend.UNKNOWN
	}

	switch strings.ToLower(*provingScheme) {
	case providersProvingSchemeGroth16:
		return backend.GROTH16
	case providersProvingSchemePlonk:
		return backend.PLONK
	default:
		common.Log.Warningf("failed to resolve proving scheme; unknown scheme: %s", *provingScheme)
	}

	return backend.UNKNOWN
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

	case backend.PLONK:
		provingKey = plonk.NewProvingKey(p.curveID)
		n, err = provingKey.(plonk.ProvingKey).ReadFrom(bytes.NewReader(pk))
	default:
		return nil, fmt.Errorf("invalid proving scheme in decodeProvingKey")
	}

	common.Log.Debugf("read %d bytes during attempted proving key deserialization", n)
	if err != nil {
		return nil, fmt.Errorf("unable to decode proving key; %s", err.Error())
	}

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

	case backend.PLONK:
		verifyingKey = plonk.NewVerifyingKey(p.curveID)
		n, err = verifyingKey.(plonk.VerifyingKey).ReadFrom(bytes.NewReader(vk))
	default:
		return nil, fmt.Errorf("invalid proving scheme in decodeVerifyingKeyy")
	}

	// verifyingKey := groth16.NewVerifyingKey(p.curveID)
	// n, err := verifyingKey.ReadFrom(bytes.NewReader(vk))
	common.Log.Debugf("read %d bytes during attempted verifying key deserialization", n)
	if err != nil {
		return nil, fmt.Errorf("unable to decode verifying key; %s", err.Error())
	}

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
		common.Log.Warningf("unable to decode proof; %s", err.Error()) // HACK?
		// return nil, fmt.Errorf("unable to decode proof; %s", err.Error())
	}

	return prf, nil
}

// Compile the circuit...
func (p *GnarkCircuitProvider) Compile(argv ...interface{}) (interface{}, error) {
	circuit := argv[0].(frontend.Circuit)
	r1cs, err := frontend.Compile(p.curveID, p.provingSchemeID, circuit)
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
	if p.provingSchemeID != backend.GROTH16 {
		return nil, fmt.Errorf("ExportVerifier not supported for plonk circuits")
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
	return nil, fmt.Errorf("gnark does not not implement GenerateProof()")
}

func nextPowerOfTwo(_n int) int {
	n := uint64(_n)
	p := uint64(1)
	if (n & (n - 1)) == 0 {
		return _n
	}
	for p < n {
		p <<= 1
	}
	return int(p)
}

func getKzgScheme(r1cs frontend.CompiledConstraintSystem) kzg.SRS {
	nbConstraints := r1cs.GetNbConstraints()
	internal, secret, public := r1cs.GetNbVariables()
	nbVariables := internal + secret + public
	var s, size int
	if nbConstraints > nbVariables {
		s = nbConstraints
	} else {
		s = nbVariables
	}
	size = nextPowerOfTwo(s)
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	alpha := new(big.Int).SetUint64(seededRand.Uint64())

	switch r1cs.CurveID() {
	case ecc.BN254:
		return kzgbn254.NewSRS(size, alpha)
	case ecc.BLS12_381:
		return kzgbls12381.NewSRS(size, alpha)
	case ecc.BLS12_377:
		return kzgbls12377.NewSRS(size, alpha)
	case ecc.BW6_761:
		return kzgbw6761.NewSRS(size*2, alpha)
	case ecc.BLS24_315:
		return kzgbls24315.NewSRS(size, alpha)
	default:
		return nil
	}
}

// Setup runs the trusted setup
func (p *GnarkCircuitProvider) Setup(circuit interface{}) (interface{}, interface{}, error) {
	r1cs, err := p.decodeR1CS(circuit.([]byte))
	if err != nil {
		return nil, nil, err
	}

	switch p.provingSchemeID {
	case backend.GROTH16:
		return groth16.Setup(r1cs)
	case backend.PLONK:
		// FIXME-- need to submit SRS via API during setup as well
		return plonk.Setup(r1cs, getKzgScheme(r1cs))
	}

	return nil, nil, fmt.Errorf("invalid proving scheme for Setup")
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

	switch p.provingSchemeID {
	case backend.GROTH16:
		return groth16.Prove(r1cs, pk.(groth16.ProvingKey), witness.(frontend.Circuit))
	case backend.PLONK:
		return plonk.Prove(r1cs, pk.(plonk.ProvingKey), witness.(frontend.Circuit))
	}

	return nil, fmt.Errorf("invalid proving scheme for Prove")
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

	switch p.provingSchemeID {
	case backend.GROTH16:
		return groth16.Verify(prf.(groth16.Proof), vk.(groth16.VerifyingKey), witness.(frontend.Circuit))
	case backend.PLONK:
		return plonk.Verify(prf.(plonk.Proof), vk.(plonk.VerifyingKey), witness.(frontend.Circuit))
	}

	return fmt.Errorf("invalid proving scheme for Verify")
}
