// +build unit

package gnark

import (
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/provideplatform/privacy/common"
	libgnark "github.com/provideplatform/privacy/zkp/lib/circuits/gnark"

	zkp "github.com/provideplatform/privacy/zkp/providers"
)

func getCircuit(t *testing.T, identifier string, p *zkp.GnarkCircuitProvider) interface{} {
	ownershipSkCircuit := &libgnark.OwnershipSkCircuit{}
	err := p.AddCircuit(identifier, ownershipSkCircuit)
	if err != nil {
		t.Errorf(err.Error())
		return nil
	}

	return p.CircuitFactory(identifier)
}

func TestOwnershipSkLibraryAdd(t *testing.T) {
	assert := groth16.NewAssert(t)

	curveID := ecc.BN254
	provingScheme := "groth16"
	p := zkp.InitGnarkCircuitProvider(common.StringOrNil(curveID.String()), &provingScheme)

	identifier := zkp.GnarkCircuitIdentifierOwnershipSk
	circuit := p.CircuitFactory(identifier)
	assert.Nil(circuit)

	circuit = getCircuit(t, identifier, p)
	assert.NotNil(circuit)

	r, err := p.Compile(circuit)
	assert.NoError(err)

	r1cs := r.(frontend.CompiledConstraintSystem)

	// Correct sk, pk
	{
		// Generate eddsa sk, pk
		src := rand.NewSource(0)
		r := rand.New(src)
		privKey, _ := eddsa.GenerateKey(r)
		assert.NoError(err)
		pubKey := privKey.Public()

		// Parse sk, pk
		pubkeyAx, pubkeyAy, privkeyScalar := parseKeys(curveID, pubKey.Bytes(), privKey.Bytes())
		privKeyScalarLength := len(privkeyScalar)
		privKeyScalarUpper := privkeyScalar[:privKeyScalarLength/2]
		privKeyScalarLower := privkeyScalar[privKeyScalarLength/2:]

		var witness libgnark.OwnershipSkCircuit
		witness.Pk.A.X.Assign(pubkeyAx)
		witness.Pk.A.Y.Assign(pubkeyAy)

		witness.Sk.Upper.Assign(privKeyScalarUpper)
		witness.Sk.Lower.Assign(privKeyScalarLower)

		assert.SolvingSucceeded(r1cs, &witness)
		//assert.ProverSucceeded(r1cs, &witness)
	}

	// Incorrect sk, pk
	{
		var witness libgnark.OwnershipSkCircuit
		witness.Pk.A.X.Assign(42) // these are nonsense values for this circuit
		witness.Pk.A.Y.Assign(42)
		witness.Sk.Upper.Assign(42)
		witness.Sk.Lower.Assign(0)

		assert.SolvingFailed(r1cs, &witness)
		//assert.ProverFailed(r1cs, &witness)
	}

}
