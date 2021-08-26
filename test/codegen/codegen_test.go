// +build unit

package test

import (
	"fmt"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var generatedCodeFolder = "./generated"

func init() {
	// os.RemoveAll(generatedCodeFolder)
}

func removeGeneratedFiles(circuitFilePath, testFilePath string) {
	os.Remove(circuitFilePath)
	os.Remove(testFilePath)
}

func writeToFile(filePath string, s string) {
	os.Mkdir(generatedCodeFolder, 0755)
	f, err := os.OpenFile(filePath,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		log.Println(err)
	}
}

type ConstraintTest struct {
	CircuitName    string
	ConstraintName string
	CurveID        string
	PackageName    string
	ProvingScheme  string
	TestName       string
	Witness        map[string]bool // map of witness values and bool for assert succeed
	Proofs         []string
}

func (t *ConstraintTest) makeTest(includeImportHeader bool) string {
	var test strings.Builder

	if includeImportHeader {
		// Package declaration
		fmt.Fprintf(&test, "package %s\n\n", t.PackageName)

		// Import list
		importList := []string{
			"testing",
			"",
			"github.com/consensys/gnark/frontend",
			"github.com/consensys/gnark-crypto/ecc",
			"github.com/consensys/gnark/backend",
		}
		importList = append(importList, fmt.Sprintf("github.com/consensys/gnark/backend/%s", t.ProvingScheme))
		fmt.Fprintf(&test, "%s\n", makeImportList(importList))
	}

	// Compile circuit
	if t.TestName == "" {
		fmt.Fprintf(&test, "func Test%s(t *testing.T) {\n", t.CircuitName)
	} else {
		fmt.Fprintf(&test, "func %s(t *testing.T) {\n", t.TestName)
	}
	fmt.Fprintf(&test, "\tassert := %s.NewAssert(t)\n\n", t.ProvingScheme)
	fmt.Fprintf(&test, "\tvar circuit %s\n", t.CircuitName)
	fmt.Fprintf(&test, "\tr1cs, err := frontend.Compile(ecc.%s, backend.%s, &circuit)\n", t.CurveID, strings.ToUpper(t.ProvingScheme))
	fmt.Fprintf(&test, "\tassert.NoError(err)\n")

	// Tests
	for w := range t.Witness {
		val, _ := sanitizeValue(w)
		fmt.Fprintf(&test, "\n\t{\n")
		fmt.Fprintf(&test, "\t\tvar witness %s\n", t.CircuitName)
		fmt.Fprintf(&test, "\t\twitness.%s.Assign(%v)\n", t.ConstraintName, val)
		if t.Witness[w] {
			fmt.Fprintf(&test, "\t\tassert.ProverSucceeded(r1cs, &witness)\n")
		} else {
			fmt.Fprintf(&test, "\t\tassert.ProverFailed(r1cs, &witness)\n")
		}
		fmt.Fprintf(&test, "\t}\n")
	}
	fmt.Fprintf(&test, "}\n\n")

	return test.String()
}

func (t *ConstraintTest) makeRollupTest(includeImportHeader bool) string {
	var test strings.Builder

	if includeImportHeader {
		// Package declaration
		fmt.Fprintf(&test, "package %s\n\n", t.PackageName)

		// Import list
		importList := []string{
			"bytes",
			"testing",
			"",
			"github.com/consensys/gnark/frontend",
			"github.com/consensys/gnark-crypto/ecc",
			"github.com/consensys/gnark/backend",
			"github.com/consensys/gnark-crypto/accumulator/merkletree",
			"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc",
			"github.com/consensys/gnark/std/accumulator/merkle",
		}
		importList = append(importList, fmt.Sprintf("github.com/consensys/gnark/backend/%s", t.ProvingScheme))
		fmt.Fprintf(&test, "%s\n", makeImportList(importList))
	}

	// Compile circuit
	if t.TestName == "" {
		fmt.Fprintf(&test, "func Test%s(t *testing.T) {\n", t.CircuitName)
	} else {
		fmt.Fprintf(&test, "func %s(t *testing.T) {\n", t.TestName)
	}
	fmt.Fprintf(&test, "\tassert := %s.NewAssert(t)\n\n", t.ProvingScheme)
	fmt.Fprintf(&test, "\tvar circuit %s\n", t.CircuitName)
	fmt.Fprintf(&test, "\tr1cs, err := frontend.Compile(ecc.%s, backend.%s, &circuit)\n", t.CurveID, strings.ToUpper(t.ProvingScheme))
	fmt.Fprintf(&test, "\tassert.NoError(err)\n")

	// Tests
	fmt.Fprintf(&test, "\n\t{\n")
	fmt.Fprintf(&test, "\t\tproofs := []string{\n")
	for _, p := range t.Proofs {
		fmt.Fprintf(&test, "\t\t\t\"%s\",\n", p)
	}
	fmt.Fprintf(&test, "\t\t}\n\n")

	fmt.Fprintf(&test, "\t\tvar buf bytes.Buffer\n")
	fmt.Fprintf(&test, "\t\tfor i := 0; i < len(proofs); i++ {\n")
	fmt.Fprintf(&test, "\t\t\tdigest, _ := mimc.Sum(\"seed\", []byte(proofs[i]))\n")
	fmt.Fprintf(&test, "\t\t\tbuf.Write(digest)\n")
	fmt.Fprintf(&test, "\t\t}\n\n")

	fmt.Fprintf(&test, "\t\tproofIndex := uint64(0)\n")
	fmt.Fprintf(&test, "\t\thFunc := mimc.NewMiMC(\"seed\")\n")
	fmt.Fprintf(&test, "\t\tsegmentSize := hFunc.Size()\n")
	fmt.Fprintf(&test, "\t\tmerkleRoot, proofSet, numLeaves, err := merkletree.BuildReaderProof(&buf, hFunc, segmentSize, proofIndex)\n")
	fmt.Fprintf(&test, "\t\tassert.NoError(err)\n\n")

	fmt.Fprintf(&test, "\t\tvar witness %s\n", t.CircuitName)
	fmt.Fprintf(&test, "\t\tproofVerified := merkletree.VerifyProof(hFunc, merkleRoot, proofSet, proofIndex, numLeaves)\n")
	fmt.Fprintf(&test, "\t\tassert.True(proofVerified)\n")
	fmt.Fprintf(&test, "\t\tmerkleProofHelper := merkle.GenerateProofHelper(proofSet, proofIndex, numLeaves)\n\n")

	fmt.Fprintf(&test, "\t\twitness.RootHash.Assign(merkleRoot)\n")
	fmt.Fprintf(&test, "\t\tfor i := 0; i < len(proofSet); i++ {\n")
	fmt.Fprintf(&test, "\t\t\twitness.Proofs[i].Assign(proofSet[i])\n")
	fmt.Fprintf(&test, "\t\t\tif i < len(proofSet)-1 {\n")
	fmt.Fprintf(&test, "\t\t\t\twitness.Helpers[i].Assign(merkleProofHelper[i])\n")
	fmt.Fprintf(&test, "\t\t\t}\n")
	fmt.Fprintf(&test, "\t\t}\n\n")

	fmt.Fprintf(&test, "\t\tassert.ProverSucceeded(r1cs, &witness)\n")
	fmt.Fprintf(&test, "\t}\n")
	fmt.Fprintf(&test, "}\n\n")

	return test.String()
}

func TestCodegen(t *testing.T) {
	circuitFilePath := generatedCodeFolder + "/generated_codegen.go"
	testFilePath := generatedCodeFolder + "/generated_codegen_test.go"

	removeGeneratedFiles(circuitFilePath, testFilePath)

	curveIDString := "BN254"
	provingScheme := "groth16"
	{
		circuitName := "GenEqual250Circuit"
		packageName := "test"
		conName := "Val"

		circuit := Circuit{
			Name:        circuitName,
			PackageName: packageName,
			Con: []Constraint{
				{
					Name:     conName,
					Operator: "==",
					Value:    "250",
					Public:   true,
				}},
		}

		circuitStr, err := circuit.Make(true)
		if err != nil {
			t.Fatalf("failed to make circuit: %s", err.Error())
		}

		test := ConstraintTest{
			CircuitName:    circuitName,
			ConstraintName: conName,
			CurveID:        curveIDString,
			PackageName:    packageName,
			ProvingScheme:  provingScheme,
			Witness: map[string]bool{
				"250": true,
				"254": false,
			},
		}
		testStr := test.makeTest(true)

		writeToFile(circuitFilePath, circuitStr)
		writeToFile(testFilePath, testStr)
	}

	{
		circuitName := "GenNotEqual250Circuit"
		packageName := "test"
		conName := "Val"

		circuit := Circuit{
			Name:        circuitName,
			PackageName: packageName,
			Con: []Constraint{
				{
					Name:     conName,
					Operator: "!=",
					Value:    "250",
					Public:   true,
				}},
		}

		circuitStr, err := circuit.Make(false)
		if err != nil {
			t.Fatalf("failed to make circuit: %s", err.Error())
		}

		test := ConstraintTest{
			CircuitName:    circuitName,
			ConstraintName: conName,
			CurveID:        curveIDString,
			PackageName:    packageName,
			ProvingScheme:  provingScheme,
			Witness: map[string]bool{
				"250": false,
				"254": true,
				"249": true,
			},
		}
		testStr := test.makeTest(false)

		writeToFile(circuitFilePath, circuitStr)
		writeToFile(testFilePath, testStr)
	}

	{
		circuitName := "GenLessEq250Circuit"
		packageName := "test"
		conName := "Val"

		circuit := Circuit{
			Name:        circuitName,
			PackageName: packageName,
			Con: []Constraint{
				{
					Name:     conName,
					Operator: "<=",
					Value:    "250",
					Public:   true,
				}},
		}

		circuitStr, err := circuit.Make(false)
		if err != nil {
			t.Fatalf("failed to make circuit: %s", err.Error())
		}

		test := ConstraintTest{
			CircuitName:    circuitName,
			ConstraintName: conName,
			CurveID:        curveIDString,
			PackageName:    packageName,
			ProvingScheme:  provingScheme,
			Witness: map[string]bool{
				"250": true,
				"120": true,
				"350": false,
			},
		}
		testStr := test.makeTest(false)

		writeToFile(circuitFilePath, circuitStr)
		writeToFile(testFilePath, testStr)
	}

	{
		circuitName := "GenGreaterEq250Circuit"
		packageName := "test"
		conName := "Val"

		circuit := Circuit{
			Name:        circuitName,
			PackageName: packageName,
			Con: []Constraint{
				{
					Name:     conName,
					Operator: ">=",
					Value:    "250",
					Public:   true,
				}},
		}

		circuitStr, err := circuit.Make(false)
		if err != nil {
			t.Fatalf("failed to make circuit: %s", err.Error())
		}

		test := ConstraintTest{
			CircuitName:    circuitName,
			ConstraintName: conName,
			CurveID:        curveIDString,
			PackageName:    packageName,
			ProvingScheme:  provingScheme,
			Witness: map[string]bool{
				"250": true,
				"120": false,
				"350": true,
			},
		}
		testStr := test.makeTest(false)

		writeToFile(circuitFilePath, circuitStr)
		writeToFile(testFilePath, testStr)
	}

	{
		circuitName := "GenLess250Circuit"
		packageName := "test"
		conName := "Val"

		circuit := Circuit{
			Name:        circuitName,
			PackageName: packageName,
			Con: []Constraint{
				{
					Name:     conName,
					Operator: "<",
					Value:    "250",
					Public:   true,
				}},
		}

		circuitStr, err := circuit.Make(false)
		if err != nil {
			t.Fatalf("failed to make circuit: %s", err.Error())
		}

		test := ConstraintTest{
			CircuitName:    circuitName,
			ConstraintName: conName,
			CurveID:        curveIDString,
			PackageName:    packageName,
			ProvingScheme:  provingScheme,
			Witness: map[string]bool{
				"250": false,
				"120": true,
				"350": false,
				"249": true,
			},
		}
		testStr := test.makeTest(false)

		writeToFile(circuitFilePath, circuitStr)
		writeToFile(testFilePath, testStr)
	}

	{
		circuitName := "GenGreater250Circuit"
		packageName := "test"
		conName := "Val"

		circuit := Circuit{
			Name:        circuitName,
			PackageName: packageName,
			Con: []Constraint{
				{
					Name:     conName,
					Operator: ">",
					Value:    "250",
					Public:   true,
				}},
		}

		circuitStr, err := circuit.Make(false)
		if err != nil {
			t.Fatalf("failed to make circuit: %s", err.Error())
		}

		test := ConstraintTest{
			CircuitName:    circuitName,
			ConstraintName: conName,
			CurveID:        curveIDString,
			PackageName:    packageName,
			ProvingScheme:  provingScheme,
			Witness: map[string]bool{
				"250": false,
				"120": false,
				"350": true,
				"249": false,
			},
		}
		testStr := test.makeTest(false)

		writeToFile(circuitFilePath, circuitStr)
		writeToFile(testFilePath, testStr)
	}

	{
		circuitName := "GenEqualFloatCircuit"
		packageName := "test"
		conName := "Val"

		circuit := Circuit{
			Name:        circuitName,
			PackageName: packageName,
			Con: []Constraint{
				{
					Name:     conName,
					Operator: "==",
					Value:    "250.123",
					Public:   true,
				}},
		}

		circuitStr, err := circuit.Make(false)
		if err != nil {
			t.Fatalf("failed to make circuit: %s", err.Error())
		}

		test := ConstraintTest{
			CircuitName:    circuitName,
			ConstraintName: conName,
			CurveID:        curveIDString,
			PackageName:    packageName,
			ProvingScheme:  provingScheme,
			Witness: map[string]bool{
				"250.123":  true,
				"250.1234": false,
				"2501":     false,
				"250.1230": true,
			},
		}
		testStr := test.makeTest(false)

		writeToFile(circuitFilePath, circuitStr)
		writeToFile(testFilePath, testStr)
	}

	{
		circuitName := "GenGreaterFloatInvalidCircuit"
		packageName := "test"
		conName := "Val"

		circuit := Circuit{
			Name:        circuitName,
			PackageName: packageName,
			Con: []Constraint{
				{
					Name:     conName,
					Operator: ">",
					Value:    "250.123",
					Public:   true,
				}},
		}

		_, err := circuit.Make(false)
		assert.Error(t, err)
	}

	{
		circuitName := "GenEqualFalseBoolCircuit"
		packageName := "test"
		conName := "Val"

		circuit := Circuit{
			Name:        circuitName,
			PackageName: packageName,
			Con: []Constraint{
				{
					Name:     conName,
					Operator: "==",
					Value:    "false",
					Public:   true,
				}},
		}

		circuitStr, err := circuit.Make(false)
		if err != nil {
			t.Fatalf("failed to make circuit: %s", err.Error())
		}

		test := ConstraintTest{
			CircuitName:    circuitName,
			ConstraintName: conName,
			CurveID:        curveIDString,
			PackageName:    packageName,
			ProvingScheme:  provingScheme,
			Witness: map[string]bool{
				"250.123": false,
				"false":   true,
				"true":    false,
				"0":       true,
			},
		}
		testStr := test.makeTest(false)

		writeToFile(circuitFilePath, circuitStr)
		writeToFile(testFilePath, testStr)
	}

	{
		circuitName := "GenGreaterBoolInvalidCircuit"
		packageName := "test"
		conName := "Val"

		circuit := Circuit{
			Name:        circuitName,
			PackageName: packageName,
			Con: []Constraint{
				{
					Name:     conName,
					Operator: ">",
					Value:    "false",
					Public:   true,
				}},
		}

		_, err := circuit.Make(false)
		assert.Error(t, err)
	}

	{
		circuitName := "GenMultiConstraintCircuit"
		packageName := "test"
		conName := "Val"

		circuit := Circuit{
			Name:        circuitName,
			PackageName: packageName,
			Con: []Constraint{
				{
					Name:     conName,
					Operator: "<",
					Value:    "250",
					Public:   true,
				},
				{
					Name:     "OtherVal",
					Operator: ">",
					Value:    "123",
					Public:   false,
				}},
		}

		circuitStr, err := circuit.Make(false)
		if err != nil {
			t.Fatalf("failed to make circuit: %s", err.Error())
		}

		writeToFile(circuitFilePath, circuitStr)
	}
}

func TestRollupCodegen(t *testing.T) {
	circuitFilePath := generatedCodeFolder + "/generated_rollup_codegen.go"
	testFilePath := generatedCodeFolder + "/generated_rollup_codegen_test.go"

	removeGeneratedFiles(circuitFilePath, testFilePath)

	curveIDString := "BN254"
	provingScheme := "groth16"
	{
		circuitName := "GenRollupCircuit"
		packageName := "test"
		proofs := []string{
			"aa5500ca9af223afdec21989169de5c63938274908f09ee85a233fd1a7396bba89ea271a41a7d38014dfffbdcbe806d0726c5dc4eef7f178ea52de45852697d51f2c74152e1fbbed79ebdfd1235788ea2b1637e6ed49a33a05653133e21a5cfdaa86f1acc9588b17838f8da88a5398cb324b1289aa7759457ddccddf53ee1ca9",
			"9f2becacfe12908f1766b00ed6c7c1d7aa0aa65d2c9651d3aa70b30d25a884aeac1e50a5848f3c2ce9877a690d56801da287224ec2be2e1f26fd73b519fa1b7a19980d9b770a872d03612bd217ea4ff2f6a3bef527997f1eea30098e6772ca8cb033c3f019ce79f794419d2db6039855759e29addc72836fb3a99379e4d5e572",
		}

		circuit := Circuit{
			Name:             circuitName,
			PackageName:      packageName,
			RollupProofCount: len(proofs),
		}

		circuitStr, err := circuit.Make(true)
		if err != nil {
			t.Fatalf("failed to make circuit: %s", err.Error())
		}

		test := ConstraintTest{
			CircuitName:   circuitName,
			CurveID:       curveIDString,
			PackageName:   packageName,
			ProvingScheme: provingScheme,
			Proofs:        proofs,
		}
		testStr := test.makeRollupTest(true)

		writeToFile(circuitFilePath, circuitStr)
		writeToFile(testFilePath, testStr)
	}
}

func TestRollupCodegenPlonk(t *testing.T) {
	circuitFilePath := generatedCodeFolder + "/generated_rollup_codegen_plonk.go"
	testFilePath := generatedCodeFolder + "/generated_rollup_codegen_plonk_test.go"

	removeGeneratedFiles(circuitFilePath, testFilePath)

	curveIDString := "BN254"
	provingScheme := "plonk"
	{
		circuitName := "GenRollupCircuitPlonk"
		packageName := "test"
		proofs := []string{
			"aa5500ca9af223afdec21989169de5c63938274908f09ee85a233fd1a7396bba89ea271a41a7d38014dfffbdcbe806d0726c5dc4eef7f178ea52de45852697d51f2c74152e1fbbed79ebdfd1235788ea2b1637e6ed49a33a05653133e21a5cfdaa86f1acc9588b17838f8da88a5398cb324b1289aa7759457ddccddf53ee1ca9",
			"9f2becacfe12908f1766b00ed6c7c1d7aa0aa65d2c9651d3aa70b30d25a884aeac1e50a5848f3c2ce9877a690d56801da287224ec2be2e1f26fd73b519fa1b7a19980d9b770a872d03612bd217ea4ff2f6a3bef527997f1eea30098e6772ca8cb033c3f019ce79f794419d2db6039855759e29addc72836fb3a99379e4d5e572",
		}

		circuit := Circuit{
			Name:             circuitName,
			PackageName:      packageName,
			RollupProofCount: len(proofs),
		}

		circuitStr, err := circuit.Make(true)
		if err != nil {
			t.Fatalf("failed to make circuit: %s", err.Error())
		}

		test := ConstraintTest{
			CircuitName:   circuitName,
			CurveID:       curveIDString,
			PackageName:   packageName,
			ProvingScheme: provingScheme,
			Proofs:        proofs,
		}
		testStr := test.makeRollupTest(true)

		writeToFile(circuitFilePath, circuitStr)
		writeToFile(testFilePath, testStr)
	}
}
