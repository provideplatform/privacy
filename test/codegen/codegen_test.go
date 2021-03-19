package test

import (
	"fmt"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func writeToFile(logPath string, s string) {
	f, err := os.OpenFile(logPath,
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
	PackageName    string
	Witness        map[string]bool // map of witness values and bool for assert succeed
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
			"github.com/consensys/gnark/backend/groth16",
			"github.com/consensys/gnark/frontend",
			"github.com/consensys/gurvy",
		}
		fmt.Fprintf(&test, "%s\n", makeImportList(importList))
	}

	// Compile circuit
	fmt.Fprintf(&test, "func Test%s(t *testing.T) {\n", t.CircuitName)
	fmt.Fprintf(&test, "\tassert := groth16.NewAssert(t)\n\n")
	fmt.Fprintf(&test, "\tvar circuit %s\n", t.CircuitName)
	fmt.Fprintf(&test, "\tr1cs, err := frontend.Compile(gurvy.BN256, &circuit)\n")
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
	fmt.Fprintln(&test, "}")

	return test.String()
}

func TestCodegen(t *testing.T) {
	circuitFilePath := "./generated_code.go"
	testFilePath := "./generated_code_test.go"
	{
		circuitName := "GenEqual250Circuit"
		packageName := "test"
		conName := "Val"

		circuit := Circuit{
			Name:        circuitName,
			PackageName: packageName,
			Con: Constraint{
				Name:     conName,
				Operator: "==",
				Value:    "250",
				Public:   true,
			},
		}

		circuitStr, err := circuit.Make(true)
		if err != nil {
			t.Fatalf("failed to make circuit: %s", err)
		}

		test := ConstraintTest{
			CircuitName:    circuitName,
			ConstraintName: conName,
			PackageName:    packageName,
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
			Con: Constraint{
				Name:     conName,
				Operator: "!=",
				Value:    "250",
				Public:   true,
			},
		}

		circuitStr, err := circuit.Make(false)
		if err != nil {
			t.Fatalf("failed to make circuit: %s", err)
		}

		test := ConstraintTest{
			CircuitName:    circuitName,
			ConstraintName: conName,
			PackageName:    packageName,
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
			Con: Constraint{
				Name:     conName,
				Operator: "<=",
				Value:    "250",
				Public:   true,
			},
		}

		circuitStr, err := circuit.Make(false)
		if err != nil {
			t.Fatalf("failed to make circuit: %s", err)
		}

		test := ConstraintTest{
			CircuitName:    circuitName,
			ConstraintName: conName,
			PackageName:    packageName,
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
			Con: Constraint{
				Name:     conName,
				Operator: ">=",
				Value:    "250",
				Public:   true,
			},
		}

		circuitStr, err := circuit.Make(false)
		if err != nil {
			t.Fatalf("failed to make circuit: %s", err)
		}

		test := ConstraintTest{
			CircuitName:    circuitName,
			ConstraintName: conName,
			PackageName:    packageName,
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
			Con: Constraint{
				Name:     conName,
				Operator: "<",
				Value:    "250",
				Public:   true,
			},
		}

		circuitStr, err := circuit.Make(false)
		if err != nil {
			t.Fatalf("failed to make circuit: %s", err)
		}

		test := ConstraintTest{
			CircuitName:    circuitName,
			ConstraintName: conName,
			PackageName:    packageName,
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
			Con: Constraint{
				Name:     conName,
				Operator: ">",
				Value:    "250",
				Public:   true,
			},
		}

		circuitStr, err := circuit.Make(false)
		if err != nil {
			t.Fatalf("failed to make circuit: %s", err)
		}

		test := ConstraintTest{
			CircuitName:    circuitName,
			ConstraintName: conName,
			PackageName:    packageName,
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
			Con: Constraint{
				Name:     conName,
				Operator: "==",
				Value:    "250.123",
				Public:   true,
			},
		}

		circuitStr, err := circuit.Make(false)
		if err != nil {
			t.Fatalf("failed to make circuit: %s", err)
		}

		test := ConstraintTest{
			CircuitName:    circuitName,
			ConstraintName: conName,
			PackageName:    packageName,
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
			Con: Constraint{
				Name:     conName,
				Operator: ">",
				Value:    "250.123",
				Public:   true,
			},
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
			Con: Constraint{
				Name:     conName,
				Operator: "==",
				Value:    "false",
				Public:   true,
			},
		}

		circuitStr, err := circuit.Make(false)
		if err != nil {
			t.Fatalf("failed to make circuit: %s", err)
		}

		test := ConstraintTest{
			CircuitName:    circuitName,
			ConstraintName: conName,
			PackageName:    packageName,
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
			Con: Constraint{
				Name:     conName,
				Operator: ">",
				Value:    "false",
				Public:   true,
			},
		}

		_, err := circuit.Make(false)
		assert.Error(t, err)
	}
}
