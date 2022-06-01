/*
 * Copyright 2017-2022 Provide Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"reflect"
	"strconv"
	"strings"
)

type Constraint struct {
	Name     string
	Operator string      // can be one of ==, !=, <=, <, >= or >
	Value    interface{} // can be of type string, bool, float, int... anything else?
	Public   bool        `default:"false"`
}

// returns true if val type can only be used with "==" or "!=" operators
func (c *Constraint) operatorIsRestricted() bool {
	valKind := reflect.TypeOf(c.Value).Kind()
	if valKind == reflect.String {
		if _, err := strconv.ParseBool(c.Value.(string)); err == nil {
			return true
		}
		if _, err := strconv.ParseFloat(c.Value.(string), 64); err == nil {
			_, err := strconv.ParseInt(c.Value.(string), 10, 64)
			return err != nil
		}
	} else if valKind == reflect.Bool || valKind == reflect.Float32 || valKind == reflect.Float64 {
		return true
	}

	return false
}

type Prover struct {
	Con              []Constraint
	Name             string
	PackageName      string // for creating the prover file
	RollupProofCount int
}

func makeImportList(list []string) string {
	var imports strings.Builder

	imports.WriteString("import (")

	for _, imp := range list {
		if len(imp) > 0 {
			fmt.Fprintf(&imports, "\n\t\"%s\"", imp)
		} else {
			fmt.Fprintln(&imports)
		}
	}
	imports.WriteString("\n)\n")

	return imports.String()
}

func sanitizeValue(val interface{}) (interface{}, error) {
	valKind := reflect.TypeOf(val).Kind()
	if valKind == reflect.String {
		if val == "true" || val == "false" {
			b, _ := strconv.ParseBool(val.(string))
			if b {
				val = 1
			} else {
				val = 0
			}
		} else if strings.Contains(val.(string), ".") {
			f, err := strconv.ParseFloat(val.(string), 64)
			if err != nil {
				return "", fmt.Errorf("unable to parse float")
			}
			buf := new(bytes.Buffer)
			err = binary.Write(buf, binary.BigEndian, f)
			if err != nil {
				return "", fmt.Errorf("unable to write float")
			}
			var i big.Int
			i.SetBytes(buf.Bytes())
			val = i.String()
		} else {
			var i big.Int
			_, success := i.SetString(val.(string), 10)
			if !success {
				return "", fmt.Errorf("unable to convert value to valid integer")
			}
		}
	} else if valKind == reflect.Float32 || valKind == reflect.Float64 {
		f := val
		buf := new(bytes.Buffer)
		err := binary.Write(buf, binary.BigEndian, f)
		if err != nil {
			return "", fmt.Errorf("unable to write float")
		}
		var i big.Int
		i.SetBytes(buf.Bytes())
		val = i.Uint64()
	}

	return val, nil
}

func (c *Prover) makeProverLogic() (string, error) {
	var logic strings.Builder

	if c.RollupProofCount > 0 {
		fmt.Fprintf(&logic, "\tmimc, err := mimc.NewMiMC(\"seed\", curveID)\n")
		fmt.Fprintf(&logic, "\tif err != nil {\n")
		fmt.Fprintf(&logic, "\t\treturn err\n\t}\n")
		fmt.Fprintf(&logic, "\tmerkle.VerifyProof(cs, mimc, prover.RootHash, prover.Proofs[:], prover.Helpers[:])\n")
	}

	for _, con := range c.Con {
		if con.operatorIsRestricted() && (con.Operator != "==" && con.Operator != "!=") {
			return "", fmt.Errorf("invalid operator for constraint type")
		}

		val, err := sanitizeValue(con.Value)
		if err != nil {
			return "", fmt.Errorf("invalid constraint value")
		}

		switch con.Operator {
		case "==":
			fmt.Fprintf(&logic, "\tcs.AssertIsLessOrEqual(prover.%s, cs.Constant(%v))\n", con.Name, val)
			fmt.Fprintf(&logic, "\tcs.AssertIsLessOrEqual(cs.Constant(%v), prover.%s)\n", val, con.Name)
		case "!=":
			fmt.Fprintf(&logic, "\tdiff := cs.Sub(prover.%s, cs.Constant(%v))\n", con.Name, val)
			fmt.Fprintf(&logic, "\tdiffIsZero := cs.IsZero(diff, curveID)\n")
			fmt.Fprintf(&logic, "\tcs.AssertIsEqual(diffIsZero, cs.Constant(0))\n")
		case "<=":
			fmt.Fprintf(&logic, "\tcs.AssertIsLessOrEqual(prover.%s, cs.Constant(%v))\n", con.Name, val)
		case "<":
			fmt.Fprintf(&logic, "\tcs.AssertIsLessOrEqual(prover.%s, cs.Sub(cs.Constant(%v), 1))\n", con.Name, val)
		case ">=":
			fmt.Fprintf(&logic, "\tcs.AssertIsLessOrEqual(cs.Constant(%v), prover.%s)\n", val, con.Name)
		case ">":
			fmt.Fprintf(&logic, "\tcs.AssertIsLessOrEqual(cs.Constant(%v), cs.Sub(prover.%s, 1))\n", val, con.Name)
		default:
			return "", fmt.Errorf("invalid operator type")
		}
		fmt.Fprintln(&logic)
	}

	logic.WriteString("\treturn nil\n")

	return logic.String(), nil
}

func (c *Prover) Make(includeImportHeader bool) (string, error) {
	var prover strings.Builder

	if includeImportHeader {
		// Package declaration
		fmt.Fprintf(&prover, "package %s\n\n", c.PackageName)

		// Import list
		importList := []string{
			"github.com/consensys/gnark/frontend",
			"github.com/consensys/gnark-crypto/ecc",
		}
		if c.RollupProofCount > 0 {
			importList = append(importList, "github.com/consensys/gnark/std/accumulator/merkle", "github.com/consensys/gnark/std/hash/mimc")
		}
		fmt.Fprintf(&prover, "%s\n", makeImportList(importList))
	}

	// Prover variable
	fmt.Fprintf(&prover, "type %s struct {\n", c.Name)
	if c.RollupProofCount > 0 {
		fmt.Fprintf(&prover, "\tProofs [%d]frontend.Variable\n", c.RollupProofCount)
		fmt.Fprintf(&prover, "\tHelpers [%d]frontend.Variable\n", c.RollupProofCount-1)
		fmt.Fprintf(&prover, "\tRootHash frontend.Variable `gnark:\",public\"`\n")
	}
	for _, con := range c.Con {
		fmt.Fprintf(&prover, "\t%s frontend.Variable", con.Name)
		if con.Public {
			fmt.Fprintf(&prover, " `gnark:\",public\"`\n")
		} else {
			fmt.Fprintf(&prover, "\n")
		}
	}
	fmt.Fprintf(&prover, "}\n\n")

	// Define function
	fmt.Fprintf(&prover, "func (prover *%s) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {\n", c.Name)
	logic, err := c.makeProverLogic()
	if err != nil {
		return "", fmt.Errorf("invalid operator type")
	}
	fmt.Fprintf(&prover, "%s}\n\n", logic)

	return prover.String(), nil
}
