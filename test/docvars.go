package test

import (
	"encoding/binary"
	"math"

	mimc "github.com/consensys/gnark/crypto/hash/mimc/bn256"
)

var hFunc = mimc.NewMiMC("seed")

// DocVars describes private identifying variables taken from a document intended for validation
type DocVars struct {
	val  float64
	text string
}

// Reset resets DocVars
func (dv *DocVars) Reset() {
	dv.val = 0
	dv.text = ""
}

// Size returns the size of the digested data
func (dv *DocVars) Size() int {
	return hFunc.Size()
}

// Digest hashes the document variables to produce a unique transaction signature of uniform length
func (dv *DocVars) Digest() []byte {
	var floatBytes [8]byte

	binary.BigEndian.PutUint64(floatBytes[:], math.Float64bits(dv.val))
	_, err := hFunc.Write(floatBytes[:])
	if err != nil {
		return nil
	}
	_, err = hFunc.Write([]byte(dv.text))
	if err != nil {
		return nil
	}

	return hFunc.Sum(nil)
}
