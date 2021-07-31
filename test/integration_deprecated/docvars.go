// +build integration-deprecated

package test

import (
	"encoding/binary"
	"math"

	mimc "github.com/consensys/gnark-crypto/hash"
)

// DocVars describes private identifying variables taken from a document intended for validation
type DocVars struct {
	val  float64
	text string
	h    mimc.Hash
}

// Reset resets DocVars
func (dv *DocVars) Reset() {
	dv.val = 0
	dv.text = ""
}

// Size returns the size of the digested data
func (dv *DocVars) Size() int {
	return dv.h.Size()
}

// Digest hashes the document variables to produce a unique transaction signature of uniform length
func (dv *DocVars) Digest() []byte {
	var floatBytes [8]byte

	hFunc := dv.h.New("seed")

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
