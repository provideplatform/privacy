package test

import (
	"encoding/binary"
	"math"
)

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

// Serialize serializes DocVars as a concatenation of the bits in the float val with the text string
// length of return array is capped at 32 bytes
func (dv *DocVars) Serialize() []byte {
	var res [32]byte

	binary.BigEndian.PutUint64(res[0:], math.Float64bits(dv.val))
	copy(res[8:32], []byte(dv.text))

	return res[:]
}

// Deserialize deserializes DocVars from a byte array comprised of the concatenation of the bits in the float val with the text string
func Deserialize(res *DocVars, data []byte) error {
	res.Reset()

	res.val = float64(binary.BigEndian.Uint64(data[:8]))
	res.text = string(data[8:32])

	return nil
}
