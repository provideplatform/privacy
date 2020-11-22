package providers

const zkSnarkCircuitProviderGnark = "gnark"
const zkSnarkCircuitProviderZoKrates = "zokrates"

// ZKSnarkCircuitProvider provides a common interface
// to interact with services such as Zokrates
type ZKSnarkCircuitProvider interface {
	Compile(source string) (interface{}, error)
	ComputeWitness(artifacts map[string]interface{}, args ...interface{}) (interface{}, error)
	ExportVerifier(verifyingKey string) (interface{}, error)
	GenerateProof(circuit interface{}, witness, provingKey string) (interface{}, error)
	Setup(circuit interface{}) (interface{}, error)
	// FIXME: Verify() error
}
