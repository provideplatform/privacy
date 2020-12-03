package providers

// GnarkCircuitIdentifierCubic gnark cubic circuit
const GnarkCircuitIdentifierCubic = "cubic"

// ZKSnarkCircuitProviderGnark gnark zksnark circuit provider
const ZKSnarkCircuitProviderGnark = "gnark"

// ZKSnarkCircuitProviderZoKrates ZoKrates zksnark circuit provider
const ZKSnarkCircuitProviderZoKrates = "zokrates"

// ZKSnarkCircuitProvider provides a common interface to interact with zksnark circuits
type ZKSnarkCircuitProvider interface {
	Compile(argv ...interface{}) (interface{}, error)
	ComputeWitness(artifacts map[string]interface{}, args ...interface{}) (interface{}, error)
	// TODO: make optional ... ExportVerifier(verifyingKey string) (interface{}, error)
	GenerateProof(circuit interface{}, witness, provingKey string) (interface{}, error)
	Setup(circuit interface{}) (interface{}, error)
	// TODO: Verify() error
}
