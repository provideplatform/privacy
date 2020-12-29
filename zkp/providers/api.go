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
	ComputeWitness(artifacts map[string]interface{}, argv ...interface{}) (interface{}, error)
	ExportVerifier(verifyingKey string) (interface{}, error)
	GenerateProof(circuit interface{}, witness map[string]interface{}, provingKey string) (interface{}, error)
	Prove(circuit, provingKey []byte, witness map[string]interface{}) (interface{}, error)
	Setup(circuit interface{}) (interface{}, interface{}, error)
	Verify(proof, verifyingKey []byte, witness map[string]interface{}) error
}
