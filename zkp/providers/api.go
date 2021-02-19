package providers

// GnarkCircuitIdentifierCubic gnark cubic circuit
const GnarkCircuitIdentifierCubic = "cubic"

// GnarkCircuitIdentifierMimc gnark mimc circuit
const GnarkCircuitIdentifierMimc = "mimc"

// GnarkCircuitIdentifierBaselineDocumentComplete baseline document complete circuit
const GnarkCircuitIdentifierBaselineDocumentComplete = "baseline_document_complete"

// ZKSnarkCircuitProviderGnark gnark zksnark circuit provider
const ZKSnarkCircuitProviderGnark = "gnark"

// ZKSnarkCircuitProviderZoKrates ZoKrates zksnark circuit provider
const ZKSnarkCircuitProviderZoKrates = "zokrates"

// ZKSnarkCircuitProvider provides a common interface to interact with zksnark circuits
type ZKSnarkCircuitProvider interface {
	Compile(argv ...interface{}) (interface{}, error)
	ComputeWitness(artifacts interface{}, argv ...interface{}) (interface{}, error)
	ExportVerifier(verifyingKey string) (interface{}, error)
	GenerateProof(circuit interface{}, witness interface{}, provingKey string) (interface{}, error)
	Prove(circuit, provingKey []byte, witness interface{}) (interface{}, error)
	Setup(circuit interface{}) (interface{}, interface{}, error)
	Verify(proof, verifyingKey []byte, witness interface{}) error

	CircuitFactory(identifier string) interface{}
	WitnessFactory(identifier string, curve string, inputs interface{}) (interface{}, error)
}
