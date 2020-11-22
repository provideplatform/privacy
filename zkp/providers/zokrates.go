package providers

// ZoKratesCircuitProvider interacts with statically-linked ZoKrates
type ZoKratesCircuitProvider struct {
	ZKSnarkCircuitProvider
}

// InitZoKratesCircuitProvider initializes and configures a new ZoKratesCircuitProvider instance
func InitZoKratesCircuitProvider() *ZoKratesCircuitProvider {
	return &ZoKratesCircuitProvider{}
}

// TODO: impl ZoKratesCircuitProvider against linked zokrates...

// Compile(source string) (interface{}, error)
// ComputeWitness(artifacts map[string]interface{}, args ...interface{}) (interface{}, error)
// ExportVerifier(verifyingKey string) (interface{}, error)
// GenerateProof(circuit interface{}, witness, provingKey string) (interface{}, error)
// Setup(circuit interface{}) (interface{}, error)
