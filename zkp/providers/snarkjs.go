package providers

// import "github.com/consensys/gnark/cs"

// SnarkJSCircuitProvider interacts with the snarkjs package
type SnarkJSCircuitProvider struct {
	ZKSnarkCircuitProvider
}

// InitSnarkJSCircuitProvider initializes and configures a new GnarkCircuitProvider instance
func InitSnarkJSCircuitProvider() *SnarkJSCircuitProvider {
	return &SnarkJSCircuitProvider{}
}

// // Compile the circuit...
// func Compile(source string) (interface{}, error) {
// 	return nil, nil
// }

// func ComputeWitness(artifacts map[string]interface{}, args ...interface{}) (interface{}, error) {
// 	return nil, nil
// }

// func ExportVerifier(verifyingKey string) (interface{}, error) {
// 	return nil, nil
// }

// func GenerateProof(circuit interface{}, witness, provingKey string) (interface{}, error) {
// 	return nil, nil
// }

// func Setup(circuit interface{}) (interface{}, error) {
// 	return nil, nil
// }
