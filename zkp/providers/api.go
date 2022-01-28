package providers

// GnarkProverIdentifierCubic gnark cubic prover
const GnarkProverIdentifierCubic = "cubic"

// GnarkProverIdentifierOwnershipSk gnark ownership sk prover
const GnarkProverIdentifierOwnershipSk = "ownership_sk"

// GnarkProverIdentifierMimc gnark mimc prover
const GnarkProverIdentifierMimc = "mimc"

// GnarkProverIdentifierBaselineDocumentComplete baseline document complete prover
const GnarkProverIdentifierBaselineDocumentComplete = "baseline_document_complete"

// GnarkProverIdentifierBaselineRollup gnark prover
const GnarkProverIdentifierBaselineRollup = "baseline_rollup"

// GnarkProverIdentifierPurchaseOrderProver gnark prover
const GnarkProverIdentifierPurchaseOrderProver = "purchase_order"

// GnarkProverIdentifierSalesOrderProver gnark prover
const GnarkProverIdentifierSalesOrderProver = "sales_order"

// GnarkProverIdentifierShipmentNotificationProver gnark prover
const GnarkProverIdentifierShipmentNotificationProver = "shipment_notification"

// GnarkProverIdentifierGoodsReceiptProver gnark prover
const GnarkProverIdentifierGoodsReceiptProver = "goods_receipt"

// GnarkProverIdentifierInvoiceProver gnark prover
const GnarkProverIdentifierInvoiceProver = "invoice"

// GnarkProverIdentifierProofHashProver gnark prover
const GnarkProverIdentifierProofHashProver = "proof_hash"

// GnarkProverIdentifierProofEddsaProver gnark prover
const GnarkProverIdentifierProofEddsaProver = "proof_eddsa"

// ZKSnarkProverProviderGnark gnark zksnark prover provider
const ZKSnarkProverProviderGnark = "gnark"

// ZKSnarkProverProviderZoKrates ZoKrates zksnark prover provider
const ZKSnarkProverProviderZoKrates = "zokrates"

// ZKSnarkProverProvider provides a common interface to interact with zksnark provers
type ZKSnarkProverProvider interface {
	Compile(argv ...interface{}) (interface{}, error)
	ComputeWitness(artifacts interface{}, argv ...interface{}) (interface{}, error)
	ExportVerifier(verifyingKey string) (interface{}, error)
	GenerateProof(prover interface{}, witness interface{}, provingKey string) (interface{}, error)
	Prove(prover, provingKey []byte, witness interface{}, srs []byte) (interface{}, error)
	Setup(prover interface{}, srs []byte) (interface{}, interface{}, error)
	Verify(proof, verifyingKey []byte, witness interface{}, srs []byte) error

	ProverFactory(identifier string) interface{}
	WitnessFactory(identifier string, curve string, inputs interface{}, isPublic bool) (interface{}, error)
}
