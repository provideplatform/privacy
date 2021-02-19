package providers

// GnarkCircuitIdentifierCubic gnark cubic circuit
const GnarkCircuitIdentifierCubic = "cubic"

// GnarkCircuitIdentifierBaselineDocument gnark circuit
const GnarkCircuitIdentifierBaselineDocument = "baseline_document"

// GnarkCircuitIdentifierBaselineRollup gnark circuit
const GnarkCircuitIdentifierBaselineRollup = "baseline_rollup"

// GnarkCircuitIdentifierPurchaseOrderCircuit gnark circuit
const GnarkCircuitIdentifierPurchaseOrderCircuit = "purchase_order"

// GnarkCircuitIdentifierSalesOrderCircuit gnark circuit
const GnarkCircuitIdentifierSalesOrderCircuit = "sales_order"

// GnarkCircuitIdentifierShipmentNotificationCircuit gnark circuit
const GnarkCircuitIdentifierShipmentNotificationCircuit = "shipment_notification"

// GnarkCircuitIdentifierGoodsReceiptCircuit gnark circuit
const GnarkCircuitIdentifierGoodsReceiptCircuit = "goods_receipt"

// GnarkCircuitIdentifierInvoiceCircuit gnark circuit
const GnarkCircuitIdentifierInvoiceCircuit = "invoice"

// GnarkCircuitIdentifierInvoiceSubdividedCircuit gnark circuit
const GnarkCircuitIdentifierInvoiceSubdividedCircuit = "invoice_sub"

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
