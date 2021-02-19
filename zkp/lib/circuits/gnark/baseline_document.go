package gnark

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
	"github.com/consensys/gurvy"
)

// BaselineDocumentCircuit defines a pre-image knowledge proof
// mimc(secret PreImage) = public hash
type BaselineDocumentCircuit struct {
	PreImage frontend.Variable
	Hash     frontend.Variable `gnark:",public"`
}

// Define declares the circuit constraints
// Hash = mimc(PreImage)
func (circuit *BaselineDocumentCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	// hash function
	mimc, _ := mimc.NewMiMC("seed", curveID)

	hash := mimc.Hash(cs, circuit.PreImage)
	cs.AssertIsEqual(circuit.Hash, hash)

	return nil
}

// PurchaseOrderCircuit defines a knowledge proof for purchase orders
type PurchaseOrderCircuit struct {
	Document BaselineDocumentCircuit
}

// SalesOrderCircuit defines a knowledge proof for sales orders
type SalesOrderCircuit struct {
	Document BaselineDocumentCircuit
}

// ShipmentNotificationCircuit defines a knowledge proof for shipment notifications
type ShipmentNotificationCircuit struct {
	Document BaselineDocumentCircuit
}

// GoodsReceiptCircuit defines a knowledge proof for goods receipts
type GoodsReceiptCircuit struct {
	Document BaselineDocumentCircuit
}

// InvoiceCircuit defines a knowledge proof for invoices
type InvoiceCircuit struct {
	PubKey eddsa.PublicKey   `gnark:",public"`
	Sig    eddsa.Signature   `gnark:",public"`
	Msg    frontend.Variable `gnark:",public"`
}

// InvoiceCircuitSubdivided defines a knowledge proof for invoices
type InvoiceCircuitSubdivided struct {
	PubKeyAX frontend.Variable `gnark:",public"`
	PubKeyAY frontend.Variable `gnark:",public"`
	SigRAX   frontend.Variable `gnark:",public"`
	SigRAY   frontend.Variable `gnark:",public"`
	SigS     frontend.Variable `gnark:",public"`
	Msg      frontend.Variable `gnark:",public"`
}

// Define declares the PO circuit constraints
func (circuit *PurchaseOrderCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	// hash function
	mimc, err := mimc.NewMiMC("seed", curveID)
	if err != nil {
		return err
	}

	hash := mimc.Hash(cs, circuit.Document.PreImage)
	cs.AssertIsEqual(circuit.Document.Hash, hash)

	return nil
}

// Define declares the SO circuit constraints
func (circuit *SalesOrderCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	// hash function
	mimc, err := mimc.NewMiMC("seed", curveID)
	if err != nil {
		return err
	}

	hash := mimc.Hash(cs, circuit.Document.PreImage)
	cs.AssertIsEqual(circuit.Document.Hash, hash)

	return nil
}

// Define declares the SN circuit constraints
func (circuit *ShipmentNotificationCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	// hash function
	mimc, err := mimc.NewMiMC("seed", curveID)
	if err != nil {
		return err
	}

	hash := mimc.Hash(cs, circuit.Document.PreImage)
	cs.AssertIsEqual(circuit.Document.Hash, hash)

	return nil
}

// Define declares the GR circuit constraints
func (circuit *GoodsReceiptCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	// hash function
	mimc, err := mimc.NewMiMC("seed", curveID)
	if err != nil {
		return err
	}

	hash := mimc.Hash(cs, circuit.Document.PreImage)
	cs.AssertIsEqual(circuit.Document.Hash, hash)

	return nil
}

// Define declares the Invoice circuit constraints
func (circuit *InvoiceCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	curve, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}
	circuit.PubKey.Curve = curve

	eddsa.Verify(cs, circuit.Sig, circuit.Msg, circuit.PubKey)

	return nil
}

// Define declares the Invoice subdivided circuit constraints
func (circuit *InvoiceCircuitSubdivided) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	curve, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}

	var pubKey eddsa.PublicKey
	pubKey.Curve = curve
	pubKey.A.X = circuit.PubKeyAX
	pubKey.A.Y = circuit.PubKeyAY

	var sig eddsa.Signature
	sig.R.A.X = circuit.SigRAX
	sig.R.A.Y = circuit.SigRAY
	sig.S = circuit.SigS

	eddsa.Verify(cs, sig, circuit.Msg, pubKey)

	return nil
}
