package gnark

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

// PurchaseOrderCircuit defines a knowledge proof for purchase orders
type PurchaseOrderCircuit struct {
	Document MimcCircuit
}

// SalesOrderCircuit defines a knowledge proof for sales orders
type SalesOrderCircuit struct {
	Document MimcCircuit
}

// ShipmentNotificationCircuit defines a knowledge proof for shipment notifications
type ShipmentNotificationCircuit struct {
	Document MimcCircuit
}

// GoodsReceiptCircuit defines a knowledge proof for goods receipts
type GoodsReceiptCircuit struct {
	Document MimcCircuit
}

// InvoiceCircuit defines a knowledge proof for invoices
type InvoiceCircuit struct {
	Document MimcCircuit
	// PubKey eddsa.PublicKey   `gnark:",public"`
	// Sig    eddsa.Signature   `gnark:",public"`
	// Msg    frontend.Variable `gnark:",public"`
}

// Define declares the PO circuit constraints
func (circuit *PurchaseOrderCircuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	// hash function
	mimc, err := mimc.NewMiMC("seed", curveID, cs)
	if err != nil {
		return err
	}

	mimc.Write(circuit.Document.Preimage)
	cs.AssertIsEqual(circuit.Document.Hash, mimc.Sum())

	return nil
}

// Define declares the SO circuit constraints
func (circuit *SalesOrderCircuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	// hash function
	mimc, err := mimc.NewMiMC("seed", curveID, cs)
	if err != nil {
		return err
	}

	mimc.Write(circuit.Document.Preimage)
	cs.AssertIsEqual(circuit.Document.Hash, mimc.Sum())

	return nil
}

// Define declares the SN circuit constraints
func (circuit *ShipmentNotificationCircuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	// hash function
	mimc, err := mimc.NewMiMC("seed", curveID, cs)
	if err != nil {
		return err
	}

	mimc.Write(circuit.Document.Preimage)
	cs.AssertIsEqual(circuit.Document.Hash, mimc.Sum())

	return nil
}

// Define declares the GR circuit constraints
func (circuit *GoodsReceiptCircuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	// hash function
	mimc, err := mimc.NewMiMC("seed", curveID, cs)
	if err != nil {
		return err
	}

	mimc.Write(circuit.Document.Preimage)
	cs.AssertIsEqual(circuit.Document.Hash, mimc.Sum())

	return nil
}

// Define declares the Invoice circuit constraints
func (circuit *InvoiceCircuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	// hash function
	mimc, err := mimc.NewMiMC("seed", curveID, cs)
	if err != nil {
		return err
	}

	mimc.Write(circuit.Document.Preimage)
	cs.AssertIsEqual(circuit.Document.Hash, mimc.Sum())

	return nil
}

// FIXME!! this fails...
// // Define declares the Invoice circuit constraints
// func (circuit *InvoiceCircuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
// 	curve, err := twistededwards.NewEdCurve(curveID)
// 	if err != nil {
// 		return err
// 	}
// 	circuit.PubKey.Curve = curve

// 	eddsa.Verify(cs, circuit.Sig, circuit.Msg, circuit.PubKey)

// 	return nil
// }
