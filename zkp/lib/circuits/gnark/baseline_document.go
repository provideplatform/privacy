package gnark

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
	"github.com/consensys/gurvy"
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
	PubKey eddsa.PublicKey   `gnark:",public"`
	Sig    eddsa.Signature   `gnark:",public"`
	Msg    frontend.Variable `gnark:",public"`
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
