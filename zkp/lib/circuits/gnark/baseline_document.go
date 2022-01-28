package gnark

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

// PurchaseOrderProver defines a knowledge proof for purchase orders
type PurchaseOrderProver struct {
	Document MimcProver
}

// SalesOrderProver defines a knowledge proof for sales orders
type SalesOrderProver struct {
	Document MimcProver
}

// ShipmentNotificationProver defines a knowledge proof for shipment notifications
type ShipmentNotificationProver struct {
	Document MimcProver
}

// GoodsReceiptProver defines a knowledge proof for goods receipts
type GoodsReceiptProver struct {
	Document MimcProver
}

// InvoiceProver defines a knowledge proof for invoices
type InvoiceProver struct {
	Document MimcProver
	// PubKey eddsa.PublicKey   `gnark:",public"`
	// Sig    eddsa.Signature   `gnark:",public"`
	// Msg    frontend.Variable `gnark:",public"`
}

// Define declares the PO prover constraints
func (prover *PurchaseOrderProver) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	// hash function
	mimc, err := mimc.NewMiMC("seed", curveID)
	if err != nil {
		return err
	}

	hash := mimc.Hash(cs, prover.Document.Preimage)
	cs.AssertIsEqual(prover.Document.Hash, hash)

	return nil
}

// Define declares the SO prover constraints
func (prover *SalesOrderProver) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	// hash function
	mimc, err := mimc.NewMiMC("seed", curveID)
	if err != nil {
		return err
	}

	hash := mimc.Hash(cs, prover.Document.Preimage)
	cs.AssertIsEqual(prover.Document.Hash, hash)

	return nil
}

// Define declares the SN prover constraints
func (prover *ShipmentNotificationProver) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	// hash function
	mimc, err := mimc.NewMiMC("seed", curveID)
	if err != nil {
		return err
	}

	hash := mimc.Hash(cs, prover.Document.Preimage)
	cs.AssertIsEqual(prover.Document.Hash, hash)

	return nil
}

// Define declares the GR prover constraints
func (prover *GoodsReceiptProver) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	// hash function
	mimc, err := mimc.NewMiMC("seed", curveID)
	if err != nil {
		return err
	}

	hash := mimc.Hash(cs, prover.Document.Preimage)
	cs.AssertIsEqual(prover.Document.Hash, hash)

	return nil
}

// Define declares the Invoice prover constraints
func (prover *InvoiceProver) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	// hash function
	mimc, err := mimc.NewMiMC("seed", curveID)
	if err != nil {
		return err
	}

	hash := mimc.Hash(cs, prover.Document.Preimage)
	cs.AssertIsEqual(prover.Document.Hash, hash)

	return nil
}

// FIXME!! this fails...
// // Define declares the Invoice prover constraints
// func (prover *InvoiceProver) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
// 	curve, err := twistededwards.NewEdCurve(curveID)
// 	if err != nil {
// 		return err
// 	}
// 	prover.PubKey.Curve = curve

// 	eddsa.Verify(cs, prover.Sig, prover.Msg, prover.PubKey)

// 	return nil
// }
