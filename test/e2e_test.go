// +build integration

package test

import (
	"hash"
	"math/big"
	"math/rand"

	"os"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"

	mimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/privacy/store/providers/merkletree"
)

const requireCircuitTimeout = time.Minute * 5
const requireCircuitTickerInterval = time.Second * 5
const requireCircuitSleepInterval = time.Millisecond * 500

func init() {
	time.Sleep(time.Second * 20)
}

var curveID = ecc.BN254

const testProvingSchemeGroth16 = "groth16"
const testProvingSchemePlonk = "plonk"

func setBobEnv() {
	os.Setenv("IDENT_API_HOST", "localhost:8084")
	os.Setenv("PRIVACY_API_HOST", "localhost:8083")
}

func setAliceEnv() {
	os.Setenv("IDENT_API_HOST", "localhost:8081")
	os.Setenv("PRIVACY_API_HOST", "localhost:8080")
}

func TestProcureToPayWorkflowGroth16(t *testing.T) {
	hFunc := mimc.NewMiMC("seed")
	tree := merkletree.NewMerkleTree(hFunc)

	testUserID, _ := uuid.NewV4()
	token, _ := userTokenFactory(testUserID)

	circuits, err := createProcureToPayWorkflow(token, testProvingSchemeGroth16)
	if err != nil {
		t.Errorf("failed to create procure to pay workflow circuits%s", err.Error())
	}

	for _, circuit := range circuits {
		t.Logf("deployed circuit %s with id %s", *circuit.Name, circuit.ID)
	}

	requireCircuits(token, circuits)

	purchaseOrderCircuit := circuits[0]
	salesOrderCircuit := circuits[1]
	shipmentNotificationCircuit := circuits[2]
	goodsReceiptCircuit := circuits[3]
	invoiceCircuit := circuits[4]

	testCircuitLifecycle(t, tree, hFunc, token, uint64(0), purchaseOrderCircuit, nil, map[string]interface{}{
		"value": 11111111,
		"hello": "world1",
	})

	testCircuitLifecycle(t, tree, hFunc, token, uint64(1), salesOrderCircuit, purchaseOrderCircuit, map[string]interface{}{
		"value": 22222222,
		"hello": "world2",
	})

	testCircuitLifecycle(t, tree, hFunc, token, uint64(2), shipmentNotificationCircuit, salesOrderCircuit, map[string]interface{}{
		"value": 33333333,
		"hello": "world3",
	})

	testCircuitLifecycle(t, tree, hFunc, token, uint64(3), goodsReceiptCircuit, shipmentNotificationCircuit, map[string]interface{}{
		"value": 44444444,
		"hello": "world4",
	})

	testCircuitLifecycle(t, tree, hFunc, token, uint64(4), invoiceCircuit, goodsReceiptCircuit, map[string]interface{}{
		"value": 55555555,
		"hello": "world5",
	})
}

type STAGE uint16

const (
	PURCHASE STAGE = iota
	SALES
	SHIPMENT
	GOODS
	INVOICE
)

func getProcurementWitness(stage STAGE, hFunc hash.Hash, proofString string, creditRating string) (string, map[string]interface{}) {
	var i big.Int

	certificateNumber, _ := uuid.FromString("12345678-1234-5678-9abc-123456789abc")
	createdOn := []byte("01/02/2021 04:40 PM UTC")
	globalGoodsReceiptNumber := []byte("ENTITY-ORDER-NUMBER-20210101-001-GR")
	globalPurchaseOrderNumber := []byte("ENTITY-ORDER-NUMBER-20210101-001") // GlobalPONumber from form
	globalSalesOrderNumber := []byte("ENTITY-1234567890")
	globalShipmentNumber := []byte("ENTITY-0000123456")
	goodsReceiptCreatedOn := []byte("01/04/2021 01:40 PM UTC")
	soldTo := []byte("56785678")
	soNumber := []byte("1234567890")

	identifier := ""
	hFunc.Reset()

	switch stage {
	case PURCHASE:
		// mimc Write never returns an error
		hFunc.Write(globalPurchaseOrderNumber)
		hFunc.Write(soNumber)
		hFunc.Write(certificateNumber.Bytes())
		identifier = "purchase_order"
	case SALES:
		hFunc.Write(globalPurchaseOrderNumber)
		hFunc.Write(globalSalesOrderNumber)
		hFunc.Write(createdOn)
		identifier = "sales_order"
	case SHIPMENT:
		hFunc.Write(globalPurchaseOrderNumber)
		hFunc.Write(globalShipmentNumber)
		hFunc.Write(soldTo)
		identifier = "shipment_notification"
	case GOODS:
		hFunc.Write(globalPurchaseOrderNumber)
		hFunc.Write(globalGoodsReceiptNumber)
		hFunc.Write(goodsReceiptCreatedOn)
		identifier = "goods_receipt"
	case INVOICE:
		privKey, _ := eddsa.GenerateKey(rand.New(rand.NewSource(time.Now().UnixNano())))
		pubKey := privKey.PublicKey

		var invoiceData big.Int
		invoiceIntStr := "123456789123456789123456789123456789"
		invoiceData.SetString(invoiceIntStr, 10)
		invoiceDataBytes := invoiceData.Bytes()

		sigBytes, err := privKey.Sign(invoiceDataBytes, hFunc)
		if err != nil {
			return "", nil
		}

		verified, err := pubKey.Verify(sigBytes, invoiceDataBytes, hFunc)
		if err != nil || !verified {
			return "", nil
		}

		var sig eddsa.Signature
		sig.SetBytes(sigBytes)

		var point twistededwards.PointAffine
		pubKeyBytes := pubKey.Bytes()
		point.SetBytes(pubKeyBytes)
		xKey := point.X.Bytes()
		xKeyString := i.SetBytes(xKey[:]).String()
		yKey := point.Y.Bytes()
		yKeyString := i.SetBytes(yKey[:]).String()

		point.SetBytes(sigBytes)
		xSig := point.X.Bytes()
		xSigString := i.SetBytes(xSig[:]).String()
		ySig := point.Y.Bytes()
		ySigString := i.SetBytes(ySig[:]).String()
		sigLen := len(sigBytes) / 2
		sigS1String := i.SetBytes(sigBytes[sigLen : sigLen+sigLen/2]).String()
		sigS2String := i.SetBytes(sigBytes[sigLen+sigLen/2:]).String()

		return "invoice", map[string]interface{}{
			"Msg":        invoiceIntStr,
			"PubKey.A.X": xKeyString,
			"PubKey.A.Y": yKeyString,
			"Sig.R.X":    xSigString,
			"Sig.R.Y":    ySigString,
			"Sig.S1":     sigS1String,
			"Sig.S2":     sigS2String,
		}
	}

	hFunc.Write([]byte(proofString))
	hFunc.Write([]byte(creditRating))
	preImage := hFunc.Sum(nil)
	preImageString := i.SetBytes(preImage).String()

	// mimc Sum merely calls Write which never returns an error
	hash, _ := mimc.Sum("seed", preImage)
	hashString := i.SetBytes(hash).String()

	return identifier, map[string]interface{}{
		"Document.Preimage": preImageString,
		"Document.Hash":     hashString,
	}
}
