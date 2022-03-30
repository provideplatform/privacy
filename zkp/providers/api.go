/*
 * Copyright 2017-2022 Provide Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package providers

const PreimageHashProver = "preimage_hash"

const RecursiveProofProver = "recursive_proof"

// // GnarkProverIdentifierCubic gnark cubic prover
// const GnarkProverIdentifierCubic = "cubic"

// // GnarkProverIdentifierOwnershipSk gnark ownership sk prover
// const GnarkProverIdentifierOwnershipSk = "ownership_sk"

// // GnarkProverIdentifierMimc gnark mimc prover
// const GnarkProverIdentifierMimc = "mimc"

// // GnarkProverIdentifierBaselineDocumentComplete baseline document complete prover
// const GnarkProverIdentifierBaselineDocumentComplete = "baseline_document_complete"

// // GnarkProverIdentifierBaselineRollup gnark prover
// const GnarkProverIdentifierBaselineRollup = "baseline_rollup"

// // GnarkProverIdentifierPurchaseOrderProver gnark prover
// const GnarkProverIdentifierPurchaseOrderProver = "purchase_order"

// // GnarkProverIdentifierSalesOrderProver gnark prover
// const GnarkProverIdentifierSalesOrderProver = "sales_order"

// // GnarkProverIdentifierShipmentNotificationProver gnark prover
// const GnarkProverIdentifierShipmentNotificationProver = "shipment_notification"

// // GnarkProverIdentifierGoodsReceiptProver gnark prover
// const GnarkProverIdentifierGoodsReceiptProver = "goods_receipt"

// // GnarkProverIdentifierInvoiceProver gnark prover
// const GnarkProverIdentifierInvoiceProver = "invoice"

// // GnarkProverIdentifierProofHashProver gnark prover
// const GnarkProverIdentifierProofHashProver = "proof_hash"

// // GnarkProverIdentifierProofEddsaProver gnark prover
// const GnarkProverIdentifierProofEddsaProver = "proof_eddsa"

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
