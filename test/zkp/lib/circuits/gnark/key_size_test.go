// +build unit

package gnark

import (
	"bytes"
	"encoding/hex"
	"io"
	"math/big"
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"

	frbls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	eddsabls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/twistededwards/eddsa"

	frbls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	eddsabls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards/eddsa"

	frbls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr"
	eddsabls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/twistededwards/eddsa"

	frbn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	eddsabn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"

	frbw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	eddsabw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/twistededwards/eddsa"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"

	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"

	"github.com/consensys/gnark/frontend"
	libgnark "github.com/provideplatform/privacy/zkp/lib/circuits/gnark"
)

type confSig struct {
	i ecc.ID
	h hash.Hash
	s signature.SignatureScheme
}

func bytesToFieldElementBytes(id ecc.ID, b []byte, v *frontend.Variable) []byte {
	switch id {
	case ecc.BLS12_377:
		var elem frbls12377.Element
		elem.SetBytes(b)
		elemBytes := elem.Bytes()
		v.Assign(elem)
		return elemBytes[:]
	case ecc.BLS12_381:
		var elem frbls12381.Element
		elem.SetBytes(b)
		elemBytes := elem.Bytes()
		v.Assign(elem)
		return elemBytes[:]
	case ecc.BLS24_315:
		var elem frbls24315.Element
		elem.SetBytes(b)
		elemBytes := elem.Bytes()
		v.Assign(elem)
		return elemBytes[:]
	case ecc.BN254:
		var elem frbn254.Element
		elem.SetBytes(b)
		elemBytes := elem.Bytes()
		v.Assign(elem)
		return elemBytes[:]
	case ecc.BW6_761:
		var elem frbw6761.Element
		elem.SetBytes(b)
		elemBytes := elem.Bytes()
		v.Assign(elem)
		return elemBytes[:]
	}
	return nil
}

func keySizeTestWitnessFactory(name *string, id ecc.ID, h hash.Hash, s signature.SignatureScheme, assignValues bool) frontend.Circuit {
	switch *name {
	case "cubic":
		var witness libgnark.CubicCircuit
		if assignValues {
			witness.X.Assign(3)
			witness.Y.Assign(35)
		}
		return &witness
	case "mimc":
		var witness libgnark.MimcCircuit
		if assignValues {
			hFunc := h.New("seed")
			var preImage big.Int
			preImage.SetString("35", 10)
			hFunc.Write(preImage.Bytes())
			hash := hFunc.Sum(nil)
			witness.Preimage.Assign(preImage)
			witness.Hash.Assign(hash)
		}
		return &witness
	case "purchase_order":
		var witness libgnark.PurchaseOrderCircuit
		if assignValues {
			hFunc := h.New("seed")
			var preImage big.Int
			preImage.SetString("35", 10)
			hFunc.Write(preImage.Bytes())
			hash := hFunc.Sum(nil)
			witness.Document.Preimage.Assign(preImage)
			witness.Document.Hash.Assign(hash)
		}
		return &witness
	case "sales_order":
		var witness libgnark.SalesOrderCircuit
		if assignValues {
			hFunc := h.New("seed")
			var preImage big.Int
			preImage.SetString("35", 10)
			hFunc.Write(preImage.Bytes())
			hash := hFunc.Sum(nil)
			witness.Document.Preimage.Assign(preImage)
			witness.Document.Hash.Assign(hash)
		}
		return &witness
	case "shipment_notification":
		var witness libgnark.ShipmentNotificationCircuit
		if assignValues {
			hFunc := h.New("seed")
			var preImage big.Int
			preImage.SetString("35", 10)
			hFunc.Write(preImage.Bytes())
			hash := hFunc.Sum(nil)
			witness.Document.Preimage.Assign(preImage)
			witness.Document.Hash.Assign(hash)
		}
		return &witness
	case "goods_receipt":
		var witness libgnark.GoodsReceiptCircuit
		if assignValues {
			hFunc := h.New("seed")
			var preImage big.Int
			preImage.SetString("35", 10)
			hFunc.Write(preImage.Bytes())
			hash := hFunc.Sum(nil)
			witness.Document.Preimage.Assign(preImage)
			witness.Document.Hash.Assign(hash)
		}
		return &witness
	case "invoice":
		var witness libgnark.InvoiceCircuit
		if assignValues {
			hFunc := h.New("seed")
			var preImage big.Int
			preImage.SetString("35", 10)
			hFunc.Write(preImage.Bytes())
			hash := hFunc.Sum(nil)
			witness.Document.Preimage.Assign(preImage)
			witness.Document.Hash.Assign(hash)
		}
		return &witness
	case "proof_eddsa":
		var witness libgnark.ProofEddsaCircuit
		if assignValues {
			proofString := "9f3aac14a60502ce8a8084d876e9da3ac85191aadc25003d3f81a41eff1f5a389b1177672ca50ee865a9a0563479ea316571d3f3895ab914a4312378f6e89e781dd0447826aebeb42335ec2ab89cd41fea4d797a376d621bf139b5030f873e3487eb40948f4c58dab967ea2e890c722e2ba85d8caa0afdb6301d360d27d966c0"
			proofBytes, _ := hex.DecodeString(proofString)

			src := rand.NewSource(0)
			r := rand.New(src)
			privKey, _ := s.New(r)
			pubKey := privKey.Public()
			pubkeyAx, pubkeyAy := parsePoint(id, pubKey.Bytes())

			hFunc := h.New("seed")
			chunks := len(witness.Msg)
			chunkSize := 32
			if id == ecc.BW6_761 {
				chunkSize = 48
			}
			for index := 0; index < chunks; index++ {
				var b []byte
				b = make([]byte, chunkSize)
				if index*chunkSize < len(proofBytes) {
					b = bytesToFieldElementBytes(id, proofBytes[index*chunkSize:(index+1)*chunkSize], &witness.Msg[index])
				} else {
					b = bytesToFieldElementBytes(id, b, &witness.Msg[index])
				}
				hFunc.Write(b[:])
			}
			hash := hFunc.Sum(nil)
			sig, _ := privKey.Sign(hash, hFunc)
			sigRx, sigRy, sigS1, sigS2 := parseSignature(id, sig)

			witness.PubKey.A.X.Assign(pubkeyAx)
			witness.PubKey.A.Y.Assign(pubkeyAy)
			witness.Sig.R.X.Assign(sigRx)
			witness.Sig.R.Y.Assign(sigRy)
			witness.Sig.S1.Assign(sigS1)
			witness.Sig.S2.Assign(sigS2)
		}
		return &witness
	}
	return nil
}

func TestKeySizesGroth16(t *testing.T) {
	assert := groth16.NewAssert(t)

	signature.Register(signature.EDDSA_BN254, eddsabn254.GenerateKeyInterfaces)
	signature.Register(signature.EDDSA_BLS12_381, eddsabls12381.GenerateKeyInterfaces)
	signature.Register(signature.EDDSA_BLS12_377, eddsabls12377.GenerateKeyInterfaces)
	signature.Register(signature.EDDSA_BW6_761, eddsabw6761.GenerateKeyInterfaces)
	signature.Register(signature.EDDSA_BLS24_315, eddsabls24315.GenerateKeyInterfaces)

	confs := []confSig{
		{ecc.BN254, hash.MIMC_BN254, signature.EDDSA_BN254},
		{ecc.BLS12_381, hash.MIMC_BLS12_381, signature.EDDSA_BLS12_381},
		{ecc.BLS12_377, hash.MIMC_BLS12_377, signature.EDDSA_BLS12_377},
		{ecc.BW6_761, hash.MIMC_BW6_761, signature.EDDSA_BW6_761},
		{ecc.BLS24_315, hash.MIMC_BLS24_315, signature.EDDSA_BLS24_315},
	}

	circuits := []string{
		"cubic",
		"mimc",
		"purchase_order",
		"sales_order",
		"shipment_notification",
		"goods_receipt",
		"invoice",
		"proof_eddsa",
	}

	for _, circuitName := range circuits {
		for _, conf := range confs {
			circuit := keySizeTestWitnessFactory(&circuitName, conf.i, conf.h, conf.s, false)
			r1cs, err := frontend.Compile(conf.i, backend.GROTH16, circuit)
			assert.NoError(err)

			{
				witness := keySizeTestWitnessFactory(&circuitName, conf.i, conf.h, conf.s, true)
				pk, vk, err := groth16.Setup(r1cs)
				assert.NoError(err, "Generating public data should not have failed")

				proof, err := groth16.Prove(r1cs, pk, witness)
				assert.NoError(err, "Proving with good witness should not output an error")

				buf := new(bytes.Buffer)
				_, err = pk.(io.WriterTo).WriteTo(buf)
				if err != nil {
					t.Errorf("failed to write proving key to buffer")
				}

				pkSize := buf.Len()

				buf.Reset()
				_, err = vk.(io.WriterTo).WriteTo(buf)
				if err != nil {
					t.Errorf("failed to write verifying key to buffer")
				}

				vkSize := buf.Len()

				buf.Reset()
				_, err = proof.(io.WriterTo).WriteTo(buf)
				if err != nil {
					t.Errorf("failed to write proof to buffer")
				}

				t.Logf("circuit: %21s | curve: %9s | pk size: %8d | vk size: %4d | pf size: %4d\n", circuitName, conf.i.String(), pkSize, vkSize, buf.Len())

				err = groth16.Verify(proof, vk, witness)
				assert.NoError(err, "Verifying correct proof with correct witness should not output an error")
			}
		}
	}

}

func TestKeySizesPlonk(t *testing.T) {
	assert := plonk.NewAssert(t)

	signature.Register(signature.EDDSA_BN254, eddsabn254.GenerateKeyInterfaces)
	signature.Register(signature.EDDSA_BLS12_381, eddsabls12381.GenerateKeyInterfaces)
	signature.Register(signature.EDDSA_BLS12_377, eddsabls12377.GenerateKeyInterfaces)
	signature.Register(signature.EDDSA_BW6_761, eddsabw6761.GenerateKeyInterfaces)
	signature.Register(signature.EDDSA_BLS24_315, eddsabls24315.GenerateKeyInterfaces)

	confs := []confSig{
		{ecc.BN254, hash.MIMC_BN254, signature.EDDSA_BN254},
		{ecc.BLS12_381, hash.MIMC_BLS12_381, signature.EDDSA_BLS12_381},
		{ecc.BLS12_377, hash.MIMC_BLS12_377, signature.EDDSA_BLS12_377},
		{ecc.BW6_761, hash.MIMC_BW6_761, signature.EDDSA_BW6_761},
		{ecc.BLS24_315, hash.MIMC_BLS24_315, signature.EDDSA_BLS24_315},
	}

	circuits := []string{
		"cubic",
		"mimc",
		"purchase_order",
		"sales_order",
		"shipment_notification",
		"goods_receipt",
		"invoice",
		"proof_eddsa",
	}

	for _, circuitName := range circuits {
		for _, conf := range confs {
			circuit := keySizeTestWitnessFactory(&circuitName, conf.i, conf.h, conf.s, false)
			r1cs, err := frontend.Compile(conf.i, backend.PLONK, circuit)
			assert.NoError(err)

			{
				kzgSRS, err := getKzgScheme(r1cs)
				assert.NoError(err, "Getting KZG scheme should not have failed")

				pk, vk, err := plonk.Setup(r1cs, kzgSRS)
				assert.NoError(err, "Generating public data should not have failed")

				witness := keySizeTestWitnessFactory(&circuitName, conf.i, conf.h, conf.s, true)
				proof, err := plonk.Prove(r1cs, pk, witness)
				assert.NoError(err, "Proving with good witness should not output an error")

				buf := new(bytes.Buffer)
				_, err = pk.(io.WriterTo).WriteTo(buf)
				if err != nil {
					t.Errorf("failed to write proving key to buffer")
				}

				pkSize := buf.Len()

				buf.Reset()
				_, err = vk.(io.WriterTo).WriteTo(buf)
				if err != nil {
					t.Errorf("failed to write verifying key to buffer")
				}

				vkSize := buf.Len()

				buf.Reset()
				_, err = proof.(io.WriterTo).WriteTo(buf)
				if err != nil {
					t.Errorf("failed to write proof to buffer")
				}

				t.Logf("circuit: %21s | curve: %9s | pk size: %8d | vk size: %4d | pf size: %4d\n", circuitName, conf.i.String(), pkSize, vkSize, buf.Len())

				err = plonk.Verify(proof, vk, witness)
				assert.NoError(err, "Verifying correct proof with correct witness should not output an error")
			}
		}
	}

}

type ProofHashSizeTestCircuit struct {
	Proof []frontend.Variable
	Hash  frontend.Variable `gnark:",public"`
}

// Define declares the circuit constraints
func (circuit *ProofHashSizeTestCircuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	hFunc, err := mimc.NewMiMC("seed", curveID)
	if err != nil {
		return err
	}

	hash := hFunc.Hash(cs, circuit.Proof[:]...)
	cs.AssertIsEqual(hash, circuit.Hash)

	return nil
}

func TestKeySizesByHashWitnessSize(t *testing.T) {
	assert := plonk.NewAssert(t)

	// in testing, proving keys increased in size for count == 1, 2, 3, 4, 6, 8, 11, 16, 22, 31, 44, 62
	// then go test errored on 72
	for count := 70; count <= 100; count++ {
		id, h := ecc.BN254, hash.MIMC_BN254

		var circuit, witness ProofHashSizeTestCircuit

		circuit.Proof = make([]frontend.Variable, count)

		r1cs, err := frontend.Compile(id, backend.PLONK, &circuit)
		assert.NoError(err)

		kzgSRS, err := getKzgScheme(r1cs)
		assert.NoError(err, "Getting KZG scheme should not have failed")

		pk, vk, err := plonk.Setup(r1cs, kzgSRS)
		assert.NoError(err, "Generating public data should not have failed")

		buf := new(bytes.Buffer)
		_, err = pk.(io.WriterTo).WriteTo(buf)
		if err != nil {
			t.Errorf("failed to write proving key to buffer")
		}

		pkSize := buf.Len()

		witness.Proof = make([]frontend.Variable, count)

		proofString := "9f3aac14a60502ce8a8084d876e9da3ac85191aadc25003d3f81a41eff1f5a389b1177672ca50ee865a9a0563479ea316571d3f3895ab914a4312378f6e89e781dd0447826aebeb42335ec2ab89cd41fea4d797a376d621bf139b5030f873e3487eb40948f4c58dab967ea2e890c722e2ba85d8caa0afdb6301d360d27d966c0"
		proofBytes, _ := hex.DecodeString(proofString)

		var i big.Int

		hFunc := h.New("seed")
		chunks := len(witness.Proof)
		chunkSize := 32
		if id == ecc.BW6_761 {
			chunkSize = 48
		}
		for index := 0; index < chunks; index++ {
			var b []byte
			b = make([]byte, chunkSize)
			if index*chunkSize < len(proofBytes) {
				b = bytesToFieldElementBytes(id, proofBytes[index*chunkSize:(index+1)*chunkSize], &witness.Proof[index])
			} else {
				b = bytesToFieldElementBytes(id, b, &witness.Proof[index])
			}
			hFunc.Write(b[:])
		}
		i.SetBytes(hFunc.Sum(nil))
		witness.Hash.Assign(i)

		proof, err := plonk.Prove(r1cs, pk, &witness)
		assert.NoError(err, "Proving with good witness should not output an error")

		buf.Reset()
		_, err = vk.(io.WriterTo).WriteTo(buf)
		if err != nil {
			t.Errorf("failed to write verifying key to buffer")
		}

		vkSize := buf.Len()

		buf.Reset()
		_, err = proof.(io.WriterTo).WriteTo(buf)
		if err != nil {
			t.Errorf("failed to write proof to buffer")
		}

		t.Logf("chunks: %5d | bytes: %5d | curve: %9s | pk size: %10d | vk size: %4d | pf size: %4d\n", count, chunkSize*count, id.String(), pkSize, vkSize, buf.Len())

		err = plonk.Verify(proof, vk, &witness)
		assert.NoError(err, "Verifying correct proof with correct witness should not output an error")
	}
}

type ProofEddsaSizeTestCircuit struct {
	Msg    []frontend.Variable
	PubKey eddsa.PublicKey `gnark:",public"`
	Sig    eddsa.Signature `gnark:",public"`
}

// Define declares the ProofEddsaCircuit circuit constraints
func (circuit *ProofEddsaSizeTestCircuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	curve, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}
	circuit.PubKey.Curve = curve

	hFunc, err := mimc.NewMiMC("seed", curveID)
	if err != nil {
		return err
	}

	hash := hFunc.Hash(cs, circuit.Msg[:]...)
	eddsa.Verify(cs, circuit.Sig, hash, circuit.PubKey)

	return nil
}

func TestKeySizesByEddsaWitnessSize(t *testing.T) {
	assert := plonk.NewAssert(t)

	// in testing, proving keys increased in size for count == 1, 8, 18, 29, 42, 61 (855638832 bytes)
	// then go test crashed on 87 with heavy RAM usage on a 32gb system
	for count := 1; count <= 86; count++ {
		id, h, s := ecc.BN254, hash.MIMC_BN254, signature.EDDSA_BN254

		var circuit, witness ProofEddsaSizeTestCircuit

		circuit.Msg = make([]frontend.Variable, count)

		r1cs, err := frontend.Compile(id, backend.PLONK, &circuit)
		assert.NoError(err)

		kzgSRS, err := getKzgScheme(r1cs)
		assert.NoError(err, "Getting KZG scheme should not have failed")

		pk, vk, err := plonk.Setup(r1cs, kzgSRS)
		assert.NoError(err, "Generating public data should not have failed")

		buf := new(bytes.Buffer)
		_, err = pk.(io.WriterTo).WriteTo(buf)
		if err != nil {
			t.Errorf("failed to write proving key to buffer")
		}

		pkSize := buf.Len()

		witness.Msg = make([]frontend.Variable, count)

		proofString := "9f3aac14a60502ce8a8084d876e9da3ac85191aadc25003d3f81a41eff1f5a389b1177672ca50ee865a9a0563479ea316571d3f3895ab914a4312378f6e89e781dd0447826aebeb42335ec2ab89cd41fea4d797a376d621bf139b5030f873e3487eb40948f4c58dab967ea2e890c722e2ba85d8caa0afdb6301d360d27d966c0"
		proofBytes, _ := hex.DecodeString(proofString)

		src := rand.NewSource(0)
		r := rand.New(src)
		privKey, _ := s.New(r)
		pubKey := privKey.Public()
		pubkeyAx, pubkeyAy := parsePoint(id, pubKey.Bytes())

		hFunc := h.New("seed")
		chunks := len(witness.Msg)
		chunkSize := 32
		if id == ecc.BW6_761 {
			chunkSize = 48
		}
		for index := 0; index < chunks; index++ {
			var b []byte
			b = make([]byte, chunkSize)
			if index*chunkSize < len(proofBytes) {
				b = bytesToFieldElementBytes(id, proofBytes[index*chunkSize:(index+1)*chunkSize], &witness.Msg[index])
			} else {
				b = bytesToFieldElementBytes(id, b, &witness.Msg[index])
			}
			hFunc.Write(b[:])
		}
		hash := hFunc.Sum(nil)
		sig, _ := privKey.Sign(hash, hFunc)
		sigRx, sigRy, sigS1, sigS2 := parseSignature(id, sig)

		witness.PubKey.A.X.Assign(pubkeyAx)
		witness.PubKey.A.Y.Assign(pubkeyAy)
		witness.Sig.R.X.Assign(sigRx)
		witness.Sig.R.Y.Assign(sigRy)
		witness.Sig.S1.Assign(sigS1)
		witness.Sig.S2.Assign(sigS2)

		proof, err := plonk.Prove(r1cs, pk, &witness)
		assert.NoError(err, "Proving with good witness should not output an error")

		buf.Reset()
		_, err = vk.(io.WriterTo).WriteTo(buf)
		if err != nil {
			t.Errorf("failed to write verifying key to buffer")
		}

		vkSize := buf.Len()

		buf.Reset()
		_, err = proof.(io.WriterTo).WriteTo(buf)
		if err != nil {
			t.Errorf("failed to write proof to buffer")
		}

		t.Logf("chunks: %5d | bytes: %5d | curve: %9s | pk size: %10d | vk size: %4d | pf size: %4d\n", count, chunkSize*count, id.String(), pkSize, vkSize, buf.Len())

		err = plonk.Verify(proof, vk, &witness)
		assert.NoError(err, "Verifying correct proof with correct witness should not output an error")
	}
}

func TestKeySizesForMerkleCircuit(t *testing.T) {
	assert := plonk.NewAssert(t)

	confs := map[ecc.ID]hash.Hash{
		ecc.BN254:     hash.MIMC_BN254,
		ecc.BLS12_381: hash.MIMC_BLS12_381,
		ecc.BLS12_377: hash.MIMC_BLS12_377,
		ecc.BW6_761:   hash.MIMC_BW6_761,
		ecc.BLS24_315: hash.MIMC_BLS24_315,
	}

	for id, h := range confs {
		for count := 8192; count <= 10000; count *= 2 {
			hFunc := h.New("seed")

			var pfbuf bytes.Buffer

			proofString := "aa5500ca9af223afdec21989169de5c63938274908f09ee85a233fd1a7396bba89ea271a41a7d38014dfffbdcbe806d0726c5dc4eef7f178ea52de45852697d51f2c74152e1fbbed79ebdfd1235788ea2b1637e6ed49a33a05653133e21a5cfdaa86f1acc9588b17838f8da88a5398cb324b1289aa7759457ddccddf53ee1ca9"

			for i := 0; i < count; i++ {
				hFunc.Reset()
				hFunc.Write([]byte(proofString))
				sum := hFunc.Sum(nil)
				pfbuf.Write(sum)
			}

			proofIndex := uint64(0)
			segmentSize := hFunc.Size()
			merkleRoot, proofSet, numLeaves, err := merkletree.BuildReaderProof(&pfbuf, hFunc, segmentSize, proofIndex)
			if err != nil {
				t.Errorf("failed to build merkle proof; %s", err.Error())
				return
			}

			proofVerified := merkletree.VerifyProof(hFunc, merkleRoot, proofSet, proofIndex, numLeaves)
			if !proofVerified {
				t.Errorf("failed to verify merkle proof; %s", err.Error())
				return
			}

			var circuit, witness libgnark.BaselineRollupCircuit

			circuit.Proofs = make([]frontend.Variable, len(proofSet))
			circuit.Helpers = make([]frontend.Variable, len(proofSet)-1)

			r1cs, err := frontend.Compile(id, backend.PLONK, &circuit)
			assert.NoError(err)

			kzgSRS, err := getKzgScheme(r1cs)
			assert.NoError(err, "Getting KZG scheme should not have failed")

			merkleProofHelper := merkle.GenerateProofHelper(proofSet, proofIndex, numLeaves)

			witness.Proofs = make([]frontend.Variable, len(proofSet))
			witness.Helpers = make([]frontend.Variable, len(proofSet)-1)
			witness.RootHash.Assign(merkleRoot)
			for i := 0; i < len(proofSet); i++ {
				witness.Proofs[i].Assign(proofSet[i])

				if i < len(proofSet)-1 {
					witness.Helpers[i].Assign(merkleProofHelper[i])
				}
			}

			pk, vk, err := plonk.Setup(r1cs, kzgSRS)
			assert.NoError(err, "Generating public data should not have failed")

			buf := new(bytes.Buffer)
			_, err = pk.(io.WriterTo).WriteTo(buf)
			if err != nil {
				t.Errorf("failed to write proving key to buffer")
			}

			pkSize := buf.Len()

			proof, err := plonk.Prove(r1cs, pk, &witness)
			assert.NoError(err, "Proving with good witness should not output an error")

			buf.Reset()
			_, err = vk.(io.WriterTo).WriteTo(buf)
			if err != nil {
				t.Errorf("failed to write verifying key to buffer")
			}

			vkSize := buf.Len()

			buf.Reset()
			_, err = proof.(io.WriterTo).WriteTo(buf)
			if err != nil {
				t.Errorf("failed to write proof to buffer")
			}

			t.Logf("chunks: %5d | set sz: %5d | curve: %9s | pk size: %10d | vk size: %4d | pf size: %4d\n", count, len(proofSet), id.String(), pkSize, vkSize, buf.Len())

			var publicWitness libgnark.BaselineRollupCircuit

			publicWitness.Proofs = make([]frontend.Variable, len(proofSet))
			publicWitness.Helpers = make([]frontend.Variable, len(proofSet)-1)
			publicWitness.RootHash.Assign(merkleRoot)

			err = plonk.Verify(proof, vk, &publicWitness)
			assert.NoError(err, "Verifying correct proof with correct witness should not output an error")
		}
	}
}
