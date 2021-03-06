package ring

import (
	"io/ioutil"
	"reflect"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/sha3"
)

func TestPadTo32Bytes(t *testing.T) {
	in := []byte{1, 2, 3, 4, 5}
	out := PadTo32Bytes(in)
	if len(out) != 32 {
		t.Error("did not pad to 32 bytes")
	}
}

func TestSerializeAndDeserialize(t *testing.T) {
	privKey, err := crypto.HexToECDSA("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")
	if err != nil {
		t.Fatal(err)
	}

	file, err := ioutil.ReadFile("../message.txt")
	if err != nil {
		t.Fatal(err)
	}
	msgHash := sha3.Sum256(file)

	s := 7

	keyring, err := GenNewKeyRing(17, privKey, s)
	if err != nil {
		t.Fatal(err)
	}

	sig, err := Sign(msgHash, keyring, privKey, s)
	if err != nil {
		t.Fatal(err)
	}

	byteSig, err := sig.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	if len(byteSig) != 32*(3*sig.Size+4)+8 {
		t.Fatal("incorrect signature length")
	}

	marshalSig, err := Deserialize(byteSig)
	if err != nil {
		t.Fatal(err)
	}

	marshalOk := reflect.DeepEqual(marshalSig.S, sig.S) &&
		reflect.DeepEqual(marshalSig.Size, sig.Size) &&
		reflect.DeepEqual(marshalSig.C, sig.C) &&
		reflect.DeepEqual(marshalSig.M, sig.M) &&
		reflect.DeepEqual(marshalSig.I, sig.I)

	for i := 0; i < sig.Size; i++ {
		marshalOk = marshalOk && reflect.DeepEqual(marshalSig.L[i].X, sig.L[i].X)
		marshalOk = marshalOk && reflect.DeepEqual(marshalSig.L[i].Y, sig.L[i].Y)
	}

	if !marshalOk {
		t.Fatal("did not marshal to correct sig")
	}
}

func TestSerializeAndDeserializeAgain(t *testing.T) {
	privKey, err := crypto.HexToECDSA("358be44145ad16a1add8622786bef07e0b00391e072855a5667eb3c78b9d3803")
	if err != nil {
		t.Fatal(err)
	}

	file, err := ioutil.ReadFile("../message.txt")
	if err != nil {
		t.Fatal(err)
	}
	msgHash := sha3.Sum256(file)

	s := 9
	keyring, err := GenNewKeyRing(100, privKey, s)
	if err != nil {
		t.Fatal(err)
	}

	sig, err := Sign(msgHash, keyring, privKey, s)
	if err != nil {
		t.Fatal(err)
	}

	byteSig, err := sig.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	if len(byteSig) != 32*(3*sig.Size+4)+8 {
		t.Fatal("incorrect signature length")
	}

	marshalSig, err := Deserialize(byteSig)
	if err != nil {
		t.Fatal(err)
	}

	marshalOk := reflect.DeepEqual(marshalSig.S, sig.S) &&
		reflect.DeepEqual(marshalSig.Size, sig.Size) &&
		reflect.DeepEqual(marshalSig.C, sig.C) &&
		reflect.DeepEqual(marshalSig.M, sig.M) &&
		reflect.DeepEqual(marshalSig.I, sig.I)

	for i := 0; i < sig.Size; i++ {
		marshalOk = marshalOk && reflect.DeepEqual(marshalSig.L[i].X, sig.L[i].X)
		marshalOk = marshalOk && reflect.DeepEqual(marshalSig.L[i].Y, sig.L[i].Y)
	}

	if !marshalOk {
		t.Fatal("did not marshal to correct sig")
	}
}
