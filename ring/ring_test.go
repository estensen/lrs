package ring

import (
	"crypto/ecdsa"
	"crypto/rand"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/blake2b"
)

var (
	privKey *ecdsa.PrivateKey
	msgHash [32]byte
)

func TestGenerateKey(t *testing.T) {
	var err error
	privKey, err = crypto.GenerateKey()
	if err != nil {
		t.Error("Could not generate key-pair")
	}
}

func TestCreateMsgHash(t *testing.T) {
	msg := "helloworld"
	msgHash = blake2b.Sum256([]byte(msg))
}

func createSig(size int, s int) *RingSign {
	keyring, err := GenNewKeyRing(size, privKey, s)
	if err != nil {
		return nil
	}

	sig, err := Sign(msgHash, keyring, privKey, s)
	if err != nil {
		return nil
	}
	return sig
}

func TestGenNewKeyRing(t *testing.T) {
	keyring, err := GenNewKeyRing(2, privKey, 0)
	if err != nil {
		t.Error(err)
	}

	if len(keyring) != 2 {
		t.Error("could not generate keyring of size 2")
	} else {
		t.Log("generation of new keyring of size 2 ok")
	}
}

func TestGenNewKeyRing3(t *testing.T) {
	keyring, err := GenNewKeyRing(3, privKey, 1)
	if err != nil {
		t.Error(err)
	}

	if len(keyring) != 3 {
		t.Error("could not generate keyring of size 3")
	} else {
		t.Log("generation of new keyring of size 3 ok")
	}
}

func TestGenKeyRing(t *testing.T) {
	s := 0
	size := 3

	pubKeys := make([]*ecdsa.PublicKey, size)
	for i := 0; i < size; i++ {
		privKey, err := crypto.GenerateKey()
		if err != nil {
			t.Error(err)
		}

		pub := privKey.Public()
		pubKeys[i] = pub.(*ecdsa.PublicKey)
	}

	keyring, err := GenKeyRing(pubKeys, privKey, s)
	if err != nil {
		t.Error(err)
	}

	if len(keyring) != size+1 {
		t.Error("could not generate keyring of size 4")
	} else if keyring[s].X.Cmp(privKey.Public().(*ecdsa.PublicKey).X) != 0 {
		t.Error("secret index in ring is not signer")
	} else {
		t.Log("generation of new keyring of size 4 ok")
	}
}

func TestGenKeyImage(t *testing.T) {
	image := GenKeyImage(privKey)

	if image == nil {
		t.Error("could not generate key image")
	}
}

func TestHashPoint(t *testing.T) {
	p, err := crypto.GenerateKey()
	if err != nil {
		t.Error(err)
	}

	hx, hy := HashPoint(p.Public().(*ecdsa.PublicKey))
	if hx == nil || hy == nil {
		t.Error("did not hash point")
	}
}

func TestSign(t *testing.T) {
	keyring, err := GenNewKeyRing(2, privKey, 0)
	if err != nil {
		t.Error(err)
	}

	sig, err := Sign(msgHash, keyring, privKey, 0)
	if err != nil {
		t.Error("error when signing with ring size of 2")
	} else {
		t.Log("signing ok with ring size of 2")
		t.Log(sig)
	}
}

func TestSignAgain(t *testing.T) {
	keyring, err := GenNewKeyRing(100, privKey, 17)
	if err != nil {
		t.Error(err)
	}

	sig, err := Sign(msgHash, keyring, privKey, 17)
	if err != nil {
		t.Error("error when signing with ring size of 100")
	} else {
		t.Log("signing ok with ring size of 100")
		t.Log(sig)
	}
}

func TestVerify(t *testing.T) {
	sig := createSig(5, 4)
	if sig == nil {
		t.Error("signing error")
	}
	ver := Verify(sig)
	if !ver {
		t.Error("verified? false")
	}
}

func TestVerifyFalse(t *testing.T) {
	sig := createSig(5, 2)
	if sig == nil {
		t.Error("signing error")
	}
	curve := sig.L[0].Curve
	sig.C, _ = rand.Int(rand.Reader, curve.Params().P)
	ver := Verify(sig)
	if ver {
		t.Error("verified? true")
	}
}

func TestVerifyWrongMessage(t *testing.T) {
	sig := createSig(5, 1)
	if sig == nil {
		t.Error("signing error")
	}

	msg := "hello"
	msgHash := blake2b.Sum256([]byte(msg))
	sig.M = msgHash

	ver := Verify(sig)
	if ver {
		t.Error("verified? true")
	}
}

func TestLinkabilityTrue(t *testing.T) {
	keyring1, err := GenNewKeyRing(2, privKey, 0)
	if err != nil {
		t.Error(err)
	}

	sig1, err := Sign(msgHash, keyring1, privKey, 0)
	if err != nil {
		t.Error("error when signing with ring size of 2")
	} else {
		t.Log("signing ok with ring size of 2")
	}

	msg2 := "hello world"
	msgHash2 := blake2b.Sum256([]byte(msg2))

	keyring2, err := GenNewKeyRing(2, privKey, 0)
	if err != nil {
		t.Error(err)
	}

	sig2, err := Sign(msgHash2, keyring2, privKey, 0)
	if err != nil {
		t.Error("error when signing with ring size of 2")
	} else {
		t.Log("signing ok with ring size of 2")
	}

	link := Link(sig1, sig2)
	if link {
		t.Log("the signatures are linkable")
	} else {
		t.Error("linkable? false")
	}
}

func TestLinkabilityFalse(t *testing.T) {
	keyring1, err := GenNewKeyRing(2, privKey, 0)
	if err != nil {
		t.Error(err)
	}

	sig1, err := Sign(msgHash, keyring1, privKey, 0)
	if err != nil {
		t.Error("error when signing with ring size of 2")
	} else {
		t.Log("signing ok with ring size of 2")
		t.Log(sig1)
	}

	privKey2, err := crypto.GenerateKey()
	if err != nil {
		t.Error("Could not generate key-pair")
	}
	msg2 := "hello world"
	msgHash2 := blake2b.Sum256([]byte(msg2))

	keyring2, err := GenNewKeyRing(2, privKey2, 0)
	if err != nil {
		t.Error(err)
	}

	sig2, err := Sign(msgHash2, keyring2, privKey2, 0)
	if err != nil {
		t.Error("error when signing with ring size of 2")
	} else {
		t.Log("signing ok with ring size of 2")
		t.Log(sig2)
	}

	link := Link(sig1, sig2)
	if !link {
		t.Log("signatures signed with different private keys are not linkable")
	} else {
		t.Error("linkable? true")
	}
}
