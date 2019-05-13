package ring

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/blake2b"
)

type Ring []*ecdsa.PublicKey

type RingSign struct {
	Size  int              // size of ring
	M     [32]byte         // message
	C     *big.Int         // ring signature value
	S     []*big.Int       // ring signature values
	Ring  Ring             // array of public keys
	I     *ecdsa.PublicKey // key image
	Curve elliptic.Curve
}

// Bytes returns the public key ring as a byte slice.
func (r Ring) Bytes() (b []byte) {
	for _, pub := range r {
		b = append(b, pub.X.Bytes()...)
		b = append(b, pub.Y.Bytes()...)
	}
	return
}

func PadTo32Bytes(in []byte) (out []byte) {
	out = append(out, in...)
	for {
		if len(out) == 32 {
			return
		}
		out = append([]byte{0}, out...)
	}
}

// Serialize converts the signature to a byte array
func (r *RingSign) Serialize() ([]byte, error) {
	var sig []byte
	// add size and message
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(r.Size))
	sig = append(sig, b[:]...)                      // 8 bytes
	sig = append(sig, PadTo32Bytes(r.M[:])...)      // 32 bytes
	sig = append(sig, PadTo32Bytes(r.C.Bytes())...) // 32 bytes

	// 96 bytes each iteration
	for i := 0; i < r.Size; i++ {
		sig = append(sig, PadTo32Bytes(r.S[i].Bytes())...)
		sig = append(sig, PadTo32Bytes(r.Ring[i].X.Bytes())...)
		sig = append(sig, PadTo32Bytes(r.Ring[i].Y.Bytes())...)
	}

	// 64 bytes
	sig = append(sig, PadTo32Bytes(r.I.X.Bytes())...)
	sig = append(sig, PadTo32Bytes(r.I.Y.Bytes())...)

	if len(sig) != 32*(3*r.Size+4)+8 {
		return []byte{}, errors.New("could not serialize ring signature")
	}

	return sig, nil
}

// Deserialize converts the byteified signature into a RingSign struct
func Deserialize(r []byte) (*RingSign, error) {
	sig := new(RingSign)
	size := r[0:8]

	if len(r) < 72 {
		return nil, errors.New("incorrect ring size")
	}

	m := r[8:40]

	var mByte [32]byte
	copy(mByte[:], m)

	size_uint := binary.BigEndian.Uint64(size)
	size_int := int(size_uint)

	sig.Size = size_int
	sig.M = mByte
	sig.C = new(big.Int).SetBytes(r[40:72])

	byteLen := size_int * 96

	if len(r) < byteLen+136 {
		return nil, errors.New("incorrect ring size")
	}

	j := 0
	sig.S = make([]*big.Int, size_int)
	sig.Ring = make([]*ecdsa.PublicKey, size_int)

	for i := 72; i < byteLen; i += 96 {
		si := r[i : i+32]
		xi := r[i+32 : i+64]
		yi := r[i+64 : i+96]

		sig.S[j] = new(big.Int).SetBytes(si)
		sig.Ring[j] = new(ecdsa.PublicKey)
		sig.Ring[j].X = new(big.Int).SetBytes(xi)
		sig.Ring[j].Y = new(big.Int).SetBytes(yi)
		sig.Ring[j].Curve = crypto.S256()
		j++
	}

	sig.I = new(ecdsa.PublicKey)
	sig.I.X = new(big.Int).SetBytes(r[byteLen+72 : byteLen+104])
	sig.I.Y = new(big.Int).SetBytes(r[byteLen+104 : byteLen+136])
	sig.Curve = crypto.S256()

	return sig, nil
}

// GenKeyRing takes public key ring and places the public key corresponding to `privKey` in index s of the ring
// Returns a key ring of type []*ecdsa.PublicKey
func GenKeyRing(ring []*ecdsa.PublicKey, privKey *ecdsa.PrivateKey, s int) ([]*ecdsa.PublicKey, error) {
	size := len(ring) + 1
	newRing := make([]*ecdsa.PublicKey, size)
	pubKey := privKey.Public().(*ecdsa.PublicKey)

	if s > len(ring) {
		return nil, errors.New("index s out of bounds")
	}

	newRing[s] = pubKey
	for i := 1; i < size; i++ {
		idx := (i + s) % size
		newRing[idx] = ring[i-1]
	}

	return newRing, nil
}

// GenNewKeyRing creates a ring with size specified by `size` and places the public key corresponding to `privKey` in index s of the ring
// Returns a new key ring of type []*ecdsa.PublicKey
func GenNewKeyRing(size int, privKey *ecdsa.PrivateKey, s int) ([]*ecdsa.PublicKey, error) {
	ring := make([]*ecdsa.PublicKey, size)
	pubKey := privKey.Public().(*ecdsa.PublicKey)

	if s > len(ring) {
		return nil, errors.New("index s out of bounds")
	}

	ring[s] = pubKey

	for i := 1; i < size; i++ {
		idx := (i + s) % size
		priv, err := crypto.GenerateKey()
		if err != nil {
			return nil, err
		}

		pub := priv.Public()
		ring[idx] = pub.(*ecdsa.PublicKey)
	}

	return ring, nil
}

// GenKeyImage calculates key image I = x * H_p(P) where H_p is a hash function that returns a point
// H_p(P) = blake2b(P) * G
func GenKeyImage(privKey *ecdsa.PrivateKey) *ecdsa.PublicKey {
	pubKey := privKey.Public().(*ecdsa.PublicKey)
	image := new(ecdsa.PublicKey)

	// blake2b(P)
	hx, hy := HashPoint(pubKey)

	// H_p(P) = x * blake2b(P) * G
	ix, iy := privKey.Curve.ScalarMult(hx, hy, privKey.D.Bytes())

	image.X = ix
	image.Y = iy
	return image
}

// HashPoint returns point on the curve
func HashPoint(p *ecdsa.PublicKey) (hx, hy *big.Int) {
	hash := blake2b.Sum256(append(p.X.Bytes(), p.Y.Bytes()...))
	return p.Curve.ScalarBaseMult(hash[:]) // g^H'()
}

// Sign creates a ring signature from list of public keys given inputs:
// msg: byte array, message to be signed
// ring: array of *ecdsa.PublicKeys to be included in the ring
// privKey: *ecdsa.PrivateKey of signer
// s: index of signer in ring
func Sign(m [32]byte, ring []*ecdsa.PublicKey, privKey *ecdsa.PrivateKey, s int) (*RingSign, error) {
	ringSize := len(ring)
	if ringSize < 2 {
		return nil, errors.New("size of ring less than two")
	} else if s >= ringSize || s < 0 {
		return nil, errors.New("secret index out of range of ring size")
	}

	// setup
	pubKey := &privKey.PublicKey
	curve := pubKey.Curve
	sig := new(RingSign)
	sig.Size = ringSize
	sig.M = m
	sig.Ring = ring
	sig.Curve = curve

	// check that key at index s is indeed the signer
	if ring[s] != pubKey {
		return nil, errors.New("secret index in ring is not signer")
	}

	// generate key image
	image := GenKeyImage(privKey)
	sig.I = image

	// start at c[1]
	// pick random scalar u (glue value), calculate c[1] = H(m, u*G) where H is a hash function and G is the base point of the curve
	C := make([]*big.Int, ringSize)
	S := make([]*big.Int, ringSize)

	// pick random scalar u
	u, err := rand.Int(rand.Reader, curve.Params().P)
	if err != nil {
		return nil, err
	}

	// start at secret index s
	// L_s = u*G
	lx, ly := curve.ScalarBaseMult(u.Bytes())
	// R_s = u*H_p(P[s])
	hx, hy := HashPoint(pubKey)
	rx, ry := curve.ScalarMult(hx, hy, u.Bytes())

	l := append(lx.Bytes(), ly.Bytes()...)
	r := append(rx.Bytes(), ry.Bytes()...)

	// concatenate m and u*G and calculate c[s+1] = H(m, L_s, R_s)
	Ci := blake2b.Sum256(append(m[:], append(l, r...)...))
	idx := (s + 1) % ringSize
	C[idx] = new(big.Int).SetBytes(Ci[:])

	// start loop at s+1
	for i := 1; i < ringSize; i++ {
		idx := (s + i) % ringSize

		// pick random scalar si
		si, err := rand.Int(rand.Reader, curve.Params().P)
		S[idx] = si
		if err != nil {
			return nil, err
		}

		if curve == nil {
			return nil, errors.New(fmt.Sprintf("No curve at index %d", idx))
		}
		if ring[idx] == nil {
			return nil, errors.New(fmt.Sprintf("No public key at index %d", idx))
		}

		// L_i = si*G + Ci*P_i
		px, py := curve.ScalarMult(ring[idx].X, ring[idx].Y, C[idx].Bytes()) // px, py = Ci*P_i
		sx, sy := curve.ScalarBaseMult(si.Bytes())                           // sx, sy = s[n-1]*G
		lx, ly := curve.Add(sx, sy, px, py)

		// R_i = si*H_p(P_i) + Ci*I
		px, py = curve.ScalarMult(image.X, image.Y, C[idx].Bytes()) // px, py = Ci*I
		hx, hy := HashPoint(ring[idx])
		sx, sy = curve.ScalarMult(hx, hy, si.Bytes()) // sx, sy = s[n-1]*H_p(P_i)
		rx, ry := curve.Add(sx, sy, px, py)

		// c[i+1] = H(m, L_i, R_i)
		l := append(lx.Bytes(), ly.Bytes()...)
		r := append(rx.Bytes(), ry.Bytes()...)
		Ci = blake2b.Sum256(append(m[:], append(l, r...)...))

		if i == ringSize-1 {
			C[s] = new(big.Int).SetBytes(Ci[:])
		} else {
			C[(idx+1)%ringSize] = new(big.Int).SetBytes(Ci[:])
		}
	}

	// close ring by finding S[s] = ( u - c[s]*k[s] ) mod P where k[s] is the private key and P is the order of the curve
	S[s] = new(big.Int).Mod(new(big.Int).Sub(u, new(big.Int).Mul(C[s], privKey.D)), curve.Params().N)

	// check that u*G = S[s]*G + c[s]*P[s]
	ux, uy := curve.ScalarBaseMult(u.Bytes()) // u*G
	px, py := curve.ScalarMult(ring[s].X, ring[s].Y, C[s].Bytes())
	sx, sy := curve.ScalarBaseMult(S[s].Bytes())
	lx, ly = curve.Add(sx, sy, px, py)

	// check that u*H_p(P[s]) = S[s]*H_p(P[s]) + C[s]*I
	px, py = curve.ScalarMult(image.X, image.Y, C[s].Bytes()) // px, py = C[s]*I
	hx, hy = HashPoint(ring[s])
	tx, ty := curve.ScalarMult(hx, hy, u.Bytes())
	sx, sy = curve.ScalarMult(hx, hy, S[s].Bytes()) // sx, sy = S[s]*H_p(P[s])
	rx, ry = curve.Add(sx, sy, px, py)

	l = append(lx.Bytes(), ly.Bytes()...)
	r = append(rx.Bytes(), ry.Bytes()...)

	// check that H(m, L[s], R[s]) == C[s+1]
	Ci = blake2b.Sum256(append(m[:], append(l, r...)...))

	if !bytes.Equal(ux.Bytes(), lx.Bytes()) || !bytes.Equal(uy.Bytes(), ly.Bytes()) || !bytes.Equal(tx.Bytes(), rx.Bytes()) || !bytes.Equal(ty.Bytes(), ry.Bytes()) {
		//|| !bytes.Equal(C[(s+1)%ringSize].Bytes(), Ci[:]) {
		return nil, errors.New("error closing ring")
	}

	// everything ok, add values to signature
	sig.S = S
	sig.C = C[0]

	return sig, nil
}

// Verify checks the validity of the ring signature contained in RingSign struct
// returns true if a valid signature, false otherwise
func Verify(sig *RingSign) bool {
	// setup
	ring := sig.Ring
	ringSize := sig.Size
	S := sig.S
	C := make([]*big.Int, ringSize)
	C[0] = sig.C
	curve := sig.Curve
	image := sig.I

	// c[i+1] = H(m, s[i]*G + c[i]*P[i]) and c[0] = H)(m, s[n-1]*G + c[n-1]*P[n-1]) where n is the ring size
	for i := 0; i < ringSize; i++ {
		// calculate L_i = si*G + Ci*P_i
		px, py := curve.ScalarMult(ring[i].X, ring[i].Y, C[i].Bytes()) // px, py = Ci*P_i
		sx, sy := curve.ScalarBaseMult(S[i].Bytes())                   // sx, sy = s[i]*G
		lx, ly := curve.Add(sx, sy, px, py)

		// R_i = si*H_p(P_i) + Ci*I
		px, py = curve.ScalarMult(image.X, image.Y, C[i].Bytes()) // px, py = c[i]*I
		hx, hy := HashPoint(ring[i])
		sx, sy = curve.ScalarMult(hx, hy, S[i].Bytes()) // sx, sy = s[i]*H_p(P[i])
		rx, ry := curve.Add(sx, sy, px, py)

		// c[i+1] = H(m, L_i, R_i)
		l := append(lx.Bytes(), ly.Bytes()...)
		r := append(rx.Bytes(), ry.Bytes()...)
		Ci := blake2b.Sum256(append(sig.M[:], append(l, r...)...))

		if i == ringSize-1 {
			C[0] = new(big.Int).SetBytes(Ci[:])
		} else {
			C[i+1] = new(big.Int).SetBytes(Ci[:])
		}
	}

	return bytes.Equal(sig.C.Bytes(), C[0].Bytes())
}

// Link compares two signatures to check if they are signed by the same private key
func Link(sig1 *RingSign, sig2 *RingSign) bool {
	return sig1.I.X.Cmp(sig2.I.X) == 0 && sig1.I.Y.Cmp(sig2.I.Y) == 0
}
