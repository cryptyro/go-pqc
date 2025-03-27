package ecmldsa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptoRand "crypto/rand"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"

	dilithium "github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// PrivateKey represents an MLDSA private key
type PrivateKey struct {
	e ecdsa.PrivateKey
	d dilithium.PrivateKey
}

// PublicKey represents an MLDSA public key
type PublicKey struct {
	e ecdsa.PublicKey
	d dilithium.PublicKey
}

// GeneratePrivateKey creates an EC private key using a P-256 curve and a dilithium key.
func GenerateKey(c elliptic.Curve, rand io.Reader) (*PrivateKey, error) {
	if rand == nil {
		rand = cryptoRand.Reader
	}

	esk, err := ecdsa.GenerateKey(c, rand)
	if err != nil {
		return nil, err
	}

	// Generate Dilithium key pair
	_, dsk, err := dilithium.GenerateKey(nil)
	if err != nil {
		return nil, err
	}

	return &PrivateKey{*esk, *dsk}, nil
}

// Public returns the PublicKey associated with PrivateKey.
func (sk *PrivateKey) Public() crypto.PublicKey {
	return &PublicKey{
		e: sk.e.PublicKey,
		d: *sk.d.Public().(*dilithium.PublicKey),
	}
}

// Sign signs the digest of the message and ensures that signatures use the Low S value.
func (priv *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts != nil {
		h := opts.HashFunc()
		if h.Size() != len(digest) {
			return nil, errors.New("ecdsa: hash length does not match hash function")
		}
	}

	return Sign(rand, priv, digest)
}

func Sign(rand io.Reader, priv *PrivateKey, digest []byte) ([]byte, error) {
	// ECDSA signature
	r, s, err := ecdsa.Sign(rand, &priv.e, digest)
	if err != nil {
		return nil, err
	}

	ecdsaSig := ToLowS(priv.e.PublicKey, ECDSASignature{R: r, S: s})

	// Marshal the ECDSA signature
	ECDSAsig, err := asn1.Marshal(ecdsaSig)
	if err != nil {
		return nil, err
	}

	// Dilithium signature
	var signature [dilithium.SignatureSize]byte
	err = dilithium.SignTo(&priv.d, digest, nil, true, signature[:])
	if err != nil {
		return nil, err
	}

	// Combine the Dilithium and ECDSA signatures manually
	// Copy Dilithium signature first
	fullSignature := append(signature[:], ECDSAsig...)
	return fullSignature, nil
}

func ToLowS(key ecdsa.PublicKey, sig ECDSASignature) ECDSASignature {
	// Calculate half order of the curve
	halfOrder := new(big.Int).Div(key.Curve.Params().N, big.NewInt(2))
	// Check if s is greater than half order of the curve
	if sig.S.Cmp(halfOrder) == 1 {
		// Set s to N - s so that s will be less than or equal to half order
		sig.S.Sub(key.Curve.Params().N, sig.S)
	}
	return sig
}

type ECDSASignature struct {
	R, S *big.Int
}

// Verify verifies the hybrid signature using both ECDSA and Dilithium public keys.
func Verify(pub *PublicKey, digest []byte, sig []byte) bool {
	// Lengths of Dilithium and ECDSA signatures
	dilithiumSigLen := dilithium.SignatureSize

	// Verify Dilithium signature
	if !dilithium.Verify(&pub.d, digest, nil, sig[:dilithiumSigLen]) {
		return false
	}

	// Unmarshal and verify ECDSA signature
	var ecdsaSig ECDSASignature
	_, err := asn1.Unmarshal(sig[dilithiumSigLen:], &ecdsaSig)
	if err != nil {
		return false
	}
	if !ecdsa.Verify(&pub.e, digest, ecdsaSig.R, ecdsaSig.S) {
		return false
	}

	return true
}

func (sk *PrivateKey) Equal(other crypto.PrivateKey) bool {
	castOther, ok := other.(*PrivateKey)
	if !ok {
		return false
	}
	return castOther.e.Equal(&sk.e) && castOther.d.Equal(&sk.d)
}

func (pk *PublicKey) Equal(other crypto.PublicKey) bool {
	castOther, ok := other.(*PublicKey)
	if !ok {
		return false
	}
	return castOther.e.Equal(&pk.e) && castOther.d.Equal(&pk.d)
}
