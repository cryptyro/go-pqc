package ecmldsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	priv, err := GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	if priv == nil {
		t.Fatal("Generated keys should not be nil")
	}
}

// func TestMarshalUnmarshalPrivateKey(t *testing.T) {
// 	priv, _ := mldsa.GenerateKey()
// 	encoded, err := x509.MarshalMLPrivateKey(priv)
// 	if err != nil {
// 		t.Fatalf("Failed to marshal private key: %v", err)
// 	}

// 	decoded, err := x509.UnmarshalMLPrivateKey(encoded)
// 	if err != nil {
// 		t.Fatalf("Failed to unmarshal private key: %v", err)
// 	}

// 	if !priv.Equal(decoded) {
// 		t.Fatal("Original and unmarshaled private keys are not equal")
// 	}
// }

// func TestMarshalUnmarshalPublicKey(t *testing.T) {
// 	priv, _ := mldsa.GenerateKey()
// 	pub := priv.PublicKey()

// 	encoded, err := x509.MarshalMLPublicKey(&pub)
// 	if err != nil {
// 		t.Fatalf("Failed to marshal public key: %v", err)
// 	}

// 	decoded, err := x509.UnmarshalMLPublicKey(encoded)
// 	if err != nil {
// 		t.Fatalf("Failed to unmarshal public key: %v", err)
// 	}

// 	if !pub.Equal(decoded) {
// 		t.Fatal("Original and unmarshaled public keys are not equal")
// 	}
// }

func TestSignVerify(t *testing.T) {
	priv, _ := GenerateKey(elliptic.P256(), rand.Reader)
	pub := priv.Public().(*PublicKey)

	message := []byte("Test message")
	hash := sha256.Sum256(message)

	sig, err := Sign(rand.Reader, priv, hash[:])
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	valid := Verify(pub, hash[:], sig)
	if !valid {
		t.Fatal("Signature verification failed")
	}
}

func TestInvalidSignature(t *testing.T) {
	priv, _ := GenerateKey(elliptic.P256(), rand.Reader)
	pub := priv.Public().(*PublicKey)

	message := []byte("Test message")
	hash := sha256.Sum256(message)

	sig, _ := priv.Sign(rand.Reader, hash[:], nil)

	modifiedHash := sha256.Sum256([]byte("Modified message"))
	valid := Verify(pub, modifiedHash[:], sig)
	if valid {
		t.Fatal("Verification should fail for modified message")
	}
}

func TestPublicKeyEquality(t *testing.T) {
	priv1, _ := GenerateKey(elliptic.P256(), rand.Reader)
	pub1 := priv1.Public().(*PublicKey)
	priv2, _ := GenerateKey(elliptic.P256(), rand.Reader)
	pub2 := priv2.Public()
	if pub1.Equal(pub2) {
		t.Fatal("Different public keys should not be equal")
	}

	if !pub1.Equal(priv1.Public()) {
		t.Fatal("Same public key should be equal to itself")
	}
}

func TestToLowS(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	r, s, _ := ecdsa.Sign(rand.Reader, privKey, []byte("test"))

	sig := ECDSASignature{R: r, S: s}
	lowSSig := ToLowS(privKey.PublicKey, sig)

	halfOrder := new(big.Int).Div(privKey.Curve.Params().N, big.NewInt(2))
	if lowSSig.S.Cmp(halfOrder) == 1 {
		t.Fatal("Signature S value is not low S")
	}
}
