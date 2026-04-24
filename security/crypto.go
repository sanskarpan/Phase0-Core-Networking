/*
Cryptography Implementation
============================

Symmetric and asymmetric encryption implementations for secure communication.

Applications:
- Data encryption at rest and in transit
- Secure key exchange
- Digital signatures
- Message authentication
*/

package security

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/pbkdf2"
)

// =============================================================================
// Symmetric Encryption (AES)
// =============================================================================

// AESCipher handles AES encryption and decryption
type AESCipher struct {
	key []byte
}

// NewAESCipher creates a new AES cipher
func NewAESCipher(key []byte) (*AESCipher, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("key must be 16, 24, or 32 bytes (AES-128, AES-192, or AES-256)")
	}

	return &AESCipher{key: key}, nil
}

// Encrypt encrypts data using AES-GCM
func (ac *AESCipher) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(ac.key)
	if err != nil {
		return nil, err
	}

	// Use GCM mode for authenticated encryption
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt and append nonce at the beginning
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts data using AES-GCM
func (ac *AESCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(ac.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	// Extract nonce and ciphertext
	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// GenerateAESKey generates a random AES key
func GenerateAESKey(bits int) ([]byte, error) {
	if bits != 128 && bits != 192 && bits != 256 {
		return nil, errors.New("bits must be 128, 192, or 256")
	}

	key := make([]byte, bits/8)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}

	return key, nil
}

// =============================================================================
// Asymmetric Encryption (RSA)
// =============================================================================

// RSACipher handles RSA encryption, decryption, and signing
type RSACipher struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// GenerateRSAKeyPair generates a new RSA key pair
func GenerateRSAKeyPair(bits int) (*RSACipher, error) {
	if bits < 2048 {
		return nil, errors.New("key size must be at least 2048 bits")
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}

	return &RSACipher{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
	}, nil
}

// LoadRSAPrivateKey loads a private key from PEM bytes
func LoadRSAPrivateKey(pemBytes []byte) (*RSACipher, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return &RSACipher{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
	}, nil
}

// LoadRSAPublicKey loads a public key from PEM bytes
func LoadRSAPublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return pub, nil
}

// ExportPrivateKey exports the private key as PEM
func (rc *RSACipher) ExportPrivateKey() []byte {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(rc.privateKey)
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
}

// ExportPublicKey exports the public key as PEM
func (rc *RSACipher) ExportPublicKey() []byte {
	publicKeyBytes := x509.MarshalPKCS1PublicKey(rc.publicKey)
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
}

// Encrypt encrypts data with the public key
func (rc *RSACipher) Encrypt(plaintext []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, rc.publicKey, plaintext, nil)
}

// Decrypt decrypts data with the private key
func (rc *RSACipher) Decrypt(ciphertext []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, rc.privateKey, ciphertext, nil)
}

// Sign signs data with the private key
func (rc *RSACipher) Sign(data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	return rsa.SignPKCS1v15(rand.Reader, rc.privateKey, crypto.SHA256, hash[:])
}

// Verify verifies a signature with the public key
func (rc *RSACipher) Verify(data, signature []byte) error {
	hash := sha256.Sum256(data)
	return rsa.VerifyPKCS1v15(rc.publicKey, crypto.SHA256, hash[:], signature)
}

// VerifyWithPublicKey verifies a signature with a specific public key
func VerifyWithPublicKey(publicKey *rsa.PublicKey, data, signature []byte) error {
	hash := sha256.Sum256(data)
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], signature)
}

// =============================================================================
// Hash Functions
// =============================================================================

// Hash represents a cryptographic hash function
type Hash struct{}

// SHA256 computes SHA-256 hash
func (h *Hash) SHA256(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// HMAC computes HMAC-SHA256
func (h *Hash) HMAC(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// VerifyHMAC verifies HMAC
func (h *Hash) VerifyHMAC(key, data, expectedMAC []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	computedMAC := mac.Sum(nil)
	return hmac.Equal(computedMAC, expectedMAC)
}

// =============================================================================
// Key Derivation
// =============================================================================

// DeriveKey derives a key from a password using PBKDF2
func DeriveKey(password, salt []byte, iterations, keyLen int) []byte {
	return pbkdf2.Key(password, salt, iterations, keyLen, sha256.New)
}

// GenerateSalt generates a random salt
func GenerateSalt(size int) ([]byte, error) {
	salt := make([]byte, size)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// =============================================================================
// Argon2id KDF (H12)
// =============================================================================

// DeriveKeyArgon2 derives a key using Argon2id. Prefer over PBKDF2 for new code.
func DeriveKeyArgon2(password, salt []byte, timeCost, memory uint32, threads uint8, keyLen uint32) []byte {
	return argon2.IDKey(password, salt, timeCost, memory, threads, keyLen)
}

// =============================================================================
// Key Material Zeroing (H13)
// =============================================================================

// ZeroBytes zeros a byte slice to clear key material from memory.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// =============================================================================
// ChaCha20-Poly1305 (H11)
// =============================================================================

// ChaCha20Cipher handles ChaCha20-Poly1305 AEAD encryption.
type ChaCha20Cipher struct {
	key [chacha20poly1305.KeySize]byte
}

// NewChaCha20Cipher creates a ChaCha20-Poly1305 cipher from a 32-byte key.
func NewChaCha20Cipher(key []byte) (*ChaCha20Cipher, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("key must be %d bytes", chacha20poly1305.KeySize)
	}
	c := &ChaCha20Cipher{}
	copy(c.key[:], key)
	return c, nil
}

// Encrypt encrypts plaintext using ChaCha20-Poly1305 with a random nonce prepended.
func (c *ChaCha20Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(c.key[:])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts ciphertext produced by Encrypt.
func (c *ChaCha20Cipher) Decrypt(ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(c.key[:])
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aead.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]
	return aead.Open(nil, nonce, ct, nil)
}

// =============================================================================
// Argon2Params and PBKDF2 → Argon2 Migration Helper (L10)
// =============================================================================

// Argon2Params holds Argon2id parameters.
type Argon2Params struct {
	TimeCost uint32
	Memory   uint32
	Threads  uint8
	KeyLen   uint32
	Salt     []byte
}

// MigrateHash verifies password against a PBKDF2 hash and returns an Argon2id hash.
// The caller must provide the original PBKDF2 parameters used to create oldHash.
func MigrateHash(password string, oldHash []byte, pbkdf2Salt []byte, pbkdf2Iters, pbkdf2KeyLen int, newParams Argon2Params) ([]byte, error) {
	check := DeriveKey([]byte(password), pbkdf2Salt, pbkdf2Iters, pbkdf2KeyLen)
	if !bytes.Equal(check, oldHash) {
		return nil, errors.New("password does not match")
	}
	if len(newParams.Salt) == 0 {
		var err error
		newParams.Salt, err = GenerateSalt(16)
		if err != nil {
			return nil, err
		}
	}
	return DeriveKeyArgon2([]byte(password), newParams.Salt, newParams.TimeCost, newParams.Memory, newParams.Threads, newParams.KeyLen), nil
}
