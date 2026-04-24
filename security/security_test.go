package security

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// =============================================================================
// AES Tests
// =============================================================================

func TestAESEncryptDecrypt(t *testing.T) {
	key, err := GenerateAESKey(256)
	if err != nil {
		t.Fatalf("GenerateAESKey failed: %v", err)
	}

	cipher, err := NewAESCipher(key)
	if err != nil {
		t.Fatalf("NewAESCipher failed: %v", err)
	}

	plaintext := []byte("Hello, AES-256-GCM!")
	ciphertext, err := cipher.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := cipher.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("round-trip mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestAESWrongKey(t *testing.T) {
	key1, _ := GenerateAESKey(256)
	key2, _ := GenerateAESKey(256)

	cipher1, _ := NewAESCipher(key1)
	cipher2, _ := NewAESCipher(key2)

	plaintext := []byte("secret data")
	ciphertext, err := cipher1.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = cipher2.Decrypt(ciphertext)
	if err == nil {
		t.Error("Decrypt with wrong key should have failed but succeeded")
	}
}

// =============================================================================
// RSA Tests
// =============================================================================

func TestRSASignVerify(t *testing.T) {
	rsa, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair failed: %v", err)
	}

	data := []byte("data to sign")
	sig, err := rsa.Sign(data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if err := rsa.Verify(data, sig); err != nil {
		t.Errorf("Verify failed on valid signature: %v", err)
	}

	// Verify with wrong data should fail
	wrongData := []byte("different data")
	if err := rsa.Verify(wrongData, sig); err == nil {
		t.Error("Verify with wrong data should have failed but succeeded")
	}
}

func TestRSAEncryptDecrypt(t *testing.T) {
	rsa, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair failed: %v", err)
	}

	plaintext := []byte("RSA encrypted message")
	ciphertext, err := rsa.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("RSA Encrypt failed: %v", err)
	}

	decrypted, err := rsa.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("RSA Decrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("RSA round-trip mismatch: got %q, want %q", decrypted, plaintext)
	}
}

// =============================================================================
// HMAC Tests
// =============================================================================

func TestHMAC(t *testing.T) {
	h := &Hash{}
	key := []byte("hmac-secret-key")
	data := []byte("message to authenticate")

	mac := h.HMAC(key, data)
	if len(mac) == 0 {
		t.Fatal("HMAC returned empty result")
	}

	// Verify correct MAC
	if !h.VerifyHMAC(key, data, mac) {
		t.Error("VerifyHMAC failed on valid MAC")
	}

	// Verify wrong MAC
	wrongMAC := make([]byte, len(mac))
	copy(wrongMAC, mac)
	wrongMAC[0] ^= 0xFF
	if h.VerifyHMAC(key, data, wrongMAC) {
		t.Error("VerifyHMAC should have failed on tampered MAC")
	}
}

// =============================================================================
// PBKDF2 Tests
// =============================================================================

func TestPBKDF2(t *testing.T) {
	password := []byte("my-password")
	salt, err := GenerateSalt(16)
	if err != nil {
		t.Fatalf("GenerateSalt failed: %v", err)
	}

	key1 := DeriveKey(password, salt, 10000, 32)
	key2 := DeriveKey(password, salt, 10000, 32)

	if string(key1) != string(key2) {
		t.Error("PBKDF2 not deterministic: same inputs produced different keys")
	}

	// Different salt should produce different key
	salt2, _ := GenerateSalt(16)
	key3 := DeriveKey(password, salt2, 10000, 32)
	if string(key1) == string(key3) {
		t.Error("PBKDF2 with different salt produced same key")
	}
}

// =============================================================================
// Bcrypt Tests
// =============================================================================

func TestBcryptHashVerify(t *testing.T) {
	hasher := NewPasswordHasher(10)
	password := "my-secure-password"

	hash, err := hasher.Hash(password)
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	if !hasher.Verify(password, hash) {
		t.Error("Verify failed for correct password")
	}

	if hasher.Verify("wrong-password", hash) {
		t.Error("Verify should have failed for wrong password")
	}
}

// =============================================================================
// JWT Tests
// =============================================================================

func TestJWTIssueValidate(t *testing.T) {
	secret := []byte("super-secret-key-at-least-32-bytes!!")
	jwt := NewJWT(secret)

	claims := &JWTClaims{
		Subject:   "user123",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Custom:    map[string]interface{}{"role": "admin"},
	}

	token, err := jwt.Create(claims)
	if err != nil {
		t.Fatalf("JWT Create failed: %v", err)
	}

	if token == "" {
		t.Fatal("JWT Create returned empty token")
	}

	parsed, err := jwt.Verify(token)
	if err != nil {
		t.Fatalf("JWT Verify failed: %v", err)
	}

	if parsed.Subject != "user123" {
		t.Errorf("subject mismatch: got %q, want %q", parsed.Subject, "user123")
	}
}

func TestJWTExpired(t *testing.T) {
	secret := []byte("super-secret-key-at-least-32-bytes!!")
	jwt := NewJWT(secret)

	claims := &JWTClaims{
		Subject:   "user123",
		ExpiresAt: time.Now().Add(-time.Hour).Unix(), // expired 1 hour ago
	}

	token, err := jwt.Create(claims)
	if err != nil {
		t.Fatalf("JWT Create failed: %v", err)
	}

	_, err = jwt.Verify(token)
	if err == nil {
		t.Error("JWT Verify should have failed for expired token")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("expected expiry error, got: %v", err)
	}
}

// =============================================================================
// API Key Tests
// =============================================================================

func TestAPIKeyGenRevoke(t *testing.T) {
	akm := NewAPIKeyManager()

	apiKey, err := akm.Generate("test-key", []string{"read", "write"}, time.Hour)
	if err != nil {
		t.Fatalf("Generate API key failed: %v", err)
	}

	if apiKey.Key == "" {
		t.Fatal("generated API key is empty")
	}

	// Verify key works
	verified, err := akm.Verify(apiKey.Key)
	if err != nil {
		t.Fatalf("Verify API key failed: %v", err)
	}

	if verified.Name != "test-key" {
		t.Errorf("name mismatch: got %q, want %q", verified.Name, "test-key")
	}

	// Revoke key
	if err := akm.Revoke(apiKey.Key); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}

	// Key should now fail
	_, err = akm.Verify(apiKey.Key)
	if err == nil {
		t.Error("Verify should have failed after revocation")
	}
}

// =============================================================================
// RBAC Tests
// =============================================================================

func TestRBACPermissions(t *testing.T) {
	rbac := NewRBAC()

	rbac.AddRole("admin", []Permission{"read", "write", "delete"})
	rbac.AddRole("viewer", []Permission{"read"})

	rbac.AddUser("u1", "alice", []string{"admin"})
	rbac.AddUser("u2", "bob", []string{"viewer"})

	// Admin should have all permissions
	if !rbac.CheckPermission("u1", "read") {
		t.Error("admin should have read permission")
	}
	if !rbac.CheckPermission("u1", "write") {
		t.Error("admin should have write permission")
	}
	if !rbac.CheckPermission("u1", "delete") {
		t.Error("admin should have delete permission")
	}

	// Viewer should only have read
	if !rbac.CheckPermission("u2", "read") {
		t.Error("viewer should have read permission")
	}
	if rbac.CheckPermission("u2", "write") {
		t.Error("viewer should NOT have write permission")
	}
	if rbac.CheckPermission("u2", "delete") {
		t.Error("viewer should NOT have delete permission")
	}

	// Non-existent user
	if rbac.CheckPermission("unknown", "read") {
		t.Error("unknown user should not have any permissions")
	}
}

// =============================================================================
// H12: Argon2id Tests
// =============================================================================

func TestArgon2id(t *testing.T) {
	password := []byte("test-password")
	salt, _ := GenerateSalt(16)

	key1 := DeriveKeyArgon2(password, salt, 1, 64*1024, 1, 32)
	key2 := DeriveKeyArgon2(password, salt, 1, 64*1024, 1, 32)

	if !bytes.Equal(key1, key2) {
		t.Error("Argon2id not deterministic")
	}

	if len(key1) != 32 {
		t.Errorf("Expected key length 32, got %d", len(key1))
	}

	// Different salt gives different result
	salt2, _ := GenerateSalt(16)
	key3 := DeriveKeyArgon2(password, salt2, 1, 64*1024, 1, 32)
	if bytes.Equal(key1, key3) {
		t.Error("Different salts should produce different keys")
	}
}

// =============================================================================
// H13: ZeroBytes Tests
// =============================================================================

func TestZeroBytes(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5}
	ZeroBytes(data)
	for i, b := range data {
		if b != 0 {
			t.Errorf("byte %d not zeroed: got %d", i, b)
		}
	}
}

// =============================================================================
// H11: ChaCha20 Tests
// =============================================================================

func TestChaCha20(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	c, err := NewChaCha20Cipher(key)
	if err != nil {
		t.Fatalf("NewChaCha20Cipher failed: %v", err)
	}

	plaintext := []byte("chacha20 test message")
	ciphertext, err := c.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := c.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("round-trip mismatch: got %q, want %q", decrypted, plaintext)
	}

	// Wrong key should fail
	key2 := make([]byte, 32)
	c2, _ := NewChaCha20Cipher(key2)
	_, err = c2.Decrypt(ciphertext)
	if err == nil {
		t.Error("Decrypt with wrong key should fail")
	}
}

// =============================================================================
// M13: EncryptedSession Tests
// =============================================================================

func TestEncryptedSession(t *testing.T) {
	key := make([]byte, 32)
	sm := NewSessionManager(time.Hour, key)

	session, err := sm.Create("user1")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	got, err := sm.Get(session.ID)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.UserID != "user1" {
		t.Errorf("UserID mismatch: got %q", got.UserID)
	}
}

// =============================================================================
// M14: LoginLockout Tests
// =============================================================================

func TestLoginLockout(t *testing.T) {
	lt := NewLoginTracker(3, 100*time.Millisecond)
	defer lt.Stop()

	// Not locked initially
	if lt.IsLocked("user1") {
		t.Error("user1 should not be locked initially")
	}

	// Record failures
	lt.RecordFailure("user1")
	lt.RecordFailure("user1")
	if lt.IsLocked("user1") {
		t.Error("user1 should not be locked after 2 failures (max 3)")
	}

	lt.RecordFailure("user1") // 3rd failure
	if !lt.IsLocked("user1") {
		t.Error("user1 should be locked after 3 failures")
	}

	// Reset should unlock
	lt.Reset("user1")
	if lt.IsLocked("user1") {
		t.Error("user1 should not be locked after Reset")
	}

	// Lock should expire
	lt.RecordFailure("user2")
	lt.RecordFailure("user2")
	lt.RecordFailure("user2")
	if !lt.IsLocked("user2") {
		t.Error("user2 should be locked")
	}
	time.Sleep(150 * time.Millisecond)
	if lt.IsLocked("user2") {
		t.Error("user2 lock should have expired")
	}
}

// =============================================================================
// M15: PasswordPepper Tests
// =============================================================================

func TestPasswordPepper(t *testing.T) {
	hasher := NewPasswordHasher(10)
	hasher.Pepper = []byte("my-secret-pepper")

	password := "test-password"
	hash, err := hasher.Hash(password)
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	if !hasher.Verify(password, hash) {
		t.Error("Verify with correct password should succeed")
	}

	// Without pepper should fail
	hasher2 := NewPasswordHasher(10)
	if hasher2.Verify(password, hash) {
		t.Error("Verify without pepper should fail on peppered hash")
	}
}

// =============================================================================
// L10: MigrateHash Tests
// =============================================================================

func TestMigrateHash(t *testing.T) {
	password := "migration-password"
	salt, _ := GenerateSalt(16)
	oldHash := DeriveKey([]byte(password), salt, 1000, 32)

	newHash, err := MigrateHash(password, oldHash, salt, 1000, 32, Argon2Params{
		TimeCost: 1,
		Memory:   64 * 1024,
		Threads:  1,
		KeyLen:   32,
	})
	if err != nil {
		t.Fatalf("MigrateHash failed: %v", err)
	}
	if len(newHash) != 32 {
		t.Errorf("Expected 32-byte new hash, got %d", len(newHash))
	}

	// Wrong password should fail
	_, err = MigrateHash("wrong-password", oldHash, salt, 1000, 32, Argon2Params{
		TimeCost: 1,
		Memory:   64 * 1024,
		Threads:  1,
		KeyLen:   32,
	})
	if err == nil {
		t.Error("MigrateHash should fail with wrong password")
	}
}
