/*
Authentication and Authorization
=================================

Authentication mechanisms and access control for secure systems.

Applications:
- User authentication
- API authentication
- Role-based access control (RBAC)
- Token-based authentication (JWT)
*/

package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// =============================================================================
// Password Hashing
// =============================================================================

// PasswordHasher handles password hashing and verification
type PasswordHasher struct {
	cost   int
	Pepper []byte // M15: optional pepper for HMAC-SHA256 pre-processing
}

// NewPasswordHasher creates a new password hasher
func NewPasswordHasher(cost int) *PasswordHasher {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		cost = bcrypt.DefaultCost
	}

	return &PasswordHasher{cost: cost}
}

// applyPepper applies HMAC-SHA256 with the pepper if set. (M15)
func (ph *PasswordHasher) applyPepper(password string) string {
	if len(ph.Pepper) == 0 {
		return password
	}
	mac := hmac.New(sha256.New, ph.Pepper)
	mac.Write([]byte(password))
	return hex.EncodeToString(mac.Sum(nil))
}

// Hash hashes a password
func (ph *PasswordHasher) Hash(password string) (string, error) {
	pw := ph.applyPepper(password)
	bytes, err := bcrypt.GenerateFromPassword([]byte(pw), ph.cost)
	if err != nil {
		return "", err
	}

	return string(bytes), nil
}

// Verify verifies a password against a hash
func (ph *PasswordHasher) Verify(password, hash string) bool {
	pw := ph.applyPepper(password)
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

// =============================================================================
// JWT (JSON Web Tokens)
// =============================================================================

// JWTClaims represents JWT claims
type JWTClaims struct {
	Subject   string                 `json:"sub"`
	IssuedAt  int64                  `json:"iat"`
	ExpiresAt int64                  `json:"exp"`
	NotBefore int64                  `json:"nbf,omitempty"`
	Issuer    string                 `json:"iss,omitempty"`
	Audience  string                 `json:"aud,omitempty"`
	Custom    map[string]interface{} `json:"custom,omitempty"`
}

// JWT handles JWT creation and verification
type JWT struct {
	secret []byte
}

// NewJWT creates a new JWT handler
func NewJWT(secret []byte) *JWT {
	return &JWT{secret: secret}
}

// Create creates a new JWT token
func (j *JWT) Create(claims *JWTClaims) (string, error) {
	if len(j.secret) < 32 {
		return "", fmt.Errorf("JWT secret must be at least 32 bytes")
	}
	if claims.IssuedAt == 0 {
		claims.IssuedAt = time.Now().Unix()
	}

	// Create header
	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	headerEncoded := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Create payload
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Create signature
	message := headerEncoded + "." + payloadEncoded
	signature := j.sign(message)
	signatureEncoded := base64.RawURLEncoding.EncodeToString(signature)

	// Combine all parts
	token := message + "." + signatureEncoded

	return token, nil
}

// Verify verifies and parses a JWT token
func (j *JWT) Verify(token string) (*JWTClaims, error) {
	if len(j.secret) < 32 {
		return nil, fmt.Errorf("JWT secret must be at least 32 bytes")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	headerEncoded := parts[0]
	payloadEncoded := parts[1]
	signatureEncoded := parts[2]

	// Verify signature
	message := headerEncoded + "." + payloadEncoded
	expectedSignature := j.sign(message)
	expectedSignatureEncoded := base64.RawURLEncoding.EncodeToString(expectedSignature)

	if !constantTimeCompare(signatureEncoded, expectedSignatureEncoded) {
		return nil, errors.New("invalid signature")
	}

	// Decode payload
	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadEncoded)
	if err != nil {
		return nil, err
	}

	var claims JWTClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, err
	}

	// Check expiration
	if claims.ExpiresAt > 0 && time.Now().Unix() > claims.ExpiresAt {
		return nil, errors.New("token expired")
	}

	// Check not before
	if claims.NotBefore > 0 && time.Now().Unix() < claims.NotBefore {
		return nil, errors.New("token not yet valid")
	}

	return &claims, nil
}

func (j *JWT) sign(message string) []byte {
	h := hmac.New(sha256.New, j.secret)
	h.Write([]byte(message))
	return h.Sum(nil)
}

func constantTimeCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// =============================================================================
// API Keys
// =============================================================================

// APIKey represents an API key
type APIKey struct {
	Key       string
	Name      string
	CreatedAt time.Time
	ExpiresAt time.Time
	Active    bool
	Scopes    []string
}

// APIKeyManager manages API keys
type APIKeyManager struct {
	keys map[string]*APIKey
	mu   sync.RWMutex
}

// NewAPIKeyManager creates a new API key manager
func NewAPIKeyManager() *APIKeyManager {
	return &APIKeyManager{
		keys: make(map[string]*APIKey),
	}
}

// Generate generates a new API key
func (akm *APIKeyManager) Generate(name string, scopes []string, expiresIn time.Duration) (*APIKey, error) {
	key, err := generateRandomString(32)
	if err != nil {
		return nil, err
	}

	apiKey := &APIKey{
		Key:       key,
		Name:      name,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(expiresIn),
		Active:    true,
		Scopes:    scopes,
	}

	akm.mu.Lock()
	akm.keys[key] = apiKey
	akm.mu.Unlock()

	return apiKey, nil
}

// Verify verifies an API key
func (akm *APIKeyManager) Verify(key string) (*APIKey, error) {
	akm.mu.RLock()
	apiKey, ok := akm.keys[key]
	akm.mu.RUnlock()

	if !ok {
		return nil, errors.New("invalid API key")
	}

	if !apiKey.Active {
		return nil, errors.New("API key inactive")
	}

	if time.Now().After(apiKey.ExpiresAt) {
		return nil, errors.New("API key expired")
	}

	return apiKey, nil
}

// Revoke revokes an API key
func (akm *APIKeyManager) Revoke(key string) error {
	akm.mu.Lock()
	defer akm.mu.Unlock()

	apiKey, ok := akm.keys[key]
	if !ok {
		return errors.New("API key not found")
	}

	apiKey.Active = false
	return nil
}

// Delete deletes an API key
func (akm *APIKeyManager) Delete(key string) error {
	akm.mu.Lock()
	defer akm.mu.Unlock()

	if _, ok := akm.keys[key]; !ok {
		return errors.New("API key not found")
	}

	delete(akm.keys, key)
	return nil
}

// HasScope checks if an API key has a specific scope
func (ak *APIKey) HasScope(scope string) bool {
	for _, s := range ak.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

func generateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(bytes), nil
}

// =============================================================================
// Role-Based Access Control (RBAC)
// =============================================================================

// Permission represents a permission
type Permission string

// Role represents a role with permissions
type Role struct {
	Name        string
	Permissions []Permission
}

// User represents a user with roles
type User struct {
	ID       string
	Username string
	Roles    []string
}

// RBAC implements role-based access control
type RBAC struct {
	roles map[string]*Role
	users map[string]*User
	mu    sync.RWMutex
}

// NewRBAC creates a new RBAC instance
func NewRBAC() *RBAC {
	return &RBAC{
		roles: make(map[string]*Role),
		users: make(map[string]*User),
	}
}

// AddRole adds a role
func (rbac *RBAC) AddRole(name string, permissions []Permission) {
	rbac.mu.Lock()
	defer rbac.mu.Unlock()

	rbac.roles[name] = &Role{
		Name:        name,
		Permissions: permissions,
	}
}

// AddUser adds a user
func (rbac *RBAC) AddUser(id, username string, roles []string) {
	rbac.mu.Lock()
	defer rbac.mu.Unlock()

	rbac.users[id] = &User{
		ID:       id,
		Username: username,
		Roles:    roles,
	}
}

// CheckPermission checks if a user has a permission
func (rbac *RBAC) CheckPermission(userID string, permission Permission) bool {
	rbac.mu.RLock()
	defer rbac.mu.RUnlock()

	user, ok := rbac.users[userID]
	if !ok {
		return false
	}

	// Check all user roles
	for _, roleName := range user.Roles {
		role, ok := rbac.roles[roleName]
		if !ok {
			continue
		}

		// Check if role has permission
		for _, perm := range role.Permissions {
			if perm == permission {
				return true
			}
		}
	}

	return false
}

// GetUserPermissions returns all permissions for a user
func (rbac *RBAC) GetUserPermissions(userID string) []Permission {
	rbac.mu.RLock()
	defer rbac.mu.RUnlock()

	user, ok := rbac.users[userID]
	if !ok {
		return nil
	}

	permMap := make(map[Permission]bool)
	for _, roleName := range user.Roles {
		role, ok := rbac.roles[roleName]
		if !ok {
			continue
		}

		for _, perm := range role.Permissions {
			permMap[perm] = true
		}
	}

	permissions := make([]Permission, 0, len(permMap))
	for perm := range permMap {
		permissions = append(permissions, perm)
	}

	return permissions
}

// =============================================================================
// Session Management
// =============================================================================

// Session represents a user session
type Session struct {
	ID        string
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time
	Data      map[string]interface{}
}

// SessionManager manages user sessions
type SessionManager struct {
	sessions map[string]*Session
	mu       sync.RWMutex
	timeout  time.Duration
	cipher   *AESCipher   // M13: nil if no encryption key
	done     chan struct{} // B10/L3: stop cleanupLoop goroutine
}

// NewSessionManager creates a new session manager.
// Optional encryptionKey enables session data encryption (M13).
func NewSessionManager(timeout time.Duration, encryptionKey ...[]byte) *SessionManager {
	sm := &SessionManager{
		sessions: make(map[string]*Session),
		timeout:  timeout,
		done:     make(chan struct{}),
	}
	if len(encryptionKey) > 0 && len(encryptionKey[0]) > 0 {
		c, err := NewAESCipher(encryptionKey[0])
		if err == nil {
			sm.cipher = c
		}
	}

	// Start cleanup goroutine
	go sm.cleanupLoop()

	return sm
}

// Close stops the background cleanup goroutine. (B10/L3)
func (sm *SessionManager) Close() {
	close(sm.done)
}

// Create creates a new session
func (sm *SessionManager) Create(userID string) (*Session, error) {
	sessionID, err := generateRandomString(32)
	if err != nil {
		return nil, err
	}

	session := &Session{
		ID:        sessionID,
		UserID:    userID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(sm.timeout),
		Data:      make(map[string]interface{}),
	}

	// M13: Encrypt session data if cipher is configured
	if sm.cipher != nil {
		dataJSON, err := json.Marshal(session.Data)
		if err == nil {
			ciphertext, err := sm.cipher.Encrypt(dataJSON)
			if err == nil {
				session.Data = map[string]interface{}{
					"__enc__": base64.StdEncoding.EncodeToString(ciphertext),
				}
			}
		}
	}

	sm.mu.Lock()
	sm.sessions[sessionID] = session
	sm.mu.Unlock()

	return session, nil
}

// Get retrieves a session
func (sm *SessionManager) Get(sessionID string) (*Session, error) {
	sm.mu.RLock()
	session, ok := sm.sessions[sessionID]
	sm.mu.RUnlock()

	if !ok {
		return nil, errors.New("session not found")
	}

	if time.Now().After(session.ExpiresAt) {
		sm.Destroy(sessionID)
		return nil, errors.New("session expired")
	}

	// B6: Use a write lock to safely extend ExpiresAt; a read lock is insufficient
	// because writing to session.ExpiresAt races with concurrent readers and the cleanup goroutine.
	sm.mu.Lock()
	session.ExpiresAt = time.Now().Add(sm.timeout)
	sm.mu.Unlock()

	return session, nil
}

// Destroy destroys a session
func (sm *SessionManager) Destroy(sessionID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if _, ok := sm.sessions[sessionID]; !ok {
		return errors.New("session not found")
	}

	delete(sm.sessions, sessionID)
	return nil
}

func (sm *SessionManager) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sm.mu.Lock()
			now := time.Now()
			for id, session := range sm.sessions {
				if now.After(session.ExpiresAt) {
					delete(sm.sessions, id)
				}
			}
			sm.mu.Unlock()
		case <-sm.done:
			return
		}
	}
}

// =============================================================================
// OAuth 2.0 (Simplified)
// =============================================================================

// OAuthToken represents an OAuth token
type OAuthToken struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresIn    int64
	Scope        string
}

// refreshEntry is an in-memory record for a single-use refresh token. (C3)
type refreshEntry struct {
	userID    string
	scopes    []string
	expiresAt time.Time
}

// OAuthProvider provides OAuth token generation
type OAuthProvider struct {
	jwt          *JWT
	refreshStore map[string]*refreshEntry // C3: refresh token store
	refreshMu    sync.RWMutex
}

// NewOAuthProvider creates a new OAuth provider
func NewOAuthProvider(secret []byte) *OAuthProvider {
	return &OAuthProvider{
		jwt:          NewJWT(secret),
		refreshStore: make(map[string]*refreshEntry),
	}
}

// GenerateToken generates an OAuth access token
func (op *OAuthProvider) GenerateToken(userID string, scopes []string, expiresIn time.Duration) (*OAuthToken, error) {
	claims := &JWTClaims{
		Subject:   userID,
		ExpiresAt: time.Now().Add(expiresIn).Unix(),
		Custom: map[string]interface{}{
			"scopes": scopes,
		},
	}

	accessToken, err := op.jwt.Create(claims)
	if err != nil {
		return nil, err
	}

	refreshToken, err := generateRandomString(32)
	if err != nil {
		return nil, err
	}

	// C3: Store the refresh token for later exchange.
	op.refreshMu.Lock()
	op.refreshStore[refreshToken] = &refreshEntry{
		userID:    userID,
		scopes:    scopes,
		expiresAt: time.Now().Add(7 * 24 * time.Hour), // 7 day refresh TTL
	}
	op.refreshMu.Unlock()

	return &OAuthToken{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(expiresIn.Seconds()),
		Scope:        strings.Join(scopes, " "),
	}, nil
}

// RefreshToken exchanges a refresh token for a new access token. (C3)
func (op *OAuthProvider) RefreshToken(refreshToken string) (*OAuthToken, error) {
	op.refreshMu.Lock()
	entry, ok := op.refreshStore[refreshToken]
	if ok {
		delete(op.refreshStore, refreshToken) // single use
	}
	op.refreshMu.Unlock()

	if !ok {
		return nil, errors.New("invalid refresh token")
	}
	if time.Now().After(entry.expiresAt) {
		return nil, errors.New("refresh token expired")
	}

	return op.GenerateToken(entry.userID, entry.scopes, time.Hour)
}

// VerifyToken verifies an OAuth token
func (op *OAuthProvider) VerifyToken(token string) (*JWTClaims, error) {
	return op.jwt.Verify(token)
}

// =============================================================================
// Login Lockout Tracker (M14)
// =============================================================================

// LoginTracker tracks failed login attempts and enforces lockouts.
type LoginTracker struct {
	MaxAttempts     int
	LockoutDuration time.Duration
	mu              sync.Mutex
	attempts        map[string]int
	lockedUntil     map[string]time.Time
	done            chan struct{}
}

// NewLoginTracker creates a new LoginTracker with the given maxAttempts and lockout duration.
func NewLoginTracker(maxAttempts int, lockout time.Duration) *LoginTracker {
	lt := &LoginTracker{
		MaxAttempts:     maxAttempts,
		LockoutDuration: lockout,
		attempts:        make(map[string]int),
		lockedUntil:     make(map[string]time.Time),
		done:            make(chan struct{}),
	}
	go lt.cleanup()
	return lt
}

// RecordFailure records a failed login attempt for userID.
func (lt *LoginTracker) RecordFailure(userID string) {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	lt.attempts[userID]++
	if lt.attempts[userID] >= lt.MaxAttempts {
		lt.lockedUntil[userID] = time.Now().Add(lt.LockoutDuration)
	}
}

// IsLocked returns true if the userID is currently locked out.
func (lt *LoginTracker) IsLocked(userID string) bool {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	until, ok := lt.lockedUntil[userID]
	if !ok {
		return false
	}
	if time.Now().After(until) {
		delete(lt.lockedUntil, userID)
		delete(lt.attempts, userID)
		return false
	}
	return true
}

// Reset clears the failure count and lockout for userID.
func (lt *LoginTracker) Reset(userID string) {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	delete(lt.attempts, userID)
	delete(lt.lockedUntil, userID)
}

// Stop stops the background cleanup goroutine.
func (lt *LoginTracker) Stop() {
	close(lt.done)
}

func (lt *LoginTracker) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			lt.mu.Lock()
			now := time.Now()
			for id, until := range lt.lockedUntil {
				if now.After(until) {
					delete(lt.lockedUntil, id)
					delete(lt.attempts, id)
				}
			}
			lt.mu.Unlock()
		case <-lt.done:
			return
		}
	}
}
