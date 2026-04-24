# Network Security Best Practices

## Table of Contents
1. [Common Vulnerabilities](#common-vulnerabilities)
2. [Encryption Best Practices](#encryption-best-practices)
3. [TLS/SSL Best Practices](#tlsssl-best-practices)
4. [Authentication & Authorization](#authentication--authorization)
5. [Secure Coding Practices](#secure-coding-practices)
6. [Network Security Checklist](#network-security-checklist)

## Common Vulnerabilities

### 1. Man-in-the-Middle (MITM) Attacks

**Description**: Attacker intercepts communication between client and server.

**Prevention**:
- Always use TLS/SSL for sensitive data transmission
- Implement certificate pinning for critical applications
- Verify server certificates properly (don't skip verification)
- Use mutual TLS (mTLS) for service-to-service communication

**Example**:
```go
// BAD - Skips certificate verification
tlsConfig.SetInsecureSkipVerify(true)

// GOOD - Proper certificate verification
tlsConfig := NewTLSConfig(certPEM, keyPEM)
// Certificate is verified by default
```

### 2. Denial of Service (DoS) / DDoS

**Description**: Overwhelming a system with requests to make it unavailable.

**Prevention**:
- Implement rate limiting
- Use connection limits
- Set appropriate timeouts
- Implement request size limits
- Use load balancing
- Deploy behind CDN/DDoS protection

**Example**:
```go
// Implement rate limiting
server.Use(RateLimitMiddleware(100)) // 100 requests per minute

// Set timeouts
client := &http.Client{
    Timeout: 30 * time.Second,
}

// Connection limits
transport := &http.Transport{
    MaxIdleConns:        100,
    MaxIdleConnsPerHost: 10,
}
```

### 3. SQL Injection

**Description**: Injecting malicious SQL code through user input.

**Prevention**:
- Always use parameterized queries
- Never concatenate user input into queries
- Use ORM frameworks with proper escaping
- Validate and sanitize all input

**Example**:
```go
// BAD
query := "SELECT * FROM users WHERE username = '" + username + "'"

// GOOD
query := "SELECT * FROM users WHERE username = ?"
db.Query(query, username)
```

### 4. Cross-Site Scripting (XSS)

**Description**: Injecting malicious scripts into web pages.

**Prevention**:
- Escape all user-generated content
- Use Content Security Policy (CSP) headers
- Validate and sanitize input
- Use frameworks that auto-escape by default

**Example**:
```go
// Set CSP header
w.Header().Set("Content-Security-Policy", "default-src 'self'")

// Escape HTML
import "html/template"
escaped := template.HTMLEscapeString(userInput)
```

### 5. Cross-Site Request Forgery (CSRF)

**Description**: Tricks users into executing unwanted actions.

**Prevention**:
- Use CSRF tokens
- Verify Origin and Referer headers
- Use SameSite cookie attribute
- Require re-authentication for sensitive actions

**Example**:
```go
// Generate CSRF token
csrfToken := generateRandomString(32)
session.Data["csrf_token"] = csrfToken

// Verify CSRF token
if r.FormValue("csrf_token") != session.Data["csrf_token"] {
    http.Error(w, "Invalid CSRF token", http.StatusForbidden)
    return
}
```

### 6. Insecure Deserialization

**Description**: Exploiting insecure object deserialization.

**Prevention**:
- Validate serialized data before deserializing
- Use safe serialization formats (JSON over pickle/marshal)
- Implement integrity checks
- Restrict deserialization to expected types

### 7. Server-Side Request Forgery (SSRF)

**Description**: Forcing the server to make requests to unintended locations.

**Prevention**:
- Validate and whitelist URLs
- Disable redirects for user-supplied URLs
- Use network segmentation
- Implement URL parsers with strict validation

### 8. Insufficient Logging & Monitoring

**Description**: Lack of detection for security incidents.

**Prevention**:
- Log all authentication attempts
- Log authorization failures
- Monitor for suspicious patterns
- Set up alerts for security events
- Regularly review logs

## Encryption Best Practices

### Symmetric Encryption

**Key Points**:
- Use AES with 256-bit keys (AES-256)
- Always use authenticated encryption (GCM mode)
- Never reuse nonces/IVs
- Use cryptographically secure random number generators
- Store keys securely (use key management systems)

**Example**:
```go
// Generate secure key
key, err := GenerateAESKey(256)

// Create cipher
cipher, err := NewAESCipher(key)

// Encrypt
ciphertext, err := cipher.Encrypt(plaintext)

// Decrypt
plaintext, err := cipher.Decrypt(ciphertext)
```

### Asymmetric Encryption

**Key Points**:
- Use RSA with at least 2048-bit keys (prefer 4096-bit)
- Use OAEP padding for encryption
- Use PSS padding for signatures
- Protect private keys rigorously
- Rotate keys periodically

**Example**:
```go
// Generate key pair
rsaCipher, err := GenerateRSAKeyPair(4096)

// Encrypt with public key
ciphertext, err := rsaCipher.Encrypt(plaintext)

// Decrypt with private key
plaintext, err := rsaCipher.Decrypt(ciphertext)

// Sign
signature, err := rsaCipher.Sign(data)

// Verify
err = rsaCipher.Verify(data, signature)
```

### Password Hashing

**Key Points**:
- Use bcrypt, scrypt, or Argon2 (not MD5 or SHA-1)
- Use appropriate cost/work factors
- Add salt automatically (bcrypt does this)
- Never store plain text passwords
- Use constant-time comparison

**Example**:
```go
hasher := NewPasswordHasher(bcrypt.DefaultCost)

// Hash password
hash, err := hasher.Hash(password)

// Verify password
valid := hasher.Verify(password, hash)
```

## TLS/SSL Best Practices

### Certificate Management

**Key Points**:
- Use certificates from trusted CAs
- Keep certificates updated before expiration
- Use automated certificate renewal (Let's Encrypt)
- Implement certificate pinning for mobile apps
- Monitor certificate expiration dates

**Example**:
```go
// Generate self-signed cert (development only)
certPEM, keyPEM, err := GenerateSelfSignedCert(CertificateConfig{
    CommonName: "localhost",
    ValidFor:   365 * 24 * time.Hour,
    DNSNames:   []string{"localhost"},
})

// Check expiration
info, err := GetCertificateInfo(certPEM)
if info.ExpiresIn() < 30*24*time.Hour {
    log.Println("Certificate expiring soon!")
}
```

### TLS Configuration

**Key Points**:
- Use TLS 1.2 or higher (prefer TLS 1.3)
- Disable older protocols (SSL v2/v3, TLS 1.0/1.1)
- Use strong cipher suites
- Enable Perfect Forward Secrecy (PFS)
- Implement HSTS headers

**Example**:
```go
config := &tls.Config{
    MinVersion:               tls.VersionTLS12,
    PreferServerCipherSuites: true,
    CipherSuites: []uint16{
        tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    },
}

// HSTS header
w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
```

### Mutual TLS (mTLS)

**Key Points**:
- Verify both server and client certificates
- Use for service-to-service communication
- Implement certificate rotation
- Use short-lived certificates

**Example**:
```go
// Server-side: Require client certificates
tlsConfig.SetClientAuth(caCertPEM)

// Client-side: Provide client certificate
tlsConfig := NewTLSConfig(clientCertPEM, clientKeyPEM)
```

## Authentication & Authorization

### JWT Best Practices

**Key Points**:
- Use strong secrets (256+ bits)
- Set appropriate expiration times
- Include issuer and audience claims
- Validate all claims
- Use refresh tokens for long sessions
- Store tokens securely (httpOnly cookies)

**Example**:
```go
jwt := NewJWT(secret)

// Create token
claims := &JWTClaims{
    Subject:   userID,
    ExpiresAt: time.Now().Add(15 * time.Minute).Unix(),
    Issuer:    "myapp",
}
token, err := jwt.Create(claims)

// Verify token
claims, err := jwt.Verify(token)
```

### API Keys

**Key Points**:
- Generate cryptographically random keys
- Set expiration dates
- Implement key rotation
- Use scopes/permissions
- Rate limit per key
- Log key usage

**Example**:
```go
manager := NewAPIKeyManager()

// Generate key
apiKey, err := manager.Generate("client-app", []string{"read", "write"}, 365*24*time.Hour)

// Verify key
key, err := manager.Verify(apiKeyString)
if !key.HasScope("write") {
    return errors.New("insufficient permissions")
}
```

### RBAC Implementation

**Key Points**:
- Principle of least privilege
- Separate roles from users
- Regular permission audits
- Implement permission inheritance
- Log authorization decisions

**Example**:
```go
rbac := NewRBAC()

// Define roles
rbac.AddRole("admin", []Permission{"read", "write", "delete"})
rbac.AddRole("user", []Permission{"read", "write"})

// Assign roles to users
rbac.AddUser("user123", "john", []string{"user"})

// Check permissions
if !rbac.CheckPermission("user123", "delete") {
    return errors.New("permission denied")
}
```

### Session Management

**Key Points**:
- Generate cryptographically random session IDs
- Set appropriate timeouts
- Implement sliding expiration
- Secure session storage
- Invalidate on logout
- Use httpOnly and secure cookie flags

**Example**:
```go
sessionMgr := NewSessionManager(30 * time.Minute)

// Create session
session, err := sessionMgr.Create(userID)

// Set secure cookie
http.SetCookie(w, &http.Cookie{
    Name:     "session_id",
    Value:    session.ID,
    HttpOnly: true,
    Secure:   true,
    SameSite: http.SameSiteStrictMode,
})

// Retrieve session
session, err := sessionMgr.Get(sessionID)
```

## Secure Coding Practices

### Input Validation

```go
// Validate email
func validateEmail(email string) bool {
    regex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
    return regex.MatchString(email)
}

// Validate length
if len(input) > maxLength {
    return errors.New("input too long")
}

// Sanitize HTML
import "html"
safe := html.EscapeString(userInput)
```

### Error Handling

```go
// DON'T expose internal details
return fmt.Errorf("database connection failed: %v", err)

// DO return generic messages to users
return errors.New("an error occurred, please try again")

// Log detailed errors internally
log.Printf("Database error for user %s: %v", userID, err)
```

### Secure Random Generation

```go
// Use crypto/rand, not math/rand
import "crypto/rand"

bytes := make([]byte, 32)
if _, err := rand.Read(bytes); err != nil {
    return err
}
```

### Safe Concurrency

```go
// Always use mutexes for shared state
type SafeMap struct {
    data map[string]string
    mu   sync.RWMutex
}

func (sm *SafeMap) Get(key string) (string, bool) {
    sm.mu.RLock()
    defer sm.mu.RUnlock()
    val, ok := sm.data[key]
    return val, ok
}
```

## Network Security Checklist

### Development
- [ ] Use HTTPS/TLS for all communications
- [ ] Validate all input data
- [ ] Escape all output data
- [ ] Use parameterized queries
- [ ] Implement proper error handling
- [ ] Use secure random number generation
- [ ] Hash passwords with bcrypt/scrypt/Argon2
- [ ] Implement CSRF protection
- [ ] Set security headers (CSP, HSTS, X-Frame-Options)
- [ ] Sanitize user-generated content

### Authentication & Authorization
- [ ] Implement multi-factor authentication
- [ ] Use strong password policies
- [ ] Implement account lockout after failed attempts
- [ ] Use JWT or similar for stateless auth
- [ ] Implement RBAC or ABAC
- [ ] Secure session management
- [ ] Implement API key rotation
- [ ] Log all authentication events

### Infrastructure
- [ ] Keep systems and dependencies updated
- [ ] Use firewalls and network segmentation
- [ ] Implement rate limiting
- [ ] Set up intrusion detection
- [ ] Use load balancers
- [ ] Implement DDoS protection
- [ ] Regular security audits
- [ ] Penetration testing

### Data Protection
- [ ] Encrypt sensitive data at rest
- [ ] Encrypt data in transit
- [ ] Implement key management
- [ ] Regular backups
- [ ] Secure backup storage
- [ ] Data retention policies
- [ ] GDPR/compliance requirements

### Monitoring & Response
- [ ] Comprehensive logging
- [ ] Log aggregation and analysis
- [ ] Security event monitoring
- [ ] Alerting for suspicious activity
- [ ] Incident response plan
- [ ] Regular log reviews
- [ ] Security metrics and KPIs

### Deployment
- [ ] Separate production and development environments
- [ ] Use environment variables for secrets
- [ ] Implement secrets management (Vault, AWS Secrets Manager)
- [ ] Minimize exposed services
- [ ] Disable debug/verbose modes
- [ ] Regular security scans
- [ ] Automated security testing in CI/CD

## Resources

- OWASP Top 10: https://owasp.org/www-project-top-ten/
- NIST Cybersecurity Framework: https://www.nist.gov/cyberframework
- CWE Top 25: https://cwe.mitre.org/top25/
- Mozilla TLS Configuration: https://wiki.mozilla.org/Security/Server_Side_TLS

## Security Reporting

If you discover a security vulnerability, please report it to the security team immediately. Do not disclose it publicly until it has been addressed.
