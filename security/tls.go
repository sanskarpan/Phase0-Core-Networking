/*
TLS/SSL Implementation
======================

TLS/SSL certificate handling and secure connections.

Applications:
- HTTPS servers
- Secure client-server communication
- Certificate management
- Mutual TLS (mTLS)
*/

package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

// =============================================================================
// Certificate Generation
// =============================================================================

// CertificateConfig contains configuration for certificate generation
type CertificateConfig struct {
	CommonName         string
	Organization       string
	Country            string
	Province           string
	Locality           string
	OrganizationalUnit string
	ValidFor           time.Duration
	IsCA               bool
	DNSNames           []string
	IPAddresses        []net.IP
}

// GenerateSelfSignedCert generates a self-signed certificate
func GenerateSelfSignedCert(config CertificateConfig) (certPEM, keyPEM []byte, err error) {
	// Generate private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Set up certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         config.CommonName,
			Organization:       []string{config.Organization},
			Country:            []string{config.Country},
			Province:           []string{config.Province},
			Locality:           []string{config.Locality},
			OrganizationalUnit: []string{config.OrganizationalUnit},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(config.ValidFor),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              config.DNSNames,
		IPAddresses:           config.IPAddresses,
	}

	if config.IsCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	// Create certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	// Encode certificate to PEM
	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	// Encode private key to PEM
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}

	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	return certPEM, keyPEM, nil
}

// GenerateCA generates a certificate authority
func GenerateCA(config CertificateConfig) (certPEM, keyPEM []byte, err error) {
	config.IsCA = true
	return GenerateSelfSignedCert(config)
}

// SignCertificate signs a certificate with a CA
func SignCertificate(caCertPEM, caKeyPEM, csrPEM []byte, validFor time.Duration) ([]byte, error) {
	// Parse CA certificate
	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil {
		return nil, errors.New("failed to decode CA certificate")
	}

	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, err
	}

	// Parse CA private key
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		return nil, errors.New("failed to decode CA key")
	}

	caKey, err := x509.ParseECPrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	// Parse CSR
	csrBlock, _ := pem.Decode(csrPEM)
	if csrBlock == nil {
		return nil, errors.New("failed to decode CSR")
	}

	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return nil, err
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	// Create certificate template from CSR
	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               csr.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(validFor),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
	}

	// Sign the certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	// Encode to PEM
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}), nil
}

// =============================================================================
// TLS Configuration
// =============================================================================

// TLSConfig wraps tls.Config with helpers
type TLSConfig struct {
	config *tls.Config
}

// NewTLSConfig creates a new TLS configuration
func NewTLSConfig(certPEM, keyPEM []byte) (*TLSConfig, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
		PreferServerCipherSuites: true,
	}

	return &TLSConfig{config: config}, nil
}

// SetClientAuth configures client authentication
func (tc *TLSConfig) SetClientAuth(caCertPEM []byte) error {
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caCertPEM) {
		return errors.New("failed to append CA certificate")
	}

	tc.config.ClientCAs = certPool
	tc.config.ClientAuth = tls.RequireAndVerifyClientCert

	return nil
}

// SetServerName sets the server name for SNI
func (tc *TLSConfig) SetServerName(serverName string) {
	tc.config.ServerName = serverName
}

// SetInsecureSkipVerify sets whether to skip certificate verification (for testing only)
func (tc *TLSConfig) SetInsecureSkipVerify(skip bool) {
	tc.config.InsecureSkipVerify = skip
}

// GetConfig returns the underlying tls.Config
func (tc *TLSConfig) GetConfig() *tls.Config {
	return tc.config
}

// =============================================================================
// TLS Server
// =============================================================================

// TLSServer wraps a TLS listener.
//
// C4: Usage note — the tcp, rpc, and websocket packages accept a raw *tls.Config
// directly (e.g. tcp.NewTLSServer, rpc.Server.ListenTLS, websocket.Upgrader.TLSConfig).
// TLSServer and TLSClient are higher-level convenience wrappers around the same
// tls.Listen / tls.Dial primitives and are useful when you want to accept connections
// without embedding a full tcp.Server (e.g. custom accept loops, proxies).
// When using the higher-level servers, prefer constructing a *tls.Config via
// security.NewTLSConfig and calling GetConfig() to pass into the respective server.
type TLSServer struct {
	Address  string
	config   *tls.Config
	listener net.Listener
}

// NewTLSServer creates a new TLS server using the security package's TLS defaults
// (TLS 1.2+, strong cipher suites) as configured by the provided TLSConfig. (C4)
func NewTLSServer(address string, tlsConfig *TLSConfig) *TLSServer {
	return &TLSServer{
		Address: address,
		config:  tlsConfig.config,
	}
}

// Listen starts listening for TLS connections
func (s *TLSServer) Listen() error {
	listener, err := tls.Listen("tcp", s.Address, s.config)
	if err != nil {
		return err
	}

	s.listener = listener
	return nil
}

// Accept accepts a TLS connection
func (s *TLSServer) Accept() (net.Conn, error) {
	return s.listener.Accept()
}

// Close closes the server
func (s *TLSServer) Close() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// =============================================================================
// TLS Client
// =============================================================================

// TLSClient represents a TLS client
type TLSClient struct {
	config *tls.Config
}

// NewTLSClient creates a new TLS client
func NewTLSClient(tlsConfig *TLSConfig) *TLSClient {
	return &TLSClient{
		config: tlsConfig.config,
	}
}

// Dial connects to a TLS server
func (c *TLSClient) Dial(address string) (net.Conn, error) {
	return tls.Dial("tcp", address, c.config)
}

// =============================================================================
// Certificate Verification
// =============================================================================

// VerifyCertificate verifies a certificate chain
func VerifyCertificate(certPEM, caCertPEM []byte) error {
	// Parse certificate
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return errors.New("failed to decode certificate")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return err
	}

	// Create CA pool
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caCertPEM) {
		return errors.New("failed to append CA certificate")
	}

	// Verify
	opts := x509.VerifyOptions{
		Roots: roots,
	}

	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("certificate verification failed: %w", err)
	}

	return nil
}

// GetCertificateInfo extracts information from a certificate
func GetCertificateInfo(certPEM []byte) (*CertificateInfo, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, errors.New("failed to decode certificate")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return &CertificateInfo{
		Subject:    cert.Subject.CommonName,
		Issuer:     cert.Issuer.CommonName,
		NotBefore:  cert.NotBefore,
		NotAfter:   cert.NotAfter,
		DNSNames:   cert.DNSNames,
		IsCA:       cert.IsCA,
		SerialNumber: cert.SerialNumber.String(),
	}, nil
}

// CertificateInfo contains certificate information
type CertificateInfo struct {
	Subject      string
	Issuer       string
	NotBefore    time.Time
	NotAfter     time.Time
	DNSNames     []string
	IsCA         bool
	SerialNumber string
}

// IsExpired checks if a certificate is expired
func (ci *CertificateInfo) IsExpired() bool {
	return time.Now().After(ci.NotAfter)
}

// ExpiresIn returns the time until the certificate expires
func (ci *CertificateInfo) ExpiresIn() time.Duration {
	return time.Until(ci.NotAfter)
}
