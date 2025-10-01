package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// SSLResult represents SSL/TLS scan results
type SSLResult struct {
	Domain      string
	Port        string
	Status      string
	Issues      []string
	Certificate CertInfo
	TLSVersion  string
	CipherSuite string
}

// CertInfo contains certificate details
type CertInfo struct {
	Subject         string
	Issuer          string
	NotBefore       string
	NotAfter        string
	DaysUntilExpiry int
	SignatureAlg    string
	KeySize         int
	SANs            []string
}

// sslScanner performs SSL/TLS security assessment
func sslScanner(domain string) ([]string, error) {
	var results []string

	// Parse domain to get hostname
	hostname := domain
	if u, err := url.Parse(domain); err == nil && u.Host != "" {
		hostname = u.Hostname()
	}

	// Common HTTPS ports
	ports := []string{"443", "8443", "9443"}

	for _, port := range ports {
		result := scanSSLPort(hostname, port)
		if result != nil {
			results = append(results, formatSSLResult(*result)...)
		}
	}

	if len(results) == 0 {
		results = append(results, "No SSL/TLS services found or all connections failed")
	}

	return results, nil
}

// scanSSLPort scans SSL on a specific port
func scanSSLPort(hostname, port string) *SSLResult {
	address := net.JoinHostPort(hostname, port)

	config := &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true, // allow analysis of invalid certs
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", address, config)
	if err != nil {
		return nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	result := &SSLResult{
		Domain:     hostname,
		Port:       port,
		Status:     "Connected",
		Issues:     []string{},
		TLSVersion: getTLSVersionString(state.Version),
	}

	if state.CipherSuite != 0 {
		result.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	}

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.Certificate = analyzeCertificate(cert, hostname)
		result.Issues = append(result.Issues, checkCertificateIssues(cert, hostname)...)
	}

	result.Issues = append(result.Issues, checkTLSVersionIssues(state.Version)...)
	result.Issues = append(result.Issues, checkCipherSuiteIssues(state.CipherSuite)...)

	return result
}

// analyzeCertificate extracts certificate information
func analyzeCertificate(cert *x509.Certificate, hostname string) CertInfo {
	daysUntilExpiry := int(time.Until(cert.NotAfter).Hours() / 24)

	keySize := 0
	if cert.PublicKey != nil {
		switch key := cert.PublicKey.(type) {
		case *rsa.PublicKey:
			keySize = key.Size() * 8
		case *ecdsa.PublicKey:
			keySize = key.Curve.Params().BitSize
		}
	}

	sans := cert.DNSNames
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}

	return CertInfo{
		Subject:         cert.Subject.String(),
		Issuer:          cert.Issuer.String(),
		NotBefore:       cert.NotBefore.Format("2006-01-02 15:04:05"),
		NotAfter:        cert.NotAfter.Format("2006-01-02 15:04:05"),
		DaysUntilExpiry: daysUntilExpiry,
		SignatureAlg:    cert.SignatureAlgorithm.String(),
		KeySize:         keySize,
		SANs:            sans,
	}
}

// checkCertificateIssues identifies certificate problems
func checkCertificateIssues(cert *x509.Certificate, hostname string) []string {
	var issues []string

	daysUntilExpiry := int(time.Until(cert.NotAfter).Hours() / 24)
	if daysUntilExpiry < 0 {
		issues = append(issues, "CRITICAL: Certificate has expired")
	} else if daysUntilExpiry < 7 {
		issues = append(issues, "CRITICAL: Certificate expires in less than 7 days")
	} else if daysUntilExpiry < 30 {
		issues = append(issues, "WARNING: Certificate expires in less than 30 days")
	}

	switch cert.SignatureAlgorithm {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA:
		issues = append(issues, "CRITICAL: Weak signature algorithm ("+cert.SignatureAlgorithm.String()+")")
	}

	if key, ok := cert.PublicKey.(*rsa.PublicKey); ok {
		keySize := key.Size() * 8
		if keySize < 2048 {
			issues = append(issues, fmt.Sprintf("CRITICAL: Weak RSA key size (%d bits)", keySize))
		}
	}

	if err := cert.VerifyHostname(hostname); err != nil {
		issues = append(issues, "CRITICAL: Certificate does not match hostname")
	}

	if cert.Issuer.String() == cert.Subject.String() {
		issues = append(issues, "WARNING: Self-signed certificate")
	}

	return issues
}

// checkTLSVersionIssues identifies TLS version problems
func checkTLSVersionIssues(version uint16) []string {
	var issues []string

	switch version {
	case tls.VersionSSL30:
		issues = append(issues, "CRITICAL: SSL 3.0 is deprecated and insecure")
	case tls.VersionTLS10:
		issues = append(issues, "CRITICAL: TLS 1.0 is deprecated and insecure")
	case tls.VersionTLS11:
		issues = append(issues, "WARNING: TLS 1.1 is deprecated, upgrade to TLS 1.2+")
	case tls.VersionTLS12:
		issues = append(issues, "OK: TLS 1.2 is acceptable")
	case tls.VersionTLS13:
		issues = append(issues, "OK: TLS 1.3 is the latest standard")
	default:
		issues = append(issues, "WARNING: Unknown TLS version")
	}

	return issues
}

// checkCipherSuiteIssues identifies cipher suite problems
func checkCipherSuiteIssues(cipherSuite uint16) []string {
	var issues []string

	weakCiphers := map[uint16]string{
		tls.TLS_RSA_WITH_RC4_128_SHA:         "RC4 is broken",
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:    "3DES is deprecated",
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:   "RC4 is broken",
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA: "RC4 is broken",
	}

	if reason, isWeak := weakCiphers[cipherSuite]; isWeak {
		issues = append(issues, fmt.Sprintf("CRITICAL: Weak cipher suite - %s", reason))
	}

	cipherName := tls.CipherSuiteName(cipherSuite)
	if strings.Contains(strings.ToLower(cipherName), "rc4") {
		issues = append(issues, "CRITICAL: RC4 cipher is broken")
	}
	if strings.Contains(strings.ToLower(cipherName), "des") {
		issues = append(issues, "WARNING: DES/3DES cipher is deprecated")
	}
	if strings.Contains(strings.ToLower(cipherName), "md5") {
		issues = append(issues, "CRITICAL: MD5 hash is broken")
	}

	return issues
}

// getTLSVersionString converts TLS version to readable string
func getTLSVersionString(version uint16) string {
	switch version {
	case tls.VersionSSL30:
		return "SSL 3.0"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

// formatSSLResult formats SSL scan results for display
func formatSSLResult(result SSLResult) []string {
	var output []string

	output = append(output, fmt.Sprintf("=== SSL/TLS Analysis for %s:%s ===", result.Domain, result.Port))
	output = append(output, fmt.Sprintf("TLS Version: %s", result.TLSVersion))
	output = append(output, fmt.Sprintf("Cipher Suite: %s", result.CipherSuite))
	output = append(output, "")

	cert := result.Certificate
	output = append(output, "Certificate Information:")
	output = append(output, fmt.Sprintf("  Subject: %s", cert.Subject))
	output = append(output, fmt.Sprintf("  Issuer: %s", cert.Issuer))
	output = append(output, fmt.Sprintf("  Valid From: %s", cert.NotBefore))
	output = append(output, fmt.Sprintf("  Valid Until: %s", cert.NotAfter))
	output = append(output, fmt.Sprintf("  Days Until Expiry: %d", cert.DaysUntilExpiry))
	output = append(output, fmt.Sprintf("  Signature Algorithm: %s", cert.SignatureAlg))

	if cert.KeySize > 0 {
		output = append(output, fmt.Sprintf("  Key Size: %d bits", cert.KeySize))
	}
	if len(cert.SANs) > 0 {
		output = append(output, fmt.Sprintf("  Subject Alternative Names: %s", strings.Join(cert.SANs, ", ")))
	}
	output = append(output, "")

	if len(result.Issues) > 0 {
		output = append(output, "Security Issues Found:")
		for _, issue := range result.Issues {
			output = append(output, fmt.Sprintf("  %s", issue))
		}
	} else {
		output = append(output, "No critical SSL/TLS issues detected")
	}

	output = append(output, "")
	return output
}
