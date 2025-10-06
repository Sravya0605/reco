package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

const (
	defaultSSLTimeout = 10 * time.Second
)

// SSLResult holds the results of an SSL scan
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

// sslScanner performs SSL/TLS security assessment on a domain
func sslScanner(domain string) ([]string, error) {
	var results []string

	hostname := domain
	if u, err := url.Parse(domain); err == nil && u.Host != "" {
		hostname = u.Host
	}

	ports := []string{"443", "8443", "9443"}

	for _, port := range ports {
		result := scanPort(hostname, port)
		if result != nil {
			results = append(results, formatSSLResult(*result)...)
		}
	}

	if len(results) == 0 {
		results = append(results, "❌ No SSL/TLS services detected or connection failed.")
	}

	return results, nil
}

func scanPort(hostname, port string) *SSLResult {
	address := net.JoinHostPort(hostname, port)

	config := &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true,
	}

	dialer := &net.Dialer{Timeout: defaultSSLTimeout}
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
		TLSVersion: tlsVersionToString(state.Version),
	}

	if state.CipherSuite != 0 {
		result.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	}

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.Certificate = analyzeCertificate(cert)
		result.Issues = append(result.Issues, checkCertificateIssues(cert, hostname)...)
	}

	result.Issues = append(result.Issues, checkTLSVersionIssues(state.Version)...)
	result.Issues = append(result.Issues, checkCipherSuiteIssues(state.CipherSuite)...)

	return result
}

func analyzeCertificate(cert *x509.Certificate) CertInfo {
	daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
	keySize := 0

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		keySize = pub.Size() * 8
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
		DaysUntilExpiry: daysLeft,
		SignatureAlg:    cert.SignatureAlgorithm.String(),
		KeySize:         keySize,
		SANs:            sans,
	}
}

func checkCertificateIssues(cert *x509.Certificate, hostname string) []string {
	var issues []string

	daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
	if daysLeft < 0 {
		issues = append(issues, "🔴 Certificate has expired")
	} else if daysLeft < 7 {
		issues = append(issues, "🔴 Certificate will expire within 7 days")
	} else if daysLeft < 30 {
		issues = append(issues, "🟡 Certificate will expire within 30 days")
	}

	switch cert.SignatureAlgorithm {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA:
		issues = append(issues, "🔴 Weak signature algorithm detected")
	}

	if pub, ok := cert.PublicKey.(*rsa.PublicKey); ok {
		if pub.Size()*8 < 2048 {
			issues = append(issues, "🔴 RSA key size less than 2048 bits")
		}
	}

	if err := cert.VerifyHostname(hostname); err != nil {
		issues = append(issues, "🔴 Certificate hostname mismatch")
	}

	if cert.Issuer.String() == cert.Subject.String() {
		issues = append(issues, "🟡 Self-signed certificate")
	}

	return issues
}

func checkTLSVersionIssues(version uint16) []string {
	var issues []string

	switch version {
	case tls.VersionSSL30:
		issues = append(issues, "🔴 SSLv3 is insecure and deprecated")
	case tls.VersionTLS10:
		issues = append(issues, "🔴 TLS 1.0 is insecure and deprecated")
	case tls.VersionTLS11:
		issues = append(issues, "🟡 TLS 1.1 is deprecated")
	case tls.VersionTLS12:
		issues = append(issues, " TLS 1.2 is acceptable")
	case tls.VersionTLS13:
		issues = append(issues, " TLS 1.3 is current standard")
	default:
		issues = append(issues, "🟡 Unknown TLS version")
	}

	return issues
}

func checkCipherSuiteIssues(cipher uint16) []string {
	var issues []string

	weakCiphers := map[uint16]string{
		tls.TLS_RSA_WITH_RC4_128_SHA:         "RC4 cipher is insecure",
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:    "3DES cipher is deprecated",
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:   "RC4 cipher is insecure",
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA: "RC4 cipher is insecure",
	}

	if reason, exists := weakCiphers[cipher]; exists {
		issues = append(issues, "🔴 "+reason)
	}

	return issues
}

func tlsVersionToString(ver uint16) string {
	switch ver {
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
		return fmt.Sprintf("Unknown (0x%04x)", ver)
	}
}

func formatSSLResult(result SSLResult) []string {
	var out []string

	out = append(out, fmt.Sprintf("=== SSL Analysis for %s:%s ===", result.Domain, result.Port))
	out = append(out, fmt.Sprintf("TLS Version: %s", result.TLSVersion))
	out = append(out, fmt.Sprintf("Cipher Suite: %s", result.CipherSuite))
	out = append(out, "")

	c := result.Certificate
	out = append(out, "Certificate Details:")
	out = append(out, fmt.Sprintf("  Subject: %s", c.Subject))
	out = append(out, fmt.Sprintf("  Issuer: %s", c.Issuer))
	out = append(out, fmt.Sprintf("  Valid From: %s", c.NotBefore))
	out = append(out, fmt.Sprintf("  Valid Until: %s", c.NotAfter))
	out = append(out, fmt.Sprintf("  Days Until Expiry: %d", c.DaysUntilExpiry))
	out = append(out, fmt.Sprintf("  Signature Algorithm: %s", c.SignatureAlg))
	if c.KeySize > 0 {
		out = append(out, fmt.Sprintf("  Key Size: %d bits", c.KeySize))
	}
	if len(c.SANs) > 0 {
		out = append(out, fmt.Sprintf("  Subject Alt Names: %s", strings.Join(c.SANs, ", ")))
	}
	out = append(out, "")

	if len(result.Issues) > 0 {
		out = append(out, "Issues Detected:")
		for _, issue := range result.Issues {
			out = append(out, "  "+issue)
		}
	} else {
		out = append(out, "No critical SSL/TLS issues detected.")
	}

	out = append(out, "")
	return out
}
