package azuredevops

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// tlsInsecureConfig is isolated in its own file so the one place that disables
// certificate verification is easy to find and audit. It is only reachable via
// scan.insecure in the config file.
func tlsInsecureConfig() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in via scan.insecure
}

// LoadCABundle returns the system roots with the certificates in the PEM file
// at path added to them.
//
// Added, not substituted. An Azure DevOps Server behind an internal CA is the
// case this exists for, but the same scan may also reach an Entra endpoint or
// a proxy with a public certificate, and replacing the roots would turn the
// fix for one host into a failure on every other. A file that cannot be read,
// or that holds no certificate at all, is an error: a bundle that silently
// added nothing would leave the operator debugging certificate errors they
// believe they have fixed — or reaching for scan.insecure instead.
func LoadCABundle(path string) (*x509.CertPool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("scan.caFile: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		// Some platforms (and stripped containers) have no system pool to
		// start from; the bundle alone is still better than nothing.
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("scan.caFile %s holds no PEM certificate", path)
	}
	return pool, nil
}

// transportTLS verifies against pool, which already holds the system roots.
func transportTLS(pool *x509.CertPool) *tls.Config {
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}
