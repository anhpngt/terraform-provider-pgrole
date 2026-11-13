package provider

import (
	"strings"
	"testing"

	"github.com/lib/pq"
)

func TestWithSSLRootCert(t *testing.T) {
	const dsn = "postgres://postgres:postgres@localhost:5432/postgres?sslmode=verify-full"

	if got := withSSLRootCert(dsn, ""); got != dsn {
		t.Errorf("unset sslrootcert must leave the DSN unchanged, got %q", got)
	}

	for _, sslrootcert := range []string{
		"/etc/ssl/certs/root-ca.pem",
		"./ca.pem",
		"/path with spaces/root&ca=1.pem",
	} {
		got := withSSLRootCert(dsn, sslrootcert)
		if !strings.HasPrefix(got, dsn+"&sslrootcert=") {
			t.Errorf("DSN must only gain the sslrootcert parameter, got %q", got)
		}

		opts, err := pq.ParseURL(got)
		if err != nil {
			t.Fatalf("pq.ParseURL(%q): %v", got, err)
		}
		if want := "sslrootcert='" + sslrootcert + "'"; !strings.Contains(opts, want) {
			t.Errorf("pq options %q do not contain %q", opts, want)
		}
		if !strings.Contains(opts, "sslmode='verify-full'") {
			t.Errorf("pq options %q lost sslmode", opts)
		}
	}
}
