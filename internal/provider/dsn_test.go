package provider

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"
)

func TestStandardPostgresDSN(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
		host     string
		database string
		wantHost string
	}{
		{"plain", "postgres", "postgres", "localhost", "postgres", "localhost"},
		{"special chars in password", "postgres", "p@ss:w/o?r#d%x y", "db.example.com", "postgres", "db.example.com"},
		{"percent-encoded looking password", "postgres", "p%40ss", "localhost", "postgres", "localhost"},
		{"special chars in username and database", "us:er@x", "secret", "localhost", "my/db?x#y", "localhost"},
		{"ipv4", "postgres", "secret", "10.0.0.1", "postgres", "10.0.0.1"},
		{"ipv6 bare", "postgres", "secret", "::1", "postgres", "::1"},
		{"ipv6 bracketed", "postgres", "secret", "[::1]", "postgres", "::1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dsn := standardPostgresDSN(tt.username, tt.password, tt.host, 5432, tt.database, "verify-full")

			u, err := url.Parse(dsn)
			if err != nil {
				t.Fatalf("url.Parse(%q): %v", dsn, err)
			}
			if got := u.User.Username(); got != tt.username {
				t.Errorf("username = %q, want %q", got, tt.username)
			}
			if got, _ := u.User.Password(); got != tt.password {
				t.Errorf("password = %q, want %q", got, tt.password)
			}
			if got := u.Hostname(); got != tt.wantHost {
				t.Errorf("host = %q, want %q", got, tt.wantHost)
			}
			if got := u.Port(); got != "5432" {
				t.Errorf("port = %q, want %q", got, "5432")
			}
			if got := u.Path; got != "/"+tt.database {
				t.Errorf("path = %q, want %q", got, "/"+tt.database)
			}
			if got := u.Query().Get("sslmode"); got != "verify-full" {
				t.Errorf("sslmode = %q, want %q", got, "verify-full")
			}

			opts, err := pq.ParseURL(dsn)
			if err != nil {
				t.Fatalf("pq.ParseURL(%q): %v", dsn, err)
			}
			for _, want := range []string{
				"user='" + tt.username + "'",
				"password='" + tt.password + "'",
				"host='" + tt.wantHost + "'",
				"port='5432'",
				"dbname='" + tt.database + "'",
				"sslmode='verify-full'",
			} {
				if !strings.Contains(opts, want) {
					t.Errorf("pq options %q do not contain %q", opts, want)
				}
			}
		})
	}
}

func TestStandardPostgresDSNSSLModeIsSingleParam(t *testing.T) {
	dsn := standardPostgresDSN("postgres", "secret", "localhost", 5432, "postgres", "verify-full&sslrootcert=/x.pem")

	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", dsn, err)
	}
	q := u.Query()
	if len(q) != 1 {
		t.Errorf("query params = %v, want only sslmode", q)
	}
	if got := q.Get("sslmode"); got != "verify-full&sslrootcert=/x.pem" {
		t.Errorf("sslmode = %q, want %q", got, "verify-full&sslrootcert=/x.pem")
	}
}

func TestStandardPostgresGetterErrorDoesNotLeakPassword(t *testing.T) {
	const password = "FAKE-pw%zz@/?#"

	hosts := []string{"127.0.0.1", "a b", "/var/run/postgresql", "host:5432", "h\x00x"}
	for _, host := range hosts {
		t.Run(host, func(t *testing.T) {
			dsn := standardPostgresDSN("postgres", password, host, 1, "postgres", "disable")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			_, err := GetStandardPostgresGetter(dsn)(ctx)
			if err == nil {
				t.Fatal("expected connection error")
			}
			for _, secret := range []string{"FAKE-pw", url.UserPassword("", password).String()[1:]} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("error leaks password: %v", err)
				}
			}
		})
	}
}

func TestStandardPostgresGetterRedactsRawURLError(t *testing.T) {
	dsn := "postgres://postgres:FAKE-pw%zz@127.0.0.1:1/postgres?sslmode=disable"

	_, err := GetStandardPostgresGetter(dsn)(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "FAKE-pw") {
		t.Errorf("error leaks password: %v", err)
	}
	if !strings.Contains(err.Error(), "invalid connection URL") {
		t.Errorf("error = %v, want invalid connection URL", err)
	}
}
