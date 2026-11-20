package provider

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	_ "github.com/lib/pq" // PostgreSQL driver
	"gocloud.dev/gcp"
	"gocloud.dev/gcp/cloudsql"
	"gocloud.dev/postgres"
	"gocloud.dev/postgres/gcppostgres"
	"google.golang.org/api/impersonate"
)

// F is a function that returns a database connection.
type F func(context.Context) (*sql.DB, error)

// GetDatabaseGetter returns a function that can be used to get a database connection.
//
// Remember to call db.Close() to cleanup the connection.
func GetDatabaseGetter(dsn string) F {
	return func(ctx context.Context) (*sql.DB, error) {
		return postgres.Open(ctx, dsn)
	}
}

// GetDatabaseGetterWithImpersonation is similar to GetDatabaseGetter
// but allows impersonating a service account.
func GetDatabaseGetterWithImpersonation(dsn string, targetServiceAccountEmail string) F {
	return func(ctx context.Context) (*sql.DB, error) {
		ts, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
			TargetPrincipal: targetServiceAccountEmail,
			Scopes:          []string{"https://www.googleapis.com/auth/sqlservice.admin"},
		})
		if err != nil {
			return nil, fmt.Errorf("error creating token source: %s", err)
		}
		client, err := gcp.NewHTTPClient(gcp.DefaultTransport(), ts)
		if err != nil {
			return nil, fmt.Errorf("error creating HTTP client: %s", err)
		}
		certSource := cloudsql.NewCertSourceWithIAM(client, ts)
		opener := gcppostgres.URLOpener{CertSource: certSource}
		dbURL, err := url.Parse(dsn)
		if err != nil {
			return nil, fmt.Errorf("error parsing database connection string: %s", err)
		}
		return opener.OpenPostgresURL(ctx, dbURL)
	}
}

// standardPostgresConfig holds the parameters of a standard PostgreSQL
// connection.
type standardPostgresConfig struct {
	Username string
	Password string
	Host     string
	Port     int64
	Database string
	SSLMode  string
	// SSLRootCert is the path to a PEM file with the root CA certificates
	// that verify the server certificate. It is not in the DSN when empty.
	SSLRootCert string
}

// standardPostgresDSN returns the connection URL for lib/pq, with every part
// escaped.
func standardPostgresDSN(c standardPostgresConfig) string {
	params := url.Values{"sslmode": {c.SSLMode}}
	if c.SSLRootCert != "" {
		params.Set("sslrootcert", c.SSLRootCert)
	}

	u := &url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(c.Username, c.Password),
		Host:     net.JoinHostPort(strings.TrimSuffix(strings.TrimPrefix(c.Host, "["), "]"), strconv.FormatInt(c.Port, 10)),
		Path:     "/" + c.Database,
		RawQuery: params.Encode(),
	}
	return u.String()
}

func redactURLError(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return fmt.Errorf("invalid connection URL: %w", urlErr.Err)
	}
	return err
}

// GetStandardPostgresGetter returns a function that can be used to get a standard PostgreSQL connection.
//
// Remember to call db.Close() to cleanup the connection.
func GetStandardPostgresGetter(dsn string) F {
	return func(ctx context.Context) (*sql.DB, error) {
		db, err := sql.Open("postgres", dsn)
		if err != nil {
			return nil, fmt.Errorf("error opening database connection: %s", err)
		}

		// Test the connection
		if err := db.PingContext(ctx); err != nil {
			db.Close()
			return nil, fmt.Errorf("error connecting to database: %s", redactURLError(err))
		}

		return db, nil
	}
}
