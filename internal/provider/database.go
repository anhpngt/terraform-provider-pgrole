package provider

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"
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
			return nil, fmt.Errorf("error connecting to database: %s", err)
		}

		return db, nil
	}
}

// GetRDSIAMPostgresGetter returns a function that can be used to get a PostgreSQL
// connection to an AWS RDS instance, authenticating with an IAM auth token.
//
// A new token is generated on every call, since tokens are only valid for 15 minutes.
//
// Remember to call db.Close() to cleanup the connection.
func GetRDSIAMPostgresGetter(creds aws.CredentialsProvider, region, host string, port int64, database, username, sslmode string) F {
	return func(ctx context.Context) (*sql.DB, error) {
		dsn, err := buildRDSIAMDSN(ctx, creds, region, host, port, database, username, sslmode)
		if err != nil {
			return nil, err
		}
		return GetStandardPostgresGetter(dsn)(ctx)
	}
}

// buildRDSIAMDSN generates an RDS IAM auth token and returns a connection string using it as the password.
func buildRDSIAMDSN(ctx context.Context, creds aws.CredentialsProvider, region, host string, port int64, database, username, sslmode string) (string, error) {
	endpoint := net.JoinHostPort(host, strconv.FormatInt(port, 10))
	token, err := auth.BuildAuthToken(ctx, endpoint, region, username, creds)
	if err != nil {
		return "", fmt.Errorf("error building RDS IAM auth token: %s", err)
	}
	return buildPostgresURL(username, token, host, port, database, sslmode), nil
}

// buildPostgresURL returns a postgres:// connection string with the credentials properly escaped.
func buildPostgresURL(username, password, host string, port int64, database, sslmode string) string {
	u := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(username, password),
		Host:     net.JoinHostPort(host, strconv.FormatInt(port, 10)),
		Path:     "/" + database,
		RawQuery: url.Values{"sslmode": {sslmode}}.Encode(),
	}
	return u.String()
}
