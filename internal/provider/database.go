// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"

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
