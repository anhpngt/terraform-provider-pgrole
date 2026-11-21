package provider

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStandardPostgresDSN(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name         string
		username     string
		password     string
		host         string
		database     string
		expectedHost string
	}{
		{"plain", "postgres", "postgres", "localhost", "postgres", "localhost"},
		{"special chars in password", "postgres", "p@ss:w/o?r#d%x y", "db.example.com", "postgres", "db.example.com"},
		{"percent-encoded looking password", "postgres", "p%40ss", "localhost", "postgres", "localhost"},
		{"special chars in username and database", "us:er@x", "secret", "localhost", "my/db?x#y", "localhost"},
		{"ipv4", "postgres", "secret", "10.0.0.1", "postgres", "10.0.0.1"},
		{"ipv6 bare", "postgres", "secret", "::1", "postgres", "::1"},
		{"ipv6 bracketed", "postgres", "secret", "[::1]", "postgres", "::1"},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dsn := standardPostgresDSN(standardPostgresConfig{
				Username: tc.username,
				Password: tc.password,
				Host:     tc.host,
				Port:     5432,
				Database: tc.database,
				SSLMode:  "verify-full",
			})

			u, err := url.Parse(dsn)
			require.NoError(t, err)
			password, _ := u.User.Password()
			assert.Equal(t, tc.username, u.User.Username())
			assert.Equal(t, tc.password, password)
			assert.Equal(t, tc.expectedHost, u.Hostname())
			assert.Equal(t, "5432", u.Port())
			assert.Equal(t, "/"+tc.database, u.Path)
			assert.Equal(t, url.Values{"sslmode": {"verify-full"}}, u.Query(), "an empty sslrootcert must not be in the DSN")

			// lib/pq parses the DSN on its own, so check its result too.
			opts, err := pq.ParseURL(dsn)
			require.NoError(t, err)
			for _, expected := range []string{
				"user='" + tc.username + "'",
				"password='" + tc.password + "'",
				"host='" + tc.expectedHost + "'",
				"port='5432'",
				"dbname='" + tc.database + "'",
				"sslmode='verify-full'",
			} {
				assert.Contains(t, opts, expected)
			}
		})
	}
}

func TestStandardPostgresDSN_SSLModeIsSingleParam(t *testing.T) {
	t.Parallel()

	const sslmode = "verify-full&sslrootcert=/x.pem"

	u, err := url.Parse(standardPostgresDSN(standardPostgresConfig{
		Username: "postgres",
		Password: "secret",
		Host:     "localhost",
		Port:     5432,
		Database: "postgres",
		SSLMode:  sslmode,
	}))
	require.NoError(t, err)

	q := u.Query()
	assert.Len(t, q, 1, "query parameters: %v", q)
	assert.Equal(t, sslmode, q.Get("sslmode"))
}

func TestStandardPostgresDSN_SSLRootCert(t *testing.T) {
	t.Parallel()

	for _, sslrootcert := range []string{
		"/etc/ssl/certs/root-ca.pem",
		"./ca.pem",
		"/path with spaces/root&ca=1.pem",
	} {
		t.Run(sslrootcert, func(t *testing.T) {
			t.Parallel()

			dsn := standardPostgresDSN(standardPostgresConfig{
				Username:    "postgres",
				Password:    "secret",
				Host:        "localhost",
				Port:        5432,
				Database:    "postgres",
				SSLMode:     "verify-full",
				SSLRootCert: sslrootcert,
			})

			u, err := url.Parse(dsn)
			require.NoError(t, err)
			assert.Equal(t, url.Values{
				"sslmode":     {"verify-full"},
				"sslrootcert": {sslrootcert},
			}, u.Query(), "the path must be one parameter, whatever characters it has")

			opts, err := pq.ParseURL(dsn)
			require.NoError(t, err)
			assert.Contains(t, opts, "sslrootcert='"+sslrootcert+"'")
			assert.Contains(t, opts, "sslmode='verify-full'")
		})
	}
}

func TestRedactURLError(t *testing.T) {
	t.Parallel()

	t.Run("url error", func(t *testing.T) {
		t.Parallel()

		// This is the error that url.Parse returns for the DSN.
		reason := url.EscapeError("%zz")
		parseErr := &url.Error{Op: "parse", URL: "postgres://user:FAKE-pw%zz@host/db", Err: reason}

		err := redactURLError(parseErr)
		assert.NotContains(t, err.Error(), "FAKE-pw")
		assert.Contains(t, err.Error(), "invalid connection URL")
		assert.ErrorIs(t, err, reason, "the parse reason must stay in the error chain")
	})

	t.Run("other error", func(t *testing.T) {
		t.Parallel()

		other := errors.New("connection refused")
		assert.Same(t, other, redactURLError(other))
	})
}

// The tests below connect to port 1 on the local host. The connection fails at
// once, so they need no server.

func TestGetStandardPostgresGetter_ErrorDoesNotLeakPassword(t *testing.T) {
	t.Parallel()

	const password = "FAKE-pw%zz@/?#"
	secrets := []string{"FAKE-pw", url.UserPassword("", password).String()[1:]}

	for _, host := range []string{"127.0.0.1", "a b", "/var/run/postgresql", "host:5432", "h\x00x"} {
		t.Run(host, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()

			dsn := standardPostgresDSN(standardPostgresConfig{
				Username: "postgres",
				Password: password,
				Host:     host,
				Port:     1,
				Database: "postgres",
				SSLMode:  "disable",
			})
			_, err := GetStandardPostgresGetter(dsn)(ctx)
			require.Error(t, err)
			for _, secret := range secrets {
				assert.NotContains(t, err.Error(), secret)
			}
		})
	}
}

func TestGetStandardPostgresGetter_RedactsRawURLError(t *testing.T) {
	t.Parallel()

	// A DSN that was not built by standardPostgresDSN is redacted too.
	_, err := GetStandardPostgresGetter("postgres://postgres:FAKE-pw%zz@127.0.0.1:1/postgres?sslmode=disable")(t.Context())
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "FAKE-pw")
	assert.Contains(t, err.Error(), "invalid connection URL")
}

func TestDSNForContext(t *testing.T) {
	t.Parallel()

	standard := standardPostgresDSN(standardPostgresConfig{
		Username: "postgres",
		Password: "p@ss:w/o?r#d",
		Host:     "db.example.com",
		Port:     5432,
		Database: "postgres",
		SSLMode:  "verify-full",
	})
	// The provider builds the Cloud SQL URL with the username as it is, and a
	// Cloud SQL IAM user has an @ in its name.
	const cloudSQL = "gcppostgres://sa@my-project.iam@my-project/my-region/my-instance/postgres"

	t.Run("no other database asked for", func(t *testing.T) {
		t.Parallel()

		// The URL must come back untouched, byte for byte: this is what every
		// resource but pgrole_revoke_on_destroy connects with.
		for _, dsn := range []string{standard, cloudSQL} {
			got, err := dsnForContext(t.Context(), dsn)
			require.NoError(t, err)
			assert.Equal(t, dsn, got)

			got, err = dsnForContext(withDatabase(t.Context(), ""), dsn)
			require.NoError(t, err)
			assert.Equal(t, dsn, got)
		}
	})

	for _, database := range []string{"app", "my-app_db", "my/db?x#y z", "naïve"} {
		t.Run("standard postgres to "+database, func(t *testing.T) {
			t.Parallel()

			dsn, err := dsnForContext(withDatabase(t.Context(), database), standard)
			require.NoError(t, err)

			u, err := url.Parse(dsn)
			require.NoError(t, err)
			password, _ := u.User.Password()
			assert.Equal(t, "postgres", u.User.Username())
			assert.Equal(t, "p@ss:w/o?r#d", password)
			assert.Equal(t, "db.example.com:5432", u.Host)
			assert.Equal(t, "/"+database, u.Path)
			assert.Equal(t, url.Values{"sslmode": {"verify-full"}}, u.Query())

			// lib/pq parses the DSN on its own, so check its result too.
			opts, err := pq.ParseURL(dsn)
			require.NoError(t, err)
			assert.Contains(t, opts, "dbname='"+database+"'")
			assert.Contains(t, opts, "password='p@ss:w/o?r#d'")
		})

		t.Run("cloud sql to "+database, func(t *testing.T) {
			t.Parallel()

			dsn, err := dsnForContext(withDatabase(t.Context(), database), cloudSQL)
			require.NoError(t, err)

			// gocloud.dev reads the project from the host, and the region,
			// the instance and the database from the path.
			u, err := url.Parse(dsn)
			require.NoError(t, err)
			assert.Equal(t, "sa@my-project.iam", u.User.Username())
			assert.Equal(t, "my-project", u.Host)
			assert.Equal(t, "/my-region/my-instance/"+database, u.Path)
		})
	}

	t.Run("invalid URL does not leak the password", func(t *testing.T) {
		t.Parallel()

		_, err := dsnForContext(withDatabase(t.Context(), "app"), "postgres://postgres:s3cret@[::1/postgres")
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "s3cret")
	})
}
