package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	providerConfig = `
provider "pgrole" {
  project_id = "my-project"
  region     = "my-region"
  instance   = "my-instance"
  database   = "my-database"

  username = "my-username"
}
`
)

var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"pgrole": providerserver.NewProtocol6WithError(New("test")()),
}

func str(v string) tftypes.Value { return tftypes.NewValue(tftypes.String, v) }

// providerConfigValue builds a provider configuration. Attributes that are not
// in attrs are null, the same as when the user does not set them.
func providerConfigValue(t *testing.T, p provider.Provider, attrs map[string]tftypes.Value) tfsdk.Config {
	t.Helper()

	schemaResp := &provider.SchemaResponse{}
	p.Schema(t.Context(), provider.SchemaRequest{}, schemaResp)
	requireNoErrors(t, schemaResp.Diagnostics)

	typ, ok := schemaResp.Schema.Type().TerraformType(t.Context()).(tftypes.Object)
	require.True(t, ok)

	values := map[string]tftypes.Value{}
	for name, attrType := range typ.AttributeTypes {
		if v, ok := attrs[name]; ok {
			values[name] = v
		} else {
			values[name] = tftypes.NewValue(attrType, nil)
		}
	}

	return tfsdk.Config{Schema: schemaResp.Schema, Raw: tftypes.NewValue(typ, values)}
}

func configureProvider(t *testing.T, attrs map[string]tftypes.Value) *provider.ConfigureResponse {
	t.Helper()

	p := New("test")()
	resp := &provider.ConfigureResponse{}
	p.Configure(t.Context(), provider.ConfigureRequest{Config: providerConfigValue(t, p, attrs)}, resp)

	return resp
}

func TestPgroleProvider_Metadata(t *testing.T) {
	t.Parallel()

	resp := &provider.MetadataResponse{}
	New("1.2.3")().Metadata(t.Context(), provider.MetadataRequest{}, resp)

	assert.Equal(t, "pgrole", resp.TypeName)
	assert.Equal(t, "1.2.3", resp.Version)
}

func TestPgroleProvider_Resources(t *testing.T) {
	t.Parallel()

	var names []string
	for _, newResource := range New("test")().Resources(t.Context()) {
		resp := &resource.MetadataResponse{}
		newResource().Metadata(t.Context(), resource.MetadataRequest{ProviderTypeName: "pgrole"}, resp)
		names = append(names, resp.TypeName)
	}

	// A change to this list renames or removes a resource type, which breaks
	// the configuration of every user of that resource.
	assert.ElementsMatch(t, []string{
		"pgrole_audit",
		"pgrole_bypassrls",
		"pgrole_connection_limit",
		"pgrole_createrole",
		"pgrole_replication",
		"pgrole_revoke_on_destroy",
		"pgrole_security_label",
		"pgrole_statement_timeout",
	}, names)
}

func TestPgroleProvider_Configure(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name  string
		attrs map[string]tftypes.Value
	}{
		{
			name: "cloud sql",
			attrs: map[string]tftypes.Value{
				"project_id": str("my-project"),
				"region":     str("my-region"),
				"instance":   str("my-instance"),
				"username":   str("me@example.com"),
			},
		},
		{
			name: "cloud sql with impersonation",
			attrs: map[string]tftypes.Value{
				"project_id":                  str("my-project"),
				"region":                      str("my-region"),
				"instance":                    str("my-instance"),
				"username":                    str("me@example.com"),
				"impersonate_service_account": str("sa@my-project.iam.gserviceaccount.com"),
			},
		},
		{
			// The host selects standard PostgreSQL, so the Cloud SQL
			// attributes are not required.
			name: "standard postgres",
			attrs: map[string]tftypes.Value{
				"host":     str("localhost"),
				"username": str("postgres"),
				"password": str("postgres"),
			},
		},
		{
			name: "standard postgres with sslrootcert",
			attrs: map[string]tftypes.Value{
				"host":        str("db.example.com"),
				"username":    str("postgres"),
				"password":    str("postgres"),
				"sslmode":     str("verify-full"),
				"sslrootcert": str("/etc/ssl/certs/root-ca.pem"),
			},
		},
		{
			// Cloud SQL handles the certificates itself and ignores
			// sslmode and sslrootcert.
			name: "cloud sql ignores sslrootcert",
			attrs: map[string]tftypes.Value{
				"project_id":  str("my-project"),
				"region":      str("my-region"),
				"instance":    str("my-instance"),
				"username":    str("me@example.com"),
				"sslrootcert": str("/etc/ssl/certs/root-ca.pem"),
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Configure does not connect to the database. The connection
			// opens only when a resource calls the getter.
			resp := configureProvider(t, tc.attrs)
			requireNoErrors(t, resp.Diagnostics)

			assert.IsType(t, F(nil), resp.ResourceData)
			assert.IsType(t, F(nil), resp.DataSourceData)
			assert.NotNil(t, resp.ResourceData)
		})
	}
}

func TestPgroleProvider_Configure_MissingCloudSQLAttributes(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name             string
		attrs            map[string]tftypes.Value
		expectedErrors   []string
		unexpectedErrors []string
	}{
		{
			name:           "nothing set except username",
			attrs:          map[string]tftypes.Value{"username": str("me")},
			expectedErrors: []string{"missing project_id", "missing region", "missing instance"},
		},
		{
			name: "missing instance",
			attrs: map[string]tftypes.Value{
				"project_id": str("my-project"),
				"region":     str("my-region"),
				"username":   str("me"),
			},
			expectedErrors:   []string{"missing instance"},
			unexpectedErrors: []string{"missing project_id", "missing region"},
		},
		{
			name: "empty database",
			attrs: map[string]tftypes.Value{
				"project_id": str("my-project"),
				"region":     str("my-region"),
				"instance":   str("my-instance"),
				"database":   str(""),
				"username":   str("me"),
			},
			expectedErrors: []string{"missing database"},
		},
		{
			name: "empty username",
			attrs: map[string]tftypes.Value{
				"project_id": str("my-project"),
				"region":     str("my-region"),
				"instance":   str("my-instance"),
				"username":   str(""),
			},
			expectedErrors: []string{"missing username"},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resp := configureProvider(t, tc.attrs)
			summaries := errorSummaries(resp.Diagnostics)
			for _, summary := range tc.expectedErrors {
				assert.Contains(t, summaries, summary)
			}
			for _, summary := range tc.unexpectedErrors {
				assert.NotContains(t, summaries, summary)
			}
			assert.Nil(t, resp.ResourceData)
		})
	}
}

func TestPgroleProvider_Configure_SSLRootCertWithoutTLS(t *testing.T) {
	t.Parallel()

	// lib/pq ignores sslrootcert without TLS. The provider must not connect
	// in plain text when the user expects a verified server.
	testcases := []struct {
		name  string
		attrs map[string]tftypes.Value
	}{
		{
			name: "sslmode not set",
			attrs: map[string]tftypes.Value{
				"host":        str("db.example.com"),
				"username":    str("postgres"),
				"sslrootcert": str("/etc/ssl/certs/root-ca.pem"),
			},
		},
		{
			name: "sslmode disable",
			attrs: map[string]tftypes.Value{
				"host":        str("db.example.com"),
				"username":    str("postgres"),
				"sslmode":     str("disable"),
				"sslrootcert": str("/etc/ssl/certs/root-ca.pem"),
			},
		},
		{
			// lib/pq drops the empty option, and PGSSLMODE would choose
			// the mode.
			name: "sslmode empty",
			attrs: map[string]tftypes.Value{
				"host":        str("db.example.com"),
				"username":    str("postgres"),
				"sslmode":     str(""),
				"sslrootcert": str("/etc/ssl/certs/root-ca.pem"),
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resp := configureProvider(t, tc.attrs)
			assertError(t, resp.Diagnostics, "sslrootcert requires TLS")
			assert.Nil(t, resp.ResourceData)
		})
	}
}

func TestPgroleProvider_Configure_UnknownValues(t *testing.T) {
	t.Parallel()

	// An unknown value comes from an attribute that depends on a resource
	// that Terraform did not create yet.
	testcases := []struct {
		attr    string
		attrTyp tftypes.Type
	}{
		{"project_id", tftypes.String},
		{"region", tftypes.String},
		{"instance", tftypes.String},
		{"database", tftypes.String},
		{"username", tftypes.String},
		{"impersonate_service_account", tftypes.String},
		{"host", tftypes.String},
		{"port", tftypes.Number},
		{"password", tftypes.String},
		{"sslmode", tftypes.String},
		{"sslrootcert", tftypes.String},
	}

	for _, tc := range testcases {
		t.Run(tc.attr, func(t *testing.T) {
			t.Parallel()

			attrs := map[string]tftypes.Value{"username": str("me")}
			attrs[tc.attr] = tftypes.NewValue(tc.attrTyp, tftypes.UnknownValue)

			resp := configureProvider(t, attrs)
			assertError(t, resp.Diagnostics, "unknown "+tc.attr)
			assert.Nil(t, resp.ResourceData)
		})
	}
}
