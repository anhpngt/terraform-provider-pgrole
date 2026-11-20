package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// providerConfigValue builds a provider configuration. Attributes that are
// not in attrs are null, the same as when the user does not set them.
func providerConfigValue(t *testing.T, p provider.Provider, attrs map[string]tftypes.Value) tfsdk.Config {
	t.Helper()

	schemaResp := &provider.SchemaResponse{}
	p.Schema(context.Background(), provider.SchemaRequest{}, schemaResp)
	requireNoDiags(t, schemaResp.Diagnostics)

	typ := schemaResp.Schema.Type().TerraformType(context.Background()).(tftypes.Object)
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
	p.Configure(context.Background(), provider.ConfigureRequest{Config: providerConfigValue(t, p, attrs)}, resp)

	return resp
}

func TestPgroleProvider_Metadata(t *testing.T) {
	t.Parallel()

	resp := &provider.MetadataResponse{}
	New("1.2.3")().Metadata(context.Background(), provider.MetadataRequest{}, resp)

	assert.Equal(t, "pgrole", resp.TypeName)
	assert.Equal(t, "1.2.3", resp.Version)
}

func TestPgroleProvider_Resources(t *testing.T) {
	t.Parallel()

	p := New("test")()
	var names []string
	for _, newResource := range p.Resources(context.Background()) {
		resp := &resource.MetadataResponse{}
		newResource().Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "pgrole"}, resp)
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
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Configure does not connect to the database. The connection
			// opens only when a resource calls the getter.
			resp := configureProvider(t, tc.attrs)
			requireNoDiags(t, resp.Diagnostics)

			assert.IsType(t, F(nil), resp.ResourceData)
			assert.IsType(t, F(nil), resp.DataSourceData)
			assert.NotNil(t, resp.ResourceData)
		})
	}
}

func TestPgroleProvider_Configure_MissingCloudSQLAttributes(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name            string
		attrs           map[string]tftypes.Value
		expectedErrors  []string
		unexpectedError string
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
			expectedErrors:  []string{"missing instance"},
			unexpectedError: "missing project_id",
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
			for _, summary := range tc.expectedErrors {
				requireErrorDiag(t, resp.Diagnostics, summary)
			}
			if tc.unexpectedError != "" {
				for _, d := range resp.Diagnostics.Errors() {
					assert.NotEqual(t, tc.unexpectedError, d.Summary())
				}
			}
			assert.Nil(t, resp.ResourceData)
		})
	}
}

func TestPgroleProvider_Configure_UnknownValues(t *testing.T) {
	t.Parallel()

	// An unknown value comes from an attribute that depends on a resource
	// that Terraform did not create yet.
	unknown := tftypes.NewValue(tftypes.String, tftypes.UnknownValue)

	for _, attr := range []string{"project_id", "region", "instance", "database", "username", "impersonate_service_account", "host", "password", "sslmode"} {
		t.Run(attr, func(t *testing.T) {
			t.Parallel()

			attrs := map[string]tftypes.Value{"username": str("me")}
			attrs[attr] = unknown

			resp := configureProvider(t, attrs)
			requireErrorDiag(t, resp.Diagnostics, "unknown "+attr)
			require.Nil(t, resp.ResourceData)
		})
	}

	t.Run("port", func(t *testing.T) {
		t.Parallel()

		resp := configureProvider(t, map[string]tftypes.Value{
			"username": str("me"),
			"port":     tftypes.NewValue(tftypes.Number, tftypes.UnknownValue),
		})
		requireErrorDiag(t, resp.Diagnostics, "unknown port")
	})
}
