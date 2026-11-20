package provider

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockDB returns a database getter backed by sqlmock, and the mock to set
// expectations on. Each resource operation closes its connection, so tests
// expect a Close to make sure that no connection leaks.
func mockDB(t *testing.T) (F, sqlmock.Sqlmock) {
	t.Helper()

	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, mock.ExpectationsWereMet(), "unmet database expectations")
	})

	return func(context.Context) (*sql.DB, error) { return db, nil }, mock
}

// failingDB returns a database getter that always fails to connect.
func failingDB() F {
	return func(context.Context) (*sql.DB, error) {
		return nil, errors.New("connection refused")
	}
}

// exact returns a regular expression that matches only the given SQL.
func exact(sqlstr string) string {
	return "^" + regexp.QuoteMeta(sqlstr) + "$"
}

// resourceSchema returns the schema of the resource and fails the test if
// the framework rejects the schema.
func resourceSchema(t *testing.T, r resource.Resource) schema.Schema {
	t.Helper()

	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)
	requireNoDiags(t, resp.Diagnostics)
	requireNoDiags(t, resp.Schema.ValidateImplementation(context.Background()))

	return resp.Schema
}

func objectValue(s schema.Schema, attrs map[string]tftypes.Value) tftypes.Value {
	return tftypes.NewValue(s.Type().TerraformType(context.Background()), attrs)
}

func newPlan(s schema.Schema, attrs map[string]tftypes.Value) tfsdk.Plan {
	return tfsdk.Plan{Schema: s, Raw: objectValue(s, attrs)}
}

func newState(s schema.Schema, attrs map[string]tftypes.Value) tfsdk.State {
	return tfsdk.State{Schema: s, Raw: objectValue(s, attrs)}
}

// emptyState is the state the framework passes to Create and ImportState.
func emptyState(s schema.Schema) tfsdk.State {
	return tfsdk.State{Schema: s, Raw: tftypes.NewValue(s.Type().TerraformType(context.Background()), nil)}
}

func str(v string) tftypes.Value   { return tftypes.NewValue(tftypes.String, v) }
func boolean(v bool) tftypes.Value { return tftypes.NewValue(tftypes.Bool, v) }
func num(v int64) tftypes.Value    { return tftypes.NewValue(tftypes.Number, v) }

func requireNoDiags(t *testing.T, diags diag.Diagnostics) {
	t.Helper()
	require.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
}

func requireErrorDiag(t *testing.T, diags diag.Diagnostics, summary string) {
	t.Helper()
	var summaries []string
	for _, d := range diags.Errors() {
		summaries = append(summaries, d.Summary())
	}
	require.Contains(t, summaries, summary, "diagnostics: %v", diags)
}

func requireState(t *testing.T, got tfsdk.State, want tftypes.Value) {
	t.Helper()
	require.True(t, got.Raw.Equal(want), "unexpected state\n got: %s\nwant: %s", got.Raw, want)
}

// configureResource passes the database getter to the resource the same way
// the provider does.
func configureResource(t *testing.T, r resource.Resource, getDB F) {
	t.Helper()

	rc, ok := r.(resource.ResourceWithConfigure)
	require.True(t, ok, "%T does not implement resource.ResourceWithConfigure", r)

	resp := &resource.ConfigureResponse{}
	rc.Configure(context.Background(), resource.ConfigureRequest{ProviderData: getDB}, resp)
	requireNoDiags(t, resp.Diagnostics)
}
