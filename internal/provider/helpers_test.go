package provider

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"regexp"
	"strings"
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

// The helpers in this file call the resource methods the same way that the
// framework does: with the request that the framework builds, and with the
// initial response state that the framework sets. Plans and states are built
// from the model struct of each resource.

// testRole is the role that the unit tests manage.
const testRole = "app"

// roleExistsSQL is the check that Read runs first, and that Delete runs after
// a failed statement.
const roleExistsSQL = "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1);"

// mockDB returns a database getter backed by sqlmock, and the mock to give the
// expected statements to. The test fails if a statement is not run in the
// expected order, or if an expected statement is not run at all.
func mockDB(t *testing.T) (F, sqlmock.Sqlmock) {
	t.Helper()

	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, mock.ExpectationsWereMet(), "unmet database expectations")
	})

	return func(context.Context) (*sql.DB, error) { return db, nil }, mock
}

// newMockedResource returns a resource that is configured with a mock database.
func newMockedResource(t *testing.T, newResource func() resource.Resource) (resource.Resource, sqlmock.Sqlmock) {
	t.Helper()

	getDB, mock := mockDB(t)
	return configured(t, newResource(), getDB), mock
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

func expectExec(mock sqlmock.Sqlmock, sqlstr string) {
	mock.ExpectExec(exact(sqlstr)).WillReturnResult(sqlmock.NewResult(0, 0))
}

func expectExecError(mock sqlmock.Sqlmock, sqlstr string, err error) {
	mock.ExpectExec(exact(sqlstr)).WillReturnError(err)
}

func expectRoleCheck(mock sqlmock.Sqlmock, exists bool) {
	mock.ExpectQuery(exact(roleExistsSQL)).WithArgs(testRole).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(exists))
}

func expectRoleCheckError(mock sqlmock.Sqlmock) {
	mock.ExpectQuery(exact(roleExistsSQL)).WithArgs(testRole).WillReturnError(sql.ErrConnDone)
}

// resourceSchema returns the schema of the resource, and fails the test if the
// framework rejects the schema.
func resourceSchema(t *testing.T, r resource.Resource) schema.Schema {
	t.Helper()

	resp := &resource.SchemaResponse{}
	r.Schema(t.Context(), resource.SchemaRequest{}, resp)
	requireNoErrors(t, resp.Diagnostics)
	requireNoErrors(t, resp.Schema.ValidateImplementation(t.Context()))

	return resp.Schema
}

// configured passes the database getter to the resource the same way that the
// provider does, and returns the resource.
func configured(t *testing.T, r resource.Resource, getDB F) resource.Resource {
	t.Helper()

	rc, ok := r.(resource.ResourceWithConfigure)
	require.True(t, ok, "%T does not implement resource.ResourceWithConfigure", r)

	resp := &resource.ConfigureResponse{}
	rc.Configure(t.Context(), resource.ConfigureRequest{ProviderData: getDB}, resp)
	requireNoErrors(t, resp.Diagnostics)

	return r
}

// planOf returns the plan that holds the given model of the resource.
func planOf(t *testing.T, r resource.Resource, model any) tfsdk.Plan {
	t.Helper()

	plan := tfsdk.Plan{Schema: resourceSchema(t, r)}
	requireNoErrors(t, plan.Set(t.Context(), model))
	return plan
}

// stateOf returns the state that holds the given model of the resource.
func stateOf(t *testing.T, r resource.Resource, model any) tfsdk.State {
	t.Helper()

	state := tfsdk.State{Schema: resourceSchema(t, r)}
	requireNoErrors(t, state.Set(t.Context(), model))
	return state
}

// nullState returns the state of a resource that does not exist. The framework
// passes it to Create and ImportState.
func nullState(t *testing.T, r resource.Resource) tfsdk.State {
	t.Helper()

	s := resourceSchema(t, r)
	return tfsdk.State{Schema: s, Raw: tftypes.NewValue(s.Type().TerraformType(t.Context()), nil)}
}

func runCreate(t *testing.T, r resource.Resource, plan any) *resource.CreateResponse {
	t.Helper()

	resp := &resource.CreateResponse{State: nullState(t, r)}
	r.Create(t.Context(), resource.CreateRequest{Plan: planOf(t, r, plan)}, resp)
	return resp
}

func runRead(t *testing.T, r resource.Resource, state any) *resource.ReadResponse {
	t.Helper()

	resp := &resource.ReadResponse{State: stateOf(t, r, state)}
	r.Read(t.Context(), resource.ReadRequest{State: stateOf(t, r, state)}, resp)
	return resp
}

func runUpdate(t *testing.T, r resource.Resource, prior, plan any) *resource.UpdateResponse {
	t.Helper()

	resp := &resource.UpdateResponse{State: stateOf(t, r, prior)}
	r.Update(t.Context(), resource.UpdateRequest{Plan: planOf(t, r, plan), State: stateOf(t, r, prior)}, resp)
	return resp
}

func runDelete(t *testing.T, r resource.Resource, state any) *resource.DeleteResponse {
	t.Helper()

	resp := &resource.DeleteResponse{State: stateOf(t, r, state)}
	r.Delete(t.Context(), resource.DeleteRequest{State: stateOf(t, r, state)}, resp)
	return resp
}

func runImport(t *testing.T, r resource.Resource, id string) *resource.ImportStateResponse {
	t.Helper()

	ri, ok := r.(resource.ResourceWithImportState)
	require.True(t, ok, "%T does not implement resource.ResourceWithImportState", r)

	resp := &resource.ImportStateResponse{State: nullState(t, r)}
	ri.ImportState(t.Context(), resource.ImportStateRequest{ID: id}, resp)
	return resp
}

// decodeState returns the model in the state, as a value of the same type as
// like.
func decodeState(t *testing.T, state tfsdk.State, like any) any {
	t.Helper()

	model := reflect.New(reflect.TypeOf(like))
	requireNoErrors(t, state.Get(t.Context(), model.Interface()))
	return model.Elem().Interface()
}

// assertState checks that the state holds the expected model.
func assertState(t *testing.T, expected any, state tfsdk.State) {
	t.Helper()

	require.False(t, state.Raw.IsNull(), "the resource is not in the state")
	assert.Equal(t, expected, decodeState(t, state, expected))
}

// assertRemoved checks that the resource is not in the state.
func assertRemoved(t *testing.T, state tfsdk.State) {
	t.Helper()

	assert.True(t, state.Raw.IsNull(), "the resource must not be in the state, got: %s", state.Raw)
}

func errorSummaries(diags diag.Diagnostics) []string {
	var summaries []string
	for _, d := range diags.Errors() {
		summaries = append(summaries, d.Summary())
	}
	return summaries
}

// diagError joins the error diagnostics into one string. It returns an empty
// string when there is no error.
func diagError(diags diag.Diagnostics) string {
	var msgs []string
	for _, d := range diags.Errors() {
		msgs = append(msgs, d.Summary()+": "+d.Detail())
	}
	return strings.Join(msgs, "; ")
}

func requireNoErrors(t *testing.T, diags diag.Diagnostics) {
	t.Helper()
	require.False(t, diags.HasError(), "unexpected diagnostics: %s", diagError(diags))
}

// assertError checks that the diagnostics hold an error with the given summary.
func assertError(t *testing.T, diags diag.Diagnostics, summary string) {
	t.Helper()
	assert.Contains(t, errorSummaries(diags), summary, "diagnostics: %s", diagError(diags))
}
