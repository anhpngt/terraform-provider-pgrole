package provider

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = (*statementTimeoutResource)(nil)
	_ resource.ResourceWithConfigure   = (*statementTimeoutResource)(nil)
	_ resource.ResourceWithImportState = (*statementTimeoutResource)(nil)
)

// NewStatementTimeoutResource is a helper function to simplify the provider implementation.
func NewStatementTimeoutResource() resource.Resource {
	return &statementTimeoutResource{}
}

type statementTimeoutResource struct {
	getDB F
}

// Metadata returns the resource type name.
func (r *statementTimeoutResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_statement_timeout"
}

var timeoutAttributeRe = regexp.MustCompile(`^\d+s$`)

// Schema defines the schema for the resource.
func (r *statementTimeoutResource) Schema(_ context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: `Manage statement_timeout for an existing role.

See Postgres [documentation](https://www.postgresql.org/docs/current/runtime-config-client.html#GUC-STATEMENT-TIMEOUT) for more details.`,
		Attributes: map[string]schema.Attribute{
			"role": schema.StringAttribute{
				Description: "Name of the role.",
				Required:    true,
			},
			"timeout": schema.StringAttribute{
				Description: "The timeout value, must be an integer follow by character \"s\", .e.g: 100s.",
				Required:    true,
				Validators: []validator.String{
					stringvalidator.RegexMatches(timeoutAttributeRe, "Timeout must be in the format of <number>s, for example: 100s, 300s."),
				},
			},
		},
	}
}

type statementTimeoutModel struct {
	Role    string `tfsdk:"role"`
	Timeout string `tfsdk:"timeout"`
}

// Configure adds the provider configured client to the resource.
func (r *statementTimeoutResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Add a nil check when handling ProviderData because Terraform
	// sets that data after it calls the ConfigureProvider RPC.
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(F)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Source Configure Type",
			fmt.Sprintf("Expected provider.F, got %T", req.ProviderData),
		)
	}

	r.getDB = client
}

// Create creates the resource and sets the initial Terraform state.
func (r *statementTimeoutResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	// Retrieve value from plan
	var plan statementTimeoutModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create the resource
	sqlstr := sqlSetStatementTimeout(plan.Role, plan.Timeout)

	db, err := r.getDB(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to get database connection",
			"Failed to get database connection: "+err.Error(),
		)
		return
	}
	defer db.Close()
	if _, err = db.ExecContext(ctx, sqlstr); err != nil {
		resp.Diagnostics.AddError(
			"Failed to execute SQL",
			"Failed to execute SQL: "+err.Error(),
		)
		return
	}

	// Set state to fully populated data
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *statementTimeoutResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	// Get the current state
	var state statementTimeoutModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read the current value from the database
	db, err := r.getDB(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to get database connection",
			"Failed to get database connection: "+err.Error(),
		)
		return
	}
	defer db.Close()

	var timeoutSetting string
	sqlstr := `SELECT setting
FROM (
	SELECT UNNEST(rolconfig) AS setting
	FROM pg_roles
	WHERE rolname = $1
) t
WHERE setting LIKE 'statement_timeout=%' LIMIT 1;`
	err = db.QueryRowContext(ctx, sqlstr, state.Role).Scan(&timeoutSetting)
	switch { // Overwrite the state with the actual value
	case errors.Is(err, sql.ErrNoRows):
		state.Timeout = "0s"
	case err == nil:
		state.Timeout = strings.TrimPrefix(timeoutSetting, "statement_timeout=")
	default:
		resp.Diagnostics.AddError(
			"Failed to execute SQL",
			"Failed to execute SQL: "+err.Error(),
		)
		return
	}

	// Set state to fully populated data
	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *statementTimeoutResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// Retrieve value from plan
	var plan statementTimeoutModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Update statement_timeout in database
	sqlstr := sqlSetStatementTimeout(plan.Role, plan.Timeout)
	db, err := r.getDB(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to get database connection",
			"Failed to get database connection: "+err.Error(),
		)
		return
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, sqlstr); err != nil {
		resp.Diagnostics.AddError(
			"Failed to execute SQL",
			"Failed to execute SQL: "+err.Error(),
		)
		return
	}

	// Set state to updated value
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *statementTimeoutResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Retrieve value from state
	var state statementTimeoutModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Reset statement_timeout in database
	sqlstr := sqlResetStatementTimeout(state.Role)
	db, err := r.getDB(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to get database connection",
			"Failed to get database connection: "+err.Error(),
		)
		return
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, sqlstr); err != nil {
		resp.Diagnostics.AddError(
			"Failed to execute SQL",
			"Failed to execute SQL: "+err.Error(),
		)
		return
	}
}

func (r *statementTimeoutResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.State.SetAttribute(ctx, path.Root("timeout"), "0s")
	resource.ImportStatePassthroughID(ctx, path.Root("role"), req, resp)
}

func sqlSetStatementTimeout(role, timeout string) string {
	return fmt.Sprintf("ALTER ROLE %q SET statement_timeout = '%s';", role, timeout)
}

func sqlResetStatementTimeout(role string) string {
	return fmt.Sprintf("ALTER ROLE %q RESET statement_timeout;", role)
}
