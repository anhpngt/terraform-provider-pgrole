package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = (*auditResource)(nil)
	_ resource.ResourceWithConfigure   = (*auditResource)(nil)
	_ resource.ResourceWithImportState = (*auditResource)(nil)
)

// NewAuditResource is a helper function to simplify the provider implementation.
func NewAuditResource() resource.Resource {
	return &auditResource{}
}

type auditResource struct {
	getDB F
}

// Metadata returns the resource type name.
func (r *auditResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_audit"
}

// Schema defines the schema for the resource.
func (r *auditResource) Schema(_ context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manage pgaudit.log setting for an existing role. See PostgreSQL [ALTER ROLE](https://www.postgresql.org/docs/current/sql-alterrole.html) and [pgAudit](https://github.com/pgaudit/pgaudit) documentation.",
		Attributes: map[string]schema.Attribute{
			"role": schema.StringAttribute{
				Description: "Name of the role.",
				Required:    true,
			},
			"audit_log_option": schema.StringAttribute{
				Description: "Value for the pgaudit.log option for this role. Examples: 'none', 'all', 'ddl', 'write', etc.",
				Required:    true,
			},
		},
	}
}

type auditModel struct {
	Role           string `tfsdk:"role"`
	AuditLogOption string `tfsdk:"audit_log_option"`
}

// Configure adds the provider configured client to the resource.
func (r *auditResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Add a nil check when handling ProviderData because Terraform
	// sets that data after it calls the ConfigureProvider RPC.
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(F)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected provider.F, got %T", req.ProviderData),
		)
	}

	r.getDB = client
}

// Create creates the resource and sets the initial Terraform state.
func (r *auditResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	// Retrieve value from plan
	var plan auditModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create the resource
	sqlstr := sqlSetAuditLog(plan.Role, plan.AuditLogOption)

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
func (r *auditResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	// Get the current state
	var state auditModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get the actual value in postgres
	db, err := r.getDB(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to get database connection",
			"Failed to get database connection: "+err.Error(),
		)
		return
	}
	defer db.Close()

	var auditLogOption string
	if err := db.QueryRowContext(ctx, "SELECT pg_catalog.current_setting('pgaudit.log') FROM pg_roles WHERE rolname = $1;", state.Role).Scan(&auditLogOption); err != nil {
		resp.Diagnostics.AddError(
			"Failed to query pgaudit.log value",
			fmt.Sprintf("Failed to query pgaudit.log value for role %s: %s", state.Role, err),
		)
		return
	}

	// Overwrite the state with the actual state
	state.AuditLogOption = auditLogOption

	// Set refreshed state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *auditResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// Retrieve value from plan
	var plan auditModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Update resource state with updated values
	sqlstr := sqlSetAuditLog(plan.Role, plan.AuditLogOption)

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

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *auditResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Retrieve value from state
	var state auditModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete the resource by unsetting the pgaudit.log parameter
	sqlstr := fmt.Sprintf("ALTER ROLE %q RESET pgaudit.log;", state.Role)
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

func (r *auditResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.State.SetAttribute(ctx, path.Root("audit_log_option"), "none")
	resource.ImportStatePassthroughID(ctx, path.Root("role"), req, resp)
}

func sqlSetAuditLog(role string, auditLogOption string) string {
	return fmt.Sprintf("ALTER ROLE %q SET pgaudit.log = '%s';", role, auditLogOption)
}
