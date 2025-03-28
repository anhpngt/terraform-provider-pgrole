package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = (*bypassrlsResource)(nil)
	_ resource.ResourceWithConfigure   = (*bypassrlsResource)(nil)
	_ resource.ResourceWithImportState = (*bypassrlsResource)(nil)
)

// NewBypassRLSResource is a helper function to simplify the provider implementation.
func NewBypassRLSResource() resource.Resource {
	return &bypassrlsResource{}
}

type bypassrlsResource struct {
	getDB F
}

// Metadata returns the resource type name.
func (r *bypassrlsResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_bypassrls"
}

// Schema defines the schema for the resource.
func (r *bypassrlsResource) Schema(_ context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manage BYPASSRLS status for an existing role.",
		Attributes: map[string]schema.Attribute{
			"role": schema.StringAttribute{
				Description: "Name of the role.",
				Required:    true,
			},
			"enabled": schema.BoolAttribute{
				Description: "Whether to enable BYPASSRLS for the role.",
				Optional:    true,
			},
		},
	}
}

type bypassrlsModel struct {
	Role    string `tfsdk:"role"`
	Enabled bool   `tfsdk:"enabled"`
}

// Configure adds the provider configured client to the resource.
func (r *bypassrlsResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
func (r *bypassrlsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	// Retrieve value from plan
	var plan bypassrlsModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create the resource
	var sqlstr string
	if plan.Enabled {
		sqlstr = sqlEnableBypassRLS(plan.Role)
	} else {
		sqlstr = sqlDisableBypassRLS(plan.Role)
	}

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
func (r *bypassrlsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	// Get the current state
	var state bypassrlsModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get the actual BYPASSRLS state in postgres
	db, err := r.getDB(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to get database connection",
			"Failed to get database connection: "+err.Error(),
		)
		return
	}
	defer db.Close()

	var enabled bool
	if err := db.QueryRowContext(ctx, "SELECT rolbypassrls FROM pg_roles WHERE rolname = $1;", state.Role).Scan(&enabled); err != nil {
		resp.Diagnostics.AddError(
			"Failed to query BYPASSRLS status",
			fmt.Sprintf("Failed to query BYPASSRLS status for role %s: %s", state.Role, err),
		)
		return
	}
	tflog.Debug(ctx, "Read BYPASSRLS for role", map[string]any{
		"role": state.Role,
		"got":  enabled,
		"want": state.Enabled,
	})

	// Overwrite the state with the actual state
	state.Enabled = enabled

	// Set refreshed state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *bypassrlsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// Retrieve value from plan
	var plan bypassrlsModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Update resource state with updated values
	var sqlstr string
	if plan.Enabled {
		sqlstr = sqlEnableBypassRLS(plan.Role)
	} else {
		sqlstr = sqlDisableBypassRLS(plan.Role)
	}

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
func (r *bypassrlsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Retrieve value from state
	var state bypassrlsModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete the resource
	sqlstr := sqlDisableBypassRLS(state.Role)
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

func (r *bypassrlsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.State.SetAttribute(ctx, path.Root("enabled"), false)
	resource.ImportStatePassthroughID(ctx, path.Root("role"), req, resp)
}

func sqlEnableBypassRLS(role string) string {
	return fmt.Sprintf("ALTER ROLE %q BYPASSRLS;", role)
}

func sqlDisableBypassRLS(role string) string {
	return fmt.Sprintf("ALTER ROLE %q NOBYPASSRLS;", role)
}
