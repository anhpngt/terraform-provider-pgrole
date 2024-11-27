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
	_ resource.Resource                = (*replicationResource)(nil)
	_ resource.ResourceWithConfigure   = (*replicationResource)(nil)
	_ resource.ResourceWithImportState = (*replicationResource)(nil)
)

// NewBypassRLSResource is a helper function to simplify the provider implementation.
func NewReplicationResource() resource.Resource {
	return &replicationResource{}
}

type replicationResource struct {
	getDB F
}

// Metadata returns the resource type name.
func (r *replicationResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_replication"
}

// Schema defines the schema for the resource.
func (r *replicationResource) Schema(_ context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manage REPLICATION status for an existing role. See PostgreSQL [ALTER ROLE](https://www.postgresql.org/docs/current/sql-alterrole.html).",
		Attributes: map[string]schema.Attribute{
			"role": schema.StringAttribute{
				Description: "Name of the role.",
				Required:    true,
			},
			"enabled": schema.BoolAttribute{
				Description: "Whether to enable REPLICATION for the role.",
				Optional:    true,
			},
		},
	}
}

type replicationModel struct {
	Role    string `tfsdk:"role"`
	Enabled bool   `tfsdk:"enabled"`
}

// Configure adds the provider configured client to the resource.
func (r *replicationResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
func (r *replicationResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	// Retrieve value from plan
	var plan replicationModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create the resource
	var sqlstr string
	if plan.Enabled {
		sqlstr = sqlEnableReplication(plan.Role)
	} else {
		sqlstr = sqlDisableReplication(plan.Role)
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
func (r *replicationResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	// Get the current state
	var state bypassrlsModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get the actual state in postgres
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
	if err := db.QueryRowContext(ctx, "SELECT rolreplication FROM pg_roles WHERE rolname = $1;", state.Role).Scan(&enabled); err != nil {
		resp.Diagnostics.AddError(
			"Failed to query REPLICATION status",
			fmt.Sprintf("Failed to query REPLICATION status for role %s: %s", state.Role, err),
		)
		return
	}

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
func (r *replicationResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// Retrieve value from plan
	var plan replicationModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Update resource state with updated values
	var sqlstr string
	if plan.Enabled {
		sqlstr = sqlEnableReplication(plan.Role)
	} else {
		sqlstr = sqlDisableReplication(plan.Role)
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
func (r *replicationResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Retrieve value from state
	var state replicationModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete the resource
	sqlstr := sqlDisableReplication(state.Role)
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

func (r *replicationResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.State.SetAttribute(ctx, path.Root("enabled"), false)
	resource.ImportStatePassthroughID(ctx, path.Root("role"), req, resp)
}

func sqlEnableReplication(role string) string {
	return fmt.Sprintf("ALTER ROLE %q REPLICATION;", role)
}

func sqlDisableReplication(role string) string {
	return fmt.Sprintf("ALTER ROLE %q NOREPLICATION;", role)
}
