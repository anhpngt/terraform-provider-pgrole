package provider

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = (*securityLabelResource)(nil)
	_ resource.ResourceWithConfigure   = (*securityLabelResource)(nil)
	_ resource.ResourceWithImportState = (*securityLabelResource)(nil)
)

// NewSecurityLabelResource is a helper function to simplify the provider implementation.
func NewSecurityLabelResource() resource.Resource {
	return &securityLabelResource{}
}

type securityLabelResource struct {
	getDB F
}

// Metadata returns the resource type name.
func (r *securityLabelResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_security_label"
}

// Schema defines the schema for the resource.
func (r *securityLabelResource) Schema(_ context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manage PostgreSQL Anonymizer security labels for roles to enable dynamic masking. See [PostgreSQL Anonymizer Dynamic Masking](https://postgresql-anonymizer.readthedocs.io/en/latest/dynamic_masking/) documentation.",
		Attributes: map[string]schema.Attribute{
			"role": schema.StringAttribute{
				Description: "Name of the role to apply the security label to.",
				Required:    true,
			},
			"label": schema.StringAttribute{
				Description: "Security label value. Use 'MASKED' to enable dynamic masking for the role, or NULL to remove the label.",
				Required:    true,
			},
		},
	}
}

type securityLabelModel struct {
	Role  string `tfsdk:"role"`
	Label string `tfsdk:"label"`
}

// Configure adds the provider configured client to the resource.
func (r *securityLabelResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
func (r *securityLabelResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	// Retrieve value from plan
	var plan securityLabelModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create the resource
	sqlstr := sqlSetSecurityLabel(plan.Role, plan.Label)

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

	tflog.Info(ctx, "Created security label for role", map[string]any{
		"role":  plan.Role,
		"label": plan.Label,
	})

	// Set state to fully populated data
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *securityLabelResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	// Get the current state
	var state securityLabelModel
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

	var label sql.NullString
	sqlstr := `SELECT label 
FROM pg_seclabels 
WHERE objtype = 'role' 
AND provider = 'anon' 
AND objname = $1`

	err = db.QueryRowContext(ctx, sqlstr, state.Role).Scan(&label)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// No security label found, set to empty
		state.Label = ""
	case err == nil:
		if label.Valid {
			state.Label = label.String
		} else {
			state.Label = ""
		}
	default:
		resp.Diagnostics.AddError(
			"Failed to query security label",
			fmt.Sprintf("Failed to query security label for role %s: %s", state.Role, err),
		)
		return
	}

	tflog.Info(ctx, "Read security label for role", map[string]any{
		"role":  state.Role,
		"label": state.Label,
	})

	// Set refreshed state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *securityLabelResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// Retrieve value from plan
	var plan securityLabelModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Update resource state with updated values
	sqlstr := sqlSetSecurityLabel(plan.Role, plan.Label)

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

	tflog.Info(ctx, "Updated security label for role", map[string]any{
		"role":  plan.Role,
		"label": plan.Label,
	})

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *securityLabelResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Retrieve value from state
	var state securityLabelModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete the resource by removing the security label
	sqlstr := sqlRemoveSecurityLabel(state.Role)
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

	tflog.Info(ctx, "Deleted security label for role", map[string]any{
		"role": state.Role,
	})
}

func (r *securityLabelResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("role"), req, resp)
}

// sqlSetSecurityLabel generates SQL to set a security label for a role
func sqlSetSecurityLabel(role string, label string) string {
	escapedLabel := strings.ReplaceAll(label, "'", "''")
	return fmt.Sprintf("SECURITY LABEL FOR anon ON ROLE %q IS '%s';", role, escapedLabel)
}

// sqlRemoveSecurityLabel generates SQL to remove a security label for a role
func sqlRemoveSecurityLabel(role string) string {
	return fmt.Sprintf("SECURITY LABEL FOR anon ON ROLE %q IS NULL;", role)
}
