package provider

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/lib/pq"
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
		MarkdownDescription: `Manages PostgreSQL Anonymizer security labels for roles to enable dynamic masking.

This resource allows you to apply security labels to PostgreSQL roles using the PostgreSQL Anonymizer extension. Security labels are used to mark roles as "MASKED" for dynamic masking purposes, where sensitive data is automatically masked when accessed by those roles.

## Prerequisites

Before using this resource, ensure that:

1. The PostgreSQL Anonymizer extension is installed and enabled in your database
2. Dynamic masking is enabled: ` + "`" + `ALTER DATABASE your_db SET anon.transparent_dynamic_masking TO true;` + "`" + `
3. The provider has sufficient privileges to manage security labels

## Dynamic Masking Workflow

1. **Enable PostgreSQL Anonymizer**: Install and enable the extension
2. **Set up masking rules**: Define masking rules for sensitive columns
3. **Create masked roles**: Use this resource to mark roles as "MASKED"
4. **Grant appropriate permissions**: Ensure masked roles have read access to the data

For more information, see the [PostgreSQL Anonymizer Dynamic Masking documentation](https://postgresql-anonymizer.readthedocs.io/en/latest/dynamic_masking/).

## SQL Operations

This resource performs the following SQL operations:

* **Create/Update**: ` + "`" + `SECURITY LABEL FOR anon ON ROLE role_name IS 'label_value';` + "`" + `
* **Delete/Null**: ` + "`" + `SECURITY LABEL FOR anon ON ROLE role_name IS NULL;` + "`" + `
* **Read**: Queries ` + "`pg_seclabels`" + ` system catalog for existing labels

## Revoking on destroy

For every role with the ` + "`MASKED`" + ` label, PostgreSQL Anonymizer 1.x grants ` + "`USAGE`" + ` on its ` + "`anon`" + ` schema and on the schema of the masking views (` + "`mask`" + ` unless ` + "`anon.maskschema`" + ` says otherwise), and ` + "`SELECT`" + ` on the tables, views and sequences in them, in each database where dynamic masking runs. It does not take them back when the label is removed, and a role that still holds them cannot be dropped:

` + "```" + `
role "x" cannot be dropped because some objects depend on it
` + "```" + `

With ` + "`revoke_on_destroy = true`" + `, destroying this resource removes the label and then revokes those privileges in every database of the server. Nothing else that the role holds is touched. If a privilege cannot be revoked the destroy fails, the resource stays in the state, and the next apply tries again.

A privilege is revoked with the privileges of the role that granted it, which is the owner of the masking views. Where the provider's user lacks them, it grants itself membership in that role for the time of the destroy, and takes it back afterwards. That works with ` + "`CREATEROLE`" + ` on PostgreSQL 15 and older. PostgreSQL 16 restricted ` + "`CREATEROLE`" + `: there the user must already be a member of that role, or have ` + "`ADMIN OPTION`" + ` on it.`,
		Attributes: map[string]schema.Attribute{
			"role": schema.StringAttribute{
				Description: "Name of the role to apply the security label to.",
				Required:    true,
			},
			"label": schema.StringAttribute{
				Description: "Security label value. Use 'MASKED' to enable dynamic masking for the role, or NULL to remove the label.",
				Required:    true,
			},
			"revoke_on_destroy": schema.BoolAttribute{
				Description: "When true, destroying the resource also revokes what PostgreSQL Anonymizer granted the role because of its label, in every database of the server, so that the role can be dropped. Defaults to false.",
				Optional:    true,
			},
		},
	}
}

type securityLabelModel struct {
	Role  string `tfsdk:"role"`
	Label string `tfsdk:"label"`
	// RevokeOnDestroy is null when it is not set, which is the same as false. It has no default
	// in the schema, so that the resources created before it existed plan no change.
	RevokeOnDestroy types.Bool `tfsdk:"revoke_on_destroy"`
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

	if err = execForRole(ctx, db, plan.Role, sqlstr); err != nil {
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

	if removeIfRoleGone(ctx, db, state.Role, resp) {
		return
	}

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

	if err := execForRole(ctx, db, plan.Role, sqlstr); err != nil {
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

	if err := undoRoleSetting(ctx, db, state.Role, sqlstr); err != nil {
		resp.Diagnostics.AddError(
			"Failed to execute SQL",
			"Failed to execute SQL: "+err.Error(),
		)
		return
	}

	tflog.Info(ctx, "Deleted security label for role", map[string]any{
		"role": state.Role,
	})

	if !state.RevokeOnDestroy.ValueBool() {
		return
	}

	// After the label, not before: as long as the role has its label, the next table that is
	// created, altered or dropped gives it everything back.
	if err := r.revokeMaskingPrivileges(ctx, db, state.Role); err != nil {
		resp.Diagnostics.AddError(
			"Failed to revoke the masking privileges of the role",
			fmt.Sprintf("The security label of role %s is removed, but what PostgreSQL Anonymizer granted it could not all be revoked, so the role may not be droppable yet. The resource stays in the state and the next apply tries again.\n\n%s", state.Role, err),
		)
		return
	}
}

func (r *securityLabelResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("role"), req, resp)
}

// sqlSetSecurityLabel generates SQL to set a security label for a role
func sqlSetSecurityLabel(role string, label string) string {
	return fmt.Sprintf("SECURITY LABEL FOR anon ON ROLE %s IS %s;", pq.QuoteIdentifier(role), pq.QuoteLiteral(label))
}

// sqlRemoveSecurityLabel generates SQL to remove a security label for a role
func sqlRemoveSecurityLabel(role string) string {
	return fmt.Sprintf("SECURITY LABEL FOR anon ON ROLE %s IS NULL;", pq.QuoteIdentifier(role))
}
