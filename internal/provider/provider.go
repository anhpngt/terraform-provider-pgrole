package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ provider.Provider              = &pgroleProvider{}
	_ provider.ProviderWithFunctions = &pgroleProvider{}
)

// pgroleProvider defines the provider implementation.
type pgroleProvider struct {
	// version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance
	// testing.
	version string
}

// pgroleModel describes the provider data model.
type pgroleModel struct {
	ProjectID                 types.String `tfsdk:"project_id"`
	Region                    types.String `tfsdk:"region"`
	Instance                  types.String `tfsdk:"instance"`
	Database                  types.String `tfsdk:"database"`
	Username                  types.String `tfsdk:"username"`
	ImpersonateServiceAccount types.String `tfsdk:"impersonate_service_account"`
}

func (p *pgroleProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "pgrole"
	resp.Version = p.version
}

func (p *pgroleProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A provider for managing roles' attributes inside a Cloud SQL PostgreSQL instance.",
		Attributes: map[string]schema.Attribute{
			"project_id": schema.StringAttribute{
				Description: "The Google Cloud project ID of the Cloud SQL instance.",
				Required:    true,
			},
			"region": schema.StringAttribute{
				Description: "The region of the Cloud SQL instance.",
				Required:    true,
			},
			"instance": schema.StringAttribute{
				Description: "The name of the Cloud SQL instance.",
				Required:    true,
			},
			"database": schema.StringAttribute{
				Description: "The name of the database to connect to. Default to postgres",
				Optional:    true,
			},
			"username": schema.StringAttribute{
				Description: "Username for the server connection.",
				Required:    true,
			},
			"impersonate_service_account": schema.StringAttribute{
				MarkdownDescription: `The service account to impersonate when connecting to the database.

When using this option, you must ensure:

  * The impersonated service account has sufficient permissions to connect to the database
  * The principal (that is impersonating the service account) has sufficient permissions to impersonate the service account`,
				Optional: true,
			},
		},
	}
}

func (p *pgroleProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	// Retrieve provider config from configuration
	var config pgroleModel
	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// If practitioner provided a configuration value for any of the
	// attributes, it must be a known value.
	if config.ProjectID.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("project_id"),
			"unknown project_id",
			"unknown project_id",
		)
	}
	if config.Region.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("region"),
			"unknown region",
			"unknown region",
		)
	}
	if config.Instance.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("instance"),
			"unknown instance",
			"unknown instance",
		)
	}
	if config.Database.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("database"),
			"unknown database",
			"unknown database",
		)
	}
	if config.Username.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("username"),
			"unknown username",
			"unknown username",
		)
	}
	if config.ImpersonateServiceAccount.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("impersonate_service_account"),
			"unknown impersonate_service_account",
			"unknown impersonate_service_account",
		)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	projectID := ""
	region := ""
	instance := ""
	database := "postgres"
	username := ""
	impersonateServiceAccount := ""
	if !config.ProjectID.IsNull() {
		projectID = config.ProjectID.ValueString()
	}
	if !config.Region.IsNull() {
		region = config.Region.ValueString()
	}
	if !config.Instance.IsNull() {
		instance = config.Instance.ValueString()
	}
	if !config.Database.IsNull() {
		database = config.Database.ValueString()
	}
	if !config.Username.IsNull() {
		username = config.Username.ValueString()
	}
	if !config.ImpersonateServiceAccount.IsNull() {
		impersonateServiceAccount = config.ImpersonateServiceAccount.ValueString()
	}

	// If any of the expected configurations are missing, return
	// errors with provider-specific guidance.
	if projectID == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("project_id"),
			"missing project_id",
			"missing project_id",
		)
	}
	if region == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("region"),
			"missing region",
			"missing region",
		)
	}
	if instance == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("instance"),
			"missing instance",
			"missing instance",
		)
	}
	if database == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("database"),
			"missing database",
			"missing database",
		)
	}
	if username == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("username"),
			"missing username",
			"missing username",
		)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Example client configuration for data sources and resources
	url := fmt.Sprintf("gcppostgres://%s@%s/%s/%s/%s", username, projectID, region, instance, database)
	var dbgetter F
	if impersonateServiceAccount != "" {
		dbgetter = GetDatabaseGetterWithImpersonation(url, impersonateServiceAccount)
	} else {
		dbgetter = GetDatabaseGetter(url)
	}
	resp.DataSourceData = dbgetter
	resp.ResourceData = dbgetter
}

func (p *pgroleProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewBypassRLSResource,
		NewStatementTimeoutResource,
	}
}

func (p *pgroleProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{}
}

func (p *pgroleProvider) Functions(ctx context.Context) []func() function.Function {
	return []func() function.Function{}
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &pgroleProvider{
			version: version,
		}
	}
}
