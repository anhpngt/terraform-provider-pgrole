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
	// Cloud SQL connection parameters
	ProjectID                 types.String `tfsdk:"project_id"`
	Region                    types.String `tfsdk:"region"`
	Instance                  types.String `tfsdk:"instance"`
	Database                  types.String `tfsdk:"database"`
	Username                  types.String `tfsdk:"username"`
	ImpersonateServiceAccount types.String `tfsdk:"impersonate_service_account"`

	// Standard PostgreSQL connection parameters
	Host     types.String `tfsdk:"host"`
	Port     types.Int64  `tfsdk:"port"`
	Password types.String `tfsdk:"password"`
	SSLMode  types.String `tfsdk:"sslmode"`
}

func (p *pgroleProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "pgrole"
	resp.Version = p.version
}

func (p *pgroleProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A provider for managing roles' attributes inside a PostgreSQL instance (Cloud SQL or standard).",
		Attributes: map[string]schema.Attribute{
			// Cloud SQL specific parameters
			"project_id": schema.StringAttribute{
				Description: "The Google Cloud project ID of the Cloud SQL instance. Required if using Cloud SQL.",
				Optional:    true,
			},
			"region": schema.StringAttribute{
				Description: "The region of the Cloud SQL instance. Required if using Cloud SQL.",
				Optional:    true,
			},
			"instance": schema.StringAttribute{
				Description: "The name of the Cloud SQL instance. Required if using Cloud SQL.",
				Optional:    true,
			},

			// Common parameters
			"database": schema.StringAttribute{
				Description: "The name of the database to connect to. Defaults to postgres.",
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

			// Standard PostgreSQL parameters
			"host": schema.StringAttribute{
				Description: "The host of the PostgreSQL server. Required if using standard PostgreSQL.",
				Optional:    true,
			},
			"port": schema.Int64Attribute{
				Description: "The port of the PostgreSQL server. Default is 5432.",
				Optional:    true,
			},
			"password": schema.StringAttribute{
				Description: "Password for the server connection. Required if using standard PostgreSQL.",
				Optional:    true,
				Sensitive:   true,
			},
			"sslmode": schema.StringAttribute{
				Description: "SSL mode for the server connection. Default is 'disable'.",
				Optional:    true,
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

	// Check for unknown values in configuration
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
	if config.Host.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("host"),
			"unknown host",
			"unknown host",
		)
	}
	if config.Port.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("port"),
			"unknown port",
			"unknown port",
		)
	}
	if config.Password.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("password"),
			"unknown password",
			"unknown password",
		)
	}
	if config.SSLMode.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("sslmode"),
			"unknown sslmode",
			"unknown sslmode",
		)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Extract values from configuration
	projectID := ""
	region := ""
	instance := ""
	database := "postgres"
	username := ""
	impersonateServiceAccount := ""
	host := ""
	port := int64(5432) // Default PostgreSQL port
	password := ""
	sslmode := "disable" // Default to disable SSL

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
	if !config.Host.IsNull() {
		host = config.Host.ValueString()
	}
	if !config.Port.IsNull() {
		port = config.Port.ValueInt64()
	}
	if !config.Password.IsNull() {
		password = config.Password.ValueString()
	}
	if !config.SSLMode.IsNull() {
		sslmode = config.SSLMode.ValueString()
	}

	var dbgetter F

	// Check if we should use standard PostgreSQL connection
	if host != "" {
		// Use standard PostgreSQL connection
		url := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
			username, password, host, port, database, sslmode)
		dbgetter = GetStandardPostgresGetter(url)
	} else {
		// Continue with Cloud SQL connection
		if projectID == "" {
			resp.Diagnostics.AddAttributeError(
				path.Root("project_id"),
				"missing project_id",
				"project_id is required for Cloud SQL connection",
			)
		}
		if region == "" {
			resp.Diagnostics.AddAttributeError(
				path.Root("region"),
				"missing region",
				"region is required for Cloud SQL connection",
			)
		}
		if instance == "" {
			resp.Diagnostics.AddAttributeError(
				path.Root("instance"),
				"missing instance",
				"instance is required for Cloud SQL connection",
			)
		}
		if database == "" {
			resp.Diagnostics.AddAttributeError(
				path.Root("database"),
				"missing database",
				"database is required for Cloud SQL connection",
			)
		}
		if username == "" {
			resp.Diagnostics.AddAttributeError(
				path.Root("username"),
				"missing username",
				"username is required for Cloud SQL connection",
			)
		}
		if resp.Diagnostics.HasError() {
			return
		}

		url := fmt.Sprintf("gcppostgres://%s@%s/%s/%s/%s", username, projectID, region, instance, database)
		if impersonateServiceAccount != "" {
			dbgetter = GetDatabaseGetterWithImpersonation(url, impersonateServiceAccount)
		} else {
			dbgetter = GetDatabaseGetter(url)
		}
	}

	resp.DataSourceData = dbgetter
	resp.ResourceData = dbgetter
}

func (p *pgroleProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewBypassRLSResource,
		NewStatementTimeoutResource,
		NewConnectionLimitResource,
		NewReplicationResource,
		NewAuditResource,
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
