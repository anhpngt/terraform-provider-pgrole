package provider

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/lib/pq"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = (*revokeOnDestroyResource)(nil)
	_ resource.ResourceWithConfigure   = (*revokeOnDestroyResource)(nil)
	_ resource.ResourceWithImportState = (*revokeOnDestroyResource)(nil)
)

// NewRevokeOnDestroyResource is a helper function to simplify the provider implementation.
func NewRevokeOnDestroyResource() resource.Resource {
	return &revokeOnDestroyResource{}
}

type revokeOnDestroyResource struct {
	getDB F
}

// Metadata returns the resource type name.
func (r *revokeOnDestroyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_revoke_on_destroy"
}

// Schema defines the schema for the resource.
func (r *revokeOnDestroyResource) Schema(_ context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: `Makes a role droppable. When this resource is destroyed, the role loses its security labels and every privilege it holds, in all databases of the server.

PostgreSQL refuses to drop a role that still holds privileges (` + "`role \"x\" cannot be dropped because some objects depend on it`" + `). Privileges granted through Terraform go away when their resources are destroyed. Others do not: for example the ones that PostgreSQL Anonymizer gives every masked role on its ` + "`anon`" + ` and ` + "`mask`" + ` schemas. Declare this resource for the role, and make it depend on whatever creates the role, so that Terraform destroys it right before the role is dropped.

Creating the resource only checks that the role exists. Destroying it:

1. Removes the security labels of the role. PostgreSQL Anonymizer grants its privileges again to every role that still has its label, each time a table is created, altered or dropped.
2. Runs ` + "`DROP OWNED BY`" + ` for the role in every database where it holds privileges.

A database where the role owns objects, or is named in a row-level security policy, is left alone: ` + "`DROP OWNED`" + ` would drop those instead of only revoking. Give them to another role there with ` + "`REASSIGN OWNED BY`" + `, then run ` + "`DROP OWNED BY`" + `.

## When the role cannot be made droppable

The destroy still succeeds, with a warning that says what the role still holds. The ` + "`DROP ROLE`" + ` that follows then fails with the error of PostgreSQL, as it would without this resource.

A failed destroy would do more harm. Terraform destroys this resource before it changes the resource that creates the role, so an error here would also stop every other change to that resource, such as creating the other roles of a ` + "`for_each`" + `.

Give the resource that creates the roles ` + "`create_before_destroy`" + `, as in the example below. Terraform then creates the new roles, and this resource for them, before it drops the roles that left. Without it, a role whose drop keeps failing also keeps Terraform from creating this resource for the roles added in the meantime.

The destroy fails only when the provider cannot query the server, or cannot take back a membership that it gave itself (see below).

## Required privileges

Revoking a privilege takes the privileges of the role that owns the object. Where the provider's user lacks them, it grants itself membership in the role and in the owners of those objects for the time of the destroy, and takes it back afterwards. That works with ` + "`CREATEROLE`" + ` on PostgreSQL 15 and older. PostgreSQL 16 restricted ` + "`CREATEROLE`" + `: there the user must already be a member of those roles, or have ` + "`ADMIN OPTION`" + ` on them.

Destroy this resource only together with the role. Destroyed on its own, it leaves the role without privileges.`,
		Attributes: map[string]schema.Attribute{
			"role": schema.StringAttribute{
				Description: "Name of the role.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
		},
	}
}

type revokeOnDestroyModel struct {
	Role string `tfsdk:"role"`
}

// Configure adds the provider configured client to the resource.
func (r *revokeOnDestroyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Add a nil check when handling ProviderData because Terraform
	// sets that data after it calls the ConfigureProvider RPC.
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(F)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected provider.F, got %T", req.ProviderData),
		)
	}

	r.getDB = client
}

// Create checks that the role exists and sets the initial Terraform state. It
// changes nothing in the database.
func (r *revokeOnDestroyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan revokeOnDestroyModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
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

	exists, err := roleExists(ctx, db, plan.Role)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to check role",
			fmt.Sprintf("Failed to check whether role %s exists: %s", plan.Role, err),
		)
		return
	}
	if !exists {
		resp.Diagnostics.AddError(
			"Role does not exist",
			fmt.Sprintf("role %q does not exist", plan.Role),
		)
		return
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

// Read keeps the state as it is, without a connection: the resource holds
// nothing in the database to compare the state with. A role that was dropped
// outside Terraform needs no special case either, because Delete has nothing to
// do for it.
func (r *revokeOnDestroyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state revokeOnDestroyModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

// Update only exists to satisfy the interface: a change of the role replaces
// the resource.
func (r *revokeOnDestroyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan revokeOnDestroyModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

// Delete removes the security labels of the role and revokes its privileges in
// every database.
func (r *revokeOnDestroyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state revokeOnDestroyModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
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

	notDroppable, err := r.revokeAll(ctx, db, state.Role)
	if notDroppable != "" {
		resp.Diagnostics.AddWarning("Role cannot be dropped yet", notDroppable)
	}
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to revoke the privileges of the role",
			err.Error(),
		)
	}
}

func (r *revokeOnDestroyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("role"), req, resp)
}

// revokeOnDestroyMu lets one destroy run at a time. A destroy gives the
// provider's user memberships and takes them back when it is done: run in
// parallel, one destroy would take away a membership that another one, for a
// role with the same object owners, still relies on.
var revokeOnDestroyMu sync.Mutex

// A roleDependency counts the entries of one kind that pg_shdepend holds for a
// role in one database.
type roleDependency struct {
	database string // empty for objects shared by all databases, such as the databases themselves
	kind     string // pg_shdepend.deptype
	count    int
}

// PostgreSQL records a privilege held by a role as an "a" (ACL) dependency.
// Every other kind is something DROP OWNED would drop instead of revoke.
const dependencyACL = "a"

func (d roleDependency) String() string {
	where := "on objects shared by all databases"
	if d.database != "" {
		where = fmt.Sprintf("in database %q", d.database)
	}

	switch d.kind {
	case dependencyACL:
		return fmt.Sprintf("%d privilege(s) %s", d.count, where)
	case "o":
		return fmt.Sprintf("%d owned object(s) %s", d.count, where)
	case "r":
		return fmt.Sprintf("%d row-level security policy(ies) that name it %s", d.count, where)
	default:
		return fmt.Sprintf("%d dependency(ies) of type %q %s", d.count, d.kind, where)
	}
}

func describeDependencies(deps []roleDependency) string {
	parts := make([]string, len(deps))
	for i, d := range deps {
		parts[i] = d.String()
	}
	return strings.Join(parts, ", ")
}

// roleDependencies returns what makes PostgreSQL refuse to drop the role.
// pg_shdepend is shared by all databases, so one connection sees the whole
// server.
func roleDependencies(ctx context.Context, db *sql.DB, roleOID int64) ([]roleDependency, error) {
	rows, err := db.QueryContext(ctx, sqlRoleDependencies, roleOID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var deps []roleDependency
	for rows.Next() {
		var d roleDependency
		if err := rows.Scan(&d.database, &d.kind, &d.count); err != nil {
			return nil, err
		}
		deps = append(deps, d)
	}
	return deps, rows.Err()
}

// queryStrings returns the single column of a query.
func queryStrings(ctx context.Context, db *sql.DB, query string, args ...any) ([]string, error) {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var values []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		values = append(values, v)
	}
	return values, rows.Err()
}

// quoteIdentifier quotes a name for use in a statement.
func quoteIdentifier(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

const (
	sqlRoleOID = "SELECT oid FROM pg_roles WHERE rolname = $1;"

	sqlRoleDependencies = `SELECT COALESCE(d.datname, ''), s.deptype::text, count(*)
FROM pg_shdepend s
LEFT JOIN pg_database d ON d.oid = s.dbid
WHERE s.refclassid = 'pg_authid'::regclass AND s.refobjid = $1::oid
GROUP BY 1, 2
ORDER BY 1, 2;`

	sqlRoleSecurityLabelProviders = `SELECT provider FROM pg_shseclabel
WHERE classoid = 'pg_authid'::regclass AND objoid = $1::oid
ORDER BY 1;`

	// The owners of the objects that the role holds privileges on, per database
	// (empty for objects shared by all databases).
	sqlPrivilegeObjectOwners = `SELECT DISTINCT COALESCE(d.datname, ''), pg_get_userbyid(o.refobjid)
FROM pg_shdepend a
JOIN pg_shdepend o ON o.dbid = a.dbid AND o.classid = a.classid AND o.objid = a.objid
	AND o.refclassid = 'pg_authid'::regclass AND o.deptype = 'o'
LEFT JOIN pg_database d ON d.oid = a.dbid
WHERE a.refclassid = 'pg_authid'::regclass AND a.refobjid = $1::oid AND a.deptype = 'a'
ORDER BY 1, 2;`

	sqlCurrentDatabase = "SELECT current_database();"

	sqlHasPrivilegesOfRole = "SELECT pg_has_role($1::name, 'USAGE');"

	// What DROP OWNED would drop, instead of revoke, in the current database.
	// It does not drop the databases and tablespaces that the role owns.
	sqlOwnedInCurrentDatabase = `SELECT count(*)
FROM pg_shdepend
WHERE refclassid = 'pg_authid'::regclass AND refobjid = $1::oid AND deptype <> 'a'
	AND dbid = (SELECT oid FROM pg_database WHERE datname = current_database());`
)

func sqlRemoveSecurityLabelOf(provider string, role string) string {
	return fmt.Sprintf("SECURITY LABEL FOR %s ON ROLE %s IS NULL;", quoteIdentifier(provider), quoteIdentifier(role))
}

func sqlGrantMembership(role string) string {
	return fmt.Sprintf("GRANT %s TO CURRENT_USER;", quoteIdentifier(role))
}

func sqlRevokeMembership(role string) string {
	return fmt.Sprintf("REVOKE %s FROM CURRENT_USER;", quoteIdentifier(role))
}

func sqlDropOwned(role string) string {
	return fmt.Sprintf("DROP OWNED BY %s;", quoteIdentifier(role))
}

// revokeAll takes the security labels of the role away, and its privileges in
// every database where that is safe. db is a connection to the database of the
// provider configuration.
//
// notDroppable is not empty when the role is left with something that makes
// PostgreSQL refuse to drop it: it says what, and why it is still there. That
// is a warning and not an error, see the description of the resource.
func (r *revokeOnDestroyResource) revokeAll(ctx context.Context, db *sql.DB, role string) (notDroppable string, err error) {
	revokeOnDestroyMu.Lock()
	defer revokeOnDestroyMu.Unlock()
	defer lockRole(role)()

	var roleOID int64
	switch err := db.QueryRowContext(ctx, sqlRoleOID, role).Scan(&roleOID); {
	case errors.Is(err, sql.ErrNoRows):
		// The role is gone, and its labels and privileges with it.
		tflog.Info(ctx, "Role no longer exists, nothing to revoke", map[string]any{"role": role})
		return "", nil
	case err != nil:
		return "", fmt.Errorf("failed to look up role %q: %w", role, err)
	}

	deps, err := roleDependencies(ctx, db, roleOID)
	if err != nil {
		return "", fmt.Errorf("failed to list what role %q holds: %w", role, err)
	}

	// notes say why something is left, for the warning.
	var notes []string

	providers, err := queryStrings(ctx, db, sqlRoleSecurityLabelProviders, roleOID)
	if err != nil {
		return "", fmt.Errorf("failed to list the security labels of role %q: %w", role, err)
	}
	for _, provider := range providers {
		if _, err := db.ExecContext(ctx, sqlRemoveSecurityLabelOf(provider, role)); err != nil {
			// Not fatal: the label does not stop a DROP ROLE. Whatever grants
			// privileges to labelled roles may grant them again, though.
			notes = append(notes, fmt.Sprintf("Its %q security label could not be removed: %s.", provider, err))
			continue
		}
		tflog.Info(ctx, "Removed security label", map[string]any{"role": role, "provider": provider})
	}
	if len(deps) == 0 {
		return "", nil
	}

	// DROP OWNED revokes the privileges of the role in one database, and drops
	// what the role owns there. A database where the role owns something, or
	// is named in a policy, is therefore left alone.
	var (
		current    string
		unsafe     []string // databases to leave alone
		databases  []string // databases to run DROP OWNED in
		revoked    []string // databases where DROP OWNED ran
		wantShared bool     // the role holds privileges on shared objects
	)
	if err := db.QueryRowContext(ctx, sqlCurrentDatabase).Scan(&current); err != nil {
		return "", fmt.Errorf("failed to get the name of the current database: %w", err)
	}
	for _, d := range deps {
		if d.kind != dependencyACL && d.database != "" && !slices.Contains(unsafe, d.database) {
			unsafe = append(unsafe, d.database)
		}
	}
	for _, d := range deps {
		switch {
		case d.kind != dependencyACL:
		case d.database == "":
			wantShared = true
		case !slices.Contains(unsafe, d.database) && !slices.Contains(databases, d.database):
			databases = append(databases, d.database)
		}
	}
	// A privilege on a shared object, such as a database, is revoked from any
	// database. When no database is visited for its own privileges, the
	// current one will do.
	if wantShared && len(databases) == 0 && !slices.Contains(unsafe, current) {
		databases = append(databases, current)
	}
	for _, database := range unsafe {
		notes = append(notes, fmt.Sprintf("Database %q was left alone, because DROP OWNED would drop what the role owns there instead of only revoking: reassign those objects with REASSIGN OWNED BY, then run DROP OWNED BY for the role in that database.", database))
	}

	if len(databases) > 0 {
		// DROP OWNED is allowed with the privileges of the role, and revokes a
		// privilege only when run with the privileges of the owner of the
		// object: otherwise it warns and leaves the privilege in place.
		// Assigned to the named result, not declared here: the deferred
		// function below reports through it.
		var owners []string
		owners, err = privilegeObjectOwners(ctx, db, roleOID, databases)
		if err != nil {
			return "", fmt.Errorf("failed to list the owners of the objects that role %q has privileges on: %w", role, err)
		}

		var granted []string
		defer func() {
			// The context may be canceled by now. The memberships must go anyway.
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			for _, member := range granted {
				if _, revokeErr := db.ExecContext(cleanupCtx, sqlRevokeMembership(member)); revokeErr != nil {
					err = errors.Join(err, fmt.Errorf("failed to take back the membership in role %q that the provider's user gave itself: %w", member, revokeErr))
				}
			}
		}()

		unable := ""
		for _, member := range append([]string{role}, owners...) {
			able, grantedNow, err := actAs(ctx, db, member)
			if grantedNow {
				granted = append(granted, member)
				tflog.Info(ctx, "Granted membership for the time of the destroy", map[string]any{"role": role, "member_of": member})
			}
			if err != nil {
				return "", fmt.Errorf("failed to check the membership in role %q: %w", member, err)
			}
			if !able.can {
				unable = fmt.Sprintf("Revoking its privileges takes the privileges of role %q, which the provider's user does not have and could not get: %s. On PostgreSQL 16 and newer it must already be a member of that role, or have ADMIN OPTION on it.", member, able.reason)
				break
			}
		}

		if unable != "" {
			notes = append(notes, unable)
		} else {
			for _, database := range databases {
				if err := r.dropOwned(ctx, db, current, database, role, roleOID); err != nil {
					notes = append(notes, fmt.Sprintf("Database %q: %s.", database, err))
					continue
				}
				revoked = append(revoked, database)
				tflog.Info(ctx, "Revoked the privileges of the role", map[string]any{"role": role, "database": database})
			}
		}
	}

	left, err := roleDependencies(ctx, db, roleOID)
	if err != nil {
		return "", fmt.Errorf("failed to list what role %q still holds: %w", role, err)
	}
	if len(left) == 0 {
		return "", nil
	}

	var ownsShared, notRevoked bool
	for _, d := range left {
		switch {
		case d.kind != dependencyACL && d.database == "":
			ownsShared = true
		case d.kind == dependencyACL && d.database == "" && len(revoked) > 0,
			d.kind == dependencyACL && slices.Contains(revoked, d.database):
			notRevoked = true
		}
	}
	if ownsShared {
		notes = append(notes, "It owns databases or tablespaces, which DROP OWNED leaves in place: give them to another role.")
	}
	if notRevoked {
		notes = append(notes, "Some privileges are on objects whose owner the provider's user cannot act as, or were granted by a role other than the owner.")
	}
	return fmt.Sprintf("Role %q still has %s, so PostgreSQL will refuse to drop it. %s", role, describeDependencies(left), strings.Join(notes, " ")), nil
}

// privilegeObjectOwners returns the owners of the objects that the role holds
// privileges on, in the given databases and among the objects shared by all
// databases.
func privilegeObjectOwners(ctx context.Context, db *sql.DB, roleOID int64, databases []string) ([]string, error) {
	rows, err := db.QueryContext(ctx, sqlPrivilegeObjectOwners, roleOID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var owners []string
	for rows.Next() {
		var database, owner string
		if err := rows.Scan(&database, &owner); err != nil {
			return nil, err
		}
		if (database == "" || slices.Contains(databases, database)) && !slices.Contains(owners, owner) {
			owners = append(owners, owner)
		}
	}
	return owners, rows.Err()
}

// An ability says whether the provider's user has the privileges of a role,
// and why not when it does not.
type ability struct {
	can    bool
	reason string
}

// actAs makes sure the provider's user has the privileges of the role, by
// granting itself membership when it lacks them. granted reports whether it
// did, also when the membership turns out not to be enough.
func actAs(ctx context.Context, db *sql.DB, role string) (result ability, granted bool, err error) {
	var has bool
	if err := db.QueryRowContext(ctx, sqlHasPrivilegesOfRole, role).Scan(&has); err != nil {
		return ability{}, false, err
	}
	if has {
		return ability{can: true}, false, nil
	}

	if _, err := db.ExecContext(ctx, sqlGrantMembership(role)); err != nil {
		// Not being allowed to is an answer, not a failure of the destroy.
		return ability{reason: err.Error()}, false, nil //nolint:nilerr
	}

	if err := db.QueryRowContext(ctx, sqlHasPrivilegesOfRole, role).Scan(&has); err != nil {
		return ability{}, true, err
	}
	if !has {
		return ability{reason: "it is a member of the role now, but does not inherit its privileges"}, true, nil
	}
	return ability{can: true}, true, nil
}

// dropOwned runs DROP OWNED BY for the role in one database. main is the
// connection to the database named current, which is used as it is.
func (r *revokeOnDestroyResource) dropOwned(ctx context.Context, main *sql.DB, current string, database string, role string, roleOID int64) error {
	db := main
	if database != current {
		other, err := r.getDB(withDatabase(ctx, database))
		if err != nil {
			return fmt.Errorf("failed to connect: %w", err)
		}
		defer other.Close()
		db = other
	}

	const attempts = 3
	var err error
	for attempt := 1; attempt <= attempts; attempt++ {
		if err = dropOwnedOnce(ctx, db, role, roleOID); err == nil || !isTransient(err) || attempt == attempts {
			return err
		}

		tflog.Warn(ctx, "Revoking the privileges of the role failed, trying again", map[string]any{
			"role": role, "database": database, "attempt": attempt, "error": err.Error(),
		})
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(attempt) * 500 * time.Millisecond):
		}
	}
	return err
}

// dropOwnedOnce runs DROP OWNED BY in a transaction, after checking once more
// that the role owns nothing in that database: what the role owns is dropped by
// DROP OWNED, and the role may have come to own something since the first
// check.
func dropOwnedOnce(ctx context.Context, db *sql.DB, role string, roleOID int64) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var owned int
	if err := tx.QueryRowContext(ctx, sqlOwnedInCurrentDatabase, roleOID).Scan(&owned); err != nil {
		return fmt.Errorf("failed to check what the role owns: %w", err)
	}
	if owned > 0 {
		return fmt.Errorf("the role came to own, or be named in the policies of, %d object(s) there while its privileges were being revoked, and nothing was dropped", owned)
	}

	if _, err := tx.ExecContext(ctx, sqlDropOwned(role)); err != nil {
		return err
	}
	return tx.Commit()
}

// isTransient reports whether a statement failed because of something else
// that ran at the same moment, and is worth running again.
func isTransient(err error) bool {
	var pqErr *pq.Error
	if !errors.As(err, &pqErr) {
		return false
	}

	switch pqErr.Code {
	case "40001", // serialization_failure
		"40P01", // deadlock_detected
		"55P03": // lock_not_available
		return true
	}
	// Two changes of the privileges of one object at the same moment. It has
	// no error code of its own.
	return strings.Contains(pqErr.Message, "tuple concurrently")
}
