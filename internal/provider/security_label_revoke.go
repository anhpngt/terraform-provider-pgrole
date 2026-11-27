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

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/lib/pq"
)

// PostgreSQL Anonymizer gives every role with the MASKED label USAGE on its own schema and on the
// schema of the masking views, and SELECT on the tables, views and sequences in them, in each
// database where dynamic masking runs. It does so when masking starts and again each time a table
// is created, altered or dropped, and it never takes them back: not when the label is removed
// either. A role that keeps them cannot be dropped ("role cannot be dropped because some objects
// depend on it").
//
// The code in this file takes those privileges back, and only those.

// maskingRevokeMu lets one revoke run at a time. A revoke may give the provider's user memberships
// and takes them back when it is done: run in parallel, one revoke would take away a membership
// that another one, for a role with privileges on objects of the same owner, still relies on.
var maskingRevokeMu sync.Mutex

const (
	sqlRoleOID = "SELECT oid FROM pg_roles WHERE rolname = $1;"

	// The databases where the role holds privileges. pg_shdepend is shared by all databases, so
	// one connection sees the whole server.
	sqlRolePrivilegeDatabases = `SELECT d.datname
FROM pg_database d
WHERE d.oid IN (
	SELECT s.dbid FROM pg_shdepend s
	WHERE s.refclassid = 'pg_authid'::regclass AND s.refobjid = $1::oid AND s.deptype = 'a'
)
ORDER BY 1;`

	sqlCurrentDatabase = "SELECT current_database();"

	sqlHasPrivilegesOfRole = "SELECT pg_has_role($1::name, 'USAGE');"

	// What the role holds in the two schemas of PostgreSQL Anonymizer in the current database, as
	// rows of kind, schema and owner of the objects. The schema of the masking views is "mask"
	// unless anon.maskschema says otherwise.
	sqlMaskingPrivileges = `WITH masking_schema AS (
	SELECT n.oid, n.nspname, n.nspowner, n.nspacl
	FROM pg_namespace n
	WHERE n.nspname IN ('anon', COALESCE(NULLIF(current_setting('anon.maskschema', true), ''), 'mask'))
)
SELECT DISTINCT 'tables', n.nspname, pg_get_userbyid(c.relowner)
FROM masking_schema n
JOIN pg_class c ON c.relnamespace = n.oid AND c.relkind <> 'S'
CROSS JOIN LATERAL aclexplode(c.relacl) a
WHERE a.grantee = $1::oid
UNION ALL
SELECT DISTINCT 'sequences', n.nspname, pg_get_userbyid(c.relowner)
FROM masking_schema n
JOIN pg_class c ON c.relnamespace = n.oid AND c.relkind = 'S'
CROSS JOIN LATERAL aclexplode(c.relacl) a
WHERE a.grantee = $1::oid
UNION ALL
SELECT 'schema', n.nspname, pg_get_userbyid(n.nspowner)
FROM masking_schema n
WHERE EXISTS (SELECT 1 FROM aclexplode(n.nspacl) a WHERE a.grantee = $1::oid)
ORDER BY 2, 1, 3;`
)

// The kinds of rows that sqlMaskingPrivileges returns.
const (
	maskingTables    = "tables"
	maskingSequences = "sequences"
	maskingSchema    = "schema"
)

// A maskingPrivilege says that the role holds privileges on objects of one kind in one of the
// schemas of PostgreSQL Anonymizer, and who owns those objects.
type maskingPrivilege struct {
	kind   string
	schema string
	owner  string
}

func (p maskingPrivilege) String() string {
	if p.kind == maskingSchema {
		return fmt.Sprintf("schema %q", p.schema)
	}
	return fmt.Sprintf("%s in schema %q", p.kind, p.schema)
}

// sqlRevoke returns the statement that takes the privileges away from the role.
func (p maskingPrivilege) sqlRevoke(role string) string {
	schema, grantee := pq.QuoteIdentifier(p.schema), pq.QuoteIdentifier(role)
	switch p.kind {
	case maskingTables:
		return fmt.Sprintf("REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA %s FROM %s;", schema, grantee)
	case maskingSequences:
		return fmt.Sprintf("REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA %s FROM %s;", schema, grantee)
	default:
		return fmt.Sprintf("REVOKE ALL PRIVILEGES ON SCHEMA %s FROM %s;", schema, grantee)
	}
}

func sqlGrantMembership(role string) string {
	return fmt.Sprintf("GRANT %s TO CURRENT_USER;", pq.QuoteIdentifier(role))
}

func sqlRevokeMembership(role string) string {
	return fmt.Sprintf("REVOKE %s FROM CURRENT_USER;", pq.QuoteIdentifier(role))
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

// maskingPrivileges returns what the role holds in the schemas of PostgreSQL Anonymizer, in the
// database of the connection.
func maskingPrivileges(ctx context.Context, db *sql.DB, roleOID int64) ([]maskingPrivilege, error) {
	rows, err := db.QueryContext(ctx, sqlMaskingPrivileges, roleOID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var held []maskingPrivilege
	for rows.Next() {
		var p maskingPrivilege
		if err := rows.Scan(&p.kind, &p.schema, &p.owner); err != nil {
			return nil, err
		}
		held = append(held, p)
	}
	return held, rows.Err()
}

func describeMaskingPrivileges(held []maskingPrivilege) string {
	var parts []string
	for _, p := range held {
		if s := p.String(); !slices.Contains(parts, s) {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, ", ")
}

// revokeMaskingPrivileges takes back what PostgreSQL Anonymizer gave the role, in every database
// of the server. db is a connection to the database of the provider configuration.
//
// Call it once the label of the role is removed: as long as the role has its label, the next table
// that is created, altered or dropped gives it everything back.
func (r *securityLabelResource) revokeMaskingPrivileges(ctx context.Context, db *sql.DB, role string) (err error) {
	if err := validateRoleName(role); err != nil {
		return err
	}

	maskingRevokeMu.Lock()
	defer maskingRevokeMu.Unlock()

	var roleOID int64
	switch err := db.QueryRowContext(ctx, sqlRoleOID, role).Scan(&roleOID); {
	case errors.Is(err, sql.ErrNoRows):
		// The role is gone, and its privileges with it.
		return nil
	case err != nil:
		return fmt.Errorf("failed to look up role %q: %w", role, err)
	}

	databases, err := queryStrings(ctx, db, sqlRolePrivilegeDatabases, roleOID)
	if err != nil {
		return fmt.Errorf("failed to list the databases where role %q holds privileges: %w", role, err)
	}
	if len(databases) == 0 {
		return nil
	}

	var current string
	if err := db.QueryRowContext(ctx, sqlCurrentDatabase).Scan(&current); err != nil {
		return fmt.Errorf("failed to get the name of the current database: %w", err)
	}

	// The memberships that the provider's user gave itself to be able to revoke.
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

	// One database that fails does not stop the others: each one that is done is one less to do
	// when the destroy is run again.
	var failures []error
	for _, database := range databases {
		newlyGranted, err := r.revokeMaskingPrivilegesIn(ctx, db, current, database, role, roleOID)
		granted = append(granted, newlyGranted...)
		if err != nil {
			failures = append(failures, fmt.Errorf("database %q: %w", database, err))
			continue
		}
	}
	return errors.Join(failures...)
}

// revokeMaskingPrivilegesIn does the work of revokeMaskingPrivileges in one database. main is the
// connection to the database named current, which is used as it is. granted lists the memberships
// that the provider's user gave itself on the way, also when an error is returned.
func (r *securityLabelResource) revokeMaskingPrivilegesIn(ctx context.Context, main *sql.DB, current string, database string, role string, roleOID int64) (granted []string, err error) {
	db := main
	if database != current {
		other, err := r.getDB(withDatabase(ctx, database))
		if err != nil {
			return nil, fmt.Errorf("failed to connect: %w", err)
		}
		defer other.Close()
		db = other
	}

	held, err := maskingPrivileges(ctx, db, roleOID)
	if err != nil {
		return nil, fmt.Errorf("failed to list what the role holds in the schemas of PostgreSQL Anonymizer: %w", err)
	}
	if len(held) == 0 {
		return nil, nil
	}

	// A REVOKE takes a privilege away only when run with the privileges of the role that granted
	// it, which for these is the owner of the object. Otherwise it warns and changes nothing.
	var checked []string
	for _, p := range held {
		if slices.Contains(checked, p.owner) {
			continue
		}
		checked = append(checked, p.owner)

		able, grantedNow, err := actAs(ctx, main, p.owner)
		if grantedNow {
			granted = append(granted, p.owner)
			tflog.Info(ctx, "Granted membership for the time of the revoke", map[string]any{"role": role, "member_of": p.owner})
		}
		if err != nil {
			return granted, fmt.Errorf("failed to check the membership in role %q: %w", p.owner, err)
		}
		if !able.can {
			return granted, fmt.Errorf("revoking takes the privileges of role %q, the owner of %s, which the provider's user does not have and could not get: %s. On PostgreSQL 16 and newer it must already be a member of that role, or have ADMIN OPTION on it", p.owner, p, able.reason)
		}
	}

	var statements []string
	for _, p := range held {
		if s := p.sqlRevoke(role); !slices.Contains(statements, s) {
			statements = append(statements, s)
		}
	}
	if err := execWithRetry(ctx, db, statements); err != nil {
		return granted, fmt.Errorf("failed to revoke: %w", err)
	}

	left, err := maskingPrivileges(ctx, db, roleOID)
	if err != nil {
		return granted, fmt.Errorf("failed to list what the role still holds in the schemas of PostgreSQL Anonymizer: %w", err)
	}
	if len(left) > 0 {
		return granted, fmt.Errorf("the role still holds privileges on %s. They were granted by a role that the provider's user cannot act as", describeMaskingPrivileges(left))
	}

	tflog.Info(ctx, "Revoked the masking privileges of the role", map[string]any{"role": role, "database": database})
	return granted, nil
}

// An ability says whether the provider's user has the privileges of a role, and why not when it
// does not.
type ability struct {
	can    bool
	reason string
}

// actAs makes sure the provider's user has the privileges of the role, by granting itself
// membership when it lacks them. granted reports whether it did, also when the membership turns
// out not to be enough.
func actAs(ctx context.Context, db *sql.DB, role string) (result ability, granted bool, err error) {
	var has bool
	if err := db.QueryRowContext(ctx, sqlHasPrivilegesOfRole, role).Scan(&has); err != nil {
		return ability{}, false, err
	}
	if has {
		return ability{can: true}, false, nil
	}

	if _, err := db.ExecContext(ctx, sqlGrantMembership(role)); err != nil {
		// Not being allowed to is an answer, not a failure of the check.
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

// execWithRetry runs the statements in one transaction, and runs them again when they fail because
// of something else that changed the same objects at the same moment. PostgreSQL Anonymizer
// rebuilds its masking views on every change of a table, so that is not rare.
func execWithRetry(ctx context.Context, db *sql.DB, statements []string) error {
	const attempts = 3

	var err error
	for attempt := 1; attempt <= attempts; attempt++ {
		if err = execInTransaction(ctx, db, statements); err == nil || !isTransient(err) || attempt == attempts {
			return err
		}

		tflog.Warn(ctx, "Statements failed on a concurrent change, trying again", map[string]any{
			"attempt": attempt, "error": err.Error(),
		})
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(attempt) * 500 * time.Millisecond):
		}
	}
	return err
}

func execInTransaction(ctx context.Context, db *sql.DB, statements []string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// isTransient reports whether a statement failed because of something else that ran at the same
// moment, and is worth running again.
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
	// Two changes of the privileges of one object at the same moment. It has no error code of
	// its own.
	return strings.Contains(pqErr.Message, "tuple concurrently")
}
