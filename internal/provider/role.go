package provider

import (
	"context"
	"database/sql"
	"fmt"
	"sync"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// roleLocks holds one lock per role name.
var roleLocks sync.Map

// lockRole takes the lock of a role and returns the function that releases it.
//
// PostgreSQL rejects concurrent changes to one role: two ALTER ROLE statements fail with "tuple
// concurrently updated", and the first two settings of a role with a duplicate key on
// pg_db_role_setting. Terraform applies resources that do not depend on each other in parallel, so
// the settings of one role would regularly collide. All resources of one provider configuration run
// in this process, which makes a lock here enough to apply them one at a time.
func lockRole(role string) (unlock func()) {
	lock, _ := roleLocks.LoadOrStore(role, &sync.Mutex{})
	mu, _ := lock.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// execForRole runs a statement that changes a role, holding the lock of that role.
func execForRole(ctx context.Context, db *sql.DB, role string, sqlstr string) error {
	defer lockRole(role)()

	_, err := db.ExecContext(ctx, sqlstr)
	return err
}

// roleExists reports whether a role with the given name exists.
func roleExists(ctx context.Context, db *sql.DB, role string) (bool, error) {
	var exists bool
	err := db.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1);", role).Scan(&exists)
	return exists, err
}

// removeIfRoleGone removes the resource being read from the state when its role no longer exists,
// and reports whether Read is done (the resource was removed, or the check itself failed).
//
// The resources of this provider are settings of a role that something else creates and drops.
// Dropping the role drops its settings too, so there is nothing left to read, update or delete:
// without this, Terraform keeps planning changes that can only fail with "role does not exist".
func removeIfRoleGone(ctx context.Context, db *sql.DB, role string, resp *resource.ReadResponse) bool {
	exists, err := roleExists(ctx, db, role)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to check role",
			fmt.Sprintf("Failed to check whether role %s exists: %s", role, err),
		)
		return true
	}
	if exists {
		return false
	}

	tflog.Warn(ctx, "Role no longer exists, removing resource from state", map[string]any{
		"role": role,
	})
	resp.State.RemoveResource(ctx)
	return true
}

// undoRoleSetting runs the statement that takes a setting off a role when its resource is deleted.
//
// A failure is not an error when the role no longer exists: the setting went away with the role,
// which is the state that Delete is asked to reach. This covers a role dropped after the plan was
// made, where Read could not have removed the resource from the state.
func undoRoleSetting(ctx context.Context, db *sql.DB, role string, sqlstr string) error {
	execErr := execForRole(ctx, db, role, sqlstr)
	if execErr == nil {
		return nil
	}

	if exists, err := roleExists(ctx, db, role); err != nil || exists {
		return execErr
	}

	tflog.Info(ctx, "Role no longer exists, nothing to undo", map[string]any{
		"role": role,
	})
	return nil
}
