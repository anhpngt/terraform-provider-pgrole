package provider

import (
	"context"
	"database/sql"
	"sync"
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
