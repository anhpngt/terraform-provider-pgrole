package provider

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// The roles in these tests have their own names, so that the tests do not
// wait on the locks that the resource tests take for role "app".

func TestLockRole_SameRoleWaits(t *testing.T) {
	t.Parallel()

	unlock := lockRole("lock-test-same")

	acquired := make(chan struct{})
	go func() {
		defer lockRole("lock-test-same")()
		close(acquired)
	}()

	select {
	case <-acquired:
		t.Fatal("a second lock on the same role must wait for the first one")
	case <-time.After(50 * time.Millisecond):
	}

	unlock()

	select {
	case <-acquired:
	case <-time.After(time.Second):
		t.Fatal("the second lock must succeed after the first one is released")
	}
}

func TestLockRole_DifferentRolesDoNotWait(t *testing.T) {
	t.Parallel()

	defer lockRole("lock-test-a")()

	acquired := make(chan struct{})
	go func() {
		defer lockRole("lock-test-b")()
		close(acquired)
	}()

	select {
	case <-acquired:
	case <-time.After(time.Second):
		t.Fatal("a lock on a different role must not wait")
	}
}

func TestLockRole_RoleNamesAreCaseSensitive(t *testing.T) {
	t.Parallel()

	// PostgreSQL role names are case sensitive when quoted, and the
	// resources always quote them. "App" and "app" are different roles.
	defer lockRole("lock-test-case")()

	acquired := make(chan struct{})
	go func() {
		defer lockRole("LOCK-TEST-CASE")()
		close(acquired)
	}()

	select {
	case <-acquired:
	case <-time.After(time.Second):
		assert.Fail(t, "roles that differ only in case must not share a lock")
	}
}
