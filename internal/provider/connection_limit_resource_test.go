package provider

import (
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
)

func TestSQLSetConnectionLimit(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name     string
		role     string
		limit    int32
		expected string
	}{
		{"limit", testRole, 10, `ALTER ROLE "app" CONNECTION LIMIT 10;`},
		{"no connections", testRole, 0, `ALTER ROLE "app" CONNECTION LIMIT 0;`},
		{"no limit", testRole, -1, `ALTER ROLE "app" CONNECTION LIMIT -1;`},
		{"double quote in role name", `app"reporting`, 10, `ALTER ROLE "app""reporting" CONNECTION LIMIT 10;`},
		{"literal backslash in role name", `app\reporting`, 10, `ALTER ROLE "app\reporting" CONNECTION LIMIT 10;`},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.expected, sqlSetConnectionLimit(tc.role, tc.limit))
		})
	}
}

func TestConnectionLimitResource_CRUD(t *testing.T) {
	t.Parallel()

	const readSQL = "SELECT rolconnlimit FROM pg_roles WHERE rolname = $1;"

	model := func(limit int32) connectionLimitModel {
		return connectionLimitModel{Role: testRole, ConnectionLimit: limit}
	}

	t.Run("create", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewConnectionLimitResource)
		expectExec(mock, `ALTER ROLE "app" CONNECTION LIMIT 10;`)
		mock.ExpectClose()

		resp := runCreate(t, r, model(10))
		requireNoErrors(t, resp.Diagnostics)
		assertState(t, model(10), resp.State)
	})

	t.Run("create SQL error", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewConnectionLimitResource)
		expectExecError(mock, `ALTER ROLE "app" CONNECTION LIMIT 10;`, errors.New("permission denied"))
		mock.ExpectClose()

		resp := runCreate(t, r, model(10))
		assertError(t, resp.Diagnostics, "Failed to execute SQL")
		assertRemoved(t, resp.State)
	})

	t.Run("read", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewConnectionLimitResource)
		expectRoleCheck(mock, true)
		mock.ExpectQuery(exact(readSQL)).WithArgs(testRole).
			WillReturnRows(sqlmock.NewRows([]string{"rolconnlimit"}).AddRow(25))
		mock.ExpectClose()

		resp := runRead(t, r, model(10))
		requireNoErrors(t, resp.Diagnostics)
		assertState(t, model(25), resp.State)
	})

	t.Run("read role dropped after check", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewConnectionLimitResource)
		expectRoleCheck(mock, true)
		mock.ExpectQuery(exact(readSQL)).WithArgs(testRole).
			WillReturnRows(sqlmock.NewRows([]string{"rolconnlimit"}))
		mock.ExpectClose()

		assertError(t, runRead(t, r, model(10)).Diagnostics, "Failed to query CONNECTION LIMIT value")
	})

	t.Run("update", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewConnectionLimitResource)
		expectExec(mock, `ALTER ROLE "app" CONNECTION LIMIT 0;`)
		mock.ExpectClose()

		resp := runUpdate(t, r, model(10), model(0))
		requireNoErrors(t, resp.Diagnostics)
		assertState(t, model(0), resp.State)
	})

	t.Run("delete removes the limit", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewConnectionLimitResource)
		expectExec(mock, `ALTER ROLE "app" CONNECTION LIMIT -1;`)
		mock.ExpectClose()

		requireNoErrors(t, runDelete(t, r, model(10)).Diagnostics)
	})

	t.Run("import", func(t *testing.T) {
		t.Parallel()

		resp := runImport(t, NewConnectionLimitResource(), testRole)
		requireNoErrors(t, resp.Diagnostics)
		assertState(t, model(-1), resp.State)
	})
}
