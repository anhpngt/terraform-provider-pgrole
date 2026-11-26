package provider

import (
	"database/sql"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
)

func TestSQLSetAuditLog(t *testing.T) {
	t.Parallel()

	assert.Equal(t, `ALTER ROLE "app" SET pgaudit.log = 'read, write';`, sqlSetAuditLog("app", "read, write"))
	assert.Equal(t, `ALTER ROLE "a""b" SET pgaudit.log = 'none''; ALTER ROLE b SUPERUSER; --';`, sqlSetAuditLog(`a"b`, `none'; ALTER ROLE b SUPERUSER; --`))
}

func TestAuditResource_CRUD(t *testing.T) {
	t.Parallel()

	readSQL := regexp.QuoteMeta("WHERE setting LIKE 'pgaudit.log=%' LIMIT 1;")

	model := func(option string) auditModel {
		return auditModel{Role: testRole, AuditLogOption: option}
	}

	t.Run("create", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewAuditResource)
		expectExec(mock, `ALTER ROLE "app" SET pgaudit.log = 'read, write';`)
		mock.ExpectClose()

		resp := runCreate(t, r, model("read, write"))
		requireNoErrors(t, resp.Diagnostics)
		assertState(t, model("read, write"), resp.State)
	})

	t.Run("read strips the setting name", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewAuditResource)
		expectRoleCheck(mock, true)
		mock.ExpectQuery(readSQL).WithArgs(testRole).
			WillReturnRows(sqlmock.NewRows([]string{"setting"}).AddRow("pgaudit.log=ddl"))
		mock.ExpectClose()

		resp := runRead(t, r, model("all"))
		requireNoErrors(t, resp.Diagnostics)
		assertState(t, model("ddl"), resp.State)
	})

	t.Run("read with no setting", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewAuditResource)
		expectRoleCheck(mock, true)
		mock.ExpectQuery(readSQL).WithArgs(testRole).
			WillReturnRows(sqlmock.NewRows([]string{"setting"}))
		mock.ExpectClose()

		resp := runRead(t, r, model("all"))
		requireNoErrors(t, resp.Diagnostics)
		assertState(t, model("none"), resp.State)
	})

	t.Run("read query error", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewAuditResource)
		expectRoleCheck(mock, true)
		mock.ExpectQuery(readSQL).WithArgs(testRole).WillReturnError(sql.ErrConnDone)
		mock.ExpectClose()

		assertError(t, runRead(t, r, model("all")).Diagnostics, "Failed to query pgaudit.log value")
	})

	t.Run("update", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewAuditResource)
		expectExec(mock, `ALTER ROLE "app" SET pgaudit.log = 'none';`)
		mock.ExpectClose()

		resp := runUpdate(t, r, model("all"), model("none"))
		requireNoErrors(t, resp.Diagnostics)
		assertState(t, model("none"), resp.State)
	})

	t.Run("delete resets the setting", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewAuditResource)
		expectExec(mock, `ALTER ROLE "app" RESET pgaudit.log;`)
		mock.ExpectClose()

		requireNoErrors(t, runDelete(t, r, model("all")).Diagnostics)
	})

	t.Run("import", func(t *testing.T) {
		t.Parallel()

		resp := runImport(t, NewAuditResource(), testRole)
		requireNoErrors(t, resp.Diagnostics)
		assertState(t, model("none"), resp.State)
	})
}
