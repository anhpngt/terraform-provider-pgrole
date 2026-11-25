package provider

import (
	"database/sql"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
)

func TestStatementTimeoutSQL(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name     string
		got      string
		expected string
	}{
		{"set", sqlSetStatementTimeout("app", "30s"), `ALTER ROLE "app" SET statement_timeout = '30s';`},
		{"reset", sqlResetStatementTimeout("app"), `ALTER ROLE "app" RESET statement_timeout;`},
		{"double quote in role name", sqlSetStatementTimeout(`a"b`, "30s"), `ALTER ROLE "a""b" SET statement_timeout = '30s';`},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.expected, tc.got)
		})
	}
}

// The timeout goes into the SQL with no escape, so the validator is the only
// protection against SQL injection through this attribute.
func TestTimeoutAttributeRe(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		input    string
		expected bool
	}{
		{"0s", true},
		{"30s", true},
		{"3600s", true},
		{"", false},
		{"30", false},
		{"30ms", false},
		{"1min", false},
		{"-1s", false},
		{"1.5s", false},
		{" 30s", false},
		{"30s'; DROP ROLE x; --", false},
	}

	for _, tc := range testcases {
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.expected, timeoutAttributeRe.MatchString(tc.input))
		})
	}
}

func TestStatementTimeoutResource_CRUD(t *testing.T) {
	t.Parallel()

	readSQL := regexp.QuoteMeta("WHERE setting LIKE 'statement_timeout=%' LIMIT 1;")

	model := func(timeout string) statementTimeoutModel {
		return statementTimeoutModel{Role: testRole, Timeout: timeout}
	}

	t.Run("create", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewStatementTimeoutResource)
		expectExec(mock, `ALTER ROLE "app" SET statement_timeout = '30s';`)
		mock.ExpectClose()

		resp := runCreate(t, r, model("30s"))
		requireNoErrors(t, resp.Diagnostics)
		assertState(t, model("30s"), resp.State)
	})

	t.Run("read strips the setting name", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewStatementTimeoutResource)
		expectRoleCheck(mock, true)
		mock.ExpectQuery(readSQL).WithArgs(testRole).
			WillReturnRows(sqlmock.NewRows([]string{"setting"}).AddRow("statement_timeout=60s"))
		mock.ExpectClose()

		resp := runRead(t, r, model("30s"))
		requireNoErrors(t, resp.Diagnostics)
		assertState(t, model("60s"), resp.State)
	})

	t.Run("read with no setting", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewStatementTimeoutResource)
		expectRoleCheck(mock, true)
		mock.ExpectQuery(readSQL).WithArgs(testRole).
			WillReturnRows(sqlmock.NewRows([]string{"setting"}))
		mock.ExpectClose()

		resp := runRead(t, r, model("30s"))
		requireNoErrors(t, resp.Diagnostics)
		assertState(t, model("0s"), resp.State)
	})

	t.Run("read query error", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewStatementTimeoutResource)
		expectRoleCheck(mock, true)
		mock.ExpectQuery(readSQL).WithArgs(testRole).WillReturnError(sql.ErrConnDone)
		mock.ExpectClose()

		assertError(t, runRead(t, r, model("30s")).Diagnostics, "Failed to execute SQL")
	})

	t.Run("update", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewStatementTimeoutResource)
		expectExec(mock, `ALTER ROLE "app" SET statement_timeout = '90s';`)
		mock.ExpectClose()

		resp := runUpdate(t, r, model("30s"), model("90s"))
		requireNoErrors(t, resp.Diagnostics)
		assertState(t, model("90s"), resp.State)
	})

	t.Run("delete resets the setting", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewStatementTimeoutResource)
		expectExec(mock, `ALTER ROLE "app" RESET statement_timeout;`)
		mock.ExpectClose()

		requireNoErrors(t, runDelete(t, r, model("30s")).Diagnostics)
	})

	t.Run("import", func(t *testing.T) {
		t.Parallel()

		resp := runImport(t, NewStatementTimeoutResource(), testRole)
		requireNoErrors(t, resp.Diagnostics)
		assertState(t, model("0s"), resp.State)
	})
}
