package provider

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSQLBuilders(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name     string
		got      string
		expected string
	}{
		{"enable bypassrls", sqlEnableBypassRLS("app"), `ALTER ROLE "app" BYPASSRLS;`},
		{"disable bypassrls", sqlDisableBypassRLS("app"), `ALTER ROLE "app" NOBYPASSRLS;`},
		{"enable createrole", sqlEnableCreateRole("app"), `ALTER ROLE "app" CREATEROLE;`},
		{"disable createrole", sqlDisableCreateRole("app"), `ALTER ROLE "app" NOCREATEROLE;`},
		{"enable replication", sqlEnableReplication("app"), `ALTER ROLE "app" REPLICATION;`},
		{"disable replication", sqlDisableReplication("app"), `ALTER ROLE "app" NOREPLICATION;`},
		{"set connection limit", sqlSetConnectionLimit("app", 10), `ALTER ROLE "app" CONNECTION LIMIT 10;`},
		{"remove connection limit", sqlSetConnectionLimit("app", -1), `ALTER ROLE "app" CONNECTION LIMIT -1;`},
		{"set statement timeout", sqlSetStatementTimeout("app", "30s"), `ALTER ROLE "app" SET statement_timeout = '30s';`},
		{"reset statement timeout", sqlResetStatementTimeout("app"), `ALTER ROLE "app" RESET statement_timeout;`},
		{"set audit log", sqlSetAuditLog("app", "read, write"), `ALTER ROLE "app" SET pgaudit.log = 'read, write';`},
		{"set security label", sqlSetSecurityLabel("app", "MASKED"), `SECURITY LABEL FOR anon ON ROLE "app" IS 'MASKED';`},
		{"escape quote in security label", sqlSetSecurityLabel("app", "it's"), `SECURITY LABEL FOR anon ON ROLE "app" IS 'it''s';`},
		{"remove security label", sqlRemoveSecurityLabel("app"), `SECURITY LABEL FOR anon ON ROLE "app" IS NULL;`},
		// Role names with upper case, dashes, and dots need quotes in SQL.
		{"quote mixed case role", sqlEnableBypassRLS("App-User.1"), `ALTER ROLE "App-User.1" BYPASSRLS;`},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.expected, tc.got)
		})
	}
}

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
