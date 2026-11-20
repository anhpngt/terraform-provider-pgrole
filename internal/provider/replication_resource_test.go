package provider

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReplicationSQL(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name     string
		got      string
		expected string
	}{
		{"enable", sqlEnableReplication("app"), `ALTER ROLE "app" REPLICATION;`},
		{"disable", sqlDisableReplication("app"), `ALTER ROLE "app" NOREPLICATION;`},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.expected, tc.got)
		})
	}
}

func TestReplicationResource_CRUD(t *testing.T) {
	t.Parallel()

	testFlagResource(t, flagResourceSpec{
		newResource:  NewReplicationResource,
		model:        func(enabled bool) any { return replicationModel{Role: testRole, Enabled: enabled} },
		enableSQL:    `ALTER ROLE "app" REPLICATION;`,
		disableSQL:   `ALTER ROLE "app" NOREPLICATION;`,
		readSQL:      "SELECT rolreplication FROM pg_roles WHERE rolname = $1;",
		column:       "rolreplication",
		queryFailure: "Failed to query REPLICATION status",
	})
}
