package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestRoleSettings(t *testing.T) {
	server := newTestServer(t)
	db := server.open(t)
	superuser := server.getter(server.username, server.password)
	anon := hasAnon(t, db)

	// A role that may log in but may not change other roles, to make Delete fail on a role that exists.
	const unprivileged = "pgrole_test_unprivileged"
	createRole(t, db, unprivileged)
	mustExec(t, db, fmt.Sprintf("ALTER ROLE %q LOGIN PASSWORD 'unprivileged';", unprivileged))

	for _, c := range roleSettingCases {
		t.Run(c.name, func(t *testing.T) {
			if c.needsAnon && !anon {
				t.Skip("the anon extension is not loaded on the test server")
			}
			r := c.configured(t, superuser)
			role := "pgrole_test_" + c.name

			t.Run("read reports the setting of an existing role", func(t *testing.T) {
				createRole(t, db, role)
				if got, want := read(t, r, c.managed(role)), c.unset(role); got != want {
					t.Errorf("before the setting is in place: got %+v, want %+v", got, want)
				}

				mustExec(t, db, c.set(role))
				if got, want := read(t, r, c.unset(role)), c.managed(role); got != want {
					t.Errorf("with the setting in place: got %+v, want %+v", got, want)
				}
			})

			t.Run("read removes the resource of a dropped role", func(t *testing.T) {
				createRole(t, db, role)
				mustExec(t, db, c.set(role))
				dropRole(t, db, role)

				if got := read(t, r, c.managed(role)); got != nil {
					t.Errorf("got %+v, want the resource removed from the state", got)
				}
			})

			t.Run("delete takes the setting off an existing role", func(t *testing.T) {
				createRole(t, db, role)
				mustExec(t, db, c.set(role))

				if msg := deleteResource(t, r, c.managed(role)); msg != "" {
					t.Fatalf("delete failed: %s", msg)
				}
				if got, want := read(t, r, c.managed(role)), c.unset(role); got != want {
					t.Errorf("after delete: got %+v, want %+v", got, want)
				}
			})

			t.Run("delete succeeds for a dropped role", func(t *testing.T) {
				createRole(t, db, role)
				mustExec(t, db, c.set(role))
				dropRole(t, db, role)

				if msg := deleteResource(t, r, c.managed(role)); msg != "" {
					t.Errorf("delete failed: %s", msg)
				}
			})

			t.Run("delete still fails for an existing role", func(t *testing.T) {
				createRole(t, db, role)
				mustExec(t, db, c.set(role))

				weak := c.configured(t, server.getter(unprivileged, "unprivileged"))
				if msg := deleteResource(t, weak, c.managed(role)); msg == "" {
					t.Error("delete succeeded although the user may not change the role")
				}
				if got, want := read(t, r, c.managed(role)), c.managed(role); got != want {
					t.Errorf("after the failed delete: got %+v, want %+v", got, want)
				}
			})
		})
	}
}

// TestAccRoleDroppedOutsideTerraform runs the provider under Terraform against the test server, for
// the case that prompted these changes: the role is dropped by whatever manages it before its
// settings are removed from the configuration.
func TestAccRoleDroppedOutsideTerraform(t *testing.T) {
	if os.Getenv(resource.EnvTfAcc) == "" {
		t.Skipf("%s is not set", resource.EnvTfAcc)
	}
	server := newTestServer(t)
	db := server.open(t)

	// Nothing orders the settings, so Terraform applies them in parallel, as it does for the settings
	// of one role in a real configuration.
	const role = "pgrole_test_acc"
	settings := fmt.Sprintf(`
resource "pgrole_audit" "test" {
  role             = %[1]q
  audit_log_option = "all"
}

resource "pgrole_statement_timeout" "test" {
  role    = %[1]q
  timeout = "300s"
}

resource "pgrole_connection_limit" "test" {
  role             = %[1]q
  connection_limit = 5
}
`, role)
	if hasAnon(t, db) {
		settings += fmt.Sprintf(`
resource "pgrole_security_label" "test" {
  role  = %q
  label = "MASKED"
}
`, role)
	}

	create := resource.TestStep{
		PreConfig: func() { createRole(t, db, role) },
		Config:    server.providerConfig() + settings,
		Check:     resource.TestCheckResourceAttr("pgrole_statement_timeout.test", "timeout", "300s"),
	}

	t.Run("settings removed from the configuration", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				create,
				{
					PreConfig: func() { dropRole(t, db, role) },
					Config:    server.providerConfig(),
				},
			},
		})
	})

	t.Run("settings kept in the configuration", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				create,
				{
					// The settings are planned again, and creating them fails because the role is gone.
					PreConfig:   func() { dropRole(t, db, role) },
					Config:      server.providerConfig() + settings,
					ExpectError: regexp.MustCompile(`role "pgrole_test_acc" does not exist`),
				},
			},
		})
	})
}
