package provider

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/credentials"
)

func TestBuildPostgresURL(t *testing.T) {
	password := "p@ss:w/o&r=d%?#"
	dsn := buildPostgresURL("my-user", password, "localhost", 5432, "my-db", "disable")

	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("error parsing dsn: %s", err)
	}
	if got := u.User.Username(); got != "my-user" {
		t.Errorf("username = %q, want %q", got, "my-user")
	}
	if got, _ := u.User.Password(); got != password {
		t.Errorf("password = %q, want %q", got, password)
	}
	if got := u.Host; got != "localhost:5432" {
		t.Errorf("host = %q, want %q", got, "localhost:5432")
	}
	if got := u.Path; got != "/my-db" {
		t.Errorf("path = %q, want %q", got, "/my-db")
	}
	if got := u.Query().Get("sslmode"); got != "disable" {
		t.Errorf("sslmode = %q, want %q", got, "disable")
	}
}

func TestBuildRDSIAMDSN(t *testing.T) {
	creds := credentials.NewStaticCredentialsProvider("AKIDEXAMPLE", "SECRETEXAMPLE", "")
	host := "mydb.abc123.us-east-1.rds.amazonaws.com"

	dsn, err := buildRDSIAMDSN(context.Background(), creds, "us-east-1", host, 5432, "postgres", "terraform", "require")
	if err != nil {
		t.Fatalf("error building dsn: %s", err)
	}

	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("error parsing dsn: %s", err)
	}
	if got := u.User.Username(); got != "terraform" {
		t.Errorf("username = %q, want %q", got, "terraform")
	}
	token, _ := u.User.Password()
	if !strings.HasPrefix(token, host+":5432?") {
		t.Errorf("token %q does not start with the RDS endpoint", token)
	}
	if !strings.Contains(token, "X-Amz-Signature=") {
		t.Errorf("token %q is not a signed auth token", token)
	}
	if !strings.Contains(token, "DBUser=terraform") {
		t.Errorf("token %q does not reference the database user", token)
	}
	if got := u.Query().Get("sslmode"); got != "require" {
		t.Errorf("sslmode = %q, want %q", got, "require")
	}
}
