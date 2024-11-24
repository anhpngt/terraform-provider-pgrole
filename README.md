# Terraform Provider for PostgreSQL role configuration

This provider allows to manage settings and configurations of existing roles (created by some other mechanisms) in [PostgreSQL](https://www.postgresql.org/).

This aims at using Google's [Cloud SQL for PostgreSQL](https://cloud.google.com/sql/docs/postgres), where [google_sql_user](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_user) is used to create roles in PostgreSQL but further configurations for those roles are not supported innately.

## Quick Starts

* [Provider Documentation](https://registry.terraform.io/providers/anhpngt/pgrole/latest/docs)

## Requirements

- [Terraform](https://developer.hashicorp.com/terraform/downloads) >= 1.0
- [Go](https://golang.org/doc/install) >= 1.22

## Building The Provider

Clone the repository and run:

```shell
$ make install
```

## Developing the Provider

If you wish to work on the provider, you'll first need [Go](http://www.golang.org) installed on your machine (see [Requirements](#requirements) above).

To compile the provider, run `make install`. This will build the provider and put the provider binary in the `$GOPATH/bin` directory.

To generate or update documentation, run `make generate`.

Testing are still under development for now.

<!-- In order to run the full suite of Acceptance tests, run `make testacc`.

*Note:* Acceptance tests create real resources, and often cost money to run.

```shell
make testacc
``` -->
