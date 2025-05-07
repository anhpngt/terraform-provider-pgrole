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

Testing are still under development for now. However, you can compile this provider
and run it locally (probably against your own infrastructure) using [dev_overrides](https://developer.hashicorp.com/terraform/cli/config/config-file#development-overrides-for-provider-developers):

1. Build this provider (after updating it to your needs):

    ```sh
    go install ./
    ```

2. The above command should install `terraform-provider-pgrole` to your `$GOPATH/bin`. Check with:

    ```sh
    # cd to the bin directory
    $ cd $(go env GOPATH)/bin
    # run the plugin binary to ensure it built correctly
    $ ./terraform-provider-pgrole
    This binary is a plugin. These are not meant to be executed directly.
    Please execute the program that consumes these plugins, which will
    load any plugins automatically
    ```

3. Create a `.terraformrc` file in your HOME directory with the following content:

    ```
    provider_installation {
        dev_overrides {
            "anhpngt/pgrole" = "/home/USER/go/bin"
        }

        direct {}
    }
    ```

4. Now you can run terraform to use the locally-developed provider.

    ```sh
    cd your/terraform/repo
    terraform init
    terraform plan
    ```
