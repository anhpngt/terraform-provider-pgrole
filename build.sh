#!/bin/bash

set -euo pipefail

BINARY=terraform-provider-pgrole
LOCAL_PLUGIN_REGISTRY=$HOME/.terraform.d/plugins/registry.terraform.io/local/pgrole/1.0.0/linux_amd64

rm -rf $HOME/.terraform.d/plugins/registry.terraform.io/
mkdir -p $LOCAL_PLUGIN_REGISTRY
go build -o $LOCAL_PLUGIN_REGISTRY/$BINARY