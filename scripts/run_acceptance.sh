#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

set -ex

make dev

vault server \
	-log-level=debug \
	-dev \
	-dev-ha -dev-transactional -dev-root-token-id=root -dev-plugin-dir=$PWD/bin &
VAULT_PID=$!
sleep 2

function cleanup {
	echo ""
	echo "==> Cleaning up"
	kill -INT "$VAULT_PID"
	rm -rf "$SCRATCH"
}
trap cleanup EXIT

export VAULT_ACC=1
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=root

go test -v ./... -run TestAcceptance
