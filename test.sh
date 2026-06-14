#!/bin/bash

# Exit on error
set -e

# 1. Locate the Go binary dynamically
GO_BIN=$(which go)

if [ -z "$GO_BIN" ]; then
    echo "Error: 'go' not found in PATH."
    exit 1
fi

echo "--- Preparing Tests ---"
# We run generate as the current user (doesn't need sudo)
$GO_BIN generate ./...

echo "--- Running eBPF Unit Tests (using $GO_BIN) ---"
# We call sudo and provide the full path to the go binary.
# We also use 'env' to ensure the test can find the local modules.
sudo $GO_BIN test -v main_test.go main.go bpf_bpfel.go