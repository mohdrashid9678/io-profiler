#!/bin/bash

# Exit on error
set -e

echo "--- Generating BPF Bindings ---"
go generate ./...

echo "--- Building Profiler Binary ---"
go build -o profiler

echo "--- Starting Profiler (Requires Sudo) ---"
sudo ./profiler --n 5