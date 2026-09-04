# Deployment Guide

Minimal steps to build or run XSGR. Requires [Go 1.24+](https://go.dev/dl/).

## Build an executable

```sh
# Linux / macOS binary
go build -o xsgr .

# Windows exe (cross-compile from any OS)
GOOS=windows GOARCH=amd64 go build -o xsgr.exe .
```

The result is a single self-contained executable — no runtime dependencies.

## Run from source

```sh
# Clone and enter the repo
git clone https://github.com/4ntyr/xessenger_cli.git
cd xessenger_cli

# Run without building
go run .
```

## Install to your PATH

```sh
go install github.com/4ntyr/xessenger_cli@latest
```

Installs the binary as `xessenger_cli` into `$GOBIN` (usually `~/go/bin`).
