# Contributing

## Development Setup

```bash
make env
```

Or use a local Go toolchain (`go >= 1.25`).

## Build and Test

```bash
make fmt
make vet
make test
make build
make e2e
make verify
make pipeline
```

The build output binary is `build/bell`.

## Pull Request Expectations

- Keep changes focused and small.
- Add or update tests for behavior changes.
- Keep `make fmt vet test` passing.
- Update `README.md` if flags, defaults, or behavior changed.
