# Contributing to OJS Codec Server

Thank you for helping improve Open Job Spec.

## Development

Prerequisites are Go 1.24+ and Make. Clone the repository, create a focused
branch, and run:

```bash
make build
make test
make lint
```

Use standard Go formatting, add tests for behavior changes, and update
documentation when user-facing behavior changes. Security-sensitive changes
must include tests for failure behavior and compatibility.

By contributing, you agree that your contributions are licensed under the
Apache License 2.0.
