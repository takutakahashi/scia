# Release process

`scia` uses Semantic Versioning.

1. Choose the next version using `MAJOR.MINOR.PATCH`.
2. Update `VERSION`.
3. Commit the version update.
4. Tag the commit with a `v` prefix, for example `v0.2.0`.
5. Push the branch and tag.

The `Release` GitHub Actions workflow runs GoReleaser and publishes:

- GitHub release archives and checksums.
- Multi-architecture container images at `ghcr.io/takutakahashi/scia:<version>`.
- `ghcr.io/takutakahashi/scia:latest`.

Use `make release-check` before tagging to verify the local `VERSION` format.
