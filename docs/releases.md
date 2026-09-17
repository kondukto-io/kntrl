# Release integrity

Tag pushes run the reusable CI workflow against the release commit. A failing
test or vulnerability scan prevents the build and publish jobs from running.

The build job has only `contents: read`, does not persist checkout credentials,
does not restore a Go build cache, and uses a fixed GoReleaser version. Build
hooks download and verify the committed module graph; compilation uses
`-mod=readonly` and `-trimpath`. Docker base images and downloaded OPA test
binaries are pinned to digests. Dependabot proposes dependency and Action updates.

The separate publishing job receives only the two release binaries and their
checksum file. It does not check out or execute project code. GitHub supplies
short-lived permissions for artifact attestations and release publication; the
workflow no longer uses `GO_RELEASER_GITHUB_TOKEN`, `DOCKERHUB_USERNAME` or
`DOCKERHUB_TOKEN`. Revocation of previously provisioned credentials is a separate
repository administration operation.

After downloading a release binary, verify its provenance before execution:

```sh
gh attestation verify ./kntrl.amd64 --repo kondukto-io/kntrl
```

Also verify the downloaded files against `checksums.txt`. Attestation records
artifact identity and workflow provenance, not an assurance that the software
has no vulnerabilities. This workflow does not yet generate an SBOM or provide
an isolated SLSA level-3 builder. The external GitLab CI include still follows
`main`; pinning it requires selecting an approved commit in that private project.

The release configuration can be checked with GoReleaser 2.18.1 using
`goreleaser check`. `goreleaser release --snapshot --clean` exercises the build
without publishing a release. Workflow syntax is checked by actionlint in CI.
