# Release integrity

Tag pushes run the reusable CI workflow against the release commit. Failing
tests, scanner errors, or vulnerabilities reachable from the code prevent the
build and publish jobs from running. Govulncheck scans the entire application
after generating the eBPF object. Module-level findings are reported as JSON
for review but do not block publication when the symbol scan passes.

The build job has only `contents: read`, does not persist checkout credentials,
does not restore a Go build cache, and uses a fixed GoReleaser version. Build
hooks download and verify the committed module graph; compilation uses
`-mod=readonly` and `-trimpath`. Docker base images and downloaded OPA test
binaries are pinned to digests. Dependabot proposes dependency and Action updates.

The separate publishing job receives only the two release binaries and their
checksum file. It checks that the manifest contains exactly those two files and
that both digests match before signing. It does not check out or execute project
code. GitHub supplies short-lived permissions for signing, artifact attestations
and release publication; the workflow no longer uses `GO_RELEASER_GITHUB_TOKEN`, `DOCKERHUB_USERNAME` or
`DOCKERHUB_TOKEN`. Revocation of previously provisioned credentials is a separate
repository administration operation.

## Keyless signatures

The publishing job uses Cosign v3.1.3, installed by a commit-pinned official
action. Cosign obtains a GitHub Actions OIDC token, creates an ephemeral signing
key and obtains a short-lived Fulcio certificate. No signing key or Cosign secret
needs to be stored in GitHub. Sigstore records the signature in its public
transparency log. Only the publishing job has `id-token: write`; the build job
cannot request a signing identity.

The signed object is `checksums.txt`. It binds both binary filenames and their
SHA256 digests. The release includes `checksums.txt.sigstore.json`, containing
the signature, certificate and transparency-log proof. The job verifies this
bundle against its exact workflow/tag identity before publication. A signing,
verification or checksum failure stops publication; there is no unsigned fallback.

The expected issuer is `https://token.actions.githubusercontent.com`, and the
certificate identity is:

```text
https://github.com/kondukto-io/kntrl/.github/workflows/release.yaml@refs/tags/<TAG>
```

Use the tag you intended to install when constructing this identity. Do not
take the expected identity from the downloaded bundle or use a broad identity
regular expression. The identity binds a tag name; protecting tags from deletion
or replacement remains a repository-administration requirement.

## Verify before running

Install Cosign v3.1.3 or a compatible newer version through its
[official installation instructions](https://docs.sigstore.dev/cosign/system_config/installation/).
On Linux, download all four assets into a new directory and run both checks:

```sh
set -eu
TAG=vX.Y.Z # Replace with the intended signed release tag.
mkdir "kntrl-$TAG"
cd "kntrl-$TAG"
gh release download "$TAG" --repo kondukto-io/kntrl \
  --pattern kntrl.amd64 --pattern kntrl_arm64.arm64 \
  --pattern checksums.txt --pattern checksums.txt.sigstore.json

cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/kondukto-io/kntrl/.github/workflows/release.yaml@refs/tags/$TAG" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
sha256sum --strict --check checksums.txt
```

Only run the binary for your architecture after both commands succeed. The
signature check authenticates the checksum file; the checksum check binds the
downloaded binaries to that file. Neither check alone replaces the other. Cosign
may need network access to obtain Sigstore's trusted verification material.
See Sigstore's [blob signing](https://docs.sigstore.dev/cosign/signing/signing_with_blobs/)
and [verification](https://docs.sigstore.dev/cosign/verifying/verify/) documentation.

This applies to new releases made with this workflow. Older releases have no
Cosign bundle and cannot pass this verification; do not silently accept them as
signed. GitHub Action and GitLab installers must adopt the verification flow
separately before signature enforcement becomes automatic for their users.

GitHub artifact attestations remain available as an additional provenance check:

```sh
gh attestation verify ./kntrl.amd64 --repo kondukto-io/kntrl
```

Attestation records artifact identity and workflow provenance, not an assurance that the software
has no vulnerabilities. This workflow does not yet generate an SBOM or provide
an isolated SLSA level-3 builder. The external GitLab CI include still follows
`main`; pinning it requires selecting an approved commit in that private project.

The release configuration can be checked with GoReleaser 2.18.1 using
`goreleaser check`. `goreleaser release --snapshot --clean` exercises the build
without publishing a release. Workflow syntax is checked by actionlint in CI.

`go test -race ./tests/release/...` exercises the workflow's actual manifest
validation commands, credential boundaries, and failure behavior. These tests
stub Cosign to check invocation and failure propagation; they do not obtain a
GitHub OIDC token or produce a live signature. End-to-end signing with this
repository's identity is checked by the sign-and-verify step on a release tag.
The signing commands stay inline so the privileged job need not check out or
execute build-supplied project scripts.
