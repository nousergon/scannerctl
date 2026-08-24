# scannerctl

scannerctl is a provider-neutral DLP scanning and egress-enforcement runtime.
It gives applications one stable contract while keeping the scanning backend
replaceable. The initial backend is gitleaks.

## Security properties

- Four exhaustive results: clean, block, error, disabled.
- block, error, disabled, malformed, and unknown results deny egress.
- Benign and must-detect canaries run before the proxy accepts work.
- No runtime downloads. Release bundles and OCI images contain the pinned
  backend and baseline config.
- Every release publishes checksums, Sigstore signatures, SLSA provenance,
  and an SPDX SBOM.
- Multi-platform bundles: Darwin/Linux on amd64/arm64; OCI on
  linux/amd64 and linux/arm64.
- Metrics expose all verdicts, canary state, last-scan timestamps, and
  runtime/config identity. A zero last-scan timestamp means no data.

## Commands

    scannerctl scan --input request.json --format json
    scannerctl self-test --format json
    scannerctl serve --routes routes.json --listen 127.0.0.1:8990
    scannerctl version --format json

Applications should integrate through their declared scannerctl adapter rather
than invoking the backend directly. Fleet-specific routes, credentials, target
identities, configs, and deployment manifests do not belong in this repository.

See docs/contract.md, examples/routes.example.json, and SECURITY.md.

## Development

    python3 -m venv .venv
    .venv/bin/pip install -e '.[dev]'
    .venv/bin/pytest
    .venv/bin/ruff check .

Licensed under AGPL-3.0-only.
