# scannerctl

[![CI](https://github.com/nousergon/scannerctl/actions/workflows/ci.yml/badge.svg)](https://github.com/nousergon/scannerctl/actions/workflows/ci.yml)
[![coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fnousergon%2Fscannerctl%2Fbadges%2Fcoverage.json)](https://github.com/nousergon/scannerctl/actions/workflows/coverage-badge.yml)
[![CodeQL](https://github.com/nousergon/scannerctl/actions/workflows/codeql.yml/badge.svg)](https://github.com/nousergon/scannerctl/actions/workflows/codeql.yml)
[![License](https://img.shields.io/github/license/nousergon/scannerctl)](LICENSE)

scannerctl is a provider-neutral DLP scanning and egress-enforcement runtime. It
inspects an outbound request body before it leaves your infrastructure and
returns one of four exhaustive verdicts — `clean`, `block`, `error`, `disabled`
— over a versioned contract. It runs two ways from the same binary: as a CLI
that scans one payload, and as a forward proxy that scans every request it
relays. The scanning backend is replaceable; the initial one is gitleaks.

## Why it exists

Egress scanning tends to be re-implemented per consumer: a copied proxy script
here, an ad-hoc `gitleaks` install there, each drifting from the others and each
with its own idea of what happens when the scanner is missing, times out, or
returns something unexpected. That variation is the failure mode — the states
nobody implemented consistently are exactly the ones that let unscanned traffic
through.

scannerctl exists so there is one runtime with one contract, and so the answer
to "what happens when scanning cannot complete?" is the same everywhere:
**egress is denied**. `block`, `error`, `disabled`, malformed output, and any
unknown state all deny. A caller cannot accidentally treat "the scanner is
broken" as "the payload is fine".

## Security properties

- Four exhaustive verdicts: `clean`, `block`, `error`, `disabled`. Anything else
  is a schema error, and a schema error denies.
- Benign and must-detect canaries run before the proxy accepts any work. Wrong
  polarity in either direction means the runtime does not start.
- No runtime downloads. Release bundles and OCI images contain the pinned
  backend and baseline config; nothing is fetched while serving a request.
- Findings are redacted: a `block` result carries rule IDs, never secret text.
- Every release publishes checksums, Sigstore signatures, SLSA provenance, and
  an SPDX SBOM, for darwin/linux on amd64/arm64 plus a linux/amd64 +
  linux/arm64 OCI index.
- Metrics expose all four verdict counters, canary state, last-scan timestamps,
  and runtime/config identity. A zero last-scan timestamp means *no data*, and
  is never rendered as healthy.

## How to run it

Prerequisites: Python 3.11+, and a `gitleaks` binary plus a config — both are
included in a release bundle; from a source checkout, point at your own with
`--backend` / `--config` or `SCANNERCTL_GITLEAKS` / `SCANNERCTL_CONFIG`.

    scannerctl version --format json
    scannerctl self-test --format json
    scannerctl scan --input request.json --format json
    scannerctl serve --routes routes.json --listen 127.0.0.1:8990

`scan` exits `0` for clean, `10` for block, and `20` for every state that is not
a decision. `serve` refuses to bind unless both startup canaries pass, and
exposes `/healthz` and `/metrics`.

Applications should integrate through their declared scannerctl adapter rather
than invoking the backend directly. Fleet-specific routes, credentials, target
identities, configs, and deployment manifests do not belong in this repository.

## How to verify it

    python3 -m venv .venv
    .venv/bin/pip install -e '.[dev]'
    .venv/bin/pytest
    .venv/bin/ruff check .

A healthy run reports every test passing and `Required test coverage of 100.0%
reached`. Coverage is measured over the whole `src/scannerctl` tree — including
modules no test imports — and the suite fails below the floor rather than
printing a number. `tests/test_coverage_scope.py` fails if that scope is ever
narrowed.

Against a real backend, `scannerctl self-test --format json` is the end-to-end
check: it reports `"success": true` only when the benign canary is `clean` and
the must-detect canary is `block`.

## Where the rest is

- [`docs/contract.md`](docs/contract.md) — the command, result, and exit-code contract.
- [`schemas/`](schemas) — versioned JSON Schemas for scan results and route tables.
- [`examples/routes.example.json`](examples/routes.example.json) — a route table.
- [`provenance/UPSTREAM.md`](provenance/UPSTREAM.md) — backend version, checksums, licence.
- [`SECURITY.md`](SECURITY.md) — how to report a vulnerability, and the response window.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — how to propose a change and what review to expect.

Licensed under AGPL-3.0-only.
