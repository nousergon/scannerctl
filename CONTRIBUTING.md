# Contributing

Changes use red-first tests. Run pytest, ruff, and the contract/schema tests
locally before opening a pull request. Keep provider-specific behavior behind
an adapter and keep deployment topology, private routes, credentials, tuned
rules, prompts, and target identities out of this public repository.

Release workflows and third-party Actions must be pinned to immutable commit
SHAs. New runtime dependencies require provenance and SBOM coverage.
