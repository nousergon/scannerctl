# Security policy

Report vulnerabilities privately through GitHub Security Advisories for this
repository. Do not open a public issue containing exploit details, credentials,
request bodies, or private scanning rules.

Supported releases are the current release and N-1 as named in each signed
release manifest. Security fixes are released for both when practical; a
manifest can explicitly retire N-1 when continued support would be unsafe.

Release signatures and provenance are verified against:

- repository: nousergon/scannerctl
- workflow: .github/workflows/release.yml
- GitHub Actions OIDC identity

Runtime fail-closed behavior is part of the public API. Changes that can turn
error, disabled, timeout, missing config/backend, or malformed output into
clean are security-breaking changes.
