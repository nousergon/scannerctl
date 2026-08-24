# Upstream provenance

Initial backend: gitleaks v8.30.1, MIT licensed.

- Source: https://github.com/gitleaks/gitleaks/tree/v8.30.1
- Release: https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1
- Authoritative checksum asset:
  gitleaks_8.30.1_checksums.txt from that release
- Local subset: gitleaks-v8.30.1-checksums.txt

The release workflow downloads only the four named archives, verifies the
committed checksum copied from the upstream release, probes gitleaks version,
and records both components in each bundle SBOM. Runtime code never downloads
the backend.
