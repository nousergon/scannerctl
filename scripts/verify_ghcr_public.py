#!/usr/bin/env python3
"""Verify a GHCR OCI index is pullable by an UNPRIVILEGED, uncredentialed consumer.

Origin: alpha-engine-config-I8283 / I8384. The release workflow's own
`oci` job ran `docker buildx imagetools inspect` with `packages: write` and
a fresh `docker login` in scope. That confirmed the index had been PUSHED —
it structurally cannot confirm a consumer who never authenticated can PULL
it. `v0.1.0` and `v0.1.1` both pushed and signed successfully while every
unauthenticated consumer got 403; the in-job check was green both times.

This script speaks raw HTTP to the GHCR anonymous token endpoint and the
registry's manifest endpoint directly. It never touches Docker, `cosign`, a
credential helper, `~/.docker/config.json`, `DOCKER_CONFIG`, or any
`GITHUB_TOKEN`/registry-password environment variable, so it cannot inherit
an ambient credential by accident the way a Docker-CLI-based check can — the
only network identity this process has is whatever the GHCR token endpoint
hands back to a request carrying no Authorization header at all.

GHCR returns 401 on ANY unauthenticated manifest request, public images
included (it always wants a bearer token, even an anonymous-scope one) — so
a bare 401 is not evidence the package is private. The two-step flow below
is the actual, minimum sufficient anonymous-consumer path:

  1. GET https://ghcr.io/token?service=ghcr.io&scope=repository:<repo>:pull
     -> 200, {"token": "..."}                     (no credential presented)
  2. GET https://ghcr.io/v2/<repo>/manifests/<ref>
     Authorization: Bearer <token from step 1>
     -> 200 with the OCI index

A private package fails at step 2 with 403 even though step 1 still returns
a token (GHCR hands out anonymous-scope tokens unconditionally; the token
only proves you asked for pull scope, not that you have it).
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request

GHCR_HOST = "ghcr.io"
TOKEN_URL = f"https://{GHCR_HOST}/token"
MANIFEST_ACCEPT = (
    "application/vnd.oci.image.index.v1+json,"
    "application/vnd.docker.distribution.manifest.list.v2+json"
)
REQUIRED_PLATFORMS = {("linux", "amd64"), ("linux", "arm64")}


class VerificationError(RuntimeError):
    """The index does not satisfy the public, multi-arch, attested contract."""


def _get(url: str, headers: dict[str, str]) -> tuple[int, dict[str, str], bytes]:
    """GET url with exactly the given headers — no ambient credential is ever added."""
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers or {}), exc.read()


def anonymous_pull_token(repo: str) -> str:
    """Step 1: obtain an anonymous, pull-scoped bearer token. Presents no credential."""
    url = f"{TOKEN_URL}?service={GHCR_HOST}&scope=repository:{repo}:pull"
    status, _headers, body = _get(url, headers={})
    if status != 200:
        raise VerificationError(
            f"anonymous token request failed: HTTP {status} for {url}\n{body[:500]!r}"
        )
    try:
        token = json.loads(body)["token"]
    except (json.JSONDecodeError, KeyError) as exc:
        raise VerificationError(f"token response had no 'token' field: {body[:500]!r}") from exc
    if not token:
        raise VerificationError("token endpoint returned an empty token")
    return token


def fetch_manifest_anonymously(repo: str, ref: str, token: str) -> tuple[dict, dict[str, str]]:
    """Step 2: fetch the tag/digest manifest using ONLY the anonymous token from step 1."""
    url = f"https://{GHCR_HOST}/v2/{repo}/manifests/{ref}"
    status, headers, body = _get(
        url, headers={"Authorization": f"Bearer {token}", "Accept": MANIFEST_ACCEPT}
    )
    if status == 401:
        raise VerificationError(
            f"unexpected 401 fetching {url} — the anonymous token was rejected outright"
        )
    if status == 403:
        raise VerificationError(
            f"{repo}:{ref} is NOT pullable by an anonymous consumer (HTTP 403) — "
            "the package is private or the anonymous pull scope was denied"
        )
    if status != 200:
        raise VerificationError(f"unexpected HTTP {status} fetching {url}\n{body[:500]!r}")
    try:
        index = json.loads(body)
    except json.JSONDecodeError as exc:
        raise VerificationError(f"manifest response was not valid JSON: {body[:500]!r}") from exc
    return index, headers


def assert_public_multiarch_attested_index(
    index: dict, response_headers: dict[str, str], expected_digest: str | None = None
) -> None:
    """Assert the fetched index carries both required platforms and their attestations."""
    manifests = index.get("manifests")
    if not isinstance(manifests, list) or not manifests:
        raise VerificationError(f"index carries no manifests entry: {index!r}")

    platforms = {
        (m["platform"]["os"], m["platform"]["architecture"])
        for m in manifests
        if m.get("platform", {}).get("architecture") not in (None, "unknown")
    }
    missing = REQUIRED_PLATFORMS - platforms
    if missing:
        raise VerificationError(f"index is missing platforms {missing}; carries {platforms}")

    platform_digests = {
        m["digest"]
        for m in manifests
        if m.get("platform", {}).get("architecture") not in (None, "unknown")
    }
    attestation_refs = {
        m["annotations"]["vnd.docker.reference.digest"]
        for m in manifests
        if m.get("annotations", {}).get("vnd.docker.reference.type") == "attestation-manifest"
    }
    missing_attestations = platform_digests - attestation_refs
    if missing_attestations:
        raise VerificationError(
            f"platform manifest(s) {missing_attestations} have no attestation-manifest entry"
        )

    if expected_digest is not None:
        # docker-content-digest header names are case-insensitive per RFC 7230.
        resolved = next(
            (v for k, v in response_headers.items() if k.lower() == "docker-content-digest"), None
        )
        if resolved != expected_digest:
            raise VerificationError(
                f"tag resolved to {resolved!r}, expected the digest just signed "
                f"{expected_digest!r} — a consumer pinning the tag would run an "
                "artifact the release workflow never attested"
            )


def verify(repo: str, ref: str, expected_digest: str | None = None) -> dict:
    """Run the full anonymous verification. Returns the index on success."""
    token = anonymous_pull_token(repo)
    index, headers = fetch_manifest_anonymously(repo, ref, token)
    assert_public_multiarch_attested_index(index, headers, expected_digest)
    return index


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="e.g. nousergon/scannerctl")
    parser.add_argument("--ref", required=True, help="tag or digest to verify")
    parser.add_argument(
        "--expected-digest",
        default=None,
        help="if given, assert the tag resolves to exactly this digest",
    )
    args = parser.parse_args(argv)

    try:
        index = verify(args.repo, args.ref, args.expected_digest)
    except VerificationError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    platforms = sorted(
        f"{m['platform']['os']}/{m['platform']['architecture']}"
        for m in index["manifests"]
        if m.get("platform", {}).get("architecture") not in (None, "unknown")
    )
    print(f"OK: {args.repo}:{args.ref} is anonymously pullable, carries {platforms}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
