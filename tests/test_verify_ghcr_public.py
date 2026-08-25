"""Unit tests for scripts/verify_ghcr_public.py.

Covers the positive case (a real v0.1.1 index shape, captured live 2026-08-25
via the anonymous flow against the now-public `ghcr.io/nousergon/scannerctl`)
and the NEGATIVE case: the exact 403 GHCR returns for a private package, with
no mocked credential able to make it pass. alpha-engine-config-I8384 requires
the negative case be demonstrated, not merely asserted possible.
"""

from __future__ import annotations

import json
import sys
import urllib.error
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import verify_ghcr_public as vgp

REAL_V011_INDEX = {
    "schemaVersion": 2,
    "mediaType": "application/vnd.oci.image.index.v1+json",
    "manifests": [
        {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": "sha256:3db1694867c7284438f975d146cf98fe8e5e79b318e12ade474e2df912e1a5c0",
            "size": 2005,
            "platform": {"architecture": "amd64", "os": "linux"},
        },
        {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": "sha256:da9115266b542e950433d152d3e25424ca535951d05dd9d93874d9c4e280048f",
            "size": 2005,
            "platform": {"architecture": "arm64", "os": "linux"},
        },
        {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": "sha256:edc05314e5546b1314a431b0e54878ca4999add6f576f7aac9c86121fbdd047d",
            "size": 1112,
            "annotations": {
                "vnd.docker.reference.digest": (
                    "sha256:3db1694867c7284438f975d146cf98fe8e5e79b318e12ade474e2df912e1a5c0"
                ),
                "vnd.docker.reference.type": "attestation-manifest",
            },
            "platform": {"architecture": "unknown", "os": "unknown"},
        },
        {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": "sha256:b4f23853461e58bab48aea5ef9aa718278b975ada8ec3333a7b8ffb956cb2bc7",
            "size": 1112,
            "annotations": {
                "vnd.docker.reference.digest": (
                    "sha256:da9115266b542e950433d152d3e25424ca535951d05dd9d93874d9c4e280048f"
                ),
                "vnd.docker.reference.type": "attestation-manifest",
            },
            "platform": {"architecture": "unknown", "os": "unknown"},
        },
    ],
}
REAL_V011_DIGEST = "sha256:faced8c965735b63d78fdf2158235446fd9c9caaf6485a42a4bf67ae8a9f1494"


def _http_response(status: int, headers: dict[str, str], body: bytes):
    response = mock.Mock()
    response.status = status
    response.headers = headers
    response.read.return_value = body
    response.__enter__ = mock.Mock(return_value=response)
    response.__exit__ = mock.Mock(return_value=False)
    return response


def test_anonymous_pull_token_presents_no_authorization_header():
    with mock.patch.object(vgp.urllib.request, "urlopen") as urlopen:
        urlopen.return_value = _http_response(200, {}, json.dumps({"token": "anon-tok"}).encode())
        token = vgp.anonymous_pull_token("nousergon/scannerctl")
    assert token == "anon-tok"
    sent_request = urlopen.call_args[0][0]
    assert "Authorization" not in sent_request.headers
    assert "authorization" not in sent_request.headers


def test_full_flow_passes_against_the_real_captured_v011_index():
    with mock.patch.object(vgp.urllib.request, "urlopen") as urlopen:
        urlopen.side_effect = [
            _http_response(200, {}, json.dumps({"token": "anon-tok"}).encode()),
            _http_response(
                200,
                {"docker-content-digest": REAL_V011_DIGEST},
                json.dumps(REAL_V011_INDEX).encode(),
            ),
        ]
        index = vgp.verify(
            "nousergon/scannerctl", "v0.1.1", expected_digest=REAL_V011_DIGEST
        )
    assert index == REAL_V011_INDEX


def test_negative_case_a_private_package_returns_403_and_verification_fails():
    """The exact behavior GHCR exhibits for a private package: token endpoint still
    hands out an anonymous-scope token (it always does), but the manifest fetch
    with that token is refused with 403. This is the case I8283/I8384 exists
    because the in-job check could never observe."""
    with mock.patch.object(vgp.urllib.request, "urlopen") as urlopen:
        urlopen.side_effect = [
            _http_response(200, {}, json.dumps({"token": "anon-tok"}).encode()),
            urllib.error.HTTPError(
                url="https://ghcr.io/v2/nousergon/scannerctl/manifests/v0.1.1",
                code=403,
                msg="Forbidden",
                hdrs={},
                fp=None,
            ),
        ]
        with pytest.raises(vgp.VerificationError, match="NOT pullable by an anonymous consumer"):
            vgp.verify("nousergon/scannerctl", "v0.1.1")


def test_negative_case_cli_reports_failure_and_exits_nonzero(capsys):
    with mock.patch.object(vgp.urllib.request, "urlopen") as urlopen:
        urlopen.side_effect = [
            _http_response(200, {}, json.dumps({"token": "anon-tok"}).encode()),
            urllib.error.HTTPError(
                url="https://ghcr.io/v2/nousergon/scannerctl/manifests/v0.1.1",
                code=403,
                msg="Forbidden",
                hdrs={},
                fp=None,
            ),
        ]
        exit_code = vgp.main(["--repo", "nousergon/scannerctl", "--ref", "v0.1.1"])
    assert exit_code == 1
    assert "FAIL" in capsys.readouterr().err


def test_bare_401_is_not_by_itself_treated_as_private():
    """GHCR returns 401 on every unauthenticated manifest request, public images
    included — asserting 401-means-private would be exactly the wrong signal.
    A 401 AFTER presenting the anonymous bearer token is a distinct, harder
    failure (the token itself was rejected) and must be reported as such,
    never silently reinterpreted as 403-style privacy."""
    with mock.patch.object(vgp.urllib.request, "urlopen") as urlopen:
        urlopen.side_effect = [
            _http_response(200, {}, json.dumps({"token": "anon-tok"}).encode()),
            urllib.error.HTTPError(
                url="https://ghcr.io/v2/nousergon/scannerctl/manifests/v0.1.1",
                code=401,
                msg="Unauthorized",
                hdrs={},
                fp=None,
            ),
        ]
        with pytest.raises(vgp.VerificationError, match="anonymous token was rejected outright"):
            vgp.verify("nousergon/scannerctl", "v0.1.1")


def test_token_endpoint_failure_is_reported():
    with mock.patch.object(vgp.urllib.request, "urlopen") as urlopen:
        urlopen.return_value = _http_response(500, {}, b"internal error")
        with pytest.raises(vgp.VerificationError, match="anonymous token request failed"):
            vgp.anonymous_pull_token("nousergon/scannerctl")


def test_index_missing_a_platform_fails():
    single_arch_index = {"manifests": [REAL_V011_INDEX["manifests"][0]]}
    with pytest.raises(vgp.VerificationError, match="missing platforms"):
        vgp.assert_public_multiarch_attested_index(single_arch_index, {})


def test_index_missing_an_attestation_manifest_fails():
    no_attestations_index = {"manifests": REAL_V011_INDEX["manifests"][:2]}
    with pytest.raises(vgp.VerificationError, match="attestation-manifest"):
        vgp.assert_public_multiarch_attested_index(no_attestations_index, {})


def test_tag_resolving_to_the_wrong_digest_fails():
    with pytest.raises(vgp.VerificationError, match="tag resolved to"):
        vgp.assert_public_multiarch_attested_index(
            REAL_V011_INDEX,
            {"docker-content-digest": "sha256:" + "0" * 64},
            expected_digest=REAL_V011_DIGEST,
        )


def test_manifest_response_header_lookup_is_case_insensitive():
    """GHCR's real header key is lowercase (`docker-content-digest`), but the
    HTTP spec makes header names case-insensitive — assert this holds
    regardless of how urllib happens to have capitalized it."""
    vgp.assert_public_multiarch_attested_index(
        REAL_V011_INDEX,
        {"Docker-Content-Digest": REAL_V011_DIGEST},
        expected_digest=REAL_V011_DIGEST,
    )
