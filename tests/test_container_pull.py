"""Unit tests for scripts/pull_container_image.py."""
import io
import os
import tarfile
from unittest import mock
import pytest
import requests

from scripts.pull_container_image import (
    normalize_repository,
    get_auth_token,
    fetch_manifest,
    pull_image,
)
from engine.scanner import IndraMeshScanner


def test_normalize_repository_official():
    assert normalize_repository("alpine") == "library/alpine"
    assert normalize_repository("nginx") == "library/nginx"
    assert normalize_repository("  ubuntu ") == "library/ubuntu"


def test_normalize_repository_namespaced():
    assert normalize_repository("prom/prometheus") == "prom/prometheus"
    assert normalize_repository("bitnami/redis") == "bitnami/redis"
    assert normalize_repository("ghcr.io/org/repo") == "ghcr.io/org/repo"


def test_get_auth_token_success():
    with mock.patch("requests.get") as mock_get:
        mock_resp = mock.Mock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {"token": "test-jwt-token-123"}
        mock_get.return_value = mock_resp

        token = get_auth_token("library/alpine")
        assert token == "test-jwt-token-123"
        mock_get.assert_called_once()
        args, kwargs = mock_get.call_args
        assert "library/alpine:pull" in args[0]
        assert "timeout" in kwargs


def test_get_auth_token_failure():
    with mock.patch("requests.get") as mock_get:
        mock_resp = mock.Mock()
        mock_resp.raise_for_status.side_effect = requests.HTTPError("401 Unauthorized")
        mock_get.return_value = mock_resp

        with pytest.raises(RuntimeError, match="Authentication failed"):
            get_auth_token("library/alpine")


def test_fetch_manifest_single_arch():
    fake_manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "layers": [{"digest": "sha256:1111", "size": 100}],
    }
    with mock.patch("requests.get") as mock_get:
        mock_resp = mock.Mock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = fake_manifest
        mock_get.return_value = mock_resp

        manifest, ref = fetch_manifest("library/alpine", "latest", "token123")
        assert manifest == fake_manifest
        assert ref == "latest"


def test_fetch_manifest_multi_arch_list():
    index_manifest = {
        "manifests": [
            {
                "digest": "sha256:arm64_digest",
                "platform": {"architecture": "arm64", "os": "linux"},
            },
            {
                "digest": "sha256:amd64_digest",
                "platform": {"architecture": "amd64", "os": "linux"},
            },
        ]
    }
    amd64_child_manifest = {
        "schemaVersion": 2,
        "layers": [{"digest": "sha256:amd64_layer_1", "size": 200}],
    }

    with mock.patch("requests.get") as mock_get:
        resp1 = mock.Mock()
        resp1.raise_for_status.return_value = None
        resp1.json.return_value = index_manifest

        resp2 = mock.Mock()
        resp2.raise_for_status.return_value = None
        resp2.json.return_value = amd64_child_manifest

        mock_get.side_effect = [resp1, resp2]

        manifest, ref = fetch_manifest("library/alpine", "latest", "token123", arch="amd64")
        assert manifest == amd64_child_manifest
        assert ref == "sha256:amd64_digest"
        assert mock_get.call_count == 2


def test_pull_image_e2e_mocked(tmp_path):
    out_file = str(tmp_path / "mocked_alpine.tar")

    # Create dummy gzipped layer payload containing an app with RSA
    layer_bytes = io.BytesIO()
    import gzip
    with gzip.GzipFile(fileobj=layer_bytes, mode="wb") as gz:
        with tarfile.open(fileobj=gz, mode="w") as inner_tar:
            content = b"from cryptography.hazmat.primitives.asymmetric import rsa\nkey = rsa.generate_private_key(65537, 2048)\n"
            info = tarfile.TarInfo(name="app/crypto.py")
            info.size = len(content)
            inner_tar.addfile(info, io.BytesIO(content))
    raw_layer_gz = layer_bytes.getvalue()

    with mock.patch("scripts.pull_container_image.get_auth_token", return_value="dummy_token"):
        with mock.patch("scripts.pull_container_image.fetch_manifest") as mock_fetch:
            mock_fetch.return_value = (
                {
                    "schemaVersion": 2,
                    "layers": [{"digest": "sha256:layer1"}],
                },
                "latest",
            )
            with mock.patch("requests.get") as mock_get:
                resp = mock.Mock()
                resp.raise_for_status.return_value = None
                resp.iter_content.return_value = [raw_layer_gz]
                mock_get.return_value = resp

                result_path = pull_image("alpine", tag="latest", out_file=out_file)
                assert os.path.exists(result_path)
                assert result_path == out_file

    # Now verify that IndraMesh scanner can scan this container image tarball!
    scanner = IndraMeshScanner()
    findings = scanner.scan_directory(out_file)
    assert any(f.get("name") == "RSA" for f in findings)
