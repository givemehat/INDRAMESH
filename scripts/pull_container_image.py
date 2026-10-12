#!/usr/bin/env python3
"""IndraMesh Container Image Pull Utility.

Pulls container images from Docker Hub or OCI registries without requiring the Docker daemon,
preserving layer archives and metadata for air-gapped cryptographic discovery.

Usage:
    python scripts/pull_container_image.py alpine --tag latest --out data/alpine_latest.tar
    python scripts/pull_container_image.py nginx --tag alpine --out data/nginx_alpine.tar
    python scripts/pull_container_image.py prom/prometheus --tag latest --out data/prometheus.tar
"""
import argparse
import json
import os
import tarfile
import tempfile
from typing import Tuple
import requests

REGISTRY_AUTH_URL = "https://auth.docker.io/token"
REGISTRY_BASE_URL = "https://registry-1.docker.io/v2"

MANIFEST_ACCEPT_HEADERS = (
    "application/vnd.docker.distribution.manifest.v2+json, "
    "application/vnd.docker.distribution.manifest.list.v2+json, "
    "application/vnd.oci.image.manifest.v1+json, "
    "application/vnd.oci.image.index.v1+json"
)


def normalize_repository(image_name: str) -> str:
    """Normalize image name to standard Docker Hub repository path.

    Official images without namespace (e.g., 'alpine', 'nginx') live under 'library/'.
    Third-party images (e.g., 'prom/prometheus', 'bitnami/redis') keep their namespace.
    """
    clean_name = image_name.strip()
    if "/" not in clean_name:
        return f"library/{clean_name}"
    return clean_name


def get_auth_token(repository: str, timeout: int = 30) -> str:
    """Acquire an anonymous bearer token for the given Docker Hub repository."""
    auth_url = f"{REGISTRY_AUTH_URL}?service=registry.docker.io&scope=repository:{repository}:pull"
    try:
        response = requests.get(auth_url, timeout=timeout)
        response.raise_for_status()
        data = response.json()
        token = data.get("token") or data.get("access_token")
        if not token:
            raise ValueError(f"No bearer token returned by auth service for repository '{repository}'")
        return token
    except requests.RequestException as exc:
        raise RuntimeError(f"Authentication failed for '{repository}': {exc}") from exc


def fetch_manifest(
    repository: str,
    reference: str,
    token: str,
    arch: str = "amd64",
    os_name: str = "linux",
    timeout: int = 30,
) -> Tuple[dict, str]:
    """Fetch image manifest, resolving multi-arch manifest lists / OCI indices if necessary.

    Returns:
        (manifest_dict, resolved_digest_or_tag)
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": MANIFEST_ACCEPT_HEADERS,
    }
    url = f"{REGISTRY_BASE_URL}/{repository}/manifests/{reference}"
    try:
        resp = requests.get(url, headers=headers, timeout=timeout)
        resp.raise_for_status()
        manifest = resp.json()
    except requests.RequestException as exc:
        raise RuntimeError(f"Failed to fetch manifest for '{repository}:{reference}': {exc}") from exc

    # Handle multi-architecture manifest list / OCI index
    if "manifests" in manifest:
        sub_manifests = manifest["manifests"]
        chosen_digest = None
        for sm in sub_manifests:
            platform = sm.get("platform", {})
            if platform.get("architecture") == arch and platform.get("os") == os_name:
                chosen_digest = sm.get("digest")
                break
        if not chosen_digest and sub_manifests:
            # Fallback to the first available manifest if exact arch not matched
            chosen_digest = sub_manifests[0].get("digest")

        if not chosen_digest:
            raise ValueError(f"No suitable platform manifest found for '{repository}:{reference}' ({os_name}/{arch})")

        # Fetch resolved child manifest
        sub_url = f"{REGISTRY_BASE_URL}/{repository}/manifests/{chosen_digest}"
        try:
            sub_resp = requests.get(sub_url, headers=headers, timeout=timeout)
            sub_resp.raise_for_status()
            return sub_resp.json(), chosen_digest
        except requests.RequestException as exc:
            raise RuntimeError(f"Failed to fetch platform child manifest '{chosen_digest}': {exc}") from exc

    return manifest, reference


def pull_image(
    image_name: str,
    tag: str = "latest",
    out_file: str = "image.tar",
    arch: str = "amd64",
    timeout: int = 60,
) -> str:
    """Pull container image layers from Docker Hub and package into an inspectable tar archive.

    Compatible with both standard container inspection and IndraMesh's layer-by-layer
    cryptographic scanner.
    """
    repo = normalize_repository(image_name)
    print(f"[*] Resolving container repository: {repo}:{tag} (arch={arch})...")

    token = get_auth_token(repo, timeout=min(timeout, 30))
    manifest, resolved_ref = fetch_manifest(repo, tag, token, arch=arch, timeout=min(timeout, 30))

    layers = manifest.get("layers")
    if not layers:
        raise ValueError(f"Malformed manifest: no 'layers' block present for {repo}:{tag}")

    print(f"[+] Found {len(layers)} image layer(s). Preparing archive...")

    # Determine destination path
    if os.path.isabs(out_file) or os.path.dirname(out_file):
        out_path = out_file
    else:
        out_path = os.path.join("data", out_file)

    dest_dir = os.path.dirname(out_path)
    if dest_dir:
        os.makedirs(dest_dir, exist_ok=True)

    # Use a secure temporary directory for staging layer downloads
    with tempfile.TemporaryDirectory(prefix="indramesh_pull_") as tmpdir:
        temp_tar_path = os.path.join(tmpdir, "output.tar")
        with tarfile.open(temp_tar_path, "w") as tar:
            # Write a minimal container manifest metadata entry
            manifest_meta = {
                "repository": repo,
                "tag": tag,
                "resolved_ref": resolved_ref,
                "layer_count": len(layers),
                "layers": [layer.get("digest") for layer in layers],
            }
            manifest_bytes = json.dumps(manifest_meta, indent=2).encode("utf-8")
            meta_info = tarfile.TarInfo(name="manifest.json")
            meta_info.size = len(manifest_bytes)
            import io
            tar.addfile(meta_info, io.BytesIO(manifest_bytes))

            # Stream and archive each layer blob
            for i, layer in enumerate(layers):
                digest = layer.get("digest", f"layer_{i}")
                print(f"    -> Downloading layer {i+1}/{len(layers)}: {digest[:24]}...")
                blob_url = f"{REGISTRY_BASE_URL}/{repo}/blobs/{digest}"
                headers = {"Authorization": f"Bearer {token}"}
                
                try:
                    resp = requests.get(blob_url, headers=headers, stream=True, timeout=timeout)
                    resp.raise_for_status()
                except requests.RequestException as exc:
                    raise RuntimeError(f"Failed to stream blob '{digest}': {exc}") from exc

                layer_local_file = os.path.join(tmpdir, f"layer_{i}.tar.gz")
                with open(layer_local_file, "wb") as f:
                    for chunk in resp.iter_content(chunk_size=65536):
                        if chunk:
                            f.write(chunk)

                # Add layer to tarball using canonical digest name
                tar.add(layer_local_file, arcname=f"{digest}.tar.gz")
                try:
                    os.remove(layer_local_file)
                except OSError:
                    pass

        # Atomic move to final destination
        if os.path.exists(out_path):
            os.remove(out_path)
        os.replace(temp_tar_path, out_path)

    print(f"[✓] Image successfully saved to: {out_path} ({os.path.getsize(out_path):,} bytes)")
    return out_path


def main():
    parser = argparse.ArgumentParser(
        description="IndraMesh Container Pull Utility -- Downloads container layers without Docker daemon"
    )
    parser.add_argument("image", nargs="?", default=None, help="Container image name (e.g., 'alpine', 'nginx', 'prom/prometheus')")
    parser.add_argument("--tag", default="latest", help="Container image tag (default: 'latest')")
    parser.add_argument("--out", default=None, help="Output tar file path (default: data/<image>_<tag>.tar)")
    parser.add_argument("--arch", default="amd64", help="Target architecture (default: 'amd64')")
    parser.add_argument("--samples", action="store_true", help="Download sample alpine and nginx verification images")

    args = parser.parse_args()

    if args.samples:
        pull_image("alpine", "latest", "alpine_latest.tar", arch=args.arch)
        pull_image("nginx", "alpine", "nginx_alpine.tar", arch=args.arch)
        return

    if not args.image:
        parser.print_help()
        print("\nExample:")
        print("    python scripts/pull_container_image.py alpine --tag latest --out data/alpine.tar")
        print("    python scripts/pull_container_image.py --samples\n")
        return

    clean_img_name = args.image.replace("/", "_")
    out_file = args.out or f"{clean_img_name}_{args.tag}.tar"
    pull_image(args.image, tag=args.tag, out_file=out_file, arch=args.arch)


if __name__ == "__main__":
    main()
