from __future__ import annotations

import importlib.util
import json

import pytest


if importlib.util.find_spec("cryptography") is None:
    pytestmark = pytest.mark.skip(reason="cryptography is not installed")


from training.bundle_packager import (  # noqa: E402
    generate_ed25519_keypair,
    package_model_bundle,
    verify_manifest_signature,
)


def test_package_bundle_signature_roundtrip(tmp_path) -> None:
    model = tmp_path / "model.onnx"
    feature_map = tmp_path / "feature_map.json"
    model.write_bytes(b"onnx-bytes")
    feature_map.write_text(json.dumps({"feature_order": ["a", "b"]}), encoding="utf-8")

    private_key = tmp_path / "private.key"
    public_key = tmp_path / "public.key"
    generate_ed25519_keypair(str(private_key), str(public_key))

    bundle_dir = tmp_path / "bundle"
    package_model_bundle(
        model_path=str(model),
        feature_map_path=str(feature_map),
        output_dir=str(bundle_dir),
        private_key_path=str(private_key),
        kek_material="test-kek",
        model_id="attack_v1",
        model_version="1.0.0",
        min_gateway_version="0.1.0",
    )

    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    signature = (bundle_dir / "signature.sig").read_text(encoding="utf-8").strip()
    public_key_b64 = public_key.read_text(encoding="utf-8").strip()

    assert verify_manifest_signature(manifest, signature, public_key_b64)
