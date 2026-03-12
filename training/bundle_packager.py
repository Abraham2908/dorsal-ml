"""Model bundle tooling: sign + encrypt ONNX artifacts for gateway runtime."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from loguru import logger


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _canonical_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _derive_kek(kek_material: str) -> bytes:
    return hashlib.sha256(kek_material.encode("utf-8")).digest()


def generate_ed25519_keypair(private_key_path: str, public_key_path: str) -> tuple[Path, Path]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    private_path = Path(private_key_path)
    public_path = Path(public_key_path)
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_text(base64.b64encode(private_bytes).decode("ascii"), encoding="utf-8")
    public_path.write_text(base64.b64encode(public_bytes).decode("ascii"), encoding="utf-8")
    return private_path, public_path


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    raw = base64.b64decode(path.read_text(encoding="utf-8").strip())
    return Ed25519PrivateKey.from_private_bytes(raw)


def verify_manifest_signature(manifest: dict[str, Any], signature_b64: str, public_key_b64: str) -> bool:
    payload = _canonical_json(manifest)
    signature = base64.b64decode(signature_b64)
    public_raw = base64.b64decode(public_key_b64)
    public_key = Ed25519PublicKey.from_public_bytes(public_raw)
    try:
        public_key.verify(signature, payload)
        return True
    except Exception:
        return False


def package_model_bundle(
    *,
    model_path: str,
    feature_map_path: str,
    output_dir: str,
    private_key_path: str,
    kek_material: str,
    model_id: str,
    model_version: str,
    min_gateway_version: str,
    tenant_scope: str = "*",
    gateway_scope: str = "*",
    key_id: str = "dorsal-default-v1",
    calibration_path: str | None = None,
    policy_defaults_path: str | None = None,
    expires_at: str | None = None,
) -> Path:
    model_file = Path(model_path)
    feature_map_file = Path(feature_map_path)
    calibration_file = Path(calibration_path) if calibration_path else None
    policy_file = Path(policy_defaults_path) if policy_defaults_path else None

    if not model_file.exists():
        raise FileNotFoundError(f"Model not found: {model_file}")
    if not feature_map_file.exists():
        raise FileNotFoundError(f"Feature map not found: {feature_map_file}")
    if calibration_file and not calibration_file.exists():
        raise FileNotFoundError(f"Calibration not found: {calibration_file}")
    if policy_file and not policy_file.exists():
        raise FileNotFoundError(f"Policy defaults not found: {policy_file}")

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    model_enc_file = out / "model.enc"
    manifest_file = out / "manifest.json"
    signature_file = out / "signature.sig"
    bundle_meta = out / "bundle.meta.json"

    model_plain = model_file.read_bytes()
    dek = os.urandom(32)
    model_nonce = os.urandom(12)
    model_cipher = AESGCM(dek).encrypt(model_nonce, model_plain, model_id.encode("utf-8"))
    model_enc_blob = model_nonce + model_cipher
    model_enc_file.write_bytes(model_enc_blob)

    kek = _derive_kek(kek_material)
    wrap_nonce = os.urandom(12)
    wrapped_dek = AESGCM(kek).encrypt(wrap_nonce, dek, model_id.encode("utf-8"))
    wrapped_dek_blob = wrap_nonce + wrapped_dek

    feature_map_target = out / "feature_map.json"
    feature_map_target.write_bytes(feature_map_file.read_bytes())

    calibration_target = None
    if calibration_file:
        calibration_target = out / "calibration.json"
        calibration_target.write_bytes(calibration_file.read_bytes())

    policy_target = None
    if policy_file:
        policy_target = out / "policy_defaults.json"
        policy_target.write_bytes(policy_file.read_bytes())

    manifest: dict[str, Any] = {
        "bundle_version": "1.0.0",
        "created_at": _now_iso(),
        "model_id": model_id,
        "model_version": model_version,
        "min_gateway_version": min_gateway_version,
        "tenant_scope": tenant_scope,
        "gateway_scope": gateway_scope,
        "intended_runtime": "gateway_client_container",
        "key_id": key_id,
        "model_file": "model.enc",
        "feature_map_file": "feature_map.json",
        "calibration_file": "calibration.json" if calibration_target else None,
        "policy_defaults_file": "policy_defaults.json" if policy_target else None,
        "hash_alg": "sha256",
        "hash_model_plain": _sha256_bytes(model_plain),
        "hash_model_enc": _sha256_file(model_enc_file),
        "hash_feature_map": _sha256_file(feature_map_target),
        "hash_calibration": _sha256_file(calibration_target) if calibration_target else None,
        "hash_policy_defaults": _sha256_file(policy_target) if policy_target else None,
        "wrapped_dek_b64": base64.b64encode(wrapped_dek_blob).decode("ascii"),
        "data_encryption": {
            "cipher": "AES-256-GCM",
            "aad": model_id,
        },
        "expires_at": expires_at,
    }

    private_key = _load_private_key(Path(private_key_path))
    manifest_payload = _canonical_json(manifest)
    signature = private_key.sign(manifest_payload)
    signature_b64 = base64.b64encode(signature).decode("ascii")

    with open(manifest_file, "w", encoding="utf-8") as file:
        json.dump(manifest, file, indent=2)
    signature_file.write_text(signature_b64, encoding="utf-8")

    bundle_summary = {
        "manifest": str(manifest_file),
        "signature": str(signature_file),
        "model_enc": str(model_enc_file),
        "hash_manifest": _sha256_file(manifest_file),
        "hash_signature": _sha256_file(signature_file),
    }
    with open(bundle_meta, "w", encoding="utf-8") as file:
        json.dump(bundle_summary, file, indent=2)

    logger.info(f"Bundle packaged at {out}")
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="DORSAL model bundle tooling")
    subparsers = parser.add_subparsers(dest="cmd", required=True)

    keygen = subparsers.add_parser("gen-keys", help="Generate Ed25519 key pair")
    keygen.add_argument("--private-key", required=True, help="Output path for base64 private key")
    keygen.add_argument("--public-key", required=True, help="Output path for base64 public key")

    pack = subparsers.add_parser("package", help="Package ONNX into encrypted signed bundle")
    pack.add_argument("--model", required=True, help="Path to ONNX model")
    pack.add_argument("--feature-map", required=True, help="Path to feature map JSON")
    pack.add_argument("--output-dir", required=True, help="Bundle output directory")
    pack.add_argument("--private-key", required=True, help="Base64 Ed25519 private key file path")
    pack.add_argument("--kek", help="Key-encryption material (string)")
    pack.add_argument("--kek-env", help="Env var containing KEK material")
    pack.add_argument("--model-id", required=True)
    pack.add_argument("--model-version", required=True)
    pack.add_argument("--min-gateway-version", default="0.1.0")
    pack.add_argument("--tenant-scope", default="*")
    pack.add_argument("--gateway-scope", default="*")
    pack.add_argument("--key-id", default="dorsal-default-v1")
    pack.add_argument("--calibration")
    pack.add_argument("--policy-defaults")
    pack.add_argument("--expires-at")

    args = parser.parse_args()
    if args.cmd == "gen-keys":
        priv, pub = generate_ed25519_keypair(args.private_key, args.public_key)
        logger.info(f"Private key: {priv}")
        logger.info(f"Public key: {pub}")
        return

    kek_material = args.kek
    if not kek_material and args.kek_env:
        kek_material = os.getenv(args.kek_env)
    if not kek_material:
        raise ValueError("Provide --kek or --kek-env.")

    package_model_bundle(
        model_path=args.model,
        feature_map_path=args.feature_map,
        output_dir=args.output_dir,
        private_key_path=args.private_key,
        kek_material=kek_material,
        model_id=args.model_id,
        model_version=args.model_version,
        min_gateway_version=args.min_gateway_version,
        tenant_scope=args.tenant_scope,
        gateway_scope=args.gateway_scope,
        key_id=args.key_id,
        calibration_path=args.calibration,
        policy_defaults_path=args.policy_defaults,
        expires_at=args.expires_at,
    )


if __name__ == "__main__":
    main()
