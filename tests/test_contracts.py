from __future__ import annotations

from training.contracts import (
    canonical_payload_hash,
    make_split_key,
    normalize_payload,
    source_family,
)


def test_normalize_payload_collapses_whitespace() -> None:
    assert normalize_payload("  A   B\tC  ") == "a b c"


def test_canonical_payload_hash_is_stable() -> None:
    h1 = canonical_payload_hash("abc", method="post", path="/x")
    h2 = canonical_payload_hash("abc", method="POST", path="/x")
    assert h1 == h2
    assert len(h1) == 64


def test_source_family_mapping() -> None:
    assert source_family("synthetic_fintech") == "synthetic"
    assert source_family("BurpSuite") == "dast_burp"
    assert source_family("OWASP_ZAP") == "dast_zap"


def test_make_split_key_format() -> None:
    key = make_split_key("payload_repo", "campaign_a", "1234567890abcdef")
    assert key.startswith("payload_repo|campaign_a|")
