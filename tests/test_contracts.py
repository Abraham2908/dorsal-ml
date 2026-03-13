from __future__ import annotations

from training.contracts import (
    LabeledRequestSample,
    RawAttackEvent,
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


def test_raw_attack_event_defaults_for_new_fields() -> None:
    event = RawAttackEvent(
        event_id="evt_1",
        source="source_a",
        source_type="payload_repo",
        source_file="sample.txt",
        payload="' OR 1=1 --",
        method="GET",
        path="/api/test",
        body="",
        category="sqli",
        severity="high",
        evidence="evidence",
        validated=True,
        label=1,
        label_confidence=0.95,
        campaign_id="campaign_a",
        observed_at="2026-01-01T00:00:00+00:00",
    )
    payload = event.to_dict()
    assert payload["scenario_type"] == "unknown"
    assert payload["validation_tier"] == "bronze"
    assert payload["effect_outcome"] == "unknown"
    assert payload["is_replay"] is False


def test_labeled_request_sample_defaults_for_new_fields() -> None:
    sample = LabeledRequestSample(
        sample_id="sample_1",
        split_key="payload_repo|campaign_a|abcd",
        source_family="payload_repo",
        is_synthetic=False,
        canonical_payload_hash="abcd1234",
        label=1,
        label_confidence=0.99,
        category="sqli",
        campaign_id="campaign_a",
    )
    payload = sample.to_dict()
    assert payload["target_app"] == "unknown"
    assert payload["lab_run_id"] == "unknown"
    assert payload["is_replay"] is False
