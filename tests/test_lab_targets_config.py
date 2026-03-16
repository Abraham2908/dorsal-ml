from __future__ import annotations

import importlib.util
import json
import sys


def _load_module(path: str, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Failed to load module from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def test_attack_targets_json_overrides_defaults(monkeypatch) -> None:
    module = _load_module("labs/traffic/ai_redteam_agent.py", "ai_redteam_agent_test")
    payload = [
        {"name": "vampi", "base_url": "http://gateway-vampi:8080", "paths": ["/users/v1", "/books/v1"]},
        {"name": "hasura", "base_url": "http://gateway-hasura:8080", "paths": ["/v1/graphql"]},
    ]
    monkeypatch.setenv("ATTACK_TARGETS_JSON", json.dumps(payload))
    targets = module.load_attack_targets()
    assert len(targets) == 2
    assert targets[0].name == "vampi"
    assert "/users/v1" in targets[0].paths


def test_legit_targets_json_overrides_defaults(monkeypatch) -> None:
    module = _load_module("labs/traffic/legit_traffic.py", "legit_traffic_test")
    payload = [
        {"name": "juice_shop", "base_url": "http://gateway-juice:8080", "flow": "juice"},
        {"name": "hasura", "base_url": "http://gateway-hasura:8080", "flow": "hasura"},
    ]
    monkeypatch.setenv("LEGIT_TARGETS_JSON", json.dumps(payload))
    targets = module.load_legit_targets()
    assert set(targets.keys()) == {"juice_shop", "hasura"}
    assert targets["hasura"].flow == "hasura"
    assert targets["juice_shop"].base_url == "http://gateway-juice:8080"
