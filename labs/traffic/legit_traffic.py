"""Stateful legitimate traffic simulator for Layer-1 lab."""

from __future__ import annotations

import json
import os
import random
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlencode

import requests


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(slots=True)
class Target:
    name: str
    base_url: str


class JsonlWriter:
    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, row: dict) -> None:
        with open(self.path, "a", encoding="utf-8") as file:
            file.write(json.dumps(row, ensure_ascii=True) + "\n")


def _safe_text(payload: object) -> str:
    if payload is None:
        return ""
    if isinstance(payload, str):
        return payload
    return json.dumps(payload, ensure_ascii=True)


def _request(
    *,
    session: requests.Session,
    target: Target,
    method: str,
    path: str,
    params: dict | None,
    body: dict | str | None,
    request_writer: JsonlWriter,
    hard_negative_writer: JsonlWriter,
) -> None:
    method_up = method.upper()
    query = urlencode(params or {}, doseq=True)
    url = f"{target.base_url}{path}"
    payload_text = _safe_text(body)
    started = time.time()
    status_code = 0

    try:
        if isinstance(body, dict):
            response = session.request(method_up, url, params=params, json=body, timeout=8)
        else:
            response = session.request(method_up, url, params=params, data=payload_text, timeout=8)
        status_code = int(response.status_code)
    except Exception:
        status_code = 0

    latency_ms = int((time.time() - started) * 1000)
    row = {
        "timestamp": now_iso(),
        "source": "lab_legit_sim",
        "target_app": target.name,
        "method": method_up,
        "path": path,
        "query_string": query,
        "body": payload_text,
        "status_code": status_code,
        "latency_ms": latency_ms,
        "scenario_type": "legit_background",
    }
    request_writer.write(row)

    if 200 <= status_code < 500:
        hard_negative_writer.write(
            {
                "payload": payload_text or f"{method_up} {path}?{query}",
                "method": method_up,
                "path": path,
                "body": payload_text,
                "source": "lab_legit_sim",
                "source_file": "legit_traffic.py",
                "category": "hard_negative",
                "severity": "info",
                "validated": True,
                "label_confidence": 0.99,
                "scenario_type": "hard_negative",
                "attack_family": "benign_hard_negative",
                "attack_technique": "benign_hard_negative",
                "validation_tier": "gold",
                "effect_outcome": "benign_confirmed",
                "is_replay": False,
            }
        )


def run_juice_flow(
    session: requests.Session,
    target: Target,
    request_writer: JsonlWriter,
    hard_negative_writer: JsonlWriter,
) -> None:
    _request(
        session=session,
        target=target,
        method="GET",
        path="/rest/products/search",
        params={"q": random.choice(["apple", "banana", "phone", "milk"])},
        body=None,
        request_writer=request_writer,
        hard_negative_writer=hard_negative_writer,
    )
    _request(
        session=session,
        target=target,
        method="GET",
        path="/api/Challenges/",
        params={"limit": 10},
        body=None,
        request_writer=request_writer,
        hard_negative_writer=hard_negative_writer,
    )
    _request(
        session=session,
        target=target,
        method="GET",
        path="/rest/products/1/reviews",
        params=None,
        body=None,
        request_writer=request_writer,
        hard_negative_writer=hard_negative_writer,
    )


def run_httpbin_flow(
    session: requests.Session,
    target: Target,
    request_writer: JsonlWriter,
    hard_negative_writer: JsonlWriter,
) -> None:
    user_sid = f"s-{uuid.uuid4().hex[:12]}"
    _request(
        session=session,
        target=target,
        method="GET",
        path=f"/cookies/set/session/{user_sid}",
        params=None,
        body=None,
        request_writer=request_writer,
        hard_negative_writer=hard_negative_writer,
    )
    _request(
        session=session,
        target=target,
        method="GET",
        path="/cookies",
        params=None,
        body=None,
        request_writer=request_writer,
        hard_negative_writer=hard_negative_writer,
    )
    _request(
        session=session,
        target=target,
        method="POST",
        path="/anything/cart",
        params=None,
        body={"item_id": random.randint(1, 100), "qty": random.randint(1, 3)},
        request_writer=request_writer,
        hard_negative_writer=hard_negative_writer,
    )


def run_petstore_flow(
    session: requests.Session,
    target: Target,
    request_writer: JsonlWriter,
    hard_negative_writer: JsonlWriter,
) -> None:
    pet_id = random.randint(1000, 9999)
    _request(
        session=session,
        target=target,
        method="GET",
        path="/api/v3/pet/findByStatus",
        params={"status": "available"},
        body=None,
        request_writer=request_writer,
        hard_negative_writer=hard_negative_writer,
    )
    _request(
        session=session,
        target=target,
        method="POST",
        path="/api/v3/pet",
        params=None,
        body={"id": pet_id, "name": f"pet-{pet_id}", "status": "available"},
        request_writer=request_writer,
        hard_negative_writer=hard_negative_writer,
    )
    _request(
        session=session,
        target=target,
        method="GET",
        path=f"/api/v3/pet/{pet_id}",
        params=None,
        body=None,
        request_writer=request_writer,
        hard_negative_writer=hard_negative_writer,
    )


def main() -> None:
    random.seed(42)

    duration_minutes = float(os.getenv("USER_SIM_DURATION_MINUTES", "45"))
    requests_per_second = float(os.getenv("USER_SIM_RPS", "3"))
    concurrency = max(1, int(os.getenv("USER_SIM_CONCURRENCY", "12")))

    request_log = os.getenv("REQUEST_LOG_PATH", "/lab-artifacts/gateway/legit_requests.jsonl")
    hard_negative_log = os.getenv(
        "HARD_NEGATIVE_PATH",
        "/lab-artifacts/hard_negatives/legit_hard_negatives.jsonl",
    )

    targets = {
        "juice": Target("juice_shop", os.getenv("GW_JUICE_URL", "http://gateway-juice:8080").rstrip("/")),
        "httpbin": Target("httpbin", os.getenv("GW_HTTPBIN_URL", "http://gateway-httpbin:8080").rstrip("/")),
        "petstore": Target("petstore", os.getenv("GW_PETSTORE_URL", "http://gateway-petstore:8080").rstrip("/")),
    }

    request_writer = JsonlWriter(request_log)
    hard_negative_writer = JsonlWriter(hard_negative_log)

    sessions = [requests.Session() for _ in range(concurrency)]
    flows = [
        ("juice", run_juice_flow),
        ("httpbin", run_httpbin_flow),
        ("petstore", run_petstore_flow),
    ]

    started = time.time()
    duration_seconds = int(duration_minutes * 60)
    sleep_base = 1.0 / max(requests_per_second, 0.2)

    print(
        f"[legit_traffic] start duration={duration_minutes}m rps={requests_per_second} "
        f"concurrency={concurrency} output={request_log}"
    )

    while int(time.time() - started) < duration_seconds:
        session = random.choice(sessions)
        target_name, flow = random.choice(flows)
        flow(
            session,
            targets[target_name],
            request_writer=request_writer,
            hard_negative_writer=hard_negative_writer,
        )
        time.sleep(max(0.01, sleep_base * random.uniform(0.4, 1.6)))

    print("[legit_traffic] done")


if __name__ == "__main__":
    main()
