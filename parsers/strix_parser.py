"""
DORSAL ML Pipeline — Parser para Strix (usestrix)
===================================================
Strix são AI agents autônomos de pentest.
https://github.com/usestrix/strix

FORMATO DE OUTPUT DO STRIX:
  strix_runs/<run-name>/
  ├── report.md                 # Relatório final markdown
  ├── report.json               # Relatório estruturado JSON
  ├── findings/                 # Findings individuais
  │   ├── finding-001.json
  │   ├── finding-002.json
  │   └── ...
  ├── evidence/                 # Evidências (screenshots, logs)
  │   ├── poc-001/
  │   └── ...
  ├── proxy/                    # Logs do HTTP proxy embutido
  │   └── requests.jsonl        # ← OURO: todas as requests HTTP
  └── logs/                     # Logs de execução dos agents

COMO USAR COM O DORSAL:
  1. Subir API vulnerável protegida pelo Dorsal
  2. Rodar Strix:
     strix --target http://dorsal-gateway:8080 --instruction "Test all OWASP API Top 10"
  3. Ou com repo (whitebox + blackbox):
     strix -t http://dorsal-gateway:8080 -t https://github.com/org/vuln-app
  4. Strix ataca, Dorsal loga, ambos geram dados pro treino

VANTAGEM DO STRIX:
  - Tem proxy HTTP embutido → requests.jsonl contém TUDO
  - Cobre mais categorias: IDOR, business logic, race conditions
  - Pode rodar em modo headless (CI/CD)
  - Python nativo → fácil de integrar
"""

import json
import re
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, unquote

from loguru import logger


STRIX_CATEGORY_MAP = {
    "sql injection": "sqli",
    "sql_injection": "sqli",
    "sqli": "sqli",
    "command injection": "command_injection",
    "command_injection": "command_injection",
    "os command": "command_injection",
    "cross-site scripting": "xss",
    "xss": "xss",
    "reflected xss": "xss",
    "stored xss": "xss",
    "dom xss": "xss",
    "server-side request forgery": "ssrf",
    "ssrf": "ssrf",
    "idor": "bola",
    "insecure direct object": "bola",
    "broken access control": "bola",
    "privilege escalation": "bola",
    "authentication bypass": "auth_bypass",
    "auth bypass": "auth_bypass",
    "broken authentication": "auth_bypass",
    "jwt": "jwt_attack",
    "race condition": "race_condition",
    "business logic": "business_logic",
    "mass assignment": "mass_assignment",
    "xxe": "xxe",
    "xml external entity": "xxe",
    "deserialization": "deserialization",
    "prototype pollution": "prototype_pollution",
    "path traversal": "path_traversal",
    "directory traversal": "path_traversal",
    "csrf": "csrf",
    "open redirect": "open_redirect",
    "misconfiguration": "misconfiguration",
}


def _classify_strix_finding(title: str, vuln_type: str = "", tags: list = None) -> str:
    """Classifica finding do Strix em categoria Dorsal."""
    combined = f"{title} {vuln_type} {' '.join(tags or [])}".lower()
    for pattern, category in STRIX_CATEGORY_MAP.items():
        if pattern in combined:
            return category
    return "unknown"


def _parse_proxy_requests(proxy_dir: Path) -> list[dict]:
    """
    Parsea o log do HTTP proxy embutido do Strix.
    Este é o dado mais rico — contém TODAS as requests HTTP
    que o Strix fez durante o pentest.
    
    Formato requests.jsonl (uma request por linha):
    {
      "timestamp": "2026-03-12T14:32:05Z",
      "method": "POST",
      "url": "http://target:8080/api/users/search",
      "headers": {"Content-Type": "application/json", ...},
      "body": "{\"q\": \"' OR 1=1--\"}",
      "response_status": 500,
      "response_size": 1234,
      "response_time_ms": 45
    }
    """
    results = []
    jsonl_files = list(proxy_dir.glob("*.jsonl")) + list(proxy_dir.glob("*.json"))

    for filepath in jsonl_files:
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            logger.warning(f"  ⚠️  Erro ao ler {filepath}: {e}")
            continue

        for line in content.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
            except json.JSONDecodeError:
                continue

            method = req.get("method", "GET").upper()
            url = req.get("url", req.get("path", "/"))
            body = req.get("body", req.get("data", ""))
            headers = req.get("headers", {})

            # Extrair path da URL
            try:
                parsed = urlparse(url)
                path = parsed.path or "/"
                if parsed.query:
                    path += f"?{parsed.query}"
            except Exception:
                path = url

            # Extrair payload mais relevante
            payload_parts = []
            if "?" in url:
                query = url.split("?", 1)[1]
                for param in query.split("&"):
                    if "=" in param:
                        val = unquote(param.split("=", 1)[1])
                        if val:
                            payload_parts.append(val)
            if body:
                if isinstance(body, dict):
                    body = json.dumps(body)
                payload_parts.append(str(body))

            payload = max(payload_parts, key=len) if payload_parts else path

            user_agent = ""
            content_type = ""
            if isinstance(headers, dict):
                user_agent = headers.get("User-Agent", headers.get("user-agent", ""))
                content_type = headers.get("Content-Type", headers.get("content-type", ""))

            results.append({
                "payload": str(payload)[:2000],
                "method": method,
                "path": path,
                "body": str(body)[:2000],
                "user_agent": user_agent,
                "content_type": content_type,
                "response_status": req.get("response_status", req.get("status_code", 200)),
                "response_size": req.get("response_size", 0),
                "response_time_ms": req.get("response_time_ms", 0),
                "timestamp": req.get("timestamp", ""),
                "source": "Strix_Proxy",
                "source_file": str(filepath.name),
                "label": 1,  # Tudo do proxy do Strix é tráfego de ataque
                "category": "unknown",  # Será refinado com os findings
            })

    return results


def _parse_findings(findings_dir: Path) -> list[dict]:
    """
    Parsea findings individuais do Strix.
    
    Cada finding-XXX.json contém:
    {
      "id": "finding-001",
      "title": "SQL Injection in User Search",
      "type": "sql_injection",
      "severity": "critical",
      "confidence": "confirmed",
      "url": "http://target/api/users/search",
      "method": "POST",
      "parameter": "q",
      "payload": "' OR 1=1--",
      "evidence": {...},
      "poc": {
        "steps": [...],
        "request": {...},
        "response": {...}
      },
      "remediation": "...",
      "tags": ["owasp-a03", "injection"]
    }
    """
    results = []

    json_files = list(findings_dir.glob("*.json"))
    for filepath in json_files:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                finding = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            continue

        # Se é uma lista de findings
        if isinstance(finding, list):
            findings_list = finding
        else:
            findings_list = [finding]

        for f in findings_list:
            title = f.get("title", f.get("name", ""))
            vuln_type = f.get("type", f.get("vulnerability_type", ""))
            tags = f.get("tags", [])
            category = _classify_strix_finding(title, vuln_type, tags)

            # Extrair payload
            payload = f.get("payload", "")
            if not payload:
                poc = f.get("poc", {})
                if isinstance(poc, dict):
                    poc_req = poc.get("request", {})
                    if isinstance(poc_req, dict):
                        payload = poc_req.get("body", poc_req.get("data", ""))
                    elif isinstance(poc_req, str):
                        payload = poc_req
                    if not payload:
                        payload = poc.get("command", poc.get("payload", ""))

            if not payload:
                payload = f.get("evidence", {}).get("payload", "") if isinstance(f.get("evidence"), dict) else ""

            if not payload:
                continue

            method = f.get("method", "GET").upper()
            url = f.get("url", f.get("endpoint", "/"))
            try:
                parsed_url = urlparse(url)
                path = parsed_url.path or "/"
            except Exception:
                path = url

            results.append({
                "payload": str(payload)[:2000],
                "category": category,
                "method": method,
                "path": path,
                "parameter": f.get("parameter", ""),
                "severity": f.get("severity", "medium").lower(),
                "confidence": f.get("confidence", ""),
                "title": title,
                "finding_id": f.get("id", ""),
                "tags": tags,
                "source": "Strix_Finding",
                "source_file": str(filepath.name),
                "label": 1,
                "validated": f.get("confidence", "").lower() in ("confirmed", "high"),
            })

    return results


def _parse_report_json(report_path: Path) -> list[dict]:
    """Parsea o report.json consolidado do Strix."""
    try:
        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return []

    findings = data.get("findings", data.get("vulnerabilities", []))
    if not isinstance(findings, list):
        return []

    results = []
    for f in findings:
        title = f.get("title", f.get("name", ""))
        category = _classify_strix_finding(
            title,
            f.get("type", ""),
            f.get("tags", [])
        )

        payload = f.get("payload", f.get("poc", ""))
        if isinstance(payload, dict):
            payload = payload.get("payload", payload.get("command", json.dumps(payload)))
        if not payload:
            continue

        results.append({
            "payload": str(payload)[:2000],
            "category": category,
            "method": f.get("method", "GET"),
            "path": f.get("url", f.get("endpoint", "/")),
            "severity": f.get("severity", "medium").lower(),
            "title": title,
            "source": "Strix_Report",
            "source_file": str(report_path.name),
            "label": 1,
        })

    return results


def parse_strix_run(run_dir: str | Path) -> list[dict]:
    """
    Parser principal: processa um run completo do Strix.
    
    Args:
        run_dir: Path para strix_runs/<run-name>/
    
    Returns:
        Lista de dicts prontos para o dataset de treino
    """
    run_dir = Path(run_dir)
    if not run_dir.exists():
        logger.warning(f"⚠️  Run Strix não encontrado: {run_dir}")
        return []

    logger.info(f"📂 Parseando run Strix: {run_dir.name}")

    all_records = []

    # 1. Proxy logs (mais rico — todas as requests HTTP)
    proxy_dir = run_dir / "proxy"
    if proxy_dir.exists():
        proxy_records = _parse_proxy_requests(proxy_dir)
        all_records.extend(proxy_records)
        logger.info(f"   Proxy: {len(proxy_records)} requests HTTP")

    # 2. Findings individuais (com labels de categoria)
    findings_dir = run_dir / "findings"
    if findings_dir.exists():
        finding_records = _parse_findings(findings_dir)
        all_records.extend(finding_records)
        logger.info(f"   Findings: {len(finding_records)} vulnerabilidades")

    # 3. Report JSON consolidado
    report_json = run_dir / "report.json"
    if report_json.exists():
        report_records = _parse_report_json(report_json)
        all_records.extend(report_records)
        logger.info(f"   Report: {len(report_records)} entries")

    # Deduplicar
    seen = set()
    unique = []
    for r in all_records:
        key = (r.get("payload", "")[:100], r.get("category", ""), r.get("method", ""))
        if key not in seen:
            seen.add(key)
            unique.append(r)

    logger.info(f"✅ Strix: {len(unique)} registros únicos (de {len(all_records)} total)")
    return unique


def parse_strix_all_runs(strix_runs_dir: str | Path) -> list[dict]:
    """Parsea TODOS os runs do Strix."""
    strix_runs_dir = Path(strix_runs_dir)
    all_records = []

    for run_dir in sorted(strix_runs_dir.iterdir()):
        if run_dir.is_dir():
            records = parse_strix_run(run_dir)
            all_records.extend(records)

    logger.info(f"✅ Strix total: {len(all_records)} registros")
    return all_records
