"""
DORSAL ML Pipeline — Parser para Acunetix
==========================================
Formato: JSON da API REST do Acunetix

COMO EXPORTAR DO ACUNETIX:
  Opção A — API REST (recomendado):
    # Listar scans
    curl -H "X-Auth: <API_KEY>" https://acunetix.local/api/v1/scans

    # Listar vulnerabilidades de um scan
    curl -H "X-Auth: <API_KEY>" \
      "https://acunetix.local/api/v1/vulnerabilities?q=status:open;severity:2,3"

    # Detalhes de uma vulnerabilidade (inclui request HTTP)
    curl -H "X-Auth: <API_KEY>" \
      "https://acunetix.local/api/v1/vulnerabilities/{vuln_id}/http_response"

  Opção B — Export JSON do Dashboard:
    1. Scans > Selecionar scan > Export
    2. Formato: Developer (JSON)
    3. Salvar como: acunetix_export.json

  Opção C — Exportar e salvar o JSON da API programaticamente:
    python scripts/export_acunetix.py --api-key KEY --output acunetix_export.json

FORMATO JSON DO ACUNETIX:
  {
    "vulnerabilities": [{
      "vuln_id": "abc-123",
      "vt_id": "...",
      "vt_name": "SQL Injection",
      "severity": 3,            # 0=Info, 1=Low, 2=Medium, 3=High, 4=Critical
      "confidence": 100,
      "affects_url": "https://target.com/api/users",
      "affects_detail": "id parameter",
      "status": "open",
      "request": "GET /api/users?id=1%27+OR+1%3D1-- HTTP/1.1\\r\\nHost: ...",
      "response_info": { "status_code": 500 },
      "tags": ["sqli", "owasp-a03"],
      "loc_id": "...",
      "source": { "reason_id": "confirmed_vulnerability" }
    }]
  }

SAÍDA:
  Lista de dicts: payload, category, method, path, severity, source, label
"""

import re
from pathlib import Path
from urllib.parse import urlparse, unquote

from loguru import logger

try:
    import orjson as json
except ImportError:
    import json


# Mapeamento de vt_name do Acunetix → categorias Dorsal
ACUNETIX_CATEGORY_MAP = {
    "sql injection": "sqli",
    "blind sql injection": "sqli",
    "sql": "sqli",
    "cross-site scripting": "xss",
    "xss": "xss",
    "cross site scripting": "xss",
    "server-side request forgery": "ssrf",
    "ssrf": "ssrf",
    "path traversal": "path_traversal",
    "directory traversal": "path_traversal",
    "file inclusion": "path_traversal",
    "local file inclusion": "path_traversal",
    "remote file inclusion": "path_traversal",
    "command injection": "command_injection",
    "os command": "command_injection",
    "code execution": "command_injection",
    "xml external entity": "xxe",
    "xxe": "xxe",
    "server-side template injection": "ssti",
    "ssti": "ssti",
    "template injection": "ssti",
    "crlf injection": "crlf",
    "http response splitting": "crlf",
    "header injection": "crlf",
    "ldap injection": "ldap_injection",
    "open redirect": "open_redirect",
    "url redirection": "open_redirect",
    "cors": "cors",
    "jwt": "jwt_attack",
    "nosql": "nosql",
    "broken access": "bola",
    "idor": "bola",
    "insecure direct object": "bola",
    "graphql": "graphql",
    "parameter tampering": "parameter_pollution",
    "mass assignment": "mass_assignment",
}

ACUNETIX_SEVERITY_MAP = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}


def _classify_acunetix_vuln(vt_name: str, tags: list[str] = None) -> str:
    """Classifica vulnerabilidade do Acunetix em categoria Dorsal."""
    name_lower = vt_name.lower()
    for pattern, category in ACUNETIX_CATEGORY_MAP.items():
        if pattern in name_lower:
            return category

    # Fallback: tentar classificar por tags
    if tags:
        tag_str = " ".join(tags).lower()
        for pattern, category in ACUNETIX_CATEGORY_MAP.items():
            if pattern in tag_str:
                return category

    return "unknown"


def _parse_raw_request(raw_request: str) -> tuple[str, str, str]:
    """
    Parsea request HTTP bruto do Acunetix.
    
    Returns:
        (method, path, body)
    """
    if not raw_request:
        return ("GET", "/", "")

    lines = raw_request.replace("\\r\\n", "\r\n").split("\r\n")
    if not lines:
        return ("GET", "/", "")

    # Request line
    parts = lines[0].split(" ")
    method = parts[0] if parts else "GET"
    path = parts[1] if len(parts) > 1 else "/"

    # Body (após linha vazia)
    body = ""
    empty_line_idx = None
    for i, line in enumerate(lines):
        if line.strip() == "":
            empty_line_idx = i
            break
    if empty_line_idx is not None:
        body = "\r\n".join(lines[empty_line_idx + 1:])

    return (method, path, body)


def _extract_payload_from_url_and_body(path: str, body: str) -> str:
    """Extrai o payload mais relevante da request."""
    payloads = []

    # URL params
    if "?" in path:
        query = path.split("?", 1)[1]
        for param in query.split("&"):
            if "=" in param:
                value = unquote(param.split("=", 1)[1])
                if value:
                    payloads.append(value)

    # Body params
    if body:
        for param in body.split("&"):
            if "=" in param:
                value = unquote(param.split("=", 1)[1])
                if value:
                    payloads.append(value)
        # JSON values
        if body.strip().startswith("{"):
            json_values = re.findall(r'"[^"]*"\s*:\s*"([^"]*)"', body)
            payloads.extend(json_values)

    if not payloads and body:
        payloads.append(body)

    return max(payloads, key=len) if payloads else path


def parse_acunetix_json(filepath: str | Path) -> list[dict]:
    """
    Parsea JSON exportado do Acunetix (API ou export).
    
    Args:
        filepath: Caminho para o JSON do Acunetix
    
    Returns:
        Lista de dicts com: payload, category, method, path, severity,
        confidence, source, label
    """
    filepath = Path(filepath)
    if not filepath.exists():
        logger.warning(f"⚠️  Arquivo Acunetix não encontrado: {filepath}")
        return []

    logger.info(f"📂 Parseando Acunetix JSON: {filepath}")

    with open(filepath, "rb") as f:
        data = json.loads(f.read())

    # Suporta tanto {"vulnerabilities": [...]} quanto array direto
    vulns = data.get("vulnerabilities", data if isinstance(data, list) else [])
    results = []

    for vuln in vulns:
        vt_name = vuln.get("vt_name", vuln.get("name", ""))
        tags = vuln.get("tags", [])
        category = _classify_acunetix_vuln(vt_name, tags)

        severity_code = vuln.get("severity", 0)
        severity = ACUNETIX_SEVERITY_MAP.get(severity_code, "info")

        # Ignorar info sem relevância
        if severity == "info" and category == "unknown":
            continue

        # Extrair payload da request
        raw_request = vuln.get("request", "")
        method, path, body = _parse_raw_request(raw_request)

        # Fallback: usar affects_url
        if path == "/" and vuln.get("affects_url"):
            try:
                parsed = urlparse(vuln["affects_url"])
                path = parsed.path or "/"
                if parsed.query:
                    path += f"?{parsed.query}"
            except Exception:
                pass

        payload = _extract_payload_from_url_and_body(path, body)

        # Se affects_detail menciona o parâmetro, enriquecer
        affects_detail = vuln.get("affects_detail", "")

        results.append({
            "payload": payload,
            "category": category,
            "method": method,
            "path": path,
            "severity": severity,
            "confidence": vuln.get("confidence", 0),
            "affects_detail": affects_detail,
            "vt_name": vt_name,
            "source": "Acunetix",
            "source_file": str(filepath.name),
            "label": 1,
        })

    logger.info(f"✅ Acunetix: {len(results)} vulnerabilidades extraídas")
    return results
