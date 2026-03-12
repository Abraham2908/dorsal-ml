"""
DORSAL ML Pipeline — Parser para Burp Suite Pro
=================================================
Formatos suportados:
  1. XML Export (Burp > Report > Export Issues as XML)
  2. JSON via Burp Enterprise REST API

COMO EXPORTAR DO BURP PRO:
  Opção A — Manual (Desktop):
    1. Abrir Burp Suite Pro
    2. Target > Site map > selecionar hosts
    3. Right-click > "Issues" > "Report selected issues"
    4. Formato: XML (inclui requests/responses)
    5. Salvar como: burp_export.xml

  Opção B — Burp Enterprise API:
    GET /api/{site_id}/scans/{scan_id}/issues
    Header: Authorization: Bearer <API_KEY>
    Response: JSON com array de issues

FORMATO XML DO BURP:
  <issues>
    <issue>
      <serialNumber>1234</serialNumber>
      <type>SQL Injection</type>
      <name>SQL injection</name>
      <severity>High</severity>
      <confidence>Certain</confidence>
      <host>https://target.com</host>
      <path>/api/users</path>
      <issueDetail>...</issueDetail>
      <requestresponse>
        <request method="POST" base64="true">UE9TVC...</request>
        <response base64="true">SFRUUC...</response>
      </requestresponse>
    </issue>
  </issues>

SAÍDA:
  Lista de dicts com: payload, category, method, path, source, label
"""

import base64
import re
from pathlib import Path
from typing import Optional
from xml.etree import ElementTree as ET

from loguru import logger

try:
    import orjson as json
except ImportError:
    import json


# Mapeamento de tipos de issue do Burp → categorias Dorsal
BURP_CATEGORY_MAP = {
    "sql injection": "sqli",
    "blind sql injection": "sqli",
    "os command injection": "command_injection",
    "cross-site scripting": "xss",
    "stored xss": "xss",
    "reflected xss": "xss",
    "dom-based xss": "xss",
    "server-side request forgery": "ssrf",
    "ssrf": "ssrf",
    "path traversal": "path_traversal",
    "file path traversal": "path_traversal",
    "file inclusion": "path_traversal",
    "xml external entity": "xxe",
    "xxe": "xxe",
    "server-side template injection": "ssti",
    "ldap injection": "ldap_injection",
    "http request smuggling": "request_smuggling",
    "open redirection": "open_redirect",
    "header injection": "crlf",
    "crlf injection": "crlf",
    "json injection": "nosql",
    "nosql injection": "nosql",
    "jwt": "jwt_attack",
    "broken access control": "bola",
    "idor": "bola",
    "mass assignment": "mass_assignment",
    "graphql": "graphql",
    "cors": "cors",
}


def _classify_burp_issue(issue_name: str, issue_type: str = "") -> str:
    """Classifica uma issue do Burp em categoria Dorsal."""
    combined = f"{issue_name} {issue_type}".lower()
    for pattern, category in BURP_CATEGORY_MAP.items():
        if pattern in combined:
            return category
    return "unknown"


def _decode_base64_request(raw: str) -> tuple[str, str, str, str]:
    """
    Decodifica request base64 do Burp e extrai componentes.
    
    Returns:
        (method, path, headers, body)
    """
    try:
        decoded = base64.b64decode(raw).decode("utf-8", errors="replace")
    except Exception:
        return ("GET", "/", "", "")

    lines = decoded.split("\r\n")
    if not lines:
        return ("GET", "/", "", "")

    # Primeira linha: "METHOD /path HTTP/1.1"
    request_line = lines[0]
    parts = request_line.split(" ")
    method = parts[0] if parts else "GET"
    path = parts[1] if len(parts) > 1 else "/"

    # Separar headers e body
    body_start = decoded.find("\r\n\r\n")
    headers = decoded[:body_start] if body_start > 0 else decoded
    body = decoded[body_start + 4:] if body_start > 0 else ""

    return (method, path, headers, body)


def _extract_payload_from_request(
    method: str, path: str, headers: str, body: str
) -> str:
    """
    Extrai o payload mais relevante de uma request.
    O payload é a parte que contém a injeção — pode estar na URL,
    nos parâmetros, ou no body.
    """
    payloads = []

    # Query string params
    if "?" in path:
        query = path.split("?", 1)[1]
        for param in query.split("&"):
            if "=" in param:
                value = param.split("=", 1)[1]
                if value:
                    payloads.append(value)

    # Body params (form-urlencoded)
    if body:
        for param in body.split("&"):
            if "=" in param:
                value = param.split("=", 1)[1]
                if value:
                    payloads.append(value)

        # JSON body — extrair valores
        if body.strip().startswith("{"):
            # Extrair valores de strings do JSON
            json_values = re.findall(r'"[^"]*"\s*:\s*"([^"]*)"', body)
            payloads.extend(json_values)

    # Se não encontrou payloads específicos, usar o body inteiro
    if not payloads and body:
        payloads.append(body)

    # Retornar o maior payload (mais provável de conter a injeção)
    return max(payloads, key=len) if payloads else path


def parse_burp_xml(filepath: str | Path) -> list[dict]:
    """
    Parsea XML exportado do Burp Suite Pro.
    
    Args:
        filepath: Caminho para o arquivo .xml exportado
    
    Returns:
        Lista de dicts com: payload, category, method, path, source,
        severity, confidence, host, label
    """
    filepath = Path(filepath)
    if not filepath.exists():
        logger.warning(f"⚠️  Arquivo Burp não encontrado: {filepath}")
        return []

    logger.info(f"📂 Parseando Burp XML: {filepath}")

    results = []

    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
    except ET.ParseError as e:
        logger.error(f"❌ Erro ao parsear XML do Burp: {e}")
        return []

    issues = root.findall(".//issue") or root.findall("issue")

    for issue in issues:
        issue_name = (issue.findtext("name") or "").strip()
        issue_type = (issue.findtext("type") or "").strip()
        severity = (issue.findtext("severity") or "Information").strip()
        confidence = (issue.findtext("confidence") or "Tentative").strip()
        host = (issue.findtext("host") or "").strip()
        issue_path = (issue.findtext("path") or "/").strip()

        category = _classify_burp_issue(issue_name, issue_type)

        # Ignorar issues informativas sem relevância para ML
        if severity.lower() == "information" and category == "unknown":
            continue

        # Extrair request/response
        reqresp = issue.find("requestresponse")
        method, req_path, headers, body = "GET", issue_path, "", ""

        if reqresp is not None:
            req_elem = reqresp.find("request")
            if req_elem is not None and req_elem.text:
                is_base64 = req_elem.get("base64", "false").lower() == "true"
                if is_base64:
                    method, req_path, headers, body = _decode_base64_request(req_elem.text)
                else:
                    method, req_path, headers, body = _decode_base64_request(
                        base64.b64encode(req_elem.text.encode()).decode()
                    )

        payload = _extract_payload_from_request(method, req_path, headers, body)

        results.append({
            "payload": payload,
            "category": category,
            "method": method,
            "path": req_path,
            "host": host,
            "severity": severity,
            "confidence": confidence,
            "source": "BurpSuite",
            "source_file": str(filepath.name),
            "label": 1,  # Tudo do Burp é finding = ataque
        })

    logger.info(f"✅ Burp: {len(results)} issues extraídas")
    return results


def parse_burp_json(filepath: str | Path) -> list[dict]:
    """
    Parsea JSON do Burp Enterprise API.
    
    Formato esperado:
    {
      "issues": [
        {
          "name": "SQL injection",
          "severity": "high",
          "confidence": "certain",
          "origin": "https://target.com",
          "path": "/api/users",
          "evidence": [{"request_response": {"request": [{"data": "..."}]}}]
        }
      ]
    }
    """
    filepath = Path(filepath)
    if not filepath.exists():
        logger.warning(f"⚠️  Arquivo Burp JSON não encontrado: {filepath}")
        return []

    logger.info(f"📂 Parseando Burp JSON: {filepath}")

    with open(filepath, "rb") as f:
        data = json.loads(f.read())

    issues = data.get("issues", data if isinstance(data, list) else [])
    results = []

    for issue in issues:
        name = issue.get("name", "")
        category = _classify_burp_issue(name, issue.get("type_index", ""))

        # Tentar extrair payload dos evidence
        payload = ""
        for ev in issue.get("evidence", []):
            rr = ev.get("request_response", {})
            req_data = rr.get("request", [{}])
            if isinstance(req_data, list) and req_data:
                payload = req_data[0].get("data", "")
            elif isinstance(req_data, dict):
                payload = req_data.get("data", "")

        if not payload:
            payload = issue.get("path", "/")

        results.append({
            "payload": payload,
            "category": category,
            "method": issue.get("http_method", "GET"),
            "path": issue.get("path", "/"),
            "host": issue.get("origin", ""),
            "severity": issue.get("severity", "info"),
            "confidence": issue.get("confidence", "tentative"),
            "source": "BurpEnterprise",
            "source_file": str(filepath.name),
            "label": 1,
        })

    logger.info(f"✅ Burp Enterprise: {len(results)} issues extraídas")
    return results
