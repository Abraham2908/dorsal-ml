"""
DORSAL ML Pipeline — Parser para OWASP ZAP
============================================
Formatos suportados:
  1. JSON Report (Report > Generate JSON Report)
  2. JSON da API REST do ZAP: GET /JSON/core/view/alerts/

COMO EXPORTAR DO ZAP:
  Opção A — GUI:
    1. Report > Generate Report
    2. Template: "Traditional JSON Report" ou "Modern JSON Report"
    3. Salvar como: zap_report.json

  Opção B — API (ZAP rodando em daemon mode):
    curl http://localhost:8080/JSON/core/view/alerts/?baseurl=https://target.com
    # Retorna: {"alerts": [...]}

  Opção C — CLI (automação):
    zap-cli report -o zap_report.json -f json

FORMATO JSON DO ZAP (Traditional):
  {
    "site": [{
      "alerts": [{
        "pluginid": "40018",
        "alertRef": "40018",
        "alert": "SQL Injection",
        "name": "SQL Injection",
        "riskcode": "3",        # 0=Info, 1=Low, 2=Medium, 3=High
        "confidence": "2",      # 1=Low, 2=Medium, 3=High
        "riskdesc": "High (Medium)",
        "desc": "...",
        "instances": [{
          "uri": "https://target.com/api/users?id=1",
          "method": "GET",
          "param": "id",
          "attack": "1 OR 1=1--",
          "evidence": "error in your SQL syntax"
        }]
      }]
    }]
  }

FORMATO JSON DA API DO ZAP:
  {
    "alerts": [{
      "id": "1",
      "pluginId": "40018",
      "alert": "SQL Injection",
      "risk": "High",
      "confidence": "Medium",
      "url": "https://target.com/api/users?id=1",
      "method": "GET",
      "param": "id",
      "attack": "1 OR 1=1--",
      "evidence": "error in your SQL syntax"
    }]
  }

SAÍDA:
  Lista de dicts: payload, category, method, path, param, source, label
"""

import re
from pathlib import Path
from urllib.parse import urlparse

from loguru import logger

try:
    import orjson as json
except ImportError:
    import json


# Mapeamento de alertas ZAP → categorias Dorsal
ZAP_CATEGORY_MAP = {
    "sql injection": "sqli",
    "blind sql injection": "sqli",
    "cross site scripting": "xss",
    "cross-site scripting": "xss",
    "xss": "xss",
    "path traversal": "path_traversal",
    "directory browsing": "path_traversal",
    "remote file inclusion": "path_traversal",
    "local file inclusion": "path_traversal",
    "server side request forgery": "ssrf",
    "ssrf": "ssrf",
    "server side template injection": "ssti",
    "external redirect": "open_redirect",
    "open redirect": "open_redirect",
    "command injection": "command_injection",
    "os command": "command_injection",
    "remote os command": "command_injection",
    "xml external entity": "xxe",
    "xxe": "xxe",
    "crlf injection": "crlf",
    "http response splitting": "crlf",
    "ldap injection": "ldap_injection",
    "parameter tampering": "parameter_pollution",
    "cors": "cors",
    "insecure direct object": "bola",
    "idor": "bola",
    "jwt": "jwt_attack",
    "nosql": "nosql",
    "graphql": "graphql",
}

ZAP_RISK_MAP = {"0": "info", "1": "low", "2": "medium", "3": "high"}


def _classify_zap_alert(alert_name: str) -> str:
    """Classifica alerta ZAP em categoria Dorsal."""
    name_lower = alert_name.lower()
    for pattern, category in ZAP_CATEGORY_MAP.items():
        if pattern in name_lower:
            return category
    return "unknown"


def _extract_path(url: str) -> str:
    """Extrai o path de uma URL completa."""
    try:
        parsed = urlparse(url)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"
        return path
    except Exception:
        return "/"


def parse_zap_json(filepath: str | Path) -> list[dict]:
    """
    Parsea JSON report ou API response do OWASP ZAP.
    
    Detecta automaticamente o formato (Traditional Report vs API Response)
    e extrai payloads de ataque com categorização.
    
    Args:
        filepath: Caminho para o JSON do ZAP
    
    Returns:
        Lista de dicts com: payload, category, method, path, param,
        severity, source, label
    """
    filepath = Path(filepath)
    if not filepath.exists():
        logger.warning(f"⚠️  Arquivo ZAP não encontrado: {filepath}")
        return []

    logger.info(f"📂 Parseando ZAP JSON: {filepath}")

    with open(filepath, "rb") as f:
        data = json.loads(f.read())

    results = []

    # ==== Formato 1: Traditional JSON Report ====
    if "site" in data:
        sites = data["site"]
        if isinstance(sites, dict):
            sites = [sites]

        for site in sites:
            alerts = site.get("alerts", [])
            for alert in alerts:
                alert_name = alert.get("alert", alert.get("name", ""))
                category = _classify_zap_alert(alert_name)
                risk = ZAP_RISK_MAP.get(
                    str(alert.get("riskcode", "0")),
                    alert.get("riskdesc", "info").split(" ")[0].lower()
                )

                # Cada alerta pode ter múltiplas instâncias
                instances = alert.get("instances", [])
                for inst in instances:
                    attack_payload = inst.get("attack", "")
                    uri = inst.get("uri", "")
                    method = inst.get("method", "GET")
                    param = inst.get("param", "")
                    evidence = inst.get("evidence", "")

                    # O payload é o campo "attack" do ZAP
                    payload = attack_payload or evidence or param
                    if not payload:
                        continue

                    results.append({
                        "payload": payload,
                        "category": category,
                        "method": method,
                        "path": _extract_path(uri),
                        "param": param,
                        "severity": risk,
                        "evidence": evidence[:200],  # truncar
                        "source": "OWASP_ZAP",
                        "source_file": str(filepath.name),
                        "label": 1,
                    })

    # ==== Formato 2: API Response ====
    elif "alerts" in data:
        alerts = data["alerts"]
        for alert in alerts:
            alert_name = alert.get("alert", alert.get("name", ""))
            category = _classify_zap_alert(alert_name)

            payload = alert.get("attack", "")
            if not payload:
                payload = alert.get("evidence", alert.get("param", ""))
            if not payload:
                continue

            results.append({
                "payload": payload,
                "category": category,
                "method": alert.get("method", "GET"),
                "path": _extract_path(alert.get("url", "/")),
                "param": alert.get("param", ""),
                "severity": alert.get("risk", "info").lower(),
                "evidence": alert.get("evidence", "")[:200],
                "source": "OWASP_ZAP",
                "source_file": str(filepath.name),
                "label": 1,
            })

    # ==== Formato 3: Array direto de alertas ====
    elif isinstance(data, list):
        for alert in data:
            alert_name = alert.get("alert", alert.get("name", ""))
            category = _classify_zap_alert(alert_name)
            payload = alert.get("attack", alert.get("evidence", ""))
            if not payload:
                continue

            results.append({
                "payload": payload,
                "category": category,
                "method": alert.get("method", "GET"),
                "path": _extract_path(alert.get("url", "/")),
                "param": alert.get("param", ""),
                "severity": alert.get("risk", "info").lower(),
                "source": "OWASP_ZAP",
                "source_file": str(filepath.name),
                "label": 1,
            })

    logger.info(f"✅ ZAP: {len(results)} payloads de ataque extraídos")
    return results
