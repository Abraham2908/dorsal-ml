"""
DORSAL ML Pipeline — Parser para Shannon (Keygraph)
=====================================================
Shannon é um AI pentester autônomo que gera exploits reais.
https://github.com/KeygraphHQ/shannon

FORMATO DE OUTPUT DO SHANNON:
  audit-logs/{hostname}_{sessionId}/
  ├── session.json              # Métricas e dados da sessão
  ├── agents/                   # Logs por agente
  │   ├── pre-recon.log
  │   ├── recon.log
  │   ├── injection-vuln.log
  │   ├── injection-exploit.log
  │   ├── xss-vuln.log
  │   ├── xss-exploit.log
  │   ├── ssrf-vuln.log
  │   ├── ssrf-exploit.log
  │   ├── auth-vuln.log
  │   └── auth-exploit.log
  ├── prompts/                  # Snapshots dos prompts
  └── deliverables/
      ├── code_analysis_report.md
      ├── reconnaissance_report.md
      ├── INJECTION_QUEUE.json         # Vulns de injection encontradas
      ├── INJECTION_EVIDENCE.json      # Evidências de exploits
      ├── XSS_QUEUE.json
      ├── XSS_EVIDENCE.json
      ├── SSRF_QUEUE.json
      ├── SSRF_EVIDENCE.json
      ├── AUTH_QUEUE.json
      ├── AUTH_EVIDENCE.json
      └── comprehensive_security_assessment_report.md

COMO USAR COM O DORSAL:
  1. Subir API vulnerável (Juice Shop, crAPI, c{api}tal)
  2. Colocar o Dorsal Gateway na frente
  3. Rodar Shannon apontando pro Dorsal:
     ./shannon start URL=http://dorsal-gateway:8080 REPO=/path/to/vuln-app
  4. O Dorsal loga todas as requests
  5. Shannon gera os relatórios com findings
  6. Este parser extrai payloads + labels dos findings
  7. O correlator cruza com os logs do gateway → dataset completo
"""

import os
import re
import json
from pathlib import Path
from typing import Optional

from loguru import logger


# Mapeamento de tipos de queue do Shannon → categorias Dorsal
SHANNON_CATEGORY_MAP = {
    "INJECTION": "sqli",        # Shannon agrupa SQL + command injection
    "XSS": "xss",
    "SSRF": "ssrf",
    "AUTH": "auth_bypass",
    "IDOR": "bola",
    "CSRF": "csrf",
    "XXE": "xxe",
    "DESERIALIZATION": "deserialization",
}

SHANNON_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
    "info": "info",
}


def _parse_queue_json(filepath: Path, queue_type: str) -> list[dict]:
    """
    Parsea um *_QUEUE.json do Shannon.
    
    Esses arquivos contêm as vulnerabilidades hipotéticas que o Shannon
    encontrou na fase de análise e que foram validadas na fase de exploit.
    
    Estrutura típica:
    [
      {
        "id": "INJ-001",
        "title": "SQL Injection in /api/users/search",
        "type": "sql_injection",
        "severity": "critical",
        "endpoint": "POST /api/users/search",
        "parameter": "q",
        "payload": "' OR 1=1--",
        "description": "...",
        "data_flow": "req.body.q → db.query()"
      }
    ]
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        logger.warning(f"  ⚠️  Erro ao ler {filepath}: {e}")
        return []

    if not isinstance(data, list):
        data = [data] if isinstance(data, dict) else []

    results = []
    base_category = SHANNON_CATEGORY_MAP.get(queue_type, "unknown")

    for finding in data:
        # Extrair payload
        payload = finding.get("payload", "")
        if not payload:
            payload = finding.get("attack", finding.get("exploit", ""))
        if not payload:
            # Tentar extrair de PoC/evidence
            poc = finding.get("poc", finding.get("proof_of_concept", ""))
            if isinstance(poc, str):
                payload = poc
            elif isinstance(poc, dict):
                payload = poc.get("payload", poc.get("command", ""))

        if not payload:
            continue

        # Extrair endpoint
        endpoint = finding.get("endpoint", "")
        method = "GET"
        path = "/"
        if endpoint:
            parts = endpoint.strip().split(" ", 1)
            if len(parts) == 2:
                method = parts[0].upper()
                path = parts[1]
            else:
                path = parts[0]

        # Subcategoria mais específica
        vuln_type = finding.get("type", finding.get("vulnerability_type", "")).lower()
        if "command" in vuln_type or "os command" in vuln_type:
            category = "command_injection"
        elif "nosql" in vuln_type:
            category = "nosql"
        elif "sql" in vuln_type:
            category = "sqli"
        elif "jwt" in vuln_type or "token" in vuln_type:
            category = "jwt_attack"
        elif "idor" in vuln_type or "authorization" in vuln_type:
            category = "bola"
        elif "brute" in vuln_type:
            category = "brute_force"
        elif "mass assignment" in vuln_type:
            category = "mass_assignment"
        else:
            category = base_category

        severity = SHANNON_SEVERITY_MAP.get(
            finding.get("severity", "medium").lower(), "medium"
        )

        results.append({
            "payload": payload,
            "category": category,
            "method": method,
            "path": path,
            "parameter": finding.get("parameter", ""),
            "severity": severity,
            "title": finding.get("title", finding.get("name", "")),
            "finding_id": finding.get("id", ""),
            "data_flow": finding.get("data_flow", ""),
            "source": "Shannon",
            "source_file": str(filepath.name),
            "label": 1,
        })

    return results


def _parse_evidence_json(filepath: Path, queue_type: str) -> list[dict]:
    """
    Parsea um *_EVIDENCE.json do Shannon.
    
    Evidence files contêm os exploits que foram executados com sucesso.
    Eles têm requests HTTP completas e respostas, o que é mais rico
    que os queue files.
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        logger.warning(f"  ⚠️  Erro ao ler {filepath}: {e}")
        return []

    if not isinstance(data, list):
        data = [data] if isinstance(data, dict) else []

    results = []
    base_category = SHANNON_CATEGORY_MAP.get(queue_type, "unknown")

    for evidence in data:
        # Evidence geralmente tem request/response completos
        request_data = evidence.get("request", {})
        if isinstance(request_data, str):
            # Request como string bruta
            payload = request_data
            method, path = "GET", "/"
        elif isinstance(request_data, dict):
            method = request_data.get("method", "GET")
            path = request_data.get("url", request_data.get("path", "/"))
            body = request_data.get("body", request_data.get("data", ""))
            headers = request_data.get("headers", {})
            payload = body if body else path
        else:
            continue

        # Extrair de campos alternativos
        if not payload or payload == "/":
            payload = evidence.get("payload", evidence.get("command", ""))
            if not payload:
                # Tentar extrair de curl commands
                curl_cmd = evidence.get("curl", evidence.get("poc", ""))
                if isinstance(curl_cmd, str) and "curl" in curl_cmd:
                    payload = curl_cmd

        if not payload:
            continue

        response_data = evidence.get("response", {})
        response_status = 200
        response_size = 0
        if isinstance(response_data, dict):
            response_status = response_data.get("status", response_data.get("status_code", 200))
            response_body = response_data.get("body", "")
            response_size = len(str(response_body))

        results.append({
            "payload": str(payload)[:2000],
            "category": base_category,
            "method": method,
            "path": path,
            "severity": evidence.get("severity", "high").lower(),
            "title": evidence.get("title", evidence.get("finding", "")),
            "response_status": response_status,
            "response_size": response_size,
            "source": "Shannon_Evidence",
            "source_file": str(filepath.name),
            "label": 1,
            "validated": True,  # Evidence = exploit confirmado
        })

    return results


def _parse_agent_logs(agents_dir: Path) -> list[dict]:
    """
    Parsea logs dos agentes do Shannon para extrair requests HTTP
    que foram feitas durante o pentest.
    
    Os logs contêm as interações reais — curls, requests do Playwright,
    e outputs de ferramentas.
    """
    results = []
    if not agents_dir.exists():
        return results

    # Regex para extrair curl commands dos logs
    curl_pattern = re.compile(
        r"curl\s+(?:-[A-Za-z]+\s+)*(?:-X\s+(\w+)\s+)?"
        r"(?:.*?-d\s+['\"](.+?)['\"]\s+)?"
        r"(?:.*?)(https?://[^\s'\"]+)",
        re.DOTALL
    )

    # Regex para extrair payloads inline
    payload_patterns = [
        re.compile(r"['\"](\s*(?:' OR |OR 1=1|UNION SELECT|SELECT .* FROM|DROP TABLE|;--).+?)['\"]", re.I),
        re.compile(r"['\"](\s*<script[^>]*>.+?</script>)['\"]", re.I),
        re.compile(r"['\"](\s*(?:\.\./){2,}.+?)['\"]", re.I),
        re.compile(r"['\"](\s*(?:http://169\.254|http://127\.0|http://localhost).+?)['\"]", re.I),
    ]

    for log_file in agents_dir.glob("*.log"):
        agent_name = log_file.stem
        # Determinar categoria pelo nome do agente
        if "injection" in agent_name:
            category = "sqli"
        elif "xss" in agent_name:
            category = "xss"
        elif "ssrf" in agent_name:
            category = "ssrf"
        elif "auth" in agent_name:
            category = "auth_bypass"
        else:
            category = "unknown"

        try:
            content = log_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        # Extrair curls
        for match in curl_pattern.finditer(content):
            method = match.group(1) or "GET"
            body = match.group(2) or ""
            url = match.group(3) or ""
            payload = body if body else url

            if payload:
                results.append({
                    "payload": payload[:1000],
                    "category": category,
                    "method": method,
                    "path": url,
                    "source": f"Shannon_Agent_{agent_name}",
                    "source_file": str(log_file.name),
                    "label": 1,
                })

        # Extrair payloads inline
        for pattern in payload_patterns:
            for match in pattern.finditer(content):
                p = match.group(1).strip()
                if len(p) >= 5:
                    results.append({
                        "payload": p[:1000],
                        "category": category,
                        "source": f"Shannon_Agent_{agent_name}",
                        "source_file": str(log_file.name),
                        "label": 1,
                    })

    return results


def parse_shannon_session(session_dir: str | Path) -> list[dict]:
    """
    Parser principal: processa uma sessão completa do Shannon.
    
    Args:
        session_dir: Path para audit-logs/{hostname}_{sessionId}/
    
    Returns:
        Lista de dicts prontos para o dataset de treino
    """
    session_dir = Path(session_dir)
    if not session_dir.exists():
        logger.warning(f"⚠️  Sessão Shannon não encontrada: {session_dir}")
        return []

    logger.info(f"📂 Parseando sessão Shannon: {session_dir.name}")

    all_records = []

    # 1. Parsear queue files (vulnerabilidades encontradas)
    deliverables = session_dir / "deliverables"
    if deliverables.exists():
        for queue_file in deliverables.glob("*_QUEUE.json"):
            queue_type = queue_file.stem.replace("_QUEUE", "")
            records = _parse_queue_json(queue_file, queue_type)
            all_records.extend(records)
            logger.info(f"   {queue_file.name}: {len(records)} findings")

        # 2. Parsear evidence files (exploits confirmados)
        for evidence_file in deliverables.glob("*_EVIDENCE.json"):
            evidence_type = evidence_file.stem.replace("_EVIDENCE", "")
            records = _parse_evidence_json(evidence_file, evidence_type)
            all_records.extend(records)
            logger.info(f"   {evidence_file.name}: {len(records)} exploits validados")

    # 3. Parsear agent logs (requests HTTP extraídas)
    agents_dir = session_dir / "agents"
    if agents_dir.exists():
        log_records = _parse_agent_logs(agents_dir)
        all_records.extend(log_records)
        logger.info(f"   Agent logs: {len(log_records)} requests extraídas")

    # 4. Ler session.json para metadados
    session_file = session_dir / "session.json"
    if session_file.exists():
        try:
            with open(session_file) as f:
                session_meta = json.load(f)
            target_url = session_meta.get("targetUrl", session_meta.get("url", ""))
            logger.info(f"   Target: {target_url}")
            logger.info(f"   Duration: {session_meta.get('duration', 'N/A')}")
        except Exception:
            pass

    # Deduplicar por payload
    seen = set()
    unique_records = []
    for r in all_records:
        key = (r.get("payload", "")[:100], r.get("category", ""))
        if key not in seen:
            seen.add(key)
            unique_records.append(r)

    logger.info(f"✅ Shannon: {len(unique_records)} registros únicos "
                f"(de {len(all_records)} total)")

    return unique_records


def parse_shannon_all_sessions(audit_logs_dir: str | Path) -> list[dict]:
    """
    Parsea TODAS as sessões do Shannon em um diretório.
    Útil para acumular dados de múltiplos pentests.
    """
    audit_logs_dir = Path(audit_logs_dir)
    all_records = []

    for session_dir in sorted(audit_logs_dir.iterdir()):
        if session_dir.is_dir() and (session_dir / "session.json").exists():
            records = parse_shannon_session(session_dir)
            all_records.extend(records)

    logger.info(f"✅ Shannon total: {len(all_records)} registros de "
                f"{len(list(audit_logs_dir.iterdir()))} sessões")
    return all_records
