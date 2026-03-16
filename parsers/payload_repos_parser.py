"""
DORSAL ML Pipeline — Parser para Repositórios de Payloads
==========================================================
Fontes: PayloadAllTheThings, SecLists, custom wordlists

FORMATO DE ENTRADA:
  - PayloadAllTheThings: estrutura de diretórios com .md e .txt
    Cada arquivo .md contém payloads dentro de blocos de código
    Cada arquivo .txt contém um payload por linha
  - SecLists: arquivos .txt com um payload/word por linha

COMO BAIXAR:
  git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git
  git clone --depth 1 --filter=blob:none --sparse https://github.com/danielmiessler/SecLists.git
  cd SecLists && git sparse-checkout set Fuzzing Discovery/Web-Content

FORMATO DE SAÍDA:
  Lista de dicts: [{"payload": str, "category": str, "source": str, "label": 1}]
"""

import os
import re
from pathlib import Path
from typing import Generator

from loguru import logger


# ============================================================
# Mapeamento de diretórios → categorias OWASP
# ============================================================

PAYLOAD_ALL_THE_THINGS_MAP = {
    "SQL Injection": "sqli",
    "XSS Injection": "xss",
    "Cross-Site Scripting": "xss",
    "Server Side Request Forgery": "ssrf",
    "SSRF": "ssrf",
    "Directory Traversal": "path_traversal",
    "File Inclusion": "path_traversal",
    "Server Side Template Injection": "ssti",
    "SSTI": "ssti",
    "NoSQL Injection": "nosql",
    "NoSQL injection": "nosql",
    "Command Injection": "command_injection",
    "XXE Injection": "xxe",
    "LDAP Injection": "ldap_injection",
    "JSON Web Token": "jwt_attack",
    "JWT": "jwt_attack",
    "CRLF Injection": "crlf",
    "CSV Injection": "csv_injection",
    "GraphQL Injection": "graphql",
    "HTTP Parameter Pollution": "parameter_pollution",
    "Mass Assignment": "mass_assignment",
    "Race Condition": "race_condition",
    "Open Redirect": "open_redirect",
    "CORS Misconfiguration": "cors",
}

SECLISTS_MAP = {
    "Fuzzing/SQLi": "sqli",
    "Fuzzing/XSS": "xss",
    "Fuzzing/LFI": "path_traversal",
    "Fuzzing/command-injection": "command_injection",
    "Fuzzing/LDAP": "ldap_injection",
    "Fuzzing/SSI": "ssi",
    "Fuzzing/Polyglots": "polyglot",
    "Fuzzing": "fuzzing_generic",
    "Discovery/Web-Content": "shadow_api",
}


def _extract_payloads_from_markdown(filepath: Path) -> Generator[str, None, None]:
    """
    Extrai payloads de arquivos .md do PayloadAllTheThings.
    Payloads ficam em blocos de código (```) ou em linhas que parecem payloads.
    """
    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        logger.warning(f"Erro ao ler {filepath}: {e}")
        return

    # Extrair de blocos de código
    code_blocks = re.findall(r"```[\w]*\n(.*?)```", content, re.DOTALL)
    for block in code_blocks:
        for line in block.strip().split("\n"):
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith("//"):
                # Filtra linhas que parecem comentários ou headers
                if len(line) >= 3:
                    yield line

    # Extrair de linhas inline que parecem payloads (entre backticks)
    inline_payloads = re.findall(r"`([^`]{3,200})`", content)
    for p in inline_payloads:
        p = p.strip()
        if any(c in p for c in ["'", '"', "<", ">", "{", "}", "$", "%", "..", "="]):
            yield p


def _extract_payloads_from_txt(filepath: Path) -> Generator[str, None, None]:
    """Extrai payloads de arquivos .txt — um por linha."""
    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        logger.warning(f"Erro ao ler {filepath}: {e}")
        return

    for line in content.split("\n"):
        line = line.strip()
        if line and not line.startswith("#"):
            yield line


def _resolve_category(filepath: Path, mapping: dict[str, str]) -> str:
    """Resolve a categoria baseado no path do arquivo."""
    path_str = str(filepath)
    for dir_name, category in mapping.items():
        if dir_name.lower() in path_str.lower():
            return category
    return "unknown"


def parse_payload_all_the_things(
    repo_dir: str | Path,
    max_per_category: int = 5000,
) -> list[dict]:
    """
    Parsea o repositório PayloadAllTheThings inteiro.
    
    Args:
        repo_dir: Caminho para o clone do repositório
        max_per_category: Máximo de payloads por categoria (evitar desbalanceamento)
    
    Returns:
        Lista de dicts com: payload, category, source, label, subcategory
    """
    repo_dir = Path(repo_dir)
    if not repo_dir.exists():
        raise FileNotFoundError(f"Repositório não encontrado: {repo_dir}")

    results = []
    category_counts: dict[str, int] = {}

    logger.info(f"📂 Parseando PayloadAllTheThings em {repo_dir}")

    for root, _dirs, files in os.walk(repo_dir):
        for fname in files:
            filepath = Path(root) / fname

            # Pular arquivos irrelevantes
            if filepath.suffix.lower() not in (".md", ".txt", ".list"):
                continue
            if any(skip in str(filepath).lower() for skip in [
                "readme", "changelog", "license", ".git", "images/", "img/"
            ]):
                continue

            category = _resolve_category(filepath, PAYLOAD_ALL_THE_THINGS_MAP)

            # Limitar por categoria
            if category_counts.get(category, 0) >= max_per_category:
                continue

            # Escolher extrator baseado na extensão
            if filepath.suffix.lower() == ".md":
                extractor = _extract_payloads_from_markdown
            else:
                extractor = _extract_payloads_from_txt

            for payload in extractor(filepath):
                if category_counts.get(category, 0) >= max_per_category:
                    break

                results.append({
                    "payload": payload,
                    "category": category,
                    "source": "PayloadAllTheThings",
                    "source_file": str(filepath.relative_to(repo_dir)),
                    "label": 1,  # Ataque
                })
                category_counts[category] = category_counts.get(category, 0) + 1

    logger.info(f"✅ PayloadAllTheThings: {len(results)} payloads extraídos")
    for cat, count in sorted(category_counts.items(), key=lambda x: -x[1]):
        logger.info(f"   {cat}: {count}")

    return results


def parse_seclists(
    repo_dir: str | Path,
    max_per_category: int = 5000,
) -> list[dict]:
    """
    Parsea as wordlists relevantes do SecLists.
    
    Args:
        repo_dir: Caminho para o clone do SecLists
        max_per_category: Máximo de payloads por categoria
    
    Returns:
        Lista de dicts com: payload, category, source, label
    """
    repo_dir = Path(repo_dir)
    if not repo_dir.exists():
        raise FileNotFoundError(f"SecLists não encontrado: {repo_dir}")

    results = []
    category_counts: dict[str, int] = {}

    logger.info(f"📂 Parseando SecLists em {repo_dir}")

    # Só parsear diretórios relevantes
    target_dirs = ["Fuzzing", "Discovery/Web-Content"]

    for target in target_dirs:
        target_path = repo_dir / target
        if not target_path.exists():
            logger.warning(f"   ⚠️  Diretório não encontrado: {target_path}")
            continue

        for root, _dirs, files in os.walk(target_path):
            for fname in files:
                filepath = Path(root) / fname
                if filepath.suffix.lower() not in (".txt", ".list", ".fuzz"):
                    continue

                category = _resolve_category(filepath, SECLISTS_MAP)
                if category_counts.get(category, 0) >= max_per_category:
                    continue

                for payload in _extract_payloads_from_txt(filepath):
                    if category_counts.get(category, 0) >= max_per_category:
                        break
                    results.append({
                        "payload": payload,
                        "category": category,
                        "source": "SecLists",
                        "source_file": str(filepath.relative_to(repo_dir)),
                        "label": 1,
                    })
                    category_counts[category] = category_counts.get(category, 0) + 1

    logger.info(f"✅ SecLists: {len(results)} payloads extraídos")
    for cat, count in sorted(category_counts.items(), key=lambda x: -x[1]):
        logger.info(f"   {cat}: {count}")

    return results
