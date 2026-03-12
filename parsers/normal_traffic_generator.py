"""
DORSAL ML Pipeline — Gerador de Tráfego Normal (Label 0)
==========================================================
Gera requests HTTP sintéticos que simulam tráfego legítimo.
Essencial para balancear o dataset (80% normal / 20% ataque).

Sem tráfego normal de qualidade, o modelo fica enviesado e o FP rate explode.
"""

import random
import string
import uuid
from typing import Optional

import numpy as np
from faker import Faker
from loguru import logger

fake = Faker(["pt_BR", "en_US"])
Faker.seed(42)
random.seed(42)


# ============================================================
# Templates de APIs reais brasileiras (fintech, healthtech, SaaS)
# ============================================================

API_TEMPLATES = {
    "fintech": {
        "endpoints": [
            ("GET", "/api/v1/accounts/{id}"),
            ("GET", "/api/v1/accounts/{id}/balance"),
            ("POST", "/api/v1/transactions"),
            ("GET", "/api/v1/transactions?page={page}&limit={limit}"),
            ("POST", "/api/v1/pix/transfer"),
            ("GET", "/api/v1/pix/keys"),
            ("POST", "/api/v1/boleto/generate"),
            ("GET", "/api/v1/statements?from={date}&to={date}"),
            ("PUT", "/api/v1/users/{id}/profile"),
            ("POST", "/api/v1/auth/login"),
            ("POST", "/api/v1/auth/refresh"),
            ("GET", "/api/v1/cards/{id}"),
            ("POST", "/api/v1/cards/{id}/block"),
        ],
        "body_templates": [
            '{"amount": {amount}, "description": "{desc}", "pix_key": "{pix}"}',
            '{"email": "{email}", "password": "{pw}"}',
            '{"cpf": "{cpf}", "name": "{name}", "phone": "{phone}"}',
            '{"from_account": "{acc}", "to_account": "{acc}", "amount": {amount}}',
        ],
    },
    "healthtech": {
        "endpoints": [
            ("GET", "/api/v1/patients/{id}"),
            ("POST", "/api/v1/appointments"),
            ("GET", "/api/v1/appointments?date={date}&doctor_id={id}"),
            ("PUT", "/api/v1/patients/{id}/medical-record"),
            ("GET", "/api/v1/prescriptions/{id}"),
            ("POST", "/api/v1/teleconsult/start"),
            ("GET", "/api/v1/exams/{id}/results"),
            ("POST", "/api/v1/auth/login"),
        ],
        "body_templates": [
            '{"patient_id": "{uuid}", "doctor_id": "{uuid}", "date": "{date}", "type": "consultation"}',
            '{"crm": "{crm}", "specialty": "{spec}"}',
            '{"symptoms": "{symptoms}", "notes": "{notes}"}',
        ],
    },
    "saas_b2b": {
        "endpoints": [
            ("GET", "/api/v2/workspaces/{id}"),
            ("POST", "/api/v2/workspaces/{id}/projects"),
            ("GET", "/api/v2/projects/{id}/tasks?status={status}"),
            ("PUT", "/api/v2/tasks/{id}"),
            ("DELETE", "/api/v2/tasks/{id}"),
            ("POST", "/api/v2/webhooks"),
            ("GET", "/api/v2/analytics/dashboard?from={date}&to={date}"),
            ("POST", "/api/v2/invites"),
            ("GET", "/api/v2/users/me"),
            ("PATCH", "/api/v2/settings"),
        ],
        "body_templates": [
            '{"name": "{name}", "description": "{desc}", "assignee_id": "{uuid}"}',
            '{"url": "https://{domain}/webhook", "events": ["task.created", "task.updated"]}',
            '{"email": "{email}", "role": "member"}',
        ],
    },
    "ecommerce": {
        "endpoints": [
            ("GET", "/api/v1/products?category={cat}&page={page}"),
            ("GET", "/api/v1/products/{id}"),
            ("POST", "/api/v1/cart/items"),
            ("PUT", "/api/v1/cart/items/{id}"),
            ("DELETE", "/api/v1/cart/items/{id}"),
            ("POST", "/api/v1/checkout"),
            ("GET", "/api/v1/orders/{id}"),
            ("GET", "/api/v1/orders/{id}/tracking"),
            ("POST", "/api/v1/reviews"),
            ("GET", "/api/v1/search?q={query}"),
        ],
        "body_templates": [
            '{"product_id": "{uuid}", "quantity": {qty}, "size": "{size}"}',
            '{"payment_method": "credit_card", "installments": {inst}}',
            '{"rating": {rating}, "comment": "{comment}", "product_id": "{uuid}"}',
        ],
    },
}


def _fill_template(template: str) -> str:
    """Preenche placeholders de templates com dados realistas."""
    replacements = {
        "{id}": str(random.randint(1, 100000)),
        "{uuid}": str(uuid.uuid4()),
        "{page}": str(random.randint(1, 50)),
        "{limit}": str(random.choice([10, 20, 50, 100])),
        "{date}": fake.date_this_year().isoformat(),
        "{amount}": f"{random.uniform(10, 50000):.2f}",
        "{desc}": fake.sentence(nb_words=4),
        "{pix}": fake.cpf() if random.random() > 0.5 else fake.email(),
        "{email}": fake.email(),
        "{pw}": fake.password(length=12),
        "{cpf}": fake.cpf(),
        "{name}": fake.name(),
        "{phone}": fake.phone_number(),
        "{acc}": str(random.randint(10000, 99999)),
        "{crm}": f"CRM/{random.randint(1000, 99999)}",
        "{spec}": random.choice(["cardiology", "orthopedics", "dermatology", "general"]),
        "{symptoms}": fake.sentence(nb_words=6),
        "{notes}": fake.paragraph(nb_sentences=2),
        "{status}": random.choice(["open", "in_progress", "done", "blocked"]),
        "{domain}": fake.domain_name(),
        "{cat}": random.choice(["electronics", "clothing", "food", "books", "sports"]),
        "{query}": fake.word(),
        "{qty}": str(random.randint(1, 5)),
        "{size}": random.choice(["S", "M", "L", "XL"]),
        "{inst}": str(random.choice([1, 2, 3, 6, 12])),
        "{rating}": str(random.randint(1, 5)),
        "{comment}": fake.sentence(nb_words=8),
    }

    result = template
    for placeholder, value in replacements.items():
        result = result.replace(placeholder, value)
    return result


def _generate_normal_user_agent() -> str:
    """Gera User-Agents realistas."""
    agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        "okhttp/4.12.0",
        "python-requests/2.31.0",
        "axios/1.6.2",
        "PostmanRuntime/7.36.0",
    ]
    return random.choice(agents)


def generate_normal_requests(
    n: int = 100_000,
    api_types: Optional[list[str]] = None,
) -> list[dict]:
    """
    Gera N requests HTTP normais (label=0) que simulam tráfego legítimo
    de APIs brasileiras típicas.
    
    Args:
        n: Número de requests a gerar
        api_types: Tipos de API (default: todos)
    
    Returns:
        Lista de dicts: payload, method, path, body, user_agent,
        content_type, category, source, label
    """
    if api_types is None:
        api_types = list(API_TEMPLATES.keys())

    logger.info(f"🔧 Gerando {n:,} requests normais (label=0)")

    results = []
    rng = np.random.default_rng(42)

    for i in range(n):
        api_type = random.choice(api_types)
        template = API_TEMPLATES[api_type]

        method, path_template = random.choice(template["endpoints"])
        path = _fill_template(path_template)

        # Body (para POST/PUT/PATCH)
        body = ""
        content_type = ""
        if method in ("POST", "PUT", "PATCH") and template["body_templates"]:
            body = _fill_template(random.choice(template["body_templates"]))
            content_type = "application/json"

        user_agent = _generate_normal_user_agent()

        # O "payload" para requests normais é a combinação de params + body
        payload_parts = []
        if "?" in path:
            query = path.split("?", 1)[1]
            for param in query.split("&"):
                if "=" in param:
                    payload_parts.append(param.split("=", 1)[1])
        if body:
            payload_parts.append(body)

        payload = " ".join(payload_parts) if payload_parts else path

        # Simular hora do dia (distribuição normal, pico em horário comercial)
        hour = int(np.clip(rng.normal(14, 4), 0, 23))
        is_weekend = random.random() < 0.2

        # Simular métricas de rede
        inter_request_ms = rng.exponential(500)  # ~500ms médio entre requests

        results.append({
            "payload": payload,
            "method": method,
            "path": path.split("?")[0],
            "body": body,
            "user_agent": user_agent,
            "content_type": content_type,
            "category": "normal",
            "source": f"synthetic_{api_type}",
            "label": 0,
            "hour_of_day": hour,
            "is_weekend": is_weekend,
            "inter_request_ms": inter_request_ms,
        })

        if (i + 1) % 25_000 == 0:
            logger.info(f"   ... {i + 1:,}/{n:,} requests gerados")

    logger.info(f"✅ Tráfego normal: {len(results):,} requests gerados")
    return results
