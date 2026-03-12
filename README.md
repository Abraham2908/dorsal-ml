# DORSAL ML Training Pipeline

Repositório de treino de modelos do Dorsal em 3 camadas:

1. **Camada 1** (`attack_*.onnx`): classificador supervisionado global de ataques.
2. **Camada 2** (gateway): baseline comportamental local por cliente.
3. **Camada 3** (`global_anomaly_*.onnx`): modelo global de anomalia com telemetria agregada.

Este repo entrega pipeline pronto para você **rodar quando quiser** com dados estáticos, DAST, snapshots de agentes e telemetria.

## 1) Pré-requisitos

- Linux/macOS com `bash`, `git`, `python3.11+`.
- `uv` instalado (`curl -LsSf https://astral.sh/uv/install.sh | sh`).
- Opcional: `docker` (para Juice Shop e build do gateway).

## 2) Setup inicial (uma vez)

```bash
cd /home/abraham/tools/dorsal-ml
make venv
make install-dev
make bootstrap
make setup-data
make smoke
make test
```

Isso cria `.venv`, estrutura de diretórios (`data/`, `models/`, `reports/`, `keys/`, `logs/`) e baixa PayloadAllTheThings/SecLists.

## 3) Treino da Camada 1 (ataques conhecidos)

### 3.1 Fluxo rápido (somente fontes públicas)

```bash
make layer1
```

Saídas principais:
- `data/curated/attack_*.parquet`
- `models/attack_*.onnx`
- `models/attack_latest.onnx`
- `reports/attack_*.benchmark.json`

### 3.2 Fluxo com DAST e agentes (opcional)

Coloque exports/snapshots locais:
- `data/dast/burp_export.xml`
- `data/dast/zap_report.json`
- `data/dast/acunetix_export.json`
- `data/raw/strix/...`
- `data/raw/shannon/...`

Execute:

```bash
BURP_FILE=./data/dast/burp_export.xml \
ZAP_FILE=./data/dast/zap_report.json \
ACUNETIX_FILE=./data/dast/acunetix_export.json \
STRIX_RUNS_DIR=./data/raw/strix \
SHANNON_SESSIONS_DIR=./data/raw/shannon \
make layer1
```

## 4) Treino da Camada 3 (global anomaly)

### 4.1 Com telemetria local de arquivo

```bash
TELEMETRY_INPUT=./data/telemetry/telemetry_real.parquet make layer3
```

### 4.2 Sem conector pronto (fallback sintético)

```bash
make layer3
```

Saídas:
- `data/raw/telemetry_*.parquet`
- `models/global_anomaly_*.onnx` (preferencial)
- `models/global_anomaly_*.pkl` (fallback se conversão ONNX falhar)
- `models/global_anomaly_latest.onnx` ou `models/global_anomaly_latest.pkl`

## 5) Rodar tudo em sequência

```bash
make all
```

Equivalente a: bootstrap -> Camada 1 -> Camada 3.

## 6) Bundle seguro para gateway (.onnx protegido)

Gerar chaves de assinatura:

```bash
.venv/bin/python -m training.bundle_packager gen-keys \
  --private-key ./keys/model_signing_private.b64 \
  --public-key ./keys/model_signing_public.b64
```

Rodar layer1 com bundle automático:

```bash
export DORSAL_MODEL_SIGNING_PRIVATE_KEY=./keys/model_signing_private.b64
export DORSAL_MODEL_KEK='troque-por-segredo-forte'
make layer1
```

Bundle gerado em `models/bundles/<model_name>/` com:
- `model.enc`
- `manifest.json`
- `signature.sig`
- `feature_map.json`
- `bundle.meta.json`

## 7) Retreino semanal

```bash
make weekly
```

Comportamento:
- prepara workspace;
- atualiza fontes públicas;
- executa Camada 1 e Camada 3;
- opcionalmente build/push de gateway se `ENABLE_GATEWAY_BUILD=1`.

Logs ficam em `logs/weekly_retrain_*.log`.

## 8) Configuração por `.env`

Use `configs/pipeline.env.example`:

```bash
cp configs/pipeline.env.example .env
set -a; source .env; set +a
```

Depois rode qualquer target (`make layer1`, `make layer3`, `make weekly`).

## 9) Comandos diretos dos módulos (sem scripts)

```bash
.venv/bin/python -m training.build_dataset --help
.venv/bin/python -m training.train_attack_model --help
.venv/bin/python -m training.validate_model --help
.venv/bin/python -m training.benchmark_inference --help
.venv/bin/python -m training.train_anomaly_model --help
.venv/bin/python scripts/fetch_telemetry.py --help
```

## 10) Critérios de aceite recomendados

- Camada 1: `precision >= 0.92`, `recall >= 0.85`, `fpr <= 0.03`.
- Benchmark ONNX: validar P50/P95/P99 com lote 1 e 32.
- Camada 3: usar holdout por tenant quando houver labels reais.
- Nunca usar `dorsal_score` como label de treino.

## 11) Estrutura de artefatos

```text
data/
  raw/
  intermediate/
  curated/
  dast/
models/
  attack_*.onnx
  global_anomaly_*.onnx
  bundles/
reports/
keys/
logs/
```
