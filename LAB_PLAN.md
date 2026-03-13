# LAB_PLAN

## Objetivo

Montar um lab repetivel para Camada 1 com:

- APIs vulneraveis e APIs conhecidas para trafego legitimo.
- Gateway Dorsal na frente de todas as APIs.
- Geracao de trafego legitimo com estado.
- Campanhas de ataque com scanner classico e agente de ataque orientado por LLM (opcional).
- Artefatos prontos para alimentar `build_dataset`, `build_lab_dataset` e `layer1-realworld`.

Arquivos entregues para este plano:

- Compose do lab: [labs/docker-compose.layer1-lab.yml](/home/abraham/tools/dorsal-ml/labs/docker-compose.layer1-lab.yml)
- Simulador de trafego legitimo: [labs/traffic/legit_traffic.py](/home/abraham/tools/dorsal-ml/labs/traffic/legit_traffic.py)
- Runner de ataque + output de agentes: [labs/traffic/ai_redteam_agent.py](/home/abraham/tools/dorsal-ml/labs/traffic/ai_redteam_agent.py)
- Build da imagem de trafego/ataque: [labs/traffic/Dockerfile](/home/abraham/tools/dorsal-ml/labs/traffic/Dockerfile)
- Exemplo de variaveis: [labs/.env.lab.example](/home/abraham/tools/dorsal-ml/labs/.env.lab.example)

## Arquitetura do Lab

- `vuln-juice-shop`: app vulneravel conhecida.
- `safe-httpbin` e `safe-petstore`: apps conhecidas para trafego funcional/benigno.
- `gateway-juice`, `gateway-httpbin`, `gateway-petstore`: um gateway por upstream.
- `traffic-legit-sim`: simula usuarios com sessao/cookies e fluxo multi-etapa.
- `attack-zap-baseline`: scanner classico (ZAP) gerando JSON/HTML.
- `attack-ai-redteam`: replay de payloads + expansao por LLM (quando chave configurada), gerando:
  - `gateway/attack_requests.jsonl`
  - estrutura estilo `strix` em `data/raw/lab/strix/...`
  - estrutura estilo `shannon` em `data/raw/lab/shannon/...`

## Pre-requisitos

1. Control plane e dashboard do Dorsal ativos.
2. Criar 3 gateways no control plane e copiar as API keys:
   - `gw_lab_juice`
   - `gw_lab_httpbin`
   - `gw_lab_petstore`
3. Preparar env do lab:

```bash
cd /home/abraham/tools/dorsal-ml
cp labs/.env.lab.example labs/.env.lab
# editar labs/.env.lab com as 3 API keys e, opcionalmente, DORSAL_TEST_ORG_TOKEN
```

## Ordem de execucao do Lab

### 1) Subir base (APIs + gateways)

```bash
cd /home/abraham/tools/dorsal-ml
docker compose --env-file labs/.env.lab -f labs/docker-compose.layer1-lab.yml up -d \
  vuln-juice-shop safe-httpbin safe-petstore \
  gateway-juice gateway-httpbin gateway-petstore
```

### 2) Rodar trafego legitimo com estado

```bash
docker compose --env-file labs/.env.lab -f labs/docker-compose.layer1-lab.yml --profile traffic up \
  --build traffic-legit-sim
```

### 3) Rodar ataques (scanner classico + agente)

```bash
docker compose --env-file labs/.env.lab -f labs/docker-compose.layer1-lab.yml --profile attacks up \
  --build attack-zap-baseline attack-ai-redteam
```

### 4) Consolidar logs do gateway para correlacao

```bash
mkdir -p data/raw/lab/gateway
cat data/raw/lab/gateway/legit_requests.jsonl data/raw/lab/gateway/attack_requests.jsonl \
  > data/raw/lab/gateway/gateway.jsonl
```

## Ordem de treinamento recomendada (estatico -> real)

## Fase A: bootstrap estatico (base publica)

1. Preparar ambiente e fontes:

```bash
cd /home/abraham/tools/dorsal-ml
make venv
make install-dev
make bootstrap
make setup-data
```

2. Treinar baseline com fontes publicas:

```bash
TARGET_APP=lab_multi \
LAB_RUN_ID=static_bootstrap \
ATTACK_RATIO=0.20 \
make layer1
```

## Fase B: enrich com dados do lab (realismo operacional)

1. Gerar dataset correlacionado de lab:

```bash
.venv/bin/python -m training.build_lab_dataset \
  --gateway-log ./data/raw/lab/gateway/gateway.jsonl \
  --strix-dirs ./data/raw/lab/strix/run_ai_redteam \
  --shannon-dirs ./data/raw/lab/shannon/session_ai_redteam \
  --campaign-id campaign_lab_real_001 \
  --target-app multi_lab \
  --lab-run-id run_lab_001 \
  --output ./data/intermediate/dataset_lab_real.parquet \
  --manifest-path ./reports/dataset_lab_manifest_real_001.json
```

2. Treinar Camada 1 com workflow realworld (train 20% ataque, validacao 2%):

```bash
TARGET_APP=multi_lab \
LAB_RUN_ID=run_lab_001 \
ZAP_FILE=./data/dast/zap/zap_juice.json \
STRIX_RUNS_DIR=./data/raw/lab/strix \
SHANNON_SESSIONS_DIR=./data/raw/lab/shannon \
HARD_NEGATIVES_PATH=./data/raw/lab/hard_negatives \
HARD_NEGATIVE_RATIO=0.25 \
SLICE_GATES_CONFIG=./configs/slice_gates.example.json \
TRAIN_ATTACK_RATIO=0.20 \
REALWORLD_ATTACK_RATIO=0.02 \
REALWORLD_MAX_FPR=0.01 \
make layer1-realworld
```

3. Conferir artefatos obrigatorios:

- `reports/*dataset_manifest*.json`
- `reports/*.validation.json`
- `reports/*.promotion_decision.json`
- `reports/*realworld_summary.json`

## Top 10 fontes para fase estatica (antes do lab)

1. OWASP API Security Top 10
2. OWASP Web Security Testing Guide (WSTG)
3. PayloadAllTheThings
4. SecLists
5. PortSwigger Web Security Academy Labs
6. OWASP Juice Shop docs + challenge catalog
7. OWASP crAPI docs/labs
8. ZAP baseline/full scan reports
9. NVD (CVE feed) focado em stacks de API
10. CISA KEV catalog para priorizar tecnicas em exploracao ativa

## Como acompanhar no Control Plane

- Use o dashboard para:
  - validar heartbeat de cada gateway,
  - revisar runtime policy por gateway em `/app/settings`,
  - monitorar metricas em `/app/overview`, `/app/threats`, `/app/traffic`.
- Opcional: definir `DORSAL_TEST_ORG_TOKEN` no `labs/.env.lab` para o agente salvar snapshot de metricas em:
  - `data/raw/lab/reports/control_metrics_after_ai_attack.json`

## Isso e suficiente para os 5 objetivos?

1. Montar lab instrumentado com apps vulneraveis e endurecidas atras do gateway:
   - **Sim**, com o compose entregue.
2. Automatizar trafego legitimo com estado:
   - **Sim**, com `traffic-legit-sim` (sessao/cookie/fluxos multi-etapa).
3. Rodar campanhas de ataque com scanners classicos + agentes de IA:
   - **Sim**, com `attack-zap-baseline` + `attack-ai-redteam` (LLM opcional).
4. Formalizar manifestos, tiers de validacao e outcomes:
   - **Sim**, o pipeline ja grava manifests e tiers (`build_dataset`, `build_lab_dataset`, `validate_model`, `promotion_gate`).
5. Transformar Camada 1 em treinamento por cenarios reais (nao so payload repo):
   - **Sim, com condicao**: precisa repetir campanhas e acumular volume/variacao de trafego para robustez estatistica.

## Criterio pratico de maturidade minima para piloto

- Pelo menos 3 campanhas completas em dias diferentes.
- Variacao de horario/carga no trafego legitimo.
- Minimo 2 apps vulneraveis + 2 apps benignas com fluxos reais.
- Gate de promocao consistente em 2 rodadas seguidas sem regressao em slices criticos.
