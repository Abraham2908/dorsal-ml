# P0 Schema Upgrade Guide

## Objetivo

Este guia documenta as mudancas da fase P0 para enriquecer o pipeline de dataset sem quebrar os fluxos atuais.

Escopo:

- novos metadados de campanha no dataset supervisionado;
- manifesto JSON por coleta;
- evolucao do dataset de lab com `validation_tier` e `effect_outcome`;
- compatibilidade com comandos antigos.

## Antes x depois

Antes:

- dataset com metadados basicos (`source`, `campaign_id`, `category`, etc.);
- sem manifesto padrao por coleta;
- correlacao de lab com `match_tier`, `label` e `label_confidence`.

Depois:

- dataset inclui metadados adicionais:
  - `scenario_type`
  - `target_app`
  - `attack_family`
  - `attack_technique`
  - `validation_tier`
  - `lab_run_id`
  - `effect_outcome`
  - `is_replay`
- manifesto JSON gerado por default em `reports/`;
- dataset de lab tambem inclui os mesmos metadados-base de campanha e confianca.

## Compatibilidade

Regra desta fase: backward-compatible.

- `make layer1` continua funcionando sem novos parametros.
- `make layer1-realworld` continua funcionando sem novos parametros.
- campos novos possuem defaults quando nao informados.
- schema antigo de uso de CLI continua valido.

## Novas flags de CLI

### `training.build_dataset`

Novas flags opcionais:

- `--target-app`
- `--lab-run-id`
- `--is-replay`
- `--manifest-path`

### `training.build_lab_dataset`

Novas flags opcionais:

- `--campaign-id`
- `--target-app`
- `--lab-run-id`
- `--is-replay`
- `--manifest-path`

## Manifesto de dataset

O manifesto JSON registra:

- `schema_version`
- `campaign_id`, `target_app`, `lab_run_id`, `is_replay`
- parametros de geracao
- fontes de dados usadas
- distribuicoes de labels e metadados
- caminhos de artefatos gerados

Defaults:

- Layer 1: `reports/dataset_manifest_<campaign_id>.json`
- Lab: `reports/dataset_lab_manifest_<campaign_id>.json`

## Exemplos

### Fluxo padrão (compatível)

```bash
make layer1
```

### Fluxo com metadados explícitos

```bash
TARGET_APP=crapi \
LAB_RUN_ID=lab_20260313 \
IS_REPLAY=0 \
DATASET_MANIFEST_PATH=./reports/crapi_v1.manifest.json \
make layer1
```

### Build de lab com manifesto customizado

```bash
.venv/bin/python -m training.build_lab_dataset \
  --gateway-log ./data/raw/lab/gateway.jsonl \
  --shannon-dirs ./data/raw/shannon/session_01 \
  --strix-dirs ./data/raw/strix/run_01 \
  --campaign-id campaign_lab_crapi \
  --target-app crapi \
  --lab-run-id run_01 \
  --manifest-path ./reports/lab_crapi.manifest.json \
  --output ./data/intermediate/dataset_lab_crapi.parquet
```

## FAQ rapido

### Isso impacta o gateway?

Nao nesta fase.

- nenhuma mudanca de runtime do gateway foi exigida;
- nenhuma mudanca no formato de inferencia ONNX foi introduzida.

### Preciso mudar meus comandos atuais?

Nao.

Os comandos antigos continuam validos. As novas flags servem para rastreabilidade e governanca de dataset.
