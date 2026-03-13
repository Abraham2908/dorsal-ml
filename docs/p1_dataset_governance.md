# P1 Dataset Governance Upgrade

## Objetivo

Esta fase adiciona governanca de promocao baseada em slices e suporte a hard negatives.

Escopo:

- ingestao de hard negatives no `build_dataset`;
- gates por slice em treino e validacao;
- decisao de promocao em JSON (`promotion_decision.json`).

## Novas flags

### `training.build_dataset`

- `--hard-negatives-path`
- `--hard-negative-ratio`
- `--scenario-profile`

### `training.train_attack_model`

- `--slice-min-support`
- `--slice-gates-config`

### `training.validate_model`

- `--slice-min-support`
- `--slice-gates-config`
- `--report-json`

### `training.promotion_gate`

- `--train-eval`
- `--validation-eval` (repetivel)
- `--output`

## Artefatos novos

- `*.validation.json`: relatorio de validacao (global + slices + gates).
- `*.promotion_decision.json`: decisao final de promocao com checks falhos.

## Config de slice gates

Use `configs/slice_gates.example.json` como modelo.

Cada regra aceita:

- `column` (obrigatorio)
- `value` (opcional; quando ausente aplica em todos os slices da coluna)
- `min_support` (opcional)
- `min_precision` (opcional)
- `min_recall` (opcional)
- `max_fpr` (opcional)

## Exemplo rapido

```bash
HARD_NEGATIVES_PATH=./data/raw/hard_negatives \
HARD_NEGATIVE_RATIO=0.25 \
SLICE_GATES_CONFIG=./configs/slice_gates.example.json \
make layer1-realworld
```
