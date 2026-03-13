# Layer-1 Real-World Playbook

## Objetivo

Treinar a Camada 1 com boa deteccao e baixo falso positivo para cenario real.
O metodo recomendado e usar duas distribuicoes de dados no mesmo fluxo:

1. Treino com `TRAIN_ATTACK_RATIO=0.20` para forcar aprendizado de padroes de ataque.
2. Validacao final com `REALWORLD_ATTACK_RATIO=0.02` (ou `0.01`) para aproximar operacao.

Esse desenho evita um problema comum: modelo "otimo" em dataset artificial, mas com ruido em producao.

## Quando usar

Use este fluxo quando:
- voce ainda nao tem muito log benigno real;
- quer reduzir falso positivo sem sacrificar recall;
- precisa de um comando repetivel para retreinos.

## Comando unico

```bash
make layer1-realworld
```

O target executa:
1. build dataset de treino;
2. treino do modelo;
3. validacao no dataset de treino;
4. build dataset de validacao real-world;
5. validacao no dataset real-world;
6. benchmark + resumo consolidado.

## Variaveis de ambiente mais importantes

```bash
TRAIN_ATTACK_RATIO=0.20
TRAIN_NORMAL_COUNT=0
REALWORLD_ATTACK_RATIO=0.02
REALWORLD_NORMAL_COUNT=0
REALWORLD_MAX_FPR=0.01
```

Notas:
- `*_NORMAL_COUNT=0` deixa o ratio controlar a proporcao com menos distorcao.
- se o ambiente for muito sensivel a falso positivo, reduza `REALWORLD_MAX_FPR`.

## Exemplo pratico

```bash
TRAIN_ATTACK_RATIO=0.20 \
REALWORLD_ATTACK_RATIO=0.02 \
REALWORLD_MAX_FPR=0.01 \
make layer1-realworld
```

## Artefatos gerados

- Modelo: `models/attack_rw_<timestamp>.onnx`
- Dataset treino: `data/curated/attack_rw_<timestamp>.train.parquet`
- Dataset real-world: `data/curated/attack_rw_<timestamp>.realworld.parquet`
- Resumo: `reports/attack_rw_<timestamp>.realworld_summary.json`

Se o modelo passar nos dois gates de validacao, ele e promovido para:
- `models/attack_latest.onnx`
- metadados `attack_latest.*.json`

## Como interpretar o summary

Arquivo: `reports/*.realworld_summary.json`

Campos principais:
- `training_metrics`: performance no conjunto de treino/teste interno.
- `realworld_metrics`: precision/recall/fpr no dataset de validacao realista.
- `validation_exit_codes`: status das duas validacoes.
- `passed`: promocao final do modelo.

## Evolucao recomendada

Quando voce passar a ter logs benignos reais:
1. use esses logs como fonte principal de legitimidade;
2. mantenha `Faker` como complemento, nao como base;
3. rode o mesmo workflow para manter comparabilidade entre retreinos.

