# CHECK PILOTO DORSAL (ML + GATEWAY + CONTROL PLANE)

Data base: 2026-03-13

## 1) Pre-flight tecnico

- [x] Repos no commit esperado e sem dirty state:
  - [x] `/home/abraham/tools/dorsal-ml` em `main`
  - [x] `/home/abraham/tools/dorsal` em `develop`
- [ ] Ambiente com `python3.11+`, `docker`, `docker compose`, `npm`.
- [ ] DNS/rede local definidos para acesso do gateway ao control plane.
- [ ] Secrets minimos definidos:
  - [ ] `DORSAL_MODEL_KEK`
  - [ ] `DORSAL_MODEL_SIGNING_PRIVATE_KEY` (quando houver empacotamento assinado)
  - [ ] credenciais do org admin no control plane.

## 2) Validacao rapida de qualidade (antes de piloto)

- [x] `dorsal-ml`:
  - [x] `cd /home/abraham/tools/dorsal-ml && .venv/bin/pytest -q`
- [x] `dorsal/control`:
  - [x] `cd /home/abraham/tools/dorsal/control && DORSAL_DATABASE_URL=sqlite:////tmp/dorsal-control-test.db .venv/bin/pytest -q -p no:cacheprovider tests/unit/test_gateways.py tests/unit/test_workspaces_gateways.py tests/unit/test_training_windows.py tests/unit/test_telemetry_gateway_event_contract.py`
- [x] `dorsal/gateway`:
  - [x] `cd /home/abraham/tools/dorsal/gateway && .venv/bin/pytest -q -p no:cacheprovider tests/unit/test_runtime_server.py tests/unit/test_config.py tests/unit/test_entrypoint.py tests/unit/test_sync_client.py`
- [x] `dorsal/dashboard`:
  - [x] `cd /home/abraham/tools/dorsal/dashboard && npm test -- --run`

## 3) Preparar artefatos ML para piloto

- [ ] Bootstrap e dependencias:
  - [ ] `cd /home/abraham/tools/dorsal-ml && make venv && make install-dev && make bootstrap && make setup-data`
- [ ] Rodar treinamento Camada 1 com validacao realista:
  - [ ] `cd /home/abraham/tools/dorsal-ml && make layer1-realworld`
- [ ] Verificar artefatos obrigatorios:
  - [ ] `models/attack_latest.onnx`
  - [ ] `reports/attack_rw_*.realworld_summary.json`
  - [ ] `reports/attack_rw_*.promotion_decision.json`
  - [ ] `reports/dataset_manifest_*.json`
- [ ] Gate de promocao aprovado no JSON:
  - [ ] `decision == "promote"`
  - [ ] sem falha em slices criticos (`scenario_type`, `target_app`, `validation_tier`, `attack_family`)

## 4) Subir stack de piloto (control + dashboard + gateway + alvo)

- [ ] Subir servicos:
  - [ ] `cd /home/abraham/tools/dorsal && DORSAL_HOST_IP=<IP_LAN> docker compose up -d --build`
- [ ] Health checks:
  - [ ] `curl -fsS http://localhost:8000/health`
  - [ ] dashboard carregando em `http://localhost:5173`
- [ ] Confirmar gateway registrado e sincronizando com control plane.

## 5) Configuracao de operacao no Control Plane

- [ ] No dashboard (`/app/settings`), selecionar gateway e configurar Runtime Policy.
- [ ] Iniciar piloto em modo conservador:
  - [ ] `policy_mode=monitor-only`
  - [ ] `default_action=monitor`
  - [ ] `ml_rollout_mode=shadow` ou `assist`
  - [ ] `ml_rollout_percent=10..20`
- [ ] Confirmar thresholds operacionais:
  - [ ] `ml_alert_threshold` inicial (ex: `0.55`)
  - [ ] `ml_block_threshold` inicial (ex: `0.85`)
  - [ ] `ml_anomaly_weight` inicial (ex: `0.30`)
- [ ] Guardrail validado:
  - [ ] se `ml_rollout_mode=enforce`, manter `ml_rollout_percent <= 20`

## 6) Campanha de eficacia (pilot readiness)

- [ ] Rodar campanha baseline:
  - [ ] `cd /home/abraham/tools/dorsal && CAMPAIGN_REPEATS=5 CAMPAIGN_OUTPUT=testing/results/effectiveness-pilot-baseline.json scripts/run_effectiveness_campaign.sh`
- [ ] Coletar metricas:
  - [ ] precision
  - [ ] recall
  - [ ] false_positive_rate
  - [ ] latency p95/p99
- [ ] Criticos de aceite para iniciar piloto assistido:
  - [ ] `precision >= 0.92`
  - [ ] `recall >= 0.95`
  - [ ] `false_positive_rate <= 0.10`
  - [ ] `latency_p95_ms <= 200` (baseline local)

## 7) Testes de resiliencia obrigatorios

- [ ] Simular indisponibilidade de control plane com trafego passando no gateway.
- [ ] Confirmar fail-open conforme politica.
- [ ] Restaurar control plane e validar retomada de sync/telemetria.

## 8) Rollout progressivo recomendado (piloto real)

- [ ] Semana 1:
  - [ ] `monitor-only` + `shadow` (10-20%)
  - [ ] ajuste de thresholds por ruido observado
- [ ] Semana 2:
  - [ ] manter `monitor-only`, mover para `assist` se FPR estabilizar
- [ ] Semana 3+:
  - [ ] considerar `inline` apenas para regras/rotas de alta confianca
  - [ ] considerar `enforce` apenas com guardrail de rollout <= 20%

## 9) Go / No-Go do piloto

## Go

- [ ] criterios de eficacia cumpridos por 2 janelas consecutivas.
- [ ] sem incidente de bloqueio indevido em fluxo critico.
- [ ] observabilidade adequada (eventos, sync, runtime-config auditavel).

## No-Go

- [ ] FPR acima do limite por 2 campanhas.
- [ ] sinais de drift sem recalibracao.
- [ ] instabilidade de sync/policy entre control plane e gateway.

## 10) Evidencias minimas para fechamento

- [ ] Arquivo de resultado da campanha (`testing/results/effectiveness-*.json`)
- [ ] Print/export do Runtime Policy aplicado no gateway piloto
- [ ] Registro de incidentes (mesmo que zero)
- [ ] Decisao final documentada:
  - [ ] `seguir para piloto assistido`
  - [ ] `recalibrar e repetir campanha`
