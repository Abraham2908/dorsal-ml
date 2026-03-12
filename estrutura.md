dorsal-ml-pipeline/
├── parsers/                          # Parsers por fonte de dados
│   ├── payload_repos_parser.py       # PayloadAllTheThings + SecLists
│   ├── burp_parser.py                # Burp Suite Pro (XML + JSON)
│   ├── zap_parser.py                 # OWASP ZAP (JSON)
│   ├── acunetix_parser.py            # Acunetix (JSON REST API)
│   ├── gateway_telemetry_parser.py   # Telemetria anonimizada do gateway
│   └── normal_traffic_generator.py   # Tráfego legítimo sintético (Faker)
├── agents/
│   ├── strix_agent.py                # 🦉 Threat Intel (CVE/NVD)
│   └── shannon_agent.py              # 🧮 Análise de Entropia
├── training/
│   ├── build_dataset.py              # Combina TUDO → dataset Parquet
│   ├── train_attack_model.py         # RandomForest → ONNX
│   └── validate_model.py             # Valida critérios obrigatórios
├── utils/
│   └── feature_extraction.py         # 30+ features por request
├── scripts/
│   ├── setup_data_sources.sh         # Setup inicial (roda 1x)
│   └── weekly_retrain.sh             # Cron semanal (todo domingo 02h)
├── configs/pipeline_config.json
├── requirements.txt
└── README.md
