# CONSELHO

## Tese central

O ouro do Dorsal nao e apenas o modelo. O ouro e o sistema de verdade que voce construir para:

- coletar trafego legitimo e malicioso com contexto suficiente;
- rotular com confianca graduada;
- separar o que e ataque conhecido, o que e abuso de fluxo, o que e anomalia e o que e operacao legitima;
- promover modelos somente quando passam em cenarios realistas;
- usar o gateway como sensor e atuador, sem violar a privacidade do cliente.

Se eu resumir em uma frase: o caminho da arquitetura esta certo, mas o moat real nao vira de `PayloadAllTheThings + RandomForest`; ele vira do pipeline de dados, rotulagem, validacao e governanca que voce construir em torno das 3 camadas.

## Veredito direto

### Voce esta no caminho certo?

Sim, conceitualmente.

A divisao atual em 3 camadas faz sentido para um produto serio:

1. Camada 1:
   classificador supervisionado global de ataques conhecidos.
2. Camada 2:
   baseline local por cliente para entender comportamento real.
3. Camada 3:
   modelo global com telemetria anonimizada para aprender padroes agregados entre tenants.

Essa divisao e boa porque respeita tres realidades:

- voce precisa ter cobertura desde o dia 1, antes de ter clientes;
- cada cliente tem um perfil operacional proprio que o global nunca vai entender sozinho;
- voce precisa aprender com o conjunto da frota sem puxar payloads, paths reais ou PII para o control plane.

### Onde ainda nao esta "elite"

Hoje o projeto ainda esta forte em bootstrap e fraco em realidade operacional. Os principais motivos:

- a Camada 1 ainda depende bastante de fontes publicas e estaticas;
- o benigno atual ainda e majoritariamente sintetico;
- ainda falta uma trilha forte de hard negatives;
- ainda falta uma taxonomia formal de cenarios, confianca e verdade de rotulo;
- ainda falta um sistema mais maduro para distinguir:
  - tentativa maliciosa;
  - exploracao bem-sucedida;
  - ataque malsucedido em app endurecida;
  - erro legitimo de cliente;
  - anomalia estatistica sem evidenca de ataque.

Se isso nao for corrigido, o risco e treinar um modelo que performa bem no laboratorio e piora quando encontrar clientes com trafego estranho, automacoes legitimas, bursts, retries, integradores agressivos e ataques multi-step de verdade.

## O que o repo ja faz certo

O estado atual do projeto ja mostra alguns sinais bons de maturidade:

- a arquitetura em 3 camadas esta descrita claramente no [README.md](/home/abraham/tools/dorsal-ml/README.md);
- a Camada 1 ja tenta separar fontes, campanhas e hashes canonicos em [training/build_dataset.py](/home/abraham/tools/dorsal-ml/training/build_dataset.py);
- o split da Camada 1 usa grupos por `source_family + campaign_id + payload_hash` em [training/train_attack_model.py](/home/abraham/tools/dorsal-ml/training/train_attack_model.py), o que ajuda a reduzir leakage trivial;
- a camada global de anomalia respeita a premissa de privacidade e trabalha com telemetria agregada em [training/train_anomaly_model.py](/home/abraham/tools/dorsal-ml/training/train_anomaly_model.py);
- o fluxo realista de treino/validacao para a Camada 1 ja foi iniciado em [docs/layer1_realworld_playbook.md](/home/abraham/tools/dorsal-ml/docs/layer1_realworld_playbook.md).

Esse ponto e importante: voce nao esta com a arquitetura errada. Voce esta na etapa em que precisa trocar "pipeline funcional" por "pipeline defensavel como produto".

## O que mais me preocupa hoje

### 1. Excesso de dependencia em payload corpora

Payload repos sao excelentes para bootstrap, regressao e cobertura de assinaturas obvias. Eles nao sao suficientes para formar o detector que vai sustentar o negocio.

Riscos:

- o modelo aprende artefatos lexicais dos payloads publicos;
- fica forte em ataques ja canonizados e fraco em abuso de fluxo;
- aprende mais "cara de payload" do que "comportamento de request malicioso".

### 2. Benigno sintetico demais

O gerador atual em [parsers/normal_traffic_generator.py](/home/abraham/tools/dorsal-ml/parsers/normal_traffic_generator.py) e util para bootstrap. Ele nao substitui:

- browser/mobile clients reais;
- integracoes backend-to-backend;
- jobs;
- retries;
- bursts por horario;
- fluxos quebrados mas legitimos;
- clientes mal configurados;
- automacoes fortes e nao maliciosas.

Sem isso, o falso positivo vai tender a explodir quando o gateway enfrentar clientes de verdade.

### 3. Rotulo fraco ainda muito proximo de rotulo definitivo

O correlator de lab em [training/gateway_correlator.py](/home/abraham/tools/dorsal-ml/training/gateway_correlator.py) e uma base boa, mas hoje ele ainda mistura:

- correlacao forte;
- correlacao temporal;
- match fraco;
- unmatched.

Isso nao deveria ser tratado como uma verdade binaria simples. Isso deveria virar um sistema de confianca e tier de validacao.

### 4. Camada 3 ainda corre risco de overtrust

A Camada 3 esta correta como detector estatistico global, mas anomalia nao e sinonimo de ataque.

Se a camada global virar base direta para bloqueio forte sem calibracao por tenant, modo de operacao e fatia de trafego, voce corre risco alto de punir:

- mudancas legitimas de negocio;
- onboarding de novos integradores;
- burst de marketing;
- erros de rollout do proprio cliente.

## Como eu desenharia o path de elite

O caminho de elite para o Dorsal e montar um sistema de dados em quatro familias.

### Familia 1: ataques publicos conhecidos

Exemplos:

- OWASP Top 10;
- PayloadAllTheThings;
- SecLists;
- ZAP;
- Burp;
- Acunetix;
- findings estruturados de agentes.

Objetivo:

- cobertura inicial;
- regressao de ataques conhecidos;
- treinamento de bootstrap da Camada 1;
- base para features lexicais e de request shape.

### Familia 2: trafego legitimo realista

Exemplos:

- fluxos funcionais em APIs open conhecidas;
- automacao de usuarios com estados reais;
- integracoes simuladas server-to-server;
- jobs periodicos;
- retries;
- bursts sazonais;
- clientes com erro legitimo.

Objetivo:

- reduzir falso positivo;
- ensinar o gateway que trafego "estranho" nem sempre e ataque;
- produzir hard negatives.

### Familia 3: ataques executados contra apps reais

Exemplos:

- apps vulneraveis atras do seu gateway;
- apps endurecidas atras do seu gateway;
- ataques via scanners;
- ataques via agentes de IA;
- ataques multi-step;
- abuso de autorizacao e de logica.

Objetivo:

- sair do mundo de payloads e entrar no mundo de interacoes completas;
- capturar requests, respostas, status, timing, retries, sequencia e efeito final;
- treinar e avaliar em cenarios mais proximos do mundo real.

### Familia 4: feedback operacional e telemetria de tenants

Exemplos:

- estatisticas por endpoint hash;
- contadores de threats;
- anomaly scores locais;
- feedback supervisionado de eventos confirmados;
- drift signals.

Objetivo:

- refinar camada local;
- acelerar camada global;
- criar inteligencia de frota sem puxar dado sensivel.

## O desenho ideal das 3 camadas

## Camada 1: global attack model

### Papel correto

Ser o detector de "ataques conhecidos e semiconhecidos" embarcado desde o primeiro deploy.

### O que ela deve aprender

- padroes lexicais;
- padroes de encoding;
- estrutura de request;
- desvio de shape;
- combinacoes suspeitas de metodo, path, params e body;
- evidencias semanticas de sqli, xss, traversal, ssrf, ssti, auth abuse e afins.

### O que ela nao pode ser

- o unico arbitro do que bloquear;
- o modelo que decide sozinho sobre abuse de fluxo complexo;
- o substituto do baseline local.

### Meta de produto

Alta cobertura inicial com risco controlado de falso positivo em modo:

- score;
- alert;
- mitigacao leve.

Bloqueio forte so depois de maturidade maior por tenant e por cenario.

## Camada 2: baseline local no cliente

### Papel correto

Aprender o normal real daquele cliente, daquele tenant, daquele endpoint e daquele horario.

### Onde mora o valor

- detectar desvios de negocio que o global nao conhece;
- proteger clientes com perfis muito diferentes;
- adaptar thresholds ao ambiente real;
- servir como sensor para drift e feedback.

### Risco principal

Confundir mudanca legitima de comportamento com ataque.

### Recomendacao

A camada local deve produzir:

- score local;
- sinais agregados;
- contadores por janela;
- feedbacks seguros para o control plane.

Ela nao deve depender de enviar dado sensivel.

## Camada 3: global anomaly model

### Papel correto

Aprender padroes agregados da frota, detectar anomalias inter-tenant e acelerar resposta a padroes emergentes.

### Onde ela brilha

- novos spikes de comportamento;
- tenants com mudanca brusca;
- campanhas distribuidas;
- abuso de volume, erro e ip churn;
- padroes que fogem ao baseline historico.

### Onde ela nao pode ser superestimada

Anomalia estatistica sem contexto nao prova ataque. Ela prova que algo mudou.

### Recomendacao

Trate a Camada 3 como:

- fonte de score;
- componente de ensemble;
- gatilho de observacao e endurecimento;
- priorizador de investigacao e retraining.

Nao como veredito unico de bloqueio.

## O laboratorio que eu montaria agora

Como voce ainda nao tem producao, o melhor caminho e um lab controlado, instrumentado e agressivamente automatizado.

### Pilar 1: apps vulneraveis

Voce precisa de APIs vulneraveis para gerar:

- ataques confirmados;
- cadeia de requests real;
- sucesso e falha de exploracao;
- efeito de resposta do gateway.

Isso produz dados com valor muito maior do que payload repos isolados.

### Pilar 2: apps nao vulneraveis ou endurecidas

Isso e tao importante quanto as vulneraveis.

Motivo:

- ataque malsucedido contra app endurecida continua sendo request maliciosa;
- trafego funcional contra app robusta gera benigno realista;
- apps endurecidas produzem hard negatives e avaliam falso positivo com honestidade.

### Pilar 3: pares vulneravel vs endurecida

Sempre que possivel, mantenha versoes pareadas da mesma API:

- uma propositalmente vulneravel;
- uma corrigida/endurecida.

Isso ajuda a separar:

- "payload malicioso";
- "exploracao bem-sucedida";
- "tentativa maliciosa sem sucesso".

Essa separacao e extremamente valiosa para produto de seguranca.

### Pilar 4: trafego legitimo automatizado

Voce precisa de automacao legitima com estado:

- cadastro;
- login;
- refresh;
- consulta;
- criacao e edicao de recursos;
- erros esperados;
- expiracao;
- concorrencia;
- fluxo mobile/web/integracao.

O objetivo aqui nao e so gerar request. E gerar rotina operacional.

### Pilar 5: campanhas de ataque automatizadas

Rode campanhas separadas, com manifesto claro, via:

- scanners classicos;
- scripts dedicados;
- agentes de IA;
- operadores humanos quando necessario.

Cada campanha precisa registrar:

- app alvo;
- versao alvo;
- objetivo;
- tool/agent;
- horario;
- sucesso/falha;
- tipo de ataque;
- confianca do rotulo.

## Uso de agentes de IA para pentest

Faz sentido usar agentes de IA. Eu recomendo, com disciplina.

### Onde eles agregam mais

- BOLA/BFLA;
- auth abuse;
- multi-step workflows;
- combinacoes de navegacao e fuzzing;
- descoberta de caminhos menos obvios;
- abuso de logica de negocio.

### Onde nao confiar cegamente

- veracidade do "sucesso" reportado pelo proprio agente;
- interpretacao de resposta parcial como exploracao confirmada;
- resumo textual do agente sem artefato tecnico.

### Regra de ouro

Agente de IA deve ser tratado como gerador de campanha, nao como oraculo.

Sempre capture:

- prompt/objetivo;
- passos executados;
- requests emitidas;
- respostas observadas;
- recurso final acessado/modificado;
- veredito independente de sucesso ou falha.

## O que seria um dataset de elite

Um dataset de elite nao e apenas grande. Ele e confiavel, diverso, versionado e auditavel.

Cada amostra supervisionada deveria, no minimo, carregar os seguintes campos logicos:

- `label`
- `label_confidence`
- `attack_family`
- `attack_technique`
- `source_family`
- `scenario_type`
- `target_app`
- `campaign_id`
- `lab_run_id`
- `validation_tier`
- `is_synthetic`
- `is_replay`
- `effect_outcome`

## Taxonomia recomendada

### `scenario_type`

Valores recomendados:

- `public_payload`
- `scanner_dast`
- `agent_attack`
- `human_attack`
- `legit_functional`
- `legit_background`
- `hard_negative`
- `chaos_but_benign`

### `validation_tier`

Valores recomendados:

- `gold`
- `silver`
- `bronze`

Definicao:

- `gold`: ataque ou benigno confirmado por instrumentacao forte;
- `silver`: correlacao forte, mas nao perfeita;
- `bronze`: heuristica, finding fraco ou inferencia indireta.

### `effect_outcome`

Valores recomendados:

- `attempt_only`
- `blocked_by_gateway`
- `reached_target`
- `exploit_confirmed`
- `benign_success`
- `benign_error`

Essa separacao e valiosissima para diferenciar o que o gateway viu, o que o alvo recebeu e o que de fato aconteceu.

## Proporcao ideal de treino e validacao

Nao use uma unica distribuicao para tudo.

### Para treino da Camada 1

Use distribuicao controlada para aprendizado, por exemplo:

- 80/20;
- 85/15;
- ou outra distribuicao que mantenha sinal suficiente de ataque.

Objetivo:

- ensinar o modelo.

### Para validacao pre-promocao

Use distribuicao proxima da operacao, por exemplo:

- 98/2;
- 99/1;
- ou fatia empirica observada no seu lab operacional.

Objetivo:

- medir falso positivo de verdade;
- medir degradacao por app e por tenant simulado;
- decidir se o modelo pode ser promovido.

### Regra critica

Modelo so deve virar `latest` se passar:

- treino/holdout supervisionado;
- slices importantes;
- validacao realista;
- latencia;
- estabilidade entre campanhas.

## O que medir se voce quiser ser elite

Precision e recall globais nao bastam.

Voce precisa acompanhar tambem:

- FPR por app;
- FPR por endpoint family;
- FPR por tenant simulado;
- recall por attack family;
- recall em ataques multi-step;
- performance em hard negatives;
- degradacao por campanha nova;
- latencia P50/P95/P99;
- score calibration;
- taxa de divergencia entre camadas;
- taxa de drift local;
- custo operacional do falso positivo.

## Regras operacionais importantes

### Regra 1

Anomalia nao e ataque.

### Regra 2

Ataque malsucedido em app endurecida nao e benigno.

### Regra 3

Erro legitimo de cliente nao e ataque.

### Regra 4

Scanner output nao e ground truth final.

### Regra 5

Benigno sintetico serve para bootstrap, nao para definir sozinho a realidade operacional.

### Regra 6

Dados de tenants nao devem alimentar retreino global sem filtros, tiers de confianca e governanca.

## Os gaps mais importantes do repo atual

### Gap 1: schema de amostra ainda curto

Os contratos em [training/contracts.py](/home/abraham/tools/dorsal-ml/training/contracts.py) ainda nao carregam metadados suficientes para um dataset de elite.

Hoje falta, pelo menos:

- `scenario_type`
- `target_app`
- `attack_family`
- `attack_technique`
- `validation_tier`
- `lab_run_id`
- `effect_outcome`
- `is_replay`

### Gap 2: avaliacao ainda muito global

A avaliacao da Camada 1 em [training/train_attack_model.py](/home/abraham/tools/dorsal-ml/training/train_attack_model.py) e [training/validate_model.py](/home/abraham/tools/dorsal-ml/training/validate_model.py) ainda pode evoluir bastante para slices mais proximas do negocio:

- por app;
- por scenario;
- por tier de validacao;
- por attack family;
- por source confidence.

### Gap 3: correlacao lab ainda heuristica demais

[training/gateway_correlator.py](/home/abraham/tools/dorsal-ml/training/gateway_correlator.py) hoje e bom como bootstrap de rotulo, mas nao como sistema maduro de ground truth.

Evolucao recomendada:

- tiers de validacao;
- manifesto de campanha;
- correlacao por request_id quando disponivel;
- confirmacao por efeito final;
- separacao entre attempt, reach e exploit.

### Gap 4: falta trilha explicita de hard negatives

O projeto precisa de um corpus separado de hard negatives:

- bursts legitimos;
- retry storms;
- client bugs;
- automacao funcional agressiva;
- scraping benigno;
- payloads estranhos porem validos;
- falhas de uso sem malicia.

### Gap 5: promotion governance ainda pode subir muito

Promocao de modelo precisa ser mais do que "passou precision/recall/fpr". Ela precisa registrar:

- quais campanhas treinaram o modelo;
- quais apps entraram;
- qual tier de confianca domina o corpus;
- quais slices falham;
- em qual modo de acao o modelo pode ser usado.

## O caminho de elite em fases

## Fase 0: consolidar o laboratorio

Objetivo:

- sair de dataset estatico e entrar em campanhas controladas.

Fazer:

- subir APIs vulneraveis;
- subir APIs nao vulneraveis/endurecidas;
- colocar todas atras do gateway;
- automatizar trafego legitimo;
- automatizar campanhas de ataque;
- registrar manifestos de campanha.

## Fase 1: formalizar verdade de dataset

Objetivo:

- padronizar rotulo, confianca e taxonomia.

Fazer:

- criar schema canonico de amostra;
- introduzir `validation_tier`;
- distinguir attack attempt, exploit confirmed e benign;
- criar manifestos de dataset/campanha;
- separar treino, validacao e benchmark por app e scenario.

## Fase 2: fortalecer a Camada 1

Objetivo:

- ter classificador global forte sem ficar refem de repos publicos.

Fazer:

- misturar public corpora com campaigns reais de lab;
- adicionar hard negatives;
- avaliar por slices;
- calibrar thresholds por modo de uso.

## Fase 3: amadurecer a Camada 2

Objetivo:

- fazer o baseline local virar vantagem pratica no cliente.

Fazer:

- medir drift;
- separar warm-up de enforcement;
- enviar apenas agregados seguros;
- usar feedback local para enriquecer o global com governanca.

## Fase 4: amadurecer a Camada 3

Objetivo:

- usar inteligencia de frota sem violar privacidade.

Fazer:

- treinar global por cohortes e slices relevantes;
- calibrar score global como componente de ensemble;
- validar contra labels confiaveis quando existirem;
- evitar promotion baseada apenas em anomalia estatistica.

## Fase 5: moat real

Objetivo:

- transformar o pipeline de dados em vantagem dificil de copiar.

Fazer:

- versao de datasets de regressao;
- corpus de ataques reais observados;
- replay continuo;
- promotion gates tecnicos e de negocio;
- telemetria global com governanca forte.

## Backlog tecnico que eu atacaria neste repo

Status em 2026-03-13:

- `[x]` implementado
- `[~]` implementado parcialmente
- `[ ]` pendente

### Prioridade P0

1. `[x]` Expandir contratos em [training/contracts.py](/home/abraham/tools/dorsal-ml/training/contracts.py) para carregar metadados de cenario, app, tier e outcome.
2. `[x]` Enriquecer [training/build_dataset.py](/home/abraham/tools/dorsal-ml/training/build_dataset.py) para persistir esses campos de forma consistente.
3. `[x]` Evoluir [training/gateway_correlator.py](/home/abraham/tools/dorsal-ml/training/gateway_correlator.py) para produzir tiers de confianca e outcomes separados.
4. `[x]` Criar manifesto de campanha/dataset em JSON para cada coleta.

### Prioridade P1

1. `[x]` Adicionar avaliacao por `scenario_type`, `target_app`, `validation_tier` e `attack_family`.
2. `[x]` Criar corpus dedicado de hard negatives.
3. `[x]` Separar melhor datasets de treino, validacao realista e benchmark.
4. `[~]` Criar uma trilha de regressao com apps vulneraveis e endurecidas.
   Situacao atual: pipeline realista e governanca prontos; plano operacional e compose do lab documentados em [LAB_PLAN.md](/home/abraham/tools/dorsal-ml/LAB_PLAN.md) e [labs/docker-compose.layer1-lab.yml](/home/abraham/tools/dorsal-ml/labs/docker-compose.layer1-lab.yml), faltando acumulo continuo de campanhas.

### Prioridade P2

1. `[~]` Melhorar calibracao de score e thresholds por modo de acao.
   Situacao atual: parte de thresholds e rollout por modo ja conectada no runtime/control plane; calibracao estatistica continua por cohort ainda pendente neste repo.
2. `[ ]` Versionar datasets e campanhas com manifestos assinados.
3. `[ ]` Evoluir a camada global para cohorts de tenants e validacao mais forte.
4. `[ ]` Introduzir replay continuo de campanhas antigas para detectar regressao.

## Conselhos de produto, nao so de ML

### 1. Nao venda "bloqueio autonomo total" cedo demais

No inicio, o produto vale mais em:

- score;
- deteccao;
- priorizacao;
- mitigacao leve;
- assistencia ao analista;

do que em bloqueio automatico agressivo em qualquer contexto.

### 2. Trate falso positivo como metrica de negocio

Cada falso positivo em API pode quebrar:

- login;
- checkout;
- integracao financeira;
- app mobile;
- job de sincronizacao;
- webhook.

Isso e mais grave do que um numero de benchmark.

### 3. Seu diferencial e ground truth operacional

Outros tambem podem baixar corpora publicos.
Poucos vao construir um sistema melhor de verdade operacional, campaign manifests, hard negatives, replay e governanca de promocao.

## Minha recomendacao final

Se eu estivesse no seu lugar, eu faria o seguinte com prioridade maxima:

1. `[~]` Montar imediatamente um lab instrumentado com apps vulneraveis e endurecidas atras do gateway.
2. `[~]` Automatizar trafego legitimo com estado, nao apenas requests aleatorias.
3. `[~]` Rodar campanhas de ataque com scanners classicos + agentes de IA.
4. `[x]` Formalizar manifestos, tiers de validacao e outcomes.
5. `[~]` Transformar a Camada 1 em modelo treinado por cenarios reais, nao so por payload repos.
6. Usar a Camada 2 como fonte de verdade local e drift.
7. Usar a Camada 3 como inteligencia global e score complementar, nao como juiz unico.

Observacao de status para os itens `[~]` acima:

- o design operacional do lab foi materializado em [LAB_PLAN.md](/home/abraham/tools/dorsal-ml/LAB_PLAN.md);
- o stack de laboratorio foi materializado em [labs/docker-compose.layer1-lab.yml](/home/abraham/tools/dorsal-ml/labs/docker-compose.layer1-lab.yml);
- os scripts de simulacao legitima e ataque foram materializados em `labs/traffic/`.

## Conclusao

O caminho esta certo.

O que falta nao e "mais um modelo". O que falta e o salto de maturidade de dados:

- mais verdade de campo;
- mais diversidade de benigno;
- mais hard negatives;
- mais cenario completo de ataque;
- mais governanca de promocao;
- mais avaliacao por slices e por custo operacional.

Se voce executar isso com disciplina, o dataset realmente vira o core do negocio.
Nao porque e grande, mas porque vira dificil de reproduzir.
