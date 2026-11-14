# Auditoria do GARBAGE antes da expansão de plataforma

Data: 2026-11-13. Base: branch `feature/attack-stix` (fases 1–8 parciais e 11
do `PLANO_OSINT_CSINT.md`). Este documento é a Fase 1 obrigatória do prompt de
expansão: inventário, lacunas, problemas e decisões de escopo antes de
qualquer implementação nova.

## 1. Inventário real

| Item | Estado medido |
| --- | --- |
| Backend | Python 3.10+ só com a biblioteca padrão (`garbage_intel/`, ~20 mil linhas), servidor HTTP em loopback, 89 rotas (48 GET, 21 POST, 11 DELETE, 7 PATCH, 2 PUT) |
| Banco | SQLite, 7 migrações aditivas, 31 tabelas (casos, entidades, relacionamentos, evidências, fontes, quadros, atividades, análises de arquivo, consultas e resultados de inteligência, cache, status de fontes, chaves de API, regras YARA, ATT&CK) |
| Frontend | JS puro sem framework (`web/`, ~12,8 mil linhas), CSP `default-src 'self'`, 17 telas, design monocromático com dock flutuante |
| Motores nativos opcionais | C (proteções de binário, entropia, TLSH, ssdeep), C++ (métricas, centralidade, Louvain, caminho mínimo), Rust (distância de domínio, scanner de assinaturas), todos com referência Python e testes de paridade |
| Conectores | 28 registrados: 3 locais, 23 de rede passivos (5 exigem chave do usuário) e 2 que contatam o alvo (com trava própria) |
| Análise de arquivos | PDF, ZIP/OOXML, TAR, GZIP, imagens, ELF, PE, Mach-O, OLE (doc/xls/ppt/msg/msi) com VBA, LNK, ISO 9660, RTF; TLSH/ssdeep; assinaturas embutidas; YARA próprio |
| CTI | Indicadores com proveniência, CISA KEV, EPSS, NVD, OSV, OTX, VirusTotal, AbuseIPDB, GreyNoise, Shodan, abuse.ch, ATT&CK offline com mapeamento por caso, exportação STIX 2.1, MISP e CSV |
| Visualização | Grafo com 8 layouts, métricas, comunidades, caminho, pivô, foco por saltos, matriz, linha do tempo, exportação SVG; quadro de investigação; painel analítico |
| Testes | 30 arquivos, 226 testes passando |

## 2. Seções do prompt contra o que existe

Legenda: **existe**, **parcial** (falta parte do pedido), **falta**, **fora**
(não será feito; ver seção 4).

| Seção do prompt | Estado | Observação |
| --- | --- | --- |
| 5. Motor global com detecção de tipo | parcial | Detecta domínio, IP, CIDR, URL, e-mail, hashes, ASN e CVE. Falta: imagem/documento como entrada da pesquisa (hoje vão pela Análise de arquivos), repositórios e organizações |
| 6. Investigação visual | existe (etapa 2) | Seleção múltipla (Shift+clique, área, Ctrl+A) com ações em lote, fixar e ocultar, desfazer/refazer, minimapa, ícones por tipo, histórico de enriquecimento no inspetor, exportação PNG/SVG/GraphML/JSON e importação de GraphML/JSON com prévia |
| 7. Motor de transformações | existe (Fundação) | Transformações declaradas sobre os conectores: entrada, saídas (tipo de entidade e relação), parâmetros, log por execução, tempo médio medido e histórico por entidade, no painel da entidade e no grafo. Falta o registro por plugin (etapa 5) |
| 8. SOCMINT | parcial / fora | Dentro do escopo: dados públicos de **organizações e comunidades** (repositórios e organizações do GitHub, metadados públicos de canais e servidores). Fora: perfis e histórico de pessoas |
| 9. Identidade digital | fora | Ver seção 4 |
| 10. Infraestrutura | existe (quase todo) | DNS, rDNS (IPinfo/Shodan), RDAP, ASN, geolocalização de rede, CT, TLS, cabeçalhos, tecnologias, portas (Shodan), histórico (Wayback). Falta: árvore de subdomínios dedicada e DNS passivo (só com provedor pago) |
| 11. Mídia | parcial | EXIF completo com GPS (etapa 4a), pHash/dHash e imagens visualmente parecidas. Falta: OCR (dependeria do Tesseract, opcional), frames de vídeo (dependeria do ffmpeg, opcional) |
| 12. GEOINT | existe (etapa 4a) | Mapa local (Natural Earth) com GPS do EXIF de imagens analisadas e localização aproximada de redes, sempre com origem e precisão |
| 13. CTI | quase todo (etapa 4b) | Cliente TAXII 2.1 com coleta paginada e envio de indicadores ao caso; regras Sigma do SigmaHQ por técnica; typosquatting em Rust. A coleta periódica de fontes passa pelos monitores (etapa 7). Falta: perfis de grupos |
| 14. Dark web | fora por ora | Exige Tor e fontes curadas; sem desenho seguro definido. Pode entrar depois como consulta a listas públicas de domínios onion em feeds de CTI |
| 15. Casos | existe (etapa 6) | Objetivo, arquivar, duplicar e pacote do caso inteiro com SHA-256, prévia e importação |
| 16. Evidências | existe (etapa 6) | Cadeia de custódia encadeada por hash (registro, verificação, acesso, anotação, exportação, importação, exclusão) e anotações |
| 17. Monitoramento | existe (etapa 7) | Consultas multifonte salvas com intervalo (15 min a 30 dias), agendador local enquanto o servidor está ligado, diferença por fonte, tipo e valor entre execuções (fonte que falhou não conta como remoção), histórico e notificações no sino. Falta: envio por e-mail ou webhook (ficou de fora por mandar dados para fora) |
| 18. Plugins | existe (etapa 5) | Pasta local, manifesto validado, permissões declaradas (hosts, requisições, tempo, saída), aprovação pelo SHA-256 do código, execução em processo separado com rede intermediada; vira transformação |
| 19. Normalização e resolução | existe (Fundação) | Candidatos exatos, prováveis e fracos com regra explicada; fusão aprovada pelo analista, com alias e registro de atividade; pares marcados como distintos não voltam. Pessoas ficam de fora |
| 20. Pesquisa global | existe (etapa 3) | FTS5 com ranking BM25, trechos destacados, sem acento e com prefixo; grupo "mais relevantes"; recai para LIKE sem FTS5 |
| 21. Relatórios | existe (etapa 6) | Seções escolhidas, metodologia gerada dos registros, grafo SVG, custódia e técnicas. Falta: PDF nativo (a impressão do navegador gera PDF) |
| 22. Arquitetura | existe | SQLite com migrações, cache, limites de taxa, erros estruturados. Execução assíncrona de consultas falta (fase 9) |
| 23. Design | existe | Monocromático, dock flutuante, cantos arredondados; ajuste contínuo |
| 24. Segurança | parcial | Anti-SSRF, CSP, validação, SQL parametrizado, chaves nunca devolvidas pela API, travas de rede. Sem autenticação (servidor só em loopback) e sem criptografia em repouso |

## 3. Problemas encontrados

1. ~~O registro de módulos marcava `nvd-connector` e `external-osint-connectors` como "planejado".~~ Corrigido na migração 8; desativá-los agora desliga os conectores correspondentes.
2. ~~Telas novas fora do registro de módulos.~~ ATT&CK, YARA, painel analítico e exportação CTI agora são módulos e protegem suas rotas.
8. ~~Excluir caso, entidade, evidência, fonte ou relação não funcionava: o redesign traduziu o método HTTP `DELETE` para "EXCLUIR".~~ Corrigido na Fundação.
3. Os resumos de atividade são gravados em inglês no backend e traduzidos por padrões no front; cada ação nova exige um padrão novo (três estavam faltando e foram corrigidos agora).
4. O arquivo original analisado não é guardado (só o resultado), então regras YARA novas não podem ser reaplicadas a análises antigas; isso está documentado na tela.
5. O grafo carrega no máximo 500 entidades e 1000 relacionamentos.
9. ~~Passar o mouse sobre um nó redesenhava o grafo em laço e engolia cliques; a exportação SVG aplicava estilos por atributo `style`, bloqueado pela CSP, e saía com fundo transparente.~~ Corrigido na etapa 2.
6. ~~Consultas multifonte síncronas.~~ Assíncronas na etapa 3, com resultados por fonte assim que cada uma responde.
7. ~~Pesquisa global sem ranking.~~ FTS5 na etapa 3.

## 4. Decisões de escopo

Ficam **fora**, porque servem para localizar, perfilar ou expor pessoas a
partir de pouca informação, mesmo restritas a dados públicos:

- busca por nome, sobrenome, nome completo ou telefone;
- enumeração de contas por username em plataformas (estilo sherlock/maigret);
- descoberta de perfis, aliases e "pegada digital" de uma pessoa;
- correlação de identidades entre contas;
- histórico de publicações e comentários de usuários (Reddit, X, Discord, Telegram);
- análise de avatares e relacionamentos sociais de pessoas.

Os tipos de entidade de pessoa (`person`, `username`, `profile`) continuam
existindo para o analista **registrar manualmente** o que já tem; nenhuma
coleta automática é feita sobre eles e as exportações CTI os omitem.

## 5. Plano de execução

Ordem de trabalho, cada item com testes, verificação no navegador e PR:

1. **Fundação** (feito) — formato de transform (entrada, saída, parâmetros, logs, tempo) sobre os conectores; registro de módulos corrigido e completo; resolução de entidades com níveis exata/provável/fraca.
2. **Investigação visual** (feito) — seleção múltipla, fixar e ocultar, minimapa, desfazer/refazer, exportação PNG e JSON/GraphML (e importação), ícones por tipo, histórico de enriquecimento no painel do nó.
3. **Pesquisa** (feito) — consultas assíncronas com progresso por fonte; FTS5 com ranking na busca global; conectores de organizações (GitHub, security.txt). Metadados de canais e servidores de chat ficaram de fora: as APIs públicas de convite expõem quem criou o convite.
4. **Inteligência especializada** (feito) — hash perceptual e duplicatas de imagem; mapa GEOINT local; Sigma; cliente TAXII 2.1; typosquatting em Rust (pendente da fase 8 original).
5. **Plugins** (feito) — manifesto, descoberta em pasta local, permissões declaradas, execução isolada em processo separado.
6. **Casos e evidências** (feito) — objetivo, arquivar, duplicar, exportar/importar caso; cadeia de custódia e anotações de evidência; relatórios com seleção de seções, grafo e metodologia.
7. **Monitoramento** (feito) — consultas salvas com agenda local, diferença entre execuções e notificações.
8. **Refinamento** — acessibilidade, testes de ponta a ponta, desempenho do grafo, documentação e matriz OpenArchive atualizadas.
