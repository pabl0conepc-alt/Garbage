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
| 6. Investigação visual | parcial | Existe grafo, painel por nó, pivô, layouts, foco, exportação SVG. Falta: seleção múltipla, fixar/ocultar nós, minimapa, desfazer/refazer, exportação PNG e dos dados do grafo (JSON/GraphML), ícones por tipo no nó, histórico de enriquecimento por nó |
| 7. Motor de transformações | parcial | Conectores + promoção já fazem "entidade → consulta → novas entidades". Falta o conceito explícito de transform (entrada → saída, parâmetros, logs, tempo estimado) e registro extensível por plugin |
| 8. SOCMINT | parcial / fora | Dentro do escopo: dados públicos de **organizações e comunidades** (repositórios e organizações do GitHub, metadados públicos de canais e servidores). Fora: perfis e histórico de pessoas |
| 9. Identidade digital | fora | Ver seção 4 |
| 10. Infraestrutura | existe (quase todo) | DNS, rDNS (IPinfo/Shodan), RDAP, ASN, geolocalização de rede, CT, TLS, cabeçalhos, tecnologias, portas (Shodan), histórico (Wayback). Falta: árvore de subdomínios dedicada e DNS passivo (só com provedor pago) |
| 11. Mídia | parcial | Metadados, hashes e EXIF básico. Falta: hash perceptual e duplicatas visuais, OCR (dependeria do Tesseract, opcional), frames de vídeo (dependeria do ffmpeg, opcional) |
| 12. GEOINT | falta | Mapa sem tiles externos (CSP) para coordenadas de EXIF de arquivos fornecidos pelo usuário e localização aproximada de **redes**, sempre com origem e precisão |
| 13. CTI | parcial | Falta: Sigma, cliente TAXII 2.1, feeds periódicos, perfis de grupos (os dados do ATT&CK já estão no banco) |
| 14. Dark web | fora por ora | Exige Tor e fontes curadas; sem desenho seguro definido. Pode entrar depois como consulta a listas públicas de domínios onion em feeds de CTI |
| 15. Casos | parcial | Falta: objetivo, arquivar, duplicar, exportar/importar o caso inteiro |
| 16. Evidências | parcial | SHA-256 e reverificação existem. Falta: cadeia de custódia (eventos), anotações por evidência, exportação/importação |
| 17. Monitoramento | falta | Previsto como fase 9 do plano |
| 18. Plugins | falta | Há registro de conectores e de módulos, mas não um formato de plugin com manifesto, permissões e isolamento |
| 19. Normalização e resolução | parcial | Resultados já são normalizados (tipo, valor, fonte, hash da resposta, data). Falta a resolução explícita com níveis exata/provável/fraca |
| 20. Pesquisa global | parcial | Busca existe sem ranking; FTS5 previsto na fase 10 |
| 21. Relatórios | parcial | HTML, JSON, CSV, Markdown, STIX, MISP e impressão. Falta: escolher seções, incluir grafo e metodologia |
| 22. Arquitetura | existe | SQLite com migrações, cache, limites de taxa, erros estruturados. Execução assíncrona de consultas falta (fase 9) |
| 23. Design | existe | Monocromático, dock flutuante, cantos arredondados; ajuste contínuo |
| 24. Segurança | parcial | Anti-SSRF, CSP, validação, SQL parametrizado, chaves nunca devolvidas pela API, travas de rede. Sem autenticação (servidor só em loopback) e sem criptografia em repouso |

## 3. Problemas encontrados

1. O registro de módulos ainda marca `nvd-connector` e `external-osint-connectors` como "planejado, não implementado", mas os conectores existem desde as fases 2 e 7. A tela de módulos fica inconsistente.
2. Telas novas (ATT&CK, YARA, painel analítico) não aparecem no registro de módulos e não podem ser desligadas por ele.
3. Os resumos de atividade são gravados em inglês no backend e traduzidos por padrões no front; cada ação nova exige um padrão novo (três estavam faltando e foram corrigidos agora).
4. O arquivo original analisado não é guardado (só o resultado), então regras YARA novas não podem ser reaplicadas a análises antigas; isso está documentado na tela.
5. O grafo carrega no máximo 500 entidades e 1000 relacionamentos.
6. Consultas multifonte são síncronas: a tela espera a fonte mais lenta (crt.sh pode levar ~27 s).
7. A pesquisa global usa `LIKE`, sem ranking.

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

1. **Fundação** — formato de transform (entrada, saída, parâmetros, logs, tempo) sobre os conectores; registro de módulos corrigido e completo; resolução de entidades com níveis exata/provável/fraca.
2. **Investigação visual** — seleção múltipla, fixar e ocultar, minimapa, desfazer/refazer, exportação PNG e JSON/GraphML (e importação), ícones por tipo, histórico de enriquecimento no painel do nó.
3. **Pesquisa** — consultas assíncronas com progresso por fonte; FTS5 com ranking na busca global; conectores públicos de organizações e comunidades (GitHub, metadados públicos de canais e servidores).
4. **Inteligência especializada** — hash perceptual e duplicatas de imagem; mapa GEOINT local; Sigma; cliente TAXII 2.1; typosquatting em Rust (pendente da fase 8 original).
5. **Plugins** — manifesto, descoberta em pasta local, permissões declaradas, execução isolada em processo separado.
6. **Casos e evidências** — objetivo, arquivar, duplicar, exportar/importar caso; cadeia de custódia e anotações de evidência; relatórios com seleção de seções, grafo e metodologia.
7. **Monitoramento** — consultas salvas com agenda local, diferença entre execuções e notificações.
8. **Refinamento** — acessibilidade, testes de ponta a ponta, desempenho do grafo, documentação e matriz OpenArchive atualizadas.
