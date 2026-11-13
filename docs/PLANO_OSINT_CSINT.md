# Plano — expansão OSINT / CTI do GARBAGE

Data da pesquisa: 2026-11-12. Este documento é um plano: nada aqui está
implementado ainda. "CSINT" foi interpretado como inteligência cibernética
(CTI — infraestrutura, malware, vulnerabilidades e ameaças).

## 1. Referências

### 1.1 openarchivex.net

O site resolve a pergunta em aberto da
[matriz anterior](OPENARCHIVE_FEATURE_MATRIX.md): o "OpenArchive" pretendido é
o **OpenArchive X**, uma plataforma comercial de OSINT. O site anuncia estas
funções:

| Função no site | Natureza | Decisão |
| --- | --- | --- |
| Multi-Source Search: uma consulta enviada a 60+ fontes ao mesmo tempo | Arquitetura de consulta paralela | **Adotar como base**, com fontes públicas e lícitas |
| Status das fontes em tempo real | Observabilidade dos conectores | **Adotar** |
| OSINT Pivot: grafo recursivo a partir de um artefato | Expansão de grafo | **Adotar**, com profundidade limitada e aprovação do analista a cada salto |
| IP Lookup (geolocalização, ASN, rede) | Inteligência de infraestrutura | **Adotar** |
| Investigation Board | Já existe no GARBAGE | **Evoluir** |
| API REST e exportação JSON/CSV | Já existe | **Evoluir** (webhooks locais) |
| Busca em bases de vazamentos (950B+ registros, Snusbase, LeakCheck, BreachDirectory) | Dados pessoais obtidos ilegalmente | **Não implementar** |
| Busca em *stealer logs* | Credenciais roubadas por malware | **Não implementar** |
| Discord/Telegram/Roblox OSINT, telefone, VIN | Rastreamento de pessoas | **Não implementar** |
| "Spider" automático de contas, vazamentos e handles de uma pessoa | Montagem de perfil de pessoas físicas (doxxing) | **Não implementar** |
| "Sem logs, sem rastros" | Antiforense | **Não implementar**: o GARBAGE mantém trilha de auditoria e proveniência |

Motivos da exclusão: essas bases contêm dados pessoais e credenciais
roubados. Consultá-las, armazená-las ou cruzá-las expõe o usuário a
responsabilidade legal (LGPD, Lei 12.737/2012) e contraria os não-objetivos já
documentados no projeto (sem doxxing, sem coleta encoberta). O GARBAGE adota a
**arquitetura** do OpenArchive X (fan-out, correlação, pivô, quadro) aplicada a
**infraestrutura e ameaças**, não a pessoas.

### 1.2 Repositórios usados como base

Somente projetos grandes e ativos (estrelas e último push conferidos via API do
GitHub em 2026-11-12).

| Repositório | ★ | Linguagem | Licença | O que tomar como base |
| --- | --- | --- | --- | --- |
| smicallef/spiderfoot | 24,5k | Python | MIT | Modelo de módulos por evento: cada módulo declara os tipos que consome e produz; o motor encadeia |
| laramies/theHarvester | 18,3k | Python | GPL-2.0 | Catálogo de fontes passivas de domínio (CT, DNS, motores) — **só ideias**, sem copiar código |
| owasp-amass/amass | 15,5k | Go | não declarada na API (verificar) | Grafo de ativos de infraestrutura, enumeração passiva de subdomínios, ASN/netblocks |
| projectdiscovery/subfinder | 14,8k | Go | MIT | Fontes passivas de subdomínio e limitação de taxa por fonte |
| projectdiscovery/httpx · dnsx | 10,6k · 2,9k | Go | MIT | Sondagem HTTP/DNS em lote, impressões digitais (título, servidor, favicon hash, TLS) |
| intelowlproject/IntelOwl | 4,8k | Python | AGPL-3.0 | Orquestração de "analyzers" por tipo de observável e "playbooks" — **só arquitetura** |
| MISP/MISP · OpenCTI | 6,7k · 10,4k | PHP · TS | AGPL / Apache | Modelo de eventos, taxonomias, galáxias e STIX 2.1 |
| VirusTotal/yara | 10,0k | C | BSD-3 | Motor de regras para arquivos — integrar via C |
| mandiant/capa | 6,3k | Python | Apache-2.0 | Detecção de capacidades em binários (regras ATT&CK/MBC) |
| lief-project/LIEF | 5,7k | C++ | Apache-2.0 | Parsing robusto de ELF/PE/Mach-O |
| ReFirmLabs/binwalk | 14,7k | Rust | MIT | Varredura de assinaturas embutidas (firmware/carving), sem extrair |
| mitre/cti · oasis-open/cti-python-stix2 | 2,2k · 0,4k | JSON · Python | — · BSD-3 | Base ATT&CK em STIX e formato de exportação |
| jivoi/awesome-osint · hslatman/awesome-threat-intelligence | 31k · 10,9k | listas | — | Catálogo para escolher fontes públicas |

Excluídos de propósito:

- **sherlock / maigret**: enumeram contas de uma pessoa por nome de usuário.
- **nuclei**: varredura ativa de vulnerabilidades em sistemas de terceiros.

Regra de licença: o GARBAGE não tem arquivo `LICENSE`. Código de projetos
GPL/AGPL **não** será copiado; serão usadas apenas ideias e formatos públicos.
Bibliotecas permissivas (YARA, LIEF, TLSH via implementação própria) entram
como dependências opcionais e com fallback.

## 2. Princípios que não mudam

1. Local-first: servidor só em loopback, dados no SQLite local.
2. Toda consulta externa é **explícita**: o analista dispara, vê a fonte e o
   custo, e o resultado fica com proveniência (fonte, URL, hora, hash da
   resposta).
3. Somente **coleta passiva** de fontes públicas ou com chave do próprio
   usuário. Nenhuma varredura ativa de alvos de terceiros.
4. Correlação não é atribuição: os resultados mantêm status de verificação.
5. Nenhum arquivo enviado é executado. Os motores nativos só leem bytes.
6. Todo módulo novo entra no registro de módulos, tem testes e fallback em
   Python puro.

## 3. Arquitetura nova

```
UI (vanilla JS)
   │  /api/intel/run   /api/intel/sources   /api/intel/pivot
   ▼
Orquestrador de consultas (Python, asyncio + ThreadPool)
   ├─ Registro de conectores (tipo de entrada → tipos de saída, como no SpiderFoot)
   ├─ Limitador de taxa, cache com TTL, orçamento por fonte, painel de status
   ├─ Cliente HTTP seguro (anti-SSRF: bloqueia IPs privados, resolve uma vez, limite de bytes/tempo)
   └─ Normalizador → entidades, indicadores e observações com proveniência
   ▼
SQLite (tabelas novas: intel_runs, intel_results, source_status, cache)
   ▲
Motores nativos opcionais (C, C++, Rust) com fallback Python
```

## 4. Melhorias nas ferramentas existentes

| Ferramenta atual | Melhoria | Linguagem |
| --- | --- | --- |
| Motor de indicadores | Novos tipos: CVE, ASN, BTC/ETH, MAC, JA3/JA4, regras YARA/Sigma referenciadas; *defang/refang* completo; detecção de domínio IDN/homógrafo | Python + Rust (extração rápida em lote) |
| Correlação | Pontuação por fontes independentes e decaimento no tempo; correlação por similaridade de arquivo (TLSH/ssdeep) além de valor exato | Python + C (TLSH/ssdeep) |
| Análise de arquivos | YARA opcional; capacidades estilo capa; hashes difusos; imphash, rich header, assinatura Authenticode (só leitura); varredura de assinaturas embutidas estilo binwalk; mais formatos (OLE/VBA, LNK, ISO, RTF, MSI) | C (YARA, parsers), C++ (LIEF opcional), Rust (scanner de assinaturas) |
| Análise de imagens | EXIF/XMP/IPTC completos, GPS só quando presente no arquivo, miniaturas embutidas, detecção de edição por inconsistência de metadados | Python + Rust |
| Grafo | Expansão por pivô com profundidade limitada, centralidade, comunidades (Louvain), caminhos mais curtos, layout em C++ para grafos grandes | C++ |
| Quadro | Soltar resultados de consulta direto no quadro; agrupar por fonte; linha do tempo do quadro | JS |
| Pesquisa global | SQLite FTS5 com ranking e filtros | Python |
| CISA KEV | Cruzar KEV com CVEs vistos no caso; adicionar EPSS (FIRST) e NVD (marcado como planejado hoje) | Python |
| Relatórios | Exportação STIX 2.1 e MISP JSON; PDF via fluxo de impressão | Python |

## 5. Ferramentas novas (não existem no GARBAGE)

Todas passivas e baseadas em fontes públicas ou com chave do usuário.

| # | Ferramenta | O que faz | Fontes / base | Linguagem |
| --- | --- | --- | --- | --- |
| 1 | **Multi-Source Search** | Um artefato (domínio, IP, hash, URL, CVE, ASN) consultado em paralelo em todas as fontes compatíveis, com resultado deduplicado | Arquitetura do OpenArchive X e do SpiderFoot | Python |
| 2 | **Painel de fontes** | Status em tempo real, latência, cota e erros de cada conector | OpenArchive X | Python + JS |
| 3 | **Inteligência de domínio** | RDAP/WHOIS, DNS completo (A, AAAA, MX, NS, TXT, CAA, SPF/DMARC), subdomínios por Certificate Transparency (crt.sh), histórico no Wayback Machine | amass, subfinder, theHarvester (só ideias) | Python + Rust (resolução DNS em lote) |
| 4 | **Inteligência de IP/ASN** | ASN, prefixo, organização (RDAP/RIR, Team Cymru), rDNS, geolocalização de bases abertas (opcional, offline) | OpenArchive X "IP Lookup", amass | Python + C (busca em árvore de prefixos) |
| 5 | **Impressão digital web** | Um GET explícito: status, título, servidor, cabeçalhos de segurança, certificado TLS, hash do favicon (mmh3), tecnologias | httpx | Python + Rust (hash/parse) |
| 6 | **Inteligência de certificados** | Cadeia, SAN, emissor, validade, pivô por SAN e por chave pública | crt.sh, CT logs | Python + C++ (parse X.509) |
| 7 | **Reputação com chave do usuário** | Conectores opcionais: VirusTotal, AbuseIPDB, Shodan, GreyNoise, URLhaus, ThreatFox, OTX | IntelOwl (só arquitetura) | Python |
| 8 | **Pivô OSINT** | Expande um nó do grafo 1 salto por vez com os conectores acima; o analista aprova cada salto | OpenArchive X "OSINT Pivot" | Python + C++ |
| 9 | **Detecção de typosquatting** | Gera variações (homóglifos, troca, omissão, TLD) e verifica quais existem no DNS/CT | dnstwist (ideia), motor Rust atual | Rust |
| 10 | **Mapeamento ATT&CK** | Base MITRE ATT&CK offline; vincular técnicas a casos e achados de arquivos | mitre/cti | Python |
| 11 | **Motor de regras YARA** | Criar, testar e rodar regras sobre evidências locais | VirusTotal/yara | C |
| 12 | **Similaridade de arquivos** | TLSH/ssdeep para agrupar amostras parecidas no workspace | tlsh, ssdeep | C |
| 13 | **Monitoramento local** | Reexecutar consultas salvas sob demanda ou em agenda local e avisar mudanças (novo subdomínio, novo certificado, nova KEV) | OpenArchive X "webhooks" | Python |
| 14 | **Exportação CTI** | STIX 2.1, MISP e CSV de IOCs | cti-python-stix2, MISP | Python |

## 6. Distribuição por linguagem

| Linguagem | Responsabilidade |
| --- | --- |
| **Python** | Orquestrador, conectores, API, normalização, persistência, testes e fallbacks de tudo |
| **C** | YARA, TLSH/ssdeep, parsers de formatos legados, busca de prefixos IP |
| **C++** | Algoritmos de grafo (centralidade, comunidades, caminhos, layout), parse X.509, LIEF opcional |
| **Rust** | Extração de indicadores em lote, resolução DNS concorrente, typosquatting, scanner de assinaturas embutidas, hashes (mmh3) |

Os motores nativos continuam opcionais (`native/`), carregados via `ctypes`,
com testes de paridade contra o fallback Python, como já acontece hoje.

## 7. Atualização da interface (HTML)

Mantendo o design system monocromático do PR #8:

- Nova tela **Pesquisa multifonte**: campo único que detecta o tipo do
  artefato, lista de fontes com status ao vivo, resultados agrupados por fonte
  e por tipo, botões "adicionar ao caso", "adicionar ao quadro" e "pivotar".
- Nova tela **Fontes**: status, latência, cota, chave configurada ou não.
- Telas **Domínio**, **IP/ASN**, **Certificados**, **Web** e **ATT&CK**,
  ou abas dentro da Pesquisa de inteligência.
- Grafo com expansão por clique (pivô) e métricas novas.
- Análise de arquivos com abas YARA, capacidades e similaridade.
- Configurações com gerenciador de chaves de API (guardadas localmente) e
  limites por fonte.
- Novos ícones no conjunto SVG e novos grupos na sidebar.

## 8. Fases

| Fase | Entrega | Depende de |
| --- | --- | --- |
| 1 | Cliente HTTP seguro (anti-SSRF), cache, limitador, tabelas `intel_*`, registro de conectores — **concluída** (`net.py`, `intel.py`, migração 4) | — |
| 2 | Conectores sem chave: RDAP, DNS, crt.sh, Wayback, Team Cymru, EPSS e KEV local — **concluída** (`modules/intel_connectors.py`). URLhaus e ThreatFox passaram para a fase 7: a abuse.ch agora exige Auth-Key em todas as APIs | 1 |
| 3 | Multi-Source Search + painel de fontes (backend e UI) | 2 |
| 4 | Inteligência de domínio, IP/ASN, certificados e web — **concluída**: domínio e IP/ASN na fase 2; certificado TLS e impressão digital web (com trava própria de contato com o alvo), parser X.509 e hash de favicon em Python | 2 |
| 5 | Pivô no grafo + algoritmos C++ — **concluída**: centralidade (grau, intermediação, harmônica), comunidades Louvain e caminho mais curto em C++ com referência Python idêntica; pivô do nó com aprovação por resultado | 3, 4 |
| 6 | Motores de arquivo — **concluída**: TLSH e ssdeep em C (idênticos ao py-tlsh 5 e ao ssdeep 2.14) com busca de arquivos parecidos; scanner de assinaturas embutidas em Rust (29 formatos, paridade com Python); OLE/VBA, MSI, LNK, ISO 9660 e RTF; motor YARA próprio (subconjunto conferido com o YARA 4.5.5, sem libyara) com conjuntos de regras no workspace | — (paralelo) |
| 7 | Mais fontes — **concluída**: 17 conectores novos. Sem chave: Shodan InternetDB, RIPEstat, PeeringDB, IPinfo, CIRCL hashlookup, urlscan.io, Cert Spotter, NVD, OSV, GreyNoise, OTX e Shodan host. Com chave do usuário: VirusTotal, AbuseIPDB, URLhaus, ThreatFox e MalwareBazaar. Gerenciador local de chaves (migração 6), que nunca devolve a chave | 1 |
| 8 | ATT&CK offline, exportação STIX/MISP, typosquatting em Rust | 2 |
| 9 | Monitoramento local e notificações | 3 |
| 10 | FTS5, revisão de acessibilidade, testes de ponta a ponta, documentação, atualização da matriz OpenArchive | todas |

A fase 6 não depende de rede e pode andar em paralelo às fases 1–5.

| 11 | Visualizações — **concluída**: 8 layouts de grafo (força, comunidade, hierárquico, radial, concêntrico por centralidade, colunas por tipo, circular, grade), tamanho por métrica, foco de 1 a 3 saltos, setas e rótulos, destaque de vizinhos, exportação SVG, matriz de adjacência, linha do tempo, painel analítico com gráficos (paleta validada para daltonismo); tudo em SVG próprio, sem bibliotecas | 5 |

Pedido de 2026-11-12, **fora do escopo e mantido excluído**: busca de contas de
pessoas no Discord, no Roblox ou por nome completo. Isso é rastreamento e
agregação de dados de indivíduos, o mesmo motivo da exclusão do sherlock e do
maigret na seção 1.2. O GARBAGE continua focado em infraestrutura, arquivos e
ameaças.

## 9. Testes

- Cada conector com respostas gravadas (fixtures) e sem rede nos testes.
- Testes de anti-SSRF: IPs privados, DNS rebinding, redirecionamentos, limite
  de bytes e de tempo.
- Paridade nativo × Python para cada motor C/C++/Rust.
- Testes de API para cada rota nova e de bloqueio quando o módulo está
  desativado.
- Verificação no navegador de cada tela nova.

## 10. Decisões pendentes do operador

1. Quais conectores com chave você usa ou pretende assinar (VirusTotal,
   Shodan, AbuseIPDB, GreyNoise, OTX)?
2. Pode haver dependências nativas opcionais (libyara, LIEF), ou tudo deve ser
   implementado do zero no repositório?
3. Monitoramento agendado é desejado, ou só execução manual?
