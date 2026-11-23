# Catálogo de ferramentas: o que existe e plano por blocos

Referência: `Ferramentas.md` (1716 itens em 24 categorias, mais as seções
IntelByte e OpenArchive). Este documento mapeia cada categoria para o que o
GARBAGE já faz, o bloco em que entra e o que fica fora do escopo, com o motivo.

Legenda: **Existe** = já implementado · **Bloco N** = planejado · **Fora** =
não será implementado.

## Já existente antes deste plano

| Área do catálogo | O que o GARBAGE já cobre |
| --- | --- |
| DNS e infraestrutura | DNS completo por DoH (A, AAAA, CNAME, MX, NS, TXT, CAA, SPF, DMARC), RDAP/WHOIS, ASN (Team Cymru, RIPEstat, PeeringDB), IPinfo, Shodan/InternetDB, GreyNoise |
| Certificados | Certificado TLS ao vivo, crt.sh, Cert Spotter |
| Websites | Fingerprint web: cabeçalhos de segurança, cookies, redirecionamentos, tecnologias, favicon hash, título e meta; Wayback Machine |
| Domínios parecidos | Detecção de lookalike/typosquatting contra o workspace |
| Threat intel | VirusTotal, AbuseIPDB, OTX, URLhaus, ThreatFox, MalwareBazaar, CIRCL, urlscan, NVD, OSV, EPSS, CISA KEV, MITRE ATT&CK, exportação STIX |
| Arquivos | Análise estática de PDF, Office, ZIP/TAR/GZIP, imagens, ELF/PE/Mach-O; YARA; ssdeep/TLSH; metadados; strings |
| Casos e grafo | Investigações, observações, linha do tempo, entidades, aliases, resolução de entidades, quadro, grafo, importação/exportação |
| Evidências | Upload com SHA-256, verificação de integridade, cadeia de custódia básica |
| Relatórios | JSON, CSV, Markdown, HTML |
| Contas (PR #47) | Discord, Roblox, Telegram, username em 11 sites, HIBP, GPS de fotos, webhook |

## Blocos

| Bloco | Conteúdo | Itens do catálogo | Estado |
| --- | --- | --- | --- |
| 1 | Postura de e-mail e domínio: nota de SPF/DMARC/DKIM/DNSSEC/MTA-STS/TLS-RPT/BIMI/CAA, provedor de e-mail, domínio descartável; análise offline de cabeçalhos de e-mail (caminho, autenticação, alinhamento, sinais de phishing, indicadores) | 51–58, 72, 73, 86–92 | **Feito** |
| 2 | Username avançado: normalização, variações (separadores, dígitos, prefixos, sufixos, erros de uma letra), traços estruturais, Minecraft e Steam públicos, 17 sites | 1–5, 9, 10, 12, 24, 25; IntelByte "Minecraft/Steam" | **Feito**; comparação lado a lado de perfis e pontuação de correspondência (36, 37) ficam para o bloco 9 |
| 3 | Watchlists e monitoramento: identificadores próprios ou autorizados, verificação periódica (1 h a 7 dias), comparação com a verificação anterior, alertas de mudança e de expiração de certificado e domínio, painel de alertas e webhook | 22, 23, 74–77, 83; Monitoramento e alertas; IntelByte "Watchlists" | **Feito**; diff visual de páginas (119–121) fica para o bloco 4 |
| 4 | Web passivo: robots.txt e caminhos sensíveis, sitemap e suas seções, SEO, Open Graph, canonical, hreflang, manifest, pontos fracos da CSP, conteúdo misto, hosts externos e hash do texto visível (mudança de página via watchlist) | 101–135 (exceto 112, 116, 122, 132), 119–121 | **Feito**; screenshot (112), verificação de links quebrados (116) e acessibilidade (122) exigem várias requisições ao alvo e ficam para depois |
| 5 | Preservação de evidências: captura de página com bytes originais, URL final, status, redirecionamentos, IP, cabeçalhos e horário; cópia de trabalho só com texto; pacote ZIP com manifest.json, cadeia de custódia, SHA256SUMS e verify.py independente; reverificação diária com alerta | Seção OpenArchive (hash na coleta, original x cópia, manifesto, verificação posterior, trilha de custódia, proveniência) | **Feito**; assinatura digital do manifesto, criptografia e envio a Internet Archive/Nextcloud ficam pendentes |
| 6 | Geoespacial: página Mapa com GPS de fotos (evidências e análises), localização aproximada de rede de IPs consultados no caso e pontos manuais; filtro por caso, detalhe com link para OpenStreetMap, exportação GeoJSON e KML | Mapas e dados geoespaciais | **Feito**; mapa base com tiles e geocodificação de endereços ficam de fora (o servidor não baixa mapas) |
| 7 | Investigador IA: modelo local (Ollama, LM Studio, llama.cpp, vLLM) ou API compatível com OpenAI (OpenRouter, OpenAI…) ou Anthropic; o modelo planeja e encadeia consultas multifonte, o GARBAGE executa com as permissões normais; relatório com evidência, inferência, hipótese e o que não foi confirmado; histórico de sessões e etapas | IA, agentes e automação; IntelByte AI | **Feito**; chat livre em tela cheia e orçamento diário por plano ficam de fora |
| 8 | Notícias, pesquisa e feeds: tipo de consulta topic:<termos> com GDELT, Hacker News, Wikipedia e Wikidata, Crossref e OpenAlex; leitor de feeds RSS/Atom por URL; topic também funciona em watchlists | Pesquisa acadêmica, notícias e dados abertos | **Feito**; portais de dados abertos (CKAN) ficam para depois: o endpoint do catalog.data.gov saiu do ar e o dados.gov.br exige cadastro |
| 9 | Qualidade e operação: comparação lado a lado de duas consultas com pontuação explicável (nome, nome normalizado, imagem, sites, links, bio, outros achados) e aviso de que não é identificação; nova tentativa automática em falhas temporárias (5xx, timeout); uso do dia por fonte (consultas, erros, cache) | 36, 37; Operação e observabilidade; Qualidade e confiabilidade | **Feito**; cotas configuráveis por fonte ficam para depois |

## Fora do escopo

| Itens | Motivo |
| --- | --- |
| Busca em bases vazadas, stealer logs, IntelX, "contas associadas a um e-mail", contexto de contas Google por e-mail | Dependem de dados roubados ou de testar a recuperação de senha de terceiros sem consentimento. O HIBP (só nomes de vazamentos, com chave própria) cobre o uso legítimo. |
| Análise de dispositivos comprometidos (seção "versão defensiva" do IntelByte) | Na prática exige processar logs de malware com credenciais e sessões de terceiros. |
| Usuários, times, permissões, planos, cobrança, checkout, créditos, missões, tickets de suporte | O GARBAGE é local e de um único operador (ver README e SECURITY.md); não há contas nem cobrança. |
| Verificação de portas, testes ativos e captura de screenshot de terceiros | Só para ativos próprios e com autorização explícita; entram, se entrarem, atrás do controle `intel.allow_target_contact`. |
| Armazenamento em fita, S3 corporativo, WORM em hardware (GRAU DATA) | Infraestrutura corporativa, não funcionalidade de uma estação local. O bloco 5 cobre integridade e imutabilidade lógica. |

## Integração com a linha dos PRs #20–#46

Os PRs #20 a #46 (busca BR, contratos e sanções, MISP/OpenCTI, ClamAV,
TAXII/Sigma, plugins, casos, monitoramento, assistente, redesign, GEOINT,
pivô automático) foram integrados ao `main` junto com os blocos 1–9. Onde as
duas linhas tinham o mesmo recurso, ficou uma implementação:

| Recurso | Ficou | Veio da outra |
| --- | --- | --- |
| EXIF / GPS | `modules/exif.py` dos PRs #20–#46 (JPEG, PNG, WebP, TIFF; coordenada inválida marcada) | — |
| Monitoramento | `monitoring.py` (monitores, notificações, webhook Discord/Slack/JSON) | filtro de valores que mudam sozinhos e aviso de certificado ou domínio perto de expirar (bloco 3); as watchlists foram removidas |
| Mapa | Mapa GEOINT com mapa-base local | fotos guardadas como evidência, pontos manuais e exportação GeoJSON/KML (bloco 6); a página Mapa foi removida |
| Cabeçalhos de e-mail | `modules/email_analysis.py` (.eml, links disfarçados, anexos) | sinal "SPF/DKIM não alinhados", horários fora de ordem e nível de risco (bloco 1); a aba da pesquisa foi removida |
| Modelo de IA | Uma configuração só (`ai.provider`, `ai.base_url`, `ai.model`, chave "AI model") para o assistente e o Investigador IA | o assistente passou a aceitar modelos locais, APIs compatíveis com OpenAI e Anthropic; a configuração antiga com chave do OpenRouter continua funcionando |
| Pacote de evidências | Os dois ficam: pacote portável do caso (reimportável) e pacote verificável (verify.py) | o pacote verificável usa a cadeia de custódia com hash dos PRs #20–#46 |
| Webhook | O do monitoramento | o webhook por consulta (PR #47) foi removido; alertas de integridade usam o do monitoramento |

As migrações das duas linhas usavam os números 10–12 para tabelas diferentes.
Agora uma migração conta como aplicada pela descrição, e bancos criados por
qualquer uma das linhas recebem as tabelas da outra ao abrir.
