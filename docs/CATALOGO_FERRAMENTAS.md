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
| 5 | Preservação de evidências (estilo OpenArchive Save): captura de página por URL com hash e timestamp, original x cópia de trabalho, manifesto de hashes assinado, verificação periódica, pacote exportável verificável | Seção OpenArchive | Planejado |
| 6 | Geoespacial: mapa de posições de fotos e IPs no caso, camadas, exportação GeoJSON/KML | Mapas e dados geoespaciais | Planejado |
| 7 | Investigador assistido por IA (opcional, chave própria): planejar consultas, encadear pivôs, relatório que separa evidência, inferência e hipótese | IA, agentes e automação; IntelByte AI | Planejado; depende de escolha de provedor |
| 8 | Notícias, dados abertos e pesquisa acadêmica: GDELT, feeds RSS, Crossref/OpenAlex, portais de dados abertos | Pesquisa acadêmica, notícias e dados abertos | Planejado |
| 9 | Qualidade e operação: painel de saúde das fontes, cotas por conector, retentativas, histórico de consultas, trilha de auditoria ampliada | Operação, observabilidade; Qualidade | Planejado |

## Fora do escopo

| Itens | Motivo |
| --- | --- |
| Busca em bases vazadas, stealer logs, IntelX, "contas associadas a um e-mail", contexto de contas Google por e-mail | Dependem de dados roubados ou de testar a recuperação de senha de terceiros sem consentimento. O HIBP (só nomes de vazamentos, com chave própria) cobre o uso legítimo. |
| Análise de dispositivos comprometidos (seção "versão defensiva" do IntelByte) | Na prática exige processar logs de malware com credenciais e sessões de terceiros. |
| Usuários, times, permissões, planos, cobrança, checkout, créditos, missões, tickets de suporte | O GARBAGE é local e de um único operador (ver README e SECURITY.md); não há contas nem cobrança. |
| Verificação de portas, testes ativos e captura de screenshot de terceiros | Só para ativos próprios e com autorização explícita; entram, se entrarem, atrás do controle `intel.allow_target_contact`. |
| Armazenamento em fita, S3 corporativo, WORM em hardware (GRAU DATA) | Infraestrutura corporativa, não funcionalidade de uma estação local. O bloco 5 cobre integridade e imutabilidade lógica. |
