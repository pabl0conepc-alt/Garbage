"use strict";

/* Multi-source intelligence: one artifact, every compatible connector. */

(function () {
  const G = window.GARBAGE;
  const {
    el, api, toast, pageHeader, panel, badge, emptyState, table, loadingBlock,
    formatDate, shortId, go, state,
  } = G;

  const CONNECTOR_TEXT = {
    "local-structure": ["Fatos estruturais", "Sintaxe, forma canônica e fatos estruturais do artefato. Nada sai da máquina."],
    "local-workspace": ["Workspace local", "Correspondências exatas em entidades, evidências, análises de arquivos e no índice de indicadores."],
    "cisa-kev-local": ["CISA KEV (snapshot local)", "Indica se a CVE está no catálogo KEV salvo localmente. Atualize o catálogo na tela CISA KEV."],
    "dns-doh": ["DNS (DNS over HTTPS)", "Registros A, AAAA, CNAME, MX, NS, TXT, CAA, SPF e DMARC pelo resolvedor público da Cloudflare. O resolvedor vê o nome consultado."],
    "cymru-asn": ["Team Cymru IP→ASN", "ASN de origem, prefixo anunciado, país, registro e nome do AS de um IP ou ASN."],
    rdap: ["RDAP (dados de registro)", "Status, datas, servidores de nome, faixas e contatos de organização (registrar, abuse). Dados pessoais de titulares não são guardados."],
    crtsh: ["Certificate Transparency (crt.sh)", "Nomes em certificados não expirados do domínio e subdomínios, com emissores."],
    wayback: ["Internet Archive (Wayback)", "Capturas arquivadas distintas de um domínio ou URL, com datas e status."],
    "first-epss": ["FIRST EPSS", "Probabilidade e percentil de exploração (EPSS) de uma CVE."],
    "tls-certificate": ["Certificado TLS", "Um handshake TLS na porta 443 do alvo: confiança, protocolo, titular, emissor, validade, SANs, chave, fingerprints e pin SPKI."],
    github: ["GitHub", "Metadados públicos de uma organização (site, repositórios) ou de um repositório a partir de uma URL do github.com. Contas pessoais não são coletadas."],
    typosquat: ["Typosquatting", "Gera erros de digitação, caracteres parecidos, bits trocados e outros TLDs do domínio e pergunta a um resolvedor DNS-over-HTTPS quais existem. Nunca contata as variações."],
    "security-txt": ["security.txt", "O arquivo RFC 9116 que a organização publica: contatos de segurança, política, chave, validade e assinatura. Um GET HTTPS ao servidor do alvo."],
    "web-fingerprint": ["Impressão digital web", "Um GET HTTPS da página do alvo (e do favicon): status, redirecionamentos, cabeçalhos de segurança, cookies, título, tecnologias e hash do favicon."],
    "shodan-internetdb": ["Shodan InternetDB", "Portas abertas, nomes, CPEs, tags e CVEs que as varreduras do Shodan registraram para um IP."],
    ripestat: ["RIPEstat", "ASN de origem, titular do AS, prefixos anunciados e contato de abuso, pelo RIPE NCC."],
    peeringdb: ["PeeringDB", "Operador, tipo de rede, perfil de tráfego e presença em pontos de troca de um ASN."],
    ipinfo: ["IPinfo", "Dono da rede, nome reverso e localização aproximada da rede de um IP."],
    "circl-hashlookup": ["CIRCL hashlookup", "Diz se o hash pertence a software conhecido e distribuído (NSRL e outras bases)."],
    urlscan: ["urlscan.io", "Varreduras públicas de páginas que são ou carregam este domínio, IP, URL ou arquivo."],
    certspotter: ["Cert Spotter", "Certificados emitidos para o domínio e subdomínios, pelo Certificate Transparency."],
    nvd: ["NVD (NIST)", "Registro da CVE: descrição, CVSS, CWE e referências."],
    osv: ["OSV.dev", "Pacotes de código aberto e versões afetadas pela vulnerabilidade, com as correções."],
    virustotal: ["VirusTotal", "Detecções dos motores, rótulo de ameaça, tags e contexto de IPs, domínios, URLs e arquivos."],
    abuseipdb: ["AbuseIPDB", "Denúncias de abuso da comunidade e pontuação de confiança de um IP em 90 dias."],
    greynoise: ["GreyNoise", "Se o IP faz varredura em massa da internet ou é um serviço benigno conhecido."],
    otx: ["AlienVault OTX", "Relatos de ameaça da comunidade (pulses), famílias de malware e técnicas ATT&CK."],
    shodan: ["Shodan", "Serviços, banners, produtos, nomes TLS e CVEs inferidas de um IP."],
    urlhaus: ["URLhaus", "URLs de distribuição de malware ligadas a uma URL, host ou hash de payload."],
    threatfox: ["ThreatFox", "Indicadores de comprometimento ligados a famílias de malware e infraestrutura de botnets."],
    malwarebazaar: ["MalwareBazaar", "Registro de amostra de malware: família, tipo, entrega e hashes de semelhança."],
    "br-documents": ["Documentos e telefones", "Dígitos verificadores de CPF e CNPJ, região fiscal, país, DDD e tipo de linha. Offline; não busca o dono."],
    "brasilapi-cnpj": ["BrasilAPI CNPJ", "Cadastro público da Receita Federal: razão social, situação, atividades, endereço, porte e capital. Sem nomes de sócios."],
    "minhareceita-cnpj": ["Minha Receita", "O mesmo cadastro público da Receita Federal por outro espelho. Sem nomes de sócios."],
    "phishing-lists": ["Listas públicas de phishing", "OpenPhish, Phishing Army, Block List Project e Phishing.Database, baixadas inteiras e conferidas aqui; o domínio não é enviado."],
    misp: ["MISP", "Eventos do seu MISP que contêm o valor."],
    opencti: ["OpenCTI", "Observáveis do seu OpenCTI com o valor: pontuação, etiquetas, indicadores e relatórios."],
    "reverse-ip": ["Domínios no mesmo IP (HackerTarget)", "Domínios cujo DNS aponta para o IP hoje (50 consultas grátis por dia)."],
    "mnemonic-pdns": ["Histórico de DNS (Mnemonic)", "Para onde um domínio ou IP já apontou, com a primeira e a última vez vistos."],
    "ip-lists": ["Listas públicas de IP", "Saída Tor, botnets do Feodo Tracker, Spamhaus DROP e faixas da AWS, Google Cloud, Cloudflare e Fastly. As listas são baixadas inteiras; o IP não é enviado."],
    "dnsbl": ["Listas antispam (DNSBL)", "Sete listas de spam e abuso consultadas pelo DNS público."],
    "hackertarget-hosts": ["HackerTarget", "Hosts do domínio e o IP de cada um, das bases de DNS da HackerTarget (50 consultas grátis por dia)."],
    "otx-hosts": ["AlienVault OTX (hosts)", "Hosts e URLs do domínio vistos pela comunidade OTX."],
    "subdomain-center": ["subdomain.center", "Subdomínios reunidos de bases públicas."],
    "dns-common-names": ["Nomes comuns (DNS)", "Confere se uns cinquenta nomes comuns (www, mail, vpn, api, dev…) existem no domínio, pelo DNS público."],
    "registrobr-cnpj": ["Registro.br", "Quantos domínios .br, blocos de IP e AS estão em nome do CNPJ, e os sites prováveis confirmados pelo titular. Contatos não são lidos."],
    "contratos-cgu": ["Contratos e pagamentos federais (CGU)", "Contratos do governo federal com a empresa e os maiores pagamentos dos últimos dois anos. Usa a mesma chave gratuita."],
    "sancoes-cgu": ["Sanções federais (CGU)", "CEIS, CNEP, CEPIM e acordos de leniência no Portal da Transparência. Precisa de uma chave gratuita."],
    nominatim: ["OpenStreetMap", "Endereço para coordenadas ou coordenadas para endereço, com dados do OpenStreetMap."],
  };

  const RESULT_LABELS = {
    fact: "Fato", warning: "Aviso", notice: "Aviso", entity: "Entidade", evidence: "Evidência",
    "file-analysis": "Análise de arquivo", indicator: "Indicador", "co-occurrence": "Coocorrência",
    lookalike: "Domínio semelhante", "dns-a": "DNS A", "dns-aaaa": "DNS AAAA", "dns-cname": "DNS CNAME",
    "dns-mx": "DNS MX", "dns-ns": "DNS NS", "dns-txt": "DNS TXT", "dns-caa": "DNS CAA",
    "dns-dmarc": "DMARC", asn: "ASN", "as-name": "Nome do AS", "rdap-handle": "Handle RDAP",
    "rdap-name": "Nome no registro", "rdap-status": "Status no registro", "rdap-event": "Evento de registro",
    nameserver: "Servidor de nomes", organization: "Organização", "abuse-contact": "Contato de abuso",
    "ip-range": "Faixa de IP", cidr: "CIDR", "asn-range": "Faixa de ASN", dnssec: "DNSSEC",
    "ct-name": "Nome em certificado", "ct-issuer": "Emissor de certificado",
    "archive-summary": "Resumo do arquivo", "archive-capture": "Captura arquivada",
    epss: "EPSS", "kev-entry": "Entrada KEV",
    "tls-trust": "Confiança TLS", "cert-subject": "Titular do certificado", "cert-issuer": "Emissor",
    "cert-validity": "Validade", "cert-key": "Chave pública", "cert-sha256": "SHA-256 do certificado",
    "cert-spki": "Pin SPKI", "cert-san": "Nome alternativo (SAN)", "cert-san-ip": "IP no SAN",
    "cert-extensions": "Extensões", "http-response": "Resposta HTTP", "http-redirect": "Redirecionamento",
    "security-header": "Cabeçalho de segurança", "missing-header": "Cabeçalho ausente",
    "disclosure-header": "Cabeçalho que expõe software", cookie: "Cookie", "page-title": "Título da página",
    "page-meta": "Meta da página", technology: "Tecnologia", favicon: "Hash do favicon (mmh3)",
    "open-port": "Porta aberta", hostname: "Nome de host", cpe: "CPE", tag: "Tag", cve: "CVE",
    "origin-asn": "ASN de origem", "as-holder": "Titular do AS", "announced-prefix": "Prefixo anunciado",
    routing: "Roteamento", "network-operator": "Operador de rede", "network-owner": "Dono da rede",
    geolocation: "Localização", "known-file": "Arquivo conhecido", scan: "Varredura urlscan",
    subdomain: "Subdomínio", certificate: "Certificado", "cve-record": "Registro da CVE",
    reference: "Referência", "affected-package": "Pacote afetado", alias: "Identificador alternativo",
    verdict: "Veredito dos motores", "threat-label": "Rótulo de ameaça", category: "Categoria",
    file: "Arquivo", "dns-record": "Registro DNS", "final-url": "URL final", "abuse-score": "Pontuação de abuso",
    "internet-noise": "Ruído na internet", "pulse-count": "Relatos (pulses)", pulse: "Relato (pulse)",
    "malware-family": "Família de malware", "attack-technique": "Técnica ATT&CK", host: "Host",
    service: "Serviço", payload: "Payload", "malicious-url": "URL maliciosa", ioc: "IOC", sample: "Amostra",
    "github-org": "Organização no GitHub", website: "Site", repository: "Repositório", "repo-homepage": "Site do repositório",
    "fork-of": "Fork de", "owner-type": "Tipo do dono", "security-txt": "security.txt",
    "security-contact-email": "Contato de segurança (e-mail)", "security-contact-url": "Contato de segurança (URL)",
    "security-contact": "Contato de segurança", "security-policy": "Política de divulgação",
    "security-encryption": "Chave de criptografia", "security-acknowledgments": "Agradecimentos",
    "security-hiring": "Vagas de segurança", "security-csaf": "CSAF",
    typosquat: "Variação existente", "typosquat-summary": "Resumo de typosquatting",
    validity: "Validade", "fiscal-region": "Região fiscal", establishment: "Estabelecimento", formatted: "Formato",
    country: "País", "phone-region": "DDD", "line-type": "Tipo de linha", "check-digits": "Dígitos verificadores", "registrobr-holder": "Registro.br", "company-domain": "Site da empresa", sanction: "Sanção", "sanction-check": "Sanções", "observed-url": "URL vista", "misp-event": "Evento no MISP", "phishing-listed": "Lista de phishing", "phishing-under": "Nomes listados abaixo", "phishing-check": "Listas de phishing", "opencti-observable": "Observável no OpenCTI", "opencti-report": "Relatório no OpenCTI", "cohosted-domain": "Domínio no mesmo IP", "pdns-name": "Nome no histórico", "pdns-answer": "Resposta no histórico",
    "tor-exit": "Saída Tor", "botnet-c2": "Botnet", "drop-listed": "Spamhaus DROP", "cloud-range": "Nuvem ou CDN", "lists-checked": "Listas conferidas",
    blocklist: "Lista antispam", "blocklist-check": "Listas antispam", contract: "Contrato federal", "contracts-summary": "Contratos federais", payment: "Pagamento federal", "payments-summary": "Pagamentos federais",
    "phone-format": "Formato para discar", state: "Estado", service: "Serviço", "phone-suggestion": "Com o 9", "trade-name": "Nome fantasia",
    "registration-status": "Situação cadastral", founded: "Início das atividades", "main-activity": "Atividade principal",
    "secondary-activity": "Atividade secundária", "legal-nature": "Natureza jurídica", "company-size": "Porte",
    "share-capital": "Capital social", address: "Endereço", "company-phone": "Telefone da empresa",
    partners: "Sócios", "tax-regime": "Regime tributário", coordinates: "Coordenadas",
  };

  const DATA_LABELS = {
    label: "", record: "registro", name: "nome", policy: "política", null_mx: "MX nulo",
    prefix: "prefixo", country: "país", registry: "registro", allocated: "alocação", asn: "ASN",
    object: "objeto", action: "ação", role: "papel", type: "tipo", certificates: "certificados",
    first_seen: "primeira vez", last_seen: "última vez", wildcard: "curinga", first: "primeira",
    last: "última", limited_to: "limite", timestamp: "data", status: "status", mimetype: "tipo MIME",
    digest: "digest", percentile: "percentil", date: "data", model_version: "modelo",
    vendor_project: "fornecedor", product: "produto", vulnerability_name: "vulnerabilidade",
    date_added: "incluída em", due_date: "prazo", ransomware_use: "uso em ransomware",
    meaning: "", origin_count: "origens", verification_status: "verificação", count: "ocorrências",
    entity_type: "categoria", identifier: "identificador", sha256: "SHA-256", format: "formato",
    integrity_status: "integridade", distance: "distância", reason: "motivo",
    error: "erro", protocol: "protocolo", cipher: "cifra", address: "endereço",
    hostname_match: "nome confere", cn: "CN", organization: "organização", self_issued: "autoassinado",
    days_remaining: "dias restantes", validity_days: "validade (dias)", expired: "expirado",
    not_yet_valid: "ainda não válido", curve: "curva", signature: "assinatura",
    weak_signature: "assinatura fraca", sha1: "SHA-1", serial: "serial", pin: "",
    sct_embedded: "SCT embutido", ca: "CA", ocsp: "OCSP", extended_key_usage: "uso estendido",
    final_url: "URL final", redirects: "redirecionamentos", content_type: "tipo", bytes: "bytes",
    value: "valor", header: "cabeçalho", secure: "Secure", httponly: "HttpOnly", samesite: "SameSite",
    category: "categoria", version: "versão", evidence: "evidência", algorithm: "algoritmo",
    md5: "MD5", url: "URL",
    source: "fonte", holder: "titular", announced: "anunciado", registry_block: "bloco no registro",
    website: "site", scope: "alcance", traffic_ratio: "tráfego", ix_count: "pontos de troca",
    facility_count: "data centers", irr_as_set: "AS-SET", anycast: "anycast", coordinates: "coordenadas",
    timezone: "fuso", source_set: "base", product_version: "versão", size_bytes: "tamanho",
    trust: "confiança", known_malicious: "malicioso conhecido", scanned_at: "varrido em",
    relation: "relação", page_domain: "domínio da página", page_ip: "IP da página", asn_name: "nome do AS",
    server: "servidor", title: "título", tls_issuer: "emissor TLS", domain_age_days: "idade do domínio (dias)",
    verdict_malicious: "veredito malicioso", report: "relatório", screenshot: "captura",
    not_before: "válido desde", not_after: "válido até", revoked: "revogado", spki_sha256: "SPKI SHA-256",
    names: "nomes", description: "descrição", published: "publicada", modified: "alterada", cvss: "CVSS",
    cwe: "CWE", kev_due_date: "prazo KEV", tags: "tags", fixed_in: "corrigido em", purl: "purl",
    versions_listed: "versões listadas", malicious: "malicioso", suspicious: "suspeito",
    harmless: "inofensivo", undetected: "não detectado", timeout: "sem resposta", reputation: "reputação",
    last_analysis: "última análise", categories: "categorias", first_submission: "primeiro envio",
    ssdeep: "ssdeep", tlsh: "TLSH", network: "rede", reports_90d: "denúncias (90 dias)",
    distinct_reporters: "denunciantes", last_reported: "última denúncia", usage_type: "uso", isp: "provedor",
    domain: "domínio", tor_exit: "saída Tor", allow_listed: "na lista de permissões",
    scanning_internet: "varre a internet", known_benign_service: "serviço benigno conhecido",
    created: "criado", adversary: "adversário", tlp: "TLP", references: "referências", link: "link",
    os: "sistema", last_update: "atualizado", ports: "portas", module: "módulo", cpe: "CPE",
    http_title: "título HTTP", http_server: "servidor HTTP", tls_subject_cn: "CN do TLS", seen: "visto em",
    file_type: "tipo de arquivo", url_count: "URLs", threat: "ameaça", threat_type: "tipo de ameaça",
    malware: "malware", aliases: "outros nomes", confidence: "confiança", file_name: "nome do arquivo",
    mime: "MIME", delivery: "entrega", imphash: "imphash",
    full_name: "nome completo", language: "linguagem", stars: "estrelas", forks: "forks", created_at: "criado em",
    pushed_at: "último push", archived: "arquivado", fork: "fork", license: "licença", topics: "tópicos",
    location: "local", public_repos: "repositórios públicos", verified: "verificada", email: "e-mail",
    repository: "repositório", owner: "dono", expires: "expira", signed: "assinado", canonical: "canônico",
    preferred_languages: "idiomas", missing_expires: "sem Expires",
    kind: "técnica", nameservers: "servidores de nomes", generated: "geradas", checked: "checadas",
    existing: "existentes", unanswered: "sem resposta", engine: "motor",
  };

  const STATUS_TEXT = {
    ok: ["Com resultados", "success"],
    empty: ["Sem resultados", "neutral"],
    error: ["Erro", "danger"],
    "rate-limited": ["Limite de taxa", "warning"],
    "network-disabled": ["Rede desativada", "warning"],
    "target-contact-disabled": ["Contato com o alvo desativado", "warning"],
    "key-missing": ["Sem chave", "neutral"],
    "module-disabled": ["Módulo desativado", "warning"],
    pending: ["Consultando…", "neutral"],
    unsupported: ["Não se aplica", "neutral"],
    ready: ["Pronto", "success"],
  };

  const TYPE_LABELS = {
    domain: "Domínio", ipv4: "IPv4", ipv6: "IPv6", cidr: "CIDR", url: "URL", email: "E-mail",
    md5: "MD5", sha1: "SHA-1", sha256: "SHA-256", asn: "ASN", cve: "CVE",
    cnpj: "CNPJ", cpf: "CPF", phone: "Telefone", location: "Local",
  };

  /* Which findings can become a shared entity, and as which category. */
  const ENTITY_FROM_RESULT = {
    "dns-a": "ipv4", "dns-aaaa": "ipv6", "dns-ns": "domain", "dns-cname": "domain",
    "dns-mx": "domain", nameserver: "domain", "ct-name": "domain", organization: "organization",
    "abuse-contact": "email", "archive-capture": "url", lookalike: "domain",
    "cert-san": "domain", "http-redirect": "url", hostname: "domain", subdomain: "domain",
    "as-holder": "organization", "network-owner": "organization", "network-operator": "organization",
    "malicious-url": "url", "final-url": "url",
  };

  const PIVOTABLE = new Set([
    "dns-a", "dns-aaaa", "dns-ns", "dns-cname", "dns-mx", "nameserver", "ct-name",
    "asn", "cidr", "abuse-contact", "lookalike", "co-occurrence", "indicator", "cert-san",
    "cert-san-ip", "http-redirect", "hostname", "origin-asn", "announced-prefix", "subdomain",
    "malicious-url", "final-url", "ioc", "cve",
  ]);

  const PROVIDER_NOTE = {
    virustotal: "Obrigatória. Chaves gratuitas: 4 consultas por minuto e 500 por dia.",
    abuseipdb: "Obrigatória. Chaves gratuitas: 1.000 consultas por dia.",
    abusech: "Obrigatória. Uma Auth-Key serve para URLhaus, ThreatFox e MalwareBazaar.",
    greynoise: "Opcional: a consulta funciona sem chave, com limite menor.",
    otx: "Opcional: a consulta de indicadores funciona sem chave.",
    shodan: "Opcional: a consulta de host funciona sem chave; com chave segue os limites do seu plano.",
    urlscan: "Opcional: a busca funciona sem chave, com limite menor.",
    nvd: "Opcional: aumenta o limite de 5 para 50 consultas a cada 30 s.",
    ipinfo: "Opcional: sem token, o limite anônimo é menor.",
  };

  function button(label, onClick, options = {}) {
    return el(
      "button",
      {
        class: `button ${options.variant || "button-secondary"} button-small`,
        type: "button",
        disabled: Boolean(options.disabled),
        "aria-label": options.ariaLabel || null,
        onClick,
      },
      label,
    );
  }

  function connectorName(id, fallback) {
    return CONNECTOR_TEXT[id]?.[0] || fallback || id;
  }

  function connectorDescription(id, fallback) {
    return CONNECTOR_TEXT[id]?.[1] || fallback || "";
  }

  function statusBadgeFor(status) {
    const [label, tone] = STATUS_TEXT[status] || [status, "neutral"];
    return badge(label, tone);
  }

  /* Normalise a finding value into something the detector and entity
     registry accept (MX priority, wildcard prefix, trailing dot). */
  function cleanValue(item) {
    let value = String(item.value || "").trim();
    if (item.result_type === "dns-mx") value = value.split(/\s+/).pop() || "";
    if (item.result_type === "ct-name") value = value.replace(/^\*\./, "");
    return value.replace(/\.$/, "");
  }

  function dataSummary(data) {
    return Object.entries(data || {})
      .filter(([, value]) => value !== "" && value !== null && value !== undefined && value !== false)
      .map(([key, value]) => {
        const label = DATA_LABELS[key] ?? key;
        const text = value === true ? "sim" : G.translateText(String(value));
        return label ? `${label}: ${text}` : text;
      })
      .join(" · ");
  }

  function downloadJson(name, data) {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = el("a", { href: url, download: name });
    document.body.append(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  async function enableNetwork(onDone) {
    const accepted = await G.confirm({
      title: "Ativar conectores de rede",
      message:
        "Os conectores de rede enviam o artefato consultado a serviços de terceiros: resolvedor DNS da Cloudflare, registros RDAP, RIPEstat, PeeringDB, Team Cymru, crt.sh, Cert Spotter, Internet Archive, urlscan.io, Shodan, GreyNoise, OTX, IPinfo, CIRCL, NVD, OSV e FIRST, além dos provedores cujas chaves você salvar. Nenhum deles acessa os servidores do alvo. Você pode desativar isso a qualquer momento em Configurações.",
      confirmLabel: "Ativar rede",
    });
    if (!accepted) return;
    try {
      const result = await api("/api/settings", {
        method: "PATCH",
        body: JSON.stringify({ "intel.allow_network": "true" }),
      });
      state.settings = result.values;
      toast("Conectores de rede ativados.");
      onDone();
    } catch (error) {
      toast(error.message, "error");
    }
  }

  async function enableTargetContact(onDone) {
    const accepted = await G.confirm({
      title: "Permitir contato com o alvo",
      message:
        "Os conectores Certificado TLS e Impressão digital web acessam diretamente os servidores do artefato: um handshake TLS na porta 443 e um GET HTTPS da página e do favicon, como um visitante comum. O alvo pode registrar o seu endereço IP. Use apenas em alvos que você está autorizado a analisar.",
      confirmLabel: "Permitir contato",
    });
    if (!accepted) return;
    try {
      const result = await api("/api/settings", {
        method: "PATCH",
        body: JSON.stringify({ "intel.allow_target_contact": "true" }),
      });
      state.settings = result.values;
      toast("Contato com o alvo permitido.");
      onDone();
    } catch (error) {
      toast(error.message, "error");
    }
  }


  /* ---------------------------------------------------------------- */
  /* Results: the dossier first, sources in one line, raw data last   */
  /* ---------------------------------------------------------------- */

  const LIST_PREVIEW = 12;
  const RAW_PREVIEW = 40;
  const SOURCE_ORDER = {
    pending: -1, ok: 0, empty: 1, error: 2, "rate-limited": 3, "key-missing": 4,
    "network-disabled": 5, "target-contact-disabled": 6, "module-disabled": 7, unsupported: 8,
  };
  const LOOKALIKE_KIND = {
    "tld-swap": "outro TLD", omission: "letra omitida", insertion: "letra inserida", addition: "letra a mais",
    transposition: "letras trocadas de lugar", replacement: "letra substituída", repetition: "letra repetida",
    homoglyph: "caractere parecido", bitsquatting: "bit trocado", hyphenation: "hífen inserido", "vowel-swap": "vogal trocada",
  };
  /* A list that follows label/value rows gets a short caption. */
  const LIST_CAPTION = {
    hosting: "Endereços no DNS",
    activity: "Atividades secundárias",
    services: "Portas abertas",
    host: "Endereços no DNS",
    reputation: "Relatórios",
    reports: "Relatórios",
  };
  const FLAG_LEVEL = {
    high: ["alert", "Importante"],
    medium: ["diamond", "Atenção"],
    info: ["info", "Nota"],
  };

  /* "1 fonte respondeu" / "12 fontes responderam". */
  function count(n, one, many) {
    return `${G.formatNumber(n)} ${n === 1 ? one : many}`;
  }

  function copyIcon() {
    return G.svgEl(
      "svg",
      {
        class: "icon", viewBox: "0 0 24 24", width: 15, height: 15, fill: "none", stroke: "currentColor",
        "stroke-width": "1.7", "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true", focusable: "false",
      },
      G.svgEl("path", { d: "M9.5 8.5h8a2 2 0 0 1 2 2v8a2 2 0 0 1 -2 2h-8a2 2 0 0 1 -2 -2v-8a2 2 0 0 1 2 -2zM15.5 8.5V6.5a2 2 0 0 0 -2 -2h-8a2 2 0 0 0 -2 2v8a2 2 0 0 0 2 2h2" }),
    );
  }

  async function copyText(text, done = "Copiado.") {
    try {
      await navigator.clipboard.writeText(text);
      toast(done);
    } catch {
      const area = el("textarea", { class: "visually-hidden", "aria-hidden": "true", tabindex: "-1" });
      area.value = text;
      document.body.append(area);
      area.select();
      let copied = false;
      try {
        copied = document.execCommand("copy");
      } catch {
        copied = false;
      }
      area.remove();
      toast(copied ? done : "Não foi possível copiar.", copied ? undefined : "error");
    }
  }

  function copyButton(value, key) {
    return el(
      "button",
      {
        type: "button",
        class: "dossier-copy",
        "aria-label": `Copiar ${value}`,
        "data-focus-key": key,
        onClick: () => copyText(value, "Valor copiado."),
      },
      copyIcon(),
    );
  }

  /* A value that starts a new search: link-styled, with an arrow on hover. */
  function pivotControl(value, ctx, key, shown = value) {
    const technique = /^T\d{4}(?:\.\d{3})?\b/.exec(value);
    const content = [el("span", { class: "dossier-pivot-text" }, shown), G.icon("arrow", { size: 14, className: "dossier-pivot-icon" })];
    if (ctx.attack && technique) {
      return el(
        "a",
        { class: "dossier-pivot", href: `#/attack?technique=${encodeURIComponent(technique[0])}`, "aria-label": `Abrir ${shown} no ATT&CK`, "data-focus-key": key },
        ...content,
      );
    }
    return el(
      "button",
      { type: "button", class: "dossier-pivot", "aria-label": `Pesquisar ${shown}`, "data-focus-key": key, onClick: () => ctx.pivot(value) },
      ...content,
    );
  }

  /* Every finding is a small box: closed it shows what it is and its
     value; a click opens the details (hint, sources, actions). The "+"
     beside it puts it on the graph and opens the graph on it. */
  function infoBox({ key, label, value, shown = value, meta, hint, sources, pivotValue, section, ctx, attack = false }) {
    const open = ctx.ui.open.has(key);
    const details = el(
      "div",
      { class: "info-box-details", hidden: !open },
      hint ? el("p", { class: "info-box-hint" }, hint) : null,
      meta ? el("p", { class: "info-box-hint" }, meta) : null,
      sources?.length ? el("p", { class: "info-box-src" }, `${sources.length > 1 ? "Fontes" : "Fonte"}: ${sources.join(", ")}`) : null,
      el(
        "div",
        { class: "info-box-actions" },
        pivotValue ? pivotControl(pivotValue, { ...ctx, attack }, `${key}-pivot`, "Pesquisar") : null,
        copyButton(value, `${key}-copy`),
      ),
    );
    const head = el(
      "button",
      { type: "button", class: "info-box-head", "aria-expanded": String(open), "data-focus-key": key },
      label ? el("span", { class: "info-box-label" }, label) : null,
      el("span", { class: "info-box-value" }, shown),
    );
    const box = el("div", { class: `info-box${open ? " is-open" : ""}` });
    head.addEventListener("click", () => {
      const next = !ctx.ui.open.has(key);
      if (next) ctx.ui.open.add(key);
      else ctx.ui.open.delete(key);
      box.classList.toggle("is-open", next);
      head.setAttribute("aria-expanded", String(next));
      details.hidden = !next;
    });
    const add = el(
      "button",
      { type: "button", class: "info-box-add", "aria-label": `Adicionar ${shown} ao grafo`, title: "Adicionar ao grafo", "data-focus-key": `${key}-add` },
      G.icon("plus", { size: 16 }),
    );
    add.addEventListener("click", () => ctx.add?.({ label, value, pivot_value: pivotValue || "", hint, meta, sources, section: section.title }));
    box.append(head, add, details);
    return box;
  }

  function dossierRow(row, section, ctx) {
    return infoBox({
      key: `row-${section.id}-${row.label}`,
      label: row.label,
      value: row.value,
      hint: row.hint,
      sources: row.sources,
      pivotValue: row.pivot ? row.value : "",
      section,
      ctx,
    });
  }

  function dossierList(section, ctx) {
    const list = section.list;
    const items = list.items || [];
    const pivotable = Boolean(list.pivot) || PIVOTABLE.has(section.id) || section.id === "others";
    const attack = section.id === "techniques";
    const long = items.length > LIST_PREVIEW;
    const ui = ctx.ui;
    const ul = el("ul", { class: "dossier-list", "aria-label": section.title });
    const foot = el("div", { class: "dossier-list-foot" });

    const item = (entry) => {
      const value = pivotable ? cleanValue({ result_type: section.id, value: entry.value }) : entry.value;
      const box = infoBox({
        key: `item-${section.id}-${entry.value}`,
        // Dialling formats read best with their name on the closed box.
        label: section.id === "formats" ? entry.meta : "",
        value: entry.value,
        meta: entry.meta && section.id !== "formats" ? (section.id === "lookalikes" ? LOOKALIKE_KIND[entry.meta] || entry.meta : entry.meta) : "",
        pivotValue: pivotable && value ? value : "",
        section,
        ctx,
        attack,
      });
      return el("li", { class: "dossier-item-box" }, box);
    };

    const draw = () => {
      const needle = (ui.filters[section.id] || "").trim().toLocaleLowerCase("pt-BR");
      const matching = needle
        ? items.filter((entry) => `${entry.value} ${entry.meta || ""}`.toLocaleLowerCase("pt-BR").includes(needle))
        : items;
      const expanded = ui.expanded.has(section.id);
      const shown = needle || expanded ? matching : matching.slice(0, LIST_PREVIEW);
      ul.replaceChildren(...shown.map(item));
      if (!shown.length) ul.append(el("li", { class: "dossier-item-box is-empty" }, "Nada corresponde ao filtro."));
      const parts = [];
      if (needle) parts.push(el("span", { class: "dossier-muted" }, `${G.formatNumber(matching.length)} de ${G.formatNumber(items.length)}`));
      else if (long) {
        parts.push(
          el(
            "button",
            {
              type: "button",
              class: "dossier-more",
              "aria-expanded": String(expanded),
              "data-focus-key": `more-${section.id}`,
              onClick: () => {
                if (ui.expanded.has(section.id)) ui.expanded.delete(section.id);
                else ui.expanded.add(section.id);
                draw();
              },
            },
            expanded ? "Mostrar menos" : `Mostrar todos (${G.formatNumber(items.length)})`,
          ),
        );
      }
      if (list.total > items.length) {
        parts.push(el("span", { class: "dossier-muted" }, `A lista guarda os primeiros ${G.formatNumber(items.length)} de ${G.formatNumber(list.total)}.`));
      }
      foot.replaceChildren(...parts);
      foot.hidden = !parts.length;
    };

    let tools = null;
    if (long) {
      const filter = el("input", {
        class: "input dossier-filter",
        type: "search",
        autocomplete: "off",
        spellcheck: "false",
        "aria-label": `Filtrar ${section.title.toLocaleLowerCase("pt-BR")}`,
        placeholder: "Filtrar",
        "data-focus-key": `filter-${section.id}`,
        value: ui.filters[section.id] || "",
      });
      filter.addEventListener("input", () => {
        ui.filters[section.id] = filter.value;
        draw();
      });
      tools = el(
        "div",
        { class: "dossier-list-tools" },
        filter,
        el(
          "button",
          {
            type: "button",
            class: "button button-secondary button-small",
            "data-focus-key": `copyall-${section.id}`,
            onClick: () => copyText(items.map((entry) => entry.value).join("\n"), `${G.formatNumber(items.length)} itens copiados.`),
          },
          "Copiar lista",
        ),
      );
    }
    draw();
    const caption = section.rows?.length ? LIST_CAPTION[section.id] : null;
    return [caption ? el("p", { class: "dossier-list-caption" }, caption) : null, tools, ul, foot];
  }

  function dossierSection(section, ctx) {
    const id = `dossier-${section.id}`;
    const listed = section.list?.items?.length || 0;
    return el(
      "section",
      { class: `dossier-block${listed > 6 ? " is-wide" : ""}`, "aria-labelledby": id },
      el(
        "h3",
        { id, class: "dossier-block-title" },
        section.title,
        section.list && section.list.total > 1 ? el("span", { class: "dossier-count" }, G.formatNumber(section.list.total)) : null,
      ),
      section.rows?.length ? el("div", { class: "info-grid" }, ...section.rows.map((row) => dossierRow(row, section, ctx))) : null,
      section.list && listed ? dossierList(section, ctx) : null,
      section.note ? el("p", { class: "dossier-note" }, section.note) : null,
    );
  }

  async function worldMap() {
    if (!state.worldMap) state.worldMap = await api("/world.json");
    return state.worldMap;
  }

  /* A small equirectangular map (the local Natural Earth outline of the
     GEOINT screen) framed around the point. */
  /* With network sources allowed, a street map (OpenStreetMap data, CARTO
     tiles) replaces the outline map. It is kept between the redraws of a
     running search so the tiles and the user's pan and zoom survive. */
  function streetFrame(map, geocoded) {
    const key = `${Number(map.lat).toFixed(6)},${Number(map.lon).toFixed(6)}`;
    if (state.streetMap?.key !== key) {
      state.streetMap = { key, element: G.streetMap({ lat: Number(map.lat), lon: Number(map.lon), zoom: geocoded ? 16 : 10, label: map.label }) };
    }
    return state.streetMap.element;
  }

  function dossierMap(map, streets = false) {
    const geocoded = map.precision !== "rede (aproximada)";
    const width = geocoded ? 36 : 64;
    const height = width / 2;
    const x = Math.max(-180, Math.min(180, Number(map.lon))) + 180;
    const y = 90 - Math.max(-90, Math.min(90, Number(map.lat)));
    const left = Math.min(360 - width, Math.max(0, x - width / 2));
    const top = Math.min(180 - height, Math.max(0, y - height / 2));
    const coords = `${Number(map.lat).toFixed(4)}, ${Number(map.lon).toFixed(4)}`;
    const base = G.svgEl("g");
    const svg = G.svgEl(
      "svg",
      {
        class: "dmap",
        viewBox: `${left} ${top} ${width} ${height}`,
        preserveAspectRatio: "xMidYMid slice",
        role: "img",
        "aria-label": `Mapa com o ponto em ${map.label || coords}`,
      },
      base,
      G.svgEl("circle", { class: "dmap-halo", cx: x, cy: y, r: width / (geocoded ? 30 : 14) }),
      G.svgEl("circle", { class: "dmap-dot", cx: x, cy: y, r: width / 110 }),
    );
    const drawBase = (world) =>
      base.replaceChildren(
        G.svgEl("rect", { class: "dmap-ocean", x: 0, y: 0, width: 360, height: 180 }),
        G.svgEl("path", { class: "dmap-land", d: world.land }),
        G.svgEl("path", { class: "dmap-borders", d: world.borders }),
      );
    if (state.worldMap) drawBase(state.worldMap);
    else worldMap().then(drawBase).catch(() => {});
    return el(
      "section",
      { class: "dossier-block dossier-map", "aria-labelledby": "dossier-map-title" },
      el("h3", { id: "dossier-map-title", class: "dossier-block-title" }, "Mapa"),
      streets && G.streetMap ? streetFrame(map, geocoded) : el("div", { class: "dmap-frame" }, svg),
      el(
        "dl",
        { class: "dossier-rows" },
        map.label ? el("div", { class: "dossier-row" }, el("dt", {}, "Ponto"), el("dd", {}, el("span", { class: "dossier-value" }, map.label))) : null,
        el(
          "div",
          { class: "dossier-row" },
          el("dt", {}, "Precisão"),
          el("dd", {}, el("span", { class: "dossier-value" }, map.precision || (geocoded ? "geocodificado" : "rede (aproximada)")),
            el("span", { class: "dossier-hint" }, /cep/i.test(map.precision || "") ? "centro do CEP do endereço cadastrado, não o prédio" : geocoded ? "endereço convertido pelo OpenStreetMap" : "cidade ou região do bloco de IPs, não de uma pessoa")),
        ),
        el("div", { class: "dossier-row" }, el("dt", {}, "Coordenadas"), el("dd", {}, el("span", { class: "dossier-value" }, coords), copyButton(coords, "map-coords-copy"))),
      ),
      el(
        "p",
        { class: "dossier-links" },
        ...(G.mapLinks
          ? (() => {
              const links = G.mapLinks(map.lat, map.lon, geocoded ? 17 : 11);
              return [
                el("a", { class: "dossier-link", href: links.osm, target: "_blank", rel: "noopener noreferrer" }, "Abrir no OpenStreetMap"),
                el("a", { class: "dossier-link", href: links.google, target: "_blank", rel: "noopener noreferrer" }, "Abrir no Google Maps"),
              ];
            })()
          : []),
        el("a", { class: "dossier-link", href: "#/geoint" }, "Abrir no mapa GEOINT"),
      ),
    );
  }

  function sourceTable(run, connectorsById) {
    const sources = [...run.sources].sort(
      (a, b) => (SOURCE_ORDER[a.status] ?? 9) - (SOURCE_ORDER[b.status] ?? 9) || a.connector_id.localeCompare(b.connector_id),
    );
    return table({
      columns: [
        {
          label: "Fonte",
          render: (row) =>
            el(
              "div",
              { class: "dossier-source-cell" },
              el("strong", {}, connectorName(row.connector_id, connectorsById[row.connector_id]?.name)),
              row.error ? el("span", { class: "source-row-error" }, G.translateError(row.error)) : null,
            ),
        },
        { label: "Situação", render: (row) => statusBadgeFor(row.status) },
        { label: "Resultados", cellClass: "numeric-col", render: (row) => (row.status === "ok" ? G.formatNumber(row.count) : "—") },
        {
          label: "Tempo",
          render: (row) => (row.cached ? "cache" : row.elapsed_ms ? `${G.formatNumber(row.elapsed_ms)} ms` : "—"),
        },
      ],
      rows: sources,
    });
  }

  function resultGroups(run, connectorsById, handlers, ui) {
    const groups = new Map();
    for (const item of run.results) {
      if (!groups.has(item.connector_id)) groups.set(item.connector_id, []);
      groups.get(item.connector_id).push(item);
    }
    if (!groups.size) return el("p", { class: "dossier-muted" }, "Nenhuma fonte retornou dados.");
    const wrap = el("div", { class: "result-groups" });
    for (const [connectorId, items] of groups) {
      const connector = connectorsById[connectorId];
      const name = connectorName(connectorId, connector?.name);
      const full = ui.rawExpanded.has(connectorId);
      const rows = full ? items : items.slice(0, RAW_PREVIEW);
      wrap.append(
        el(
          "section",
          { class: "result-group", "aria-label": name },
          el(
            "header",
            { class: "result-group-head" },
            el("h3", {}, name),
            el("span", { class: "result-group-count" }, `${items.length}`),
            items[0]?.source_url
              ? el(
                  "a",
                  { class: "result-source", href: items[0].source_url, target: "_blank", rel: "noopener noreferrer" },
                  new URL(items[0].source_url).host,
                )
              : null,
          ),
          table({
            columns: [
              { label: "Tipo", render: (row) => el("span", { class: "result-type" }, RESULT_LABELS[row.result_type] || row.result_type) },
              { label: "Valor", render: (row) => el("code", { class: "result-value" }, G.translateText(row.value)) },
              { label: "Detalhes", render: (row) => el("span", { class: "result-data" }, dataSummary(row.data)) },
              {
                label: "",
                cellClass: "result-actions",
                render: (row) => el(
                  "div",
                  { class: "result-row-actions" },
                  PIVOTABLE.has(row.result_type)
                    ? button("Pivotar", () => handlers.pivot(cleanValue(row)), { ariaLabel: `Pivotar em ${row.value}` })
                    : null,
                  ENTITY_FROM_RESULT[row.result_type]
                    ? button("Entidade", () => handlers.entity(row), { ariaLabel: `Registrar ${row.value} como entidade` })
                    : null,
                ),
              },
            ],
            rows,
          }),
          items.length > RAW_PREVIEW
            ? el(
                "button",
                {
                  type: "button",
                  class: "dossier-more",
                  "aria-expanded": String(full),
                  onClick: (event) => {
                    if (full) ui.rawExpanded.delete(connectorId);
                    else ui.rawExpanded.add(connectorId);
                    const group = event.currentTarget.closest(".result-groups");
                    group.replaceWith(resultGroups(run, connectorsById, handlers, ui));
                  },
                },
                full ? "Mostrar menos" : `Mostrar todos (${G.formatNumber(items.length)})`,
              )
            : null,
        ),
      );
    }
    return wrap;
  }

  /* ---------------------------------------------------------------- */
  /* Sources and API keys (shown in Configurações)                    */
  /* ---------------------------------------------------------------- */

  async function renderIntelConnectors(host) {
    host.replaceChildren(loadingBlock("Carregando fontes…"));
    let connectorData;
    try {
      connectorData = await api("/api/intel/connectors");
    } catch (error) {
      host.replaceChildren(G.inlineError(error.message));
      return;
    }
    const refresh = () => renderIntelConnectors(host);
    const actions = !connectorData.network_allowed
      ? [button("Ativar rede", () => enableNetwork(refresh), { variant: "button-primary" })]
      : !connectorData.target_contact_allowed
        ? [button("Permitir contato com o alvo", () => enableTargetContact(refresh))]
        : [];
    host.replaceChildren(
      panel(
        {
          title: "Fontes",
          caption: connectorData.network_allowed ? "Rede ativada" : "Rede desativada",
          actions,
        },
        table({
          columns: [
            {
              label: "FONTE",
              render: (row) =>
                el(
                  "strong",
                  {
                    tabindex: "0",
                    "data-tooltip": [
                      connectorDescription(row.connector_id, row.description),
                      `${row.rate_per_minute}/min`,
                      row.ttl_seconds ? `cache ${Math.round(row.ttl_seconds / 3600) || 1} h` : "sem cache",
                    ].filter(Boolean).join(" · "),
                  },
                  connectorName(row.connector_id, row.name),
                ),
            },
            { label: "ACEITA", render: (row) => row.accepts.map((type) => TYPE_LABELS[type] || type).join(", ") },
            {
              label: "ACESSO",
              render: (row) =>
                el(
                  "div",
                  { class: "connector-cell" },
                  el("span", {}, row.contacts_target ? "Contata o alvo" : row.network ? "Rede" : "Local"),
                  row.key_id
                    ? el(
                        "a",
                        { class: "table-link", href: "#/settings/chaves" },
                        row.key_configured ? "Chave salva" : row.requires_key ? "Precisa de chave" : "Chave opcional",
                      )
                    : null,
                ),
            },
            { label: "ESTADO", render: (row) => statusBadgeFor(row.availability) },
            {
              label: "ÚLTIMA EXECUÇÃO",
              render: (row) =>
                row.status
                  ? el(
                      "div",
                      { class: "connector-cell" },
                      statusBadgeFor(row.status.last_status),
                      el("span", {}, `${G.relativeTime(row.status.last_run_at)} · ${row.status.success_count} / ${row.status.error_count}`),
                      row.status.last_error
                        ? el("span", { class: "source-row-error" }, G.translateError(row.status.last_error))
                        : null,
                    )
                  : el("span", { class: "muted" }, "Nunca"),
            },
          ],
          rows: connectorData.items,
        }),
      ),
    );
    G.hydrateIcons(host);
  }

  async function renderIntelKeys(host) {
    host.replaceChildren(loadingBlock("Carregando chaves…"));
    let keys;
    let connectorData;
    try {
      [keys, connectorData] = await Promise.all([api("/api/intel/keys"), api("/api/intel/connectors")]);
    } catch (error) {
      host.replaceChildren(G.inlineError(error.message));
      return;
    }
    const refresh = () => renderIntelKeys(host);
    const usedBy = {};
    for (const item of connectorData.items) {
      if (item.key_id) (usedBy[item.key_id] ||= []).push(connectorName(item.connector_id, item.name));
    }
    const row = (provider) => {
      const input = el("input", {
        class: "input key-input",
        type: "password",
        autocomplete: "off",
        spellcheck: "false",
        placeholder: provider.configured ? `Substituir (${provider.hint})` : "Cole a chave",
        "aria-label": `Chave de API de ${provider.name}`,
      });
      const save = async () => {
        if (!input.value.trim()) return;
        try {
          await api(`/api/intel/keys/${provider.provider_id}`, { method: "PUT", body: JSON.stringify({ key: input.value }) });
          input.value = "";
          toast(`Chave de ${provider.name} salva neste computador.`);
          refresh();
        } catch (error) {
          toast(error.message, "error");
        }
      };
      input.addEventListener("keydown", (event) => {
        if (event.key === "Enter") save();
      });
      const note = [PROVIDER_NOTE[provider.provider_id] || provider.note, `Usada por: ${(usedBy[provider.provider_id] || []).join(", ")}`]
        .filter(Boolean)
        .join(" · ");
      return el(
        "div",
        { class: "key-row" },
        el(
          "div",
          { class: "key-info" },
          el("strong", { tabindex: "0", "data-tooltip": note }, provider.name),
        ),
        el(
          "div",
          { class: "key-state" },
          provider.configured ? badge(`Salva ${provider.hint}`, "success") : badge("Não configurada", "neutral"),
          el("a", { class: "table-link", href: provider.signup_url, target: "_blank", rel: "noopener noreferrer" }, "Obter chave"),
        ),
        el(
          "div",
          { class: "key-actions" },
          input,
          button("Salvar", save, { variant: "button-primary" }),
          provider.configured
            ? button("Remover", async () => {
                const confirmed = await G.confirm({
                  title: "Remover chave",
                  message: `A chave de ${provider.name} será apagada deste computador. As fontes que dependem dela deixam de rodar.`,
                  confirmLabel: "Remover",
                  danger: true,
                });
                if (!confirmed) return;
                try {
                  await api(`/api/intel/keys/${provider.provider_id}`, { method: "DELETE" });
                  toast(`Chave de ${provider.name} removida.`);
                  refresh();
                } catch (error) {
                  toast(error.message, "error");
                }
              })
            : null,
        ),
      );
    };
    host.replaceChildren(
      panel(
        {
          title: "Chaves de API",
          caption: `${keys.items.filter((item) => item.configured).length} de ${keys.total} salvas`,
        },
        el("p", { class: "panel-note" }, "Ficam só neste computador e vão apenas ao provedor de cada uma."),
        el("div", { class: "key-list" }, ...keys.items.map(row)),
      ),
    );
  }

  /* ---------------------------------------------------------------- */
  /* Search screen                                                    */
  /* ---------------------------------------------------------------- */

  function freshUi() {
    return { expanded: new Set(), open: new Set(), filters: {}, rawExpanded: new Set(), sourcesOpen: false, rawOpen: false };
  }

  /* Coverage computed on the client when a run carries no dossier. */
  function fallbackDossier(run) {
    const sources = run.sources || [];
    const names = (status) => sources.filter((item) => status.includes(item.status)).map((item) => connectorName(item.connector_id));
    return {
      type: run.query_type,
      type_label: TYPE_LABELS[run.query_type] || run.query_type,
      value: run.query_value,
      title: run.query_value,
      subtitle: "",
      facts: [],
      flags: [],
      sections: [],
      coverage: {
        answered: names(["ok"]).length,
        empty: names(["empty"]).length,
        failed: names(["error", "rate-limited"]),
        missing_key: names(["key-missing"]),
        network_off: names(["network-disabled", "target-contact-disabled"]).length,
        pending: names(["pending"]).length,
      },
    };
  }

  async function renderMultiSearch(root, params = []) {
    // The source and key screens moved to Configurações.
    const moved = { conectores: "conectores", chaves: "chaves" }[params[0]];
    if (moved) {
      location.hash = `#/settings/${moved}`;
      return;
    }
    const connectorData = await api("/api/intel/connectors");
    await G.loadInvestigations?.();
    const investigations = (state.investigations || []).filter((item) => item.status === "open");
    const connectorsById = Object.fromEntries(connectorData.items.map((item) => [item.connector_id, item]));
    let detected = null;
    let detectedFor = null;
    let detectError = "";
    let pollToken = 0;
    let detectTimer = null;
    let ui = freshUi();
    G.cleanupFns.push(() => {
      pollToken += 1;
      clearTimeout(detectTimer);
    });

    const input = el("input", {
      class: "input query-input",
      type: "text",
      id: "multisearch-input",
      autocomplete: "off",
      spellcheck: "false",
      "aria-label": "Artefato para consultar",
      maxlength: "2000",
    });
    const detectedNode = el("span", { class: "query-detected", "aria-live": "polite" });
    const caseSelect = el(
      "select",
      { class: "input compact-select query-case", "aria-label": "Associar a uma investigação" },
      el("option", { value: "" }, "Sem investigação"),
      ...investigations.map((item) => el("option", { value: item.id }, item.name)),
    );
    const cacheToggle = el("input", { type: "checkbox", checked: true, id: "multisearch-cache" });
    const runButton = el(
      "button",
      { class: "button button-primary query-run", type: "submit" },
      el("span", { "data-icon": "search", "aria-hidden": "true" }),
      "Consultar",
    );
    const resultArea = el("div", { class: "multisearch-results" });

    async function detect() {
      const value = input.value.trim();
      clearTimeout(detectTimer);
      if (!value) {
        detected = null;
        detectedFor = "";
        detectError = "";
        detectedNode.replaceChildren();
        return;
      }
      try {
        const answer = await api(`/api/intel/detect?value=${encodeURIComponent(value)}`);
        if (input.value.trim() !== value) return;
        detected = answer;
        detectError = "";
        detectedNode.replaceChildren(
          ...[
            badge(TYPE_LABELS[detected.type] || detected.type, "info"),
            detected.value !== value ? el("code", {}, detected.value) : null,
          ].filter(Boolean),
        );
      } catch (error) {
        if (input.value.trim() !== value) return;
        detected = null;
        detectError = error.message;
        detectedNode.replaceChildren(el("span", { class: "query-invalid" }, error.message));
      }
      detectedFor = value;
    }

    /* Re-render without losing the control the user is on (a filter being
       typed into, a "Mostrar todos" just pressed) while sources arrive. */
    function keepFocus(render) {
      const active = document.activeElement;
      const key = active && resultArea.contains(active) ? active.dataset?.focusKey : null;
      const selection = key && typeof active.selectionStart === "number" ? [active.selectionStart, active.selectionEnd] : null;
      render();
      if (!key) return;
      const next = [...resultArea.querySelectorAll("[data-focus-key]")].find((node) => node.dataset.focusKey === key);
      if (!next) return;
      next.focus({ preventScroll: true });
      if (selection && next.setSelectionRange) next.setSelectionRange(...selection);
    }

    const handlers = {
      pivot: (value) => {
        input.value = value;
        window.scrollTo({ top: 0, behavior: "auto" });
        submit({ fromPivot: true });
      },
      entity: (row) =>
        G.entityDialog(
          {
            entity_type: ENTITY_FROM_RESULT[row.result_type],
            identifier: cleanValue(row),
            name: cleanValue(row),
            description: `${RESULT_LABELS[row.result_type] || row.result_type} obtido na consulta multifonte de ${row.run_value || input.value.trim()}.`,
            source_reference: row.source_url || `note://garbage/intel-run/${row.run_id}`,
            collection_basis: "public",
          },
          {},
        ),
    };

    async function addToGraph(run, item = null) {
      try {
        const added = await api("/api/graph/add", {
          method: "POST",
          body: JSON.stringify({ run_id: run.id, item, investigation_id: caseSelect.value || run.investigation_id || null }),
        });
        G.state.graphFocus = added.entity_id;
        G.state.graphRoot = added.root_id;
        toast(item ? `${item.value} foi para o grafo.` : `${run.query_value} foi para o grafo.`);
        G.go("graph", added.investigation_id || undefined);
      } catch (error) {
        toast(error.message, "error");
      }
    }

    async function recordRun(run) {
      const investigationId = caseSelect.value || run.investigation_id;
      if (!investigationId) {
        toast("Escolha uma investigação aberta, na barra de pesquisa, para registrar os resultados.", "warning");
        caseSelect.focus();
        return;
      }
      try {
        const recorded = await api(`/api/intel/runs/${run.id}/record`, {
          method: "POST",
          body: JSON.stringify({ investigation_id: investigationId }),
        });
        toast(
          `Observação registrada com ${recorded.finding_count} resultado(s)${recorded.truncated ? " (texto truncado no limite)" : ""}.`,
        );
      } catch (error) {
        toast(error.message, "error");
      }
    }

    function header(run, dossier) {
      const progress = run.progress || { total: run.sources.length, pending: dossier.coverage?.pending || 0 };
      const running = run.status === "running" && progress.pending > 0;
      const answered = progress.total - progress.pending;
      const fill = el("span", { class: "dossier-progress-fill" });
      fill.style.width = `${Math.round((answered / Math.max(1, progress.total)) * 100)}%`;
      const facts = (dossier.facts || []).filter((fact) => fact && fact.value);
      const flags = dossier.flags || [];
      const caseId = caseSelect.value || run.investigation_id || "";
      return el(
        "header",
        { class: "dossier-head" },
        el(
          "div",
          { class: "dossier-head-top" },
          el("span", { class: "dossier-type" }, dossier.type_label || TYPE_LABELS[run.query_type] || run.query_type),
          el(
            "div",
            { class: "dossier-actions" },
            button("Adicionar ao grafo", () => addToGraph(run), { variant: "button-primary" }),
            button("Exportar JSON", () => downloadJson(`garbage-intel-${shortId(run.id)}.json`, run)),
            button("Registrar no caso", () => recordRun(run), {
              variant: caseId ? "button-primary" : "button-secondary",
              disabled: !run.results.length,
            }),
          ),
        ),
        el("h2", { class: "dossier-title", tabindex: "-1", "data-focus-key": "title" }, dossier.title || run.query_value),
        dossier.subtitle ? el("p", { class: "dossier-subtitle" }, dossier.subtitle) : null,
        facts.length
          ? el(
              "dl",
              { class: "dossier-facts" },
              ...facts.map((fact) => el("div", { class: "dossier-fact" }, el("dt", {}, fact.label), el("dd", {}, fact.value))),
            )
          : null,
        flags.length
          ? el(
              "ul",
              { class: "dossier-flags", "aria-label": "Pontos de atenção" },
              ...flags.map((flag) => {
                const [glyph, label] = FLAG_LEVEL[flag.level] || FLAG_LEVEL.info;
                return el(
                  "li",
                  { class: `dossier-flag level-${FLAG_LEVEL[flag.level] ? flag.level : "info"}` },
                  G.icon(glyph, { size: 16, className: "dossier-flag-icon" }),
                  el("span", { class: "visually-hidden" }, `${label}: `),
                  el("span", {}, flag.text),
                );
              }),
            )
          : null,
        running
          ? el(
              "div",
              { class: "dossier-progress", role: "status" },
              el("span", { class: "dossier-progress-track", "aria-hidden": "true" }, fill),
              el("span", {}, `${answered} de ${progress.total} fontes responderam…`),
              progress.pending <= 3
                ? el(
                    "span",
                    { class: "dossier-muted" },
                    `aguardando ${run.sources
                      .filter((item) => item.status === "pending")
                      .map((item) => connectorName(item.connector_id, connectorsById[item.connector_id]?.name))
                      .join(", ")}`,
                  )
                : null,
            )
          : run.status === "interrupted"
            ? el("p", { class: "dossier-progress", role: "status" }, "A consulta foi interrompida antes de todas as fontes responderem.")
            : null,
      );
    }

    /* One clear line when sources were left out by configuration. */
    function configurationNotice(run) {
      const network = run.sources.filter((item) => item.status === "network-disabled").length;
      const target = run.sources.filter((item) => item.status === "target-contact-disabled").length;
      const lines = [];
      if (network) {
        lines.push(
          el(
            "p",
            { class: "dossier-alert", role: "note" },
            G.icon("alert", { size: 16, className: "dossier-flag-icon" }),
            el("span", {}, `A rede está desativada: ${count(network, "fonte não foi consultada", "fontes não foram consultadas")}.`),
            el("a", { class: "dossier-link", href: "#/settings/conectores" }, "Ativar em Configurações › Conectores"),
          ),
        );
      }
      if (target) {
        lines.push(
          el(
            "p",
            { class: "dossier-alert", role: "note" },
            G.icon("info", { size: 16, className: "dossier-flag-icon" }),
            el("span", {}, `${count(target, "fonte que acessa", "fontes que acessam")} o próprio alvo ${target === 1 ? "ficou" : "ficaram"} de fora.`),
            el("a", { class: "dossier-link", href: "#/settings/conectores" }, "Permitir em Configurações › Conectores"),
          ),
        );
      }
      return lines;
    }

    function coverageLine(run, dossier) {
      const coverage = dossier.coverage || {};
      const parts = [];
      const waiting = run.status === "running" && coverage.pending > 0;
      parts.push(el("span", {}, count(coverage.answered || 0, "fonte respondeu", "fontes responderam")));
      if (coverage.empty) parts.push(el("span", {}, `${G.formatNumber(coverage.empty)} sem resultado`));
      if (coverage.missing_key?.length) {
        parts.push(
          el("span", {}, `${G.formatNumber(coverage.missing_key.length)} sem chave (${coverage.missing_key.join(", ")})`),
          el("a", { class: "dossier-link", href: "#/settings/chaves" }, "Configurar chaves"),
        );
      }
      if (coverage.failed?.length) {
        parts.push(
          el("span", {}, `${G.formatNumber(coverage.failed.length)} ${coverage.failed.length === 1 ? "falhou" : "falharam"} (${coverage.failed.join(", ")})`),
        );
      }
      if (coverage.network_off) parts.push(el("span", {}, `${G.formatNumber(coverage.network_off)} fora por configuração`));
      if (waiting) parts.push(el("span", {}, `${G.formatNumber(coverage.pending)} ainda consultando`));
      if (run.started_at) parts.push(el("span", { class: "dossier-muted" }, formatDate(run.started_at, { time: true })));
      const line = [];
      parts.forEach((part, index) => {
        if (index) line.push(el("span", { class: "dossier-sep", "aria-hidden": "true" }, "·"));
        line.push(part);
      });
      const tableHost = el("div", { class: "dossier-sources", id: "dossier-sources" });
      const toggle = el("button", {
        type: "button",
        class: "dossier-more",
        "aria-controls": "dossier-sources",
        "data-focus-key": "sources-toggle",
      });
      const sync = () => {
        toggle.setAttribute("aria-expanded", String(ui.sourcesOpen));
        toggle.textContent = ui.sourcesOpen ? "Ocultar fontes" : "Ver fontes";
        tableHost.hidden = !ui.sourcesOpen;
        tableHost.replaceChildren(...(ui.sourcesOpen ? [sourceTable(run, connectorsById)] : []));
      };
      toggle.addEventListener("click", () => {
        ui.sourcesOpen = !ui.sourcesOpen;
        sync();
      });
      sync();
      return el(
        "section",
        { class: "dossier-coverage", "aria-label": "Fontes consultadas" },
        el("p", { class: "dossier-coverage-line" }, ...line, el("span", { class: "dossier-sep", "aria-hidden": "true" }, "·"), toggle),
        tableHost,
      );
    }

    function rawData(run) {
      const host = el("div", { class: "dossier-raw-body" });
      const fill = () => {
        if (host.childElementCount) return;
        const rowHandlers = {
          pivot: handlers.pivot,
          entity: (row) => handlers.entity({ ...row, run_value: run.query_value, run_id: run.id }),
        };
        host.append(resultGroups(run, connectorsById, rowHandlers, ui));
        G.hydrateIcons(host);
      };
      const details = el(
        "details",
        { class: "dossier-raw", open: ui.rawOpen },
        el(
          "summary",
          { "data-focus-key": "raw-summary" },
          el("span", {}, "Dados brutos por fonte"),
          el("span", { class: "dossier-count" }, G.formatNumber(run.results.length)),
        ),
        host,
      );
      details.addEventListener("toggle", () => {
        ui.rawOpen = details.open;
        if (details.open) fill();
      });
      if (ui.rawOpen) fill();
      return details;
    }

    /* What stands in for the sections when there is nothing to show. */
    function emptyAnswer(run, dossier) {
      const coverage = dossier.coverage || {};
      const pending = run.status === "running" && coverage.pending > 0;
      if (pending) {
        return el("p", { class: "dossier-waiting" }, "As respostas aparecem aqui conforme as fontes respondem.");
      }
      // Nothing to show: say why (failures, network off) before "not found".
      if (coverage.failed?.length) {
        return el(
          "div",
          { class: "dossier-empty", role: "status" },
          el("h3", {}, coverage.answered ? "Nenhuma resposta útil" : "Nenhuma fonte conseguiu responder"),
          el("p", {}, `${count(coverage.failed.length, "fonte falhou", "fontes falharam")}: ${coverage.failed.join(", ")}. Pode ser limite de taxa ou instabilidade do serviço; as outras não trouxeram dados.`),
          button("Consultar de novo", () => {
            input.value = run.query_value;
            submit({ fresh: true });
          }, { variant: "button-primary" }),
        );
      }
      if (coverage.network_off) {
        return el(
          "div",
          { class: "dossier-empty", role: "status" },
          el("h3", {}, "Só as verificações locais rodaram"),
          el("p", {}, `Elas não têm nada a dizer sobre ${run.query_value}. As outras fontes precisam de rede ou de contato com o alvo.`),
        );
      }
      return el(
        "div",
        { class: "dossier-empty", role: "status" },
        el("h3", {}, "Nenhuma fonte encontrou dados"),
        el("p", {}, `As fontes consultadas não têm registros sobre ${run.query_value}.`),
      );
    }

    function showRun(run) {
      const dossier = run.dossier || fallbackDossier(run);
      const sections = dossier.sections || [];
      const blocks = sections.map((section) => dossierSection(section, { ui, pivot: handlers.pivot, add: (item) => addToGraph(run, item) }));
      if (dossier.map && Number.isFinite(Number(dossier.map.lat)) && Number.isFinite(Number(dossier.map.lon))) {
        const anchor = sections.findIndex((section) => ["location", "place", "network", "company", "contact"].includes(section.id));
        const at = sections.findIndex((section) => ["location", "place"].includes(section.id));
        blocks.splice((at >= 0 ? at : anchor >= 0 ? anchor : 0) + 1, 0, dossierMap(dossier.map, Boolean(connectorData.network_allowed)));
      }
      keepFocus(() => {
        resultArea.replaceChildren(
          el(
            "article",
            { class: "dossier", "aria-label": `Resultado para ${run.query_value}` },
            header(run, dossier),
            ...configurationNotice(run),
            blocks.length ? el("div", { class: "dossier-grid" }, ...blocks) : emptyAnswer(run, dossier),
            coverageLine(run, dossier),
            run.results.length ? rawData(run) : null,
          ),
        );
        G.hydrateIcons(resultArea);
      });
    }

    function showMessage(title, description) {
      resultArea.replaceChildren(
        el(
          "div",
          { class: "dossier" },
          el("div", { class: "dossier-empty", role: "status" }, el("h2", {}, title), description ? el("p", {}, description) : null),
        ),
      );
    }

    /* Sources answer one by one: poll and redraw while any is pending. */
    async function follow(run, token) {
      let seen = run.progress?.pending;
      while (run.status === "running" && token === pollToken) {
        await new Promise((resolve) => window.setTimeout(resolve, 700));
        if (token !== pollToken) return;
        run = await api(`/api/intel/runs/${run.id}`);
        if (token !== pollToken) return;
        if (run.progress?.pending !== seen || run.status !== "running") {
          seen = run.progress?.pending;
          showRun(run);
        }
      }
    }

    async function submit({ fromPivot = false, fresh = false } = {}) {
      const value = input.value.trim();
      if (!value) {
        input.focus();
        return;
      }
      if (detectedFor !== value) await detect();
      if (!detected) {
        showMessage("Não reconheci este artefato", detectError ? G.translateError(detectError) : "");
        return;
      }
      // Every compatible source runs; there is no per-source choice.
      const compatible = connectorData.items
        .filter((item) => item.accepts.includes(detected.type))
        .map((item) => item.connector_id);
      if (!compatible.length) {
        showMessage(
          "Nenhuma fonte aceita este tipo de artefato",
          `${detected.value} foi reconhecido como ${TYPE_LABELS[detected.type] || detected.type}, mas nenhuma fonte instalada consulta esse tipo.`,
        );
        return;
      }
      const token = ++pollToken;
      runButton.disabled = true;
      resultArea.replaceChildren(
        el(
          "div",
          { class: "dossier" },
          el(
            "header",
            { class: "dossier-head" },
            el("div", { class: "dossier-head-top" }, el("span", { class: "dossier-type" }, TYPE_LABELS[detected.type] || detected.type)),
            el("h2", { class: "dossier-title", tabindex: "-1", "data-focus-key": "title" }, detected.value),
            el("div", { class: "dossier-progress", role: "status" }, el("span", {}, `Consultando ${count(compatible.length, "fonte", "fontes")}…`)),
          ),
        ),
      );
      try {
        const run = await api("/api/intel/runs", {
          method: "POST",
          body: JSON.stringify({
            value,
            connectors: compatible,
            investigation_id: caseSelect.value || null,
            use_cache: fresh ? false : cacheToggle.checked,
            async: true,
          }),
        });
        if (token !== pollToken) return;
        // Each search is a history entry: Back returns to the previous answer.
        const target = `#/multisearch/${run.id}`;
        if (location.hash !== target) history.pushState(null, "", target);
        state.currentParams = [run.id];
        ui = freshUi();
        showRun(run);
        if (fromPivot) resultArea.querySelector(".dossier-title")?.focus({ preventScroll: true });
        runButton.disabled = false;
        await follow(run, token);
        if (token === pollToken) renderHistory();
      } catch (error) {
        if (token === pollToken) resultArea.replaceChildren(G.inlineError(error.message));
      } finally {
        runButton.disabled = false;
      }
    }

    const historyHost = el("div");
    const historyPanel = panel({ title: "Consultas recentes" }, historyHost);
    historyPanel.hidden = true;
    async function renderHistory() {
      const data = await api("/api/intel/runs?limit=15").catch(() => ({ items: [] }));
      // Nothing to list yet: the search bar stands alone.
      historyPanel.hidden = !data.items.length;
      historyHost.replaceChildren(
        table({
          columns: [
            { label: "ARTEFATO", render: (row) => el("code", {}, row.query_value) },
            { label: "TIPO", render: (row) => badge(TYPE_LABELS[row.query_type] || row.query_type, "neutral") },
            { label: "RESULTADOS", cellClass: "numeric-col", render: (row) => G.formatNumber(row.result_count) },
            { label: "QUANDO", render: (row) => G.relativeTime(row.started_at) },
          ],
          rows: data.items,
          emptyMessage: "Nenhuma consulta ainda.",
          onRowClick: (row) => go("multisearch", row.id),
        }),
      );
    }

    input.addEventListener("input", () => {
      clearTimeout(detectTimer);
      detectTimer = window.setTimeout(detect, 250);
    });
    // Enter always searches, even while a previous search is still running.
    input.addEventListener("keydown", (event) => {
      if (event.key !== "Enter" || event.isComposing) return;
      event.preventDefault();
      submit();
    });
    const form = el(
      "form",
      {
        class: "query-bar",
        role: "search",
        onSubmit: (event) => {
          event.preventDefault();
          submit();
          input.focus();
        },
      },
      el("div", { class: "query-field" }, el("span", { class: "query-icon", "aria-hidden": "true" }, G.icon("search", { size: 18 })), input, detectedNode),
      caseSelect,
      el(
        "label",
        { class: "query-cache", for: "multisearch-cache", "data-tooltip": "Reutilizar respostas recentes das fontes" },
        cacheToggle,
        el("span", {}, "Cache"),
      ),
      runButton,
    );

    root.append(
      ...[
        pageHeader({
          title: "Pesquisa multifonte",
          description: "Um artefato, todas as fontes compatíveis.",
        }),
        connectorData.network_allowed
          ? null
          : el(
              "div",
              { class: "notice-bar", role: "note" },
              el("span", {}, "Rede desativada: só fontes locais."),
              button("Ativar rede", () => enableNetwork(() => G.refreshView())),
            ),
        el("section", { class: "query-panel" }, form),
        resultArea,
        historyPanel,
      ].filter(Boolean),
    );
    G.hydrateIcons(root);
    renderHistory();

    const runId = params[0] && /^[0-9a-f-]{36}$/i.test(params[0]) ? params[0] : null;
    if (runId) {
      try {
        const run = await api(`/api/intel/runs/${runId}`);
        input.value = run.query_value;
        detect();
        showRun(run);
        if (run.status === "running") follow(run, ++pollToken).catch(() => {});
      } catch (error) {
        resultArea.replaceChildren(G.inlineError(error.message));
      }
    } else if (state.pendingMultiSearch) {
      input.value = state.pendingMultiSearch;
      state.pendingMultiSearch = "";
      await detect();
      submit();
    } else {
      window.setTimeout(() => input.focus(), 50);
    }
  }

  G.views.multisearch = renderMultiSearch;
  G.renderIntelConnectors = renderIntelConnectors;
  G.renderIntelKeys = renderIntelKeys;
  G.connectorLabel = (id) => connectorName(id, id);
  G.resultTypeLabel = (type) => RESULT_LABELS[type] || type;
  G.sourceStatusLabel = (status) => (STATUS_TEXT[status] || [status])[0];
  G.sourceStatusTone = (status) => (STATUS_TEXT[status] || [status, "neutral"])[1];
  G.connectorDescription = (id, fallback) => connectorDescription(id, fallback);
  G.multiSearch = function multiSearch(value) {
    state.pendingMultiSearch = value;
    go("multisearch");
  };
})();
