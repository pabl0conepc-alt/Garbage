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
    geolocation: "Localização da rede", "known-file": "Arquivo conhecido", scan: "Varredura urlscan",
    subdomain: "Subdomínio", certificate: "Certificado", "cve-record": "Registro da CVE",
    reference: "Referência", "affected-package": "Pacote afetado", alias: "Identificador alternativo",
    verdict: "Veredito dos motores", "threat-label": "Rótulo de ameaça", category: "Categoria",
    file: "Arquivo", "dns-record": "Registro DNS", "final-url": "URL final", "abuse-score": "Pontuação de abuso",
    "internet-noise": "Ruído na internet", "pulse-count": "Relatos (pulses)", pulse: "Relato (pulse)",
    "malware-family": "Família de malware", "attack-technique": "Técnica ATT&CK", host: "Host",
    service: "Serviço", payload: "Payload", "malicious-url": "URL maliciosa", ioc: "IOC", sample: "Amostra",
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
  };

  const STATUS_TEXT = {
    ok: ["Com resultados", "success"],
    empty: ["Sem resultados", "neutral"],
    error: ["Erro", "danger"],
    "rate-limited": ["Limite de taxa", "warning"],
    "network-disabled": ["Rede desativada", "warning"],
    "target-contact-disabled": ["Contato com o alvo desativado", "warning"],
    "key-missing": ["Sem chave", "neutral"],
    unsupported: ["Não se aplica", "neutral"],
    ready: ["Pronto", "success"],
  };

  const TYPE_LABELS = {
    domain: "Domínio", ipv4: "IPv4", ipv6: "IPv6", cidr: "CIDR", url: "URL", email: "E-mail",
    md5: "MD5", sha1: "SHA-1", sha256: "SHA-256", asn: "ASN", cve: "CVE",
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
        const text = value === true ? "sim" : String(value);
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
  /* Results                                                          */
  /* ---------------------------------------------------------------- */

  function sourceList(run, connectorsById) {
    const list = el("ol", { class: "source-list", "aria-label": "Status por fonte" });
    const order = { ok: 0, empty: 1, error: 2, "rate-limited": 3, "key-missing": 4, "network-disabled": 5, unsupported: 6 };
    const sources = [...run.sources].sort(
      (a, b) => (order[a.status] ?? 9) - (order[b.status] ?? 9) || a.connector_id.localeCompare(b.connector_id),
    );
    for (const source of sources) {
      const connector = connectorsById[source.connector_id];
      list.append(
        el(
          "li",
          { class: `source-row status-${source.status}` },
          el(
            "div",
            { class: "source-row-main" },
            el("strong", {}, connectorName(source.connector_id, connector?.name)),
            el(
              "span",
              { class: "source-row-meta" },
              ...[
                source.status === "ok" ? `${source.count} resultado(s)` : null,
                source.elapsed_ms ? `${G.formatNumber(source.elapsed_ms)} ms` : null,
                source.cached ? "cache" : null,
                connector?.network ? "rede" : "local",
              ]
                .filter(Boolean)
                .map((text) => el("span", {}, text)),
            ),
          ),
          statusBadgeFor(source.status),
          source.error ? el("p", { class: "source-row-error" }, G.translateError(source.error)) : null,
        ),
      );
    }
    return list;
  }

  function resultGroups(run, connectorsById, handlers) {
    const groups = new Map();
    for (const item of run.results) {
      if (!groups.has(item.connector_id)) groups.set(item.connector_id, []);
      groups.get(item.connector_id).push(item);
    }
    if (!groups.size) {
      return emptyState({
        icon: "search",
        title: "Nenhum resultado",
        description: "Nenhuma fonte retornou dados para este artefato. Verifique o status de cada fonte ao lado.",
      });
    }
    const wrap = el("div", { class: "result-groups" });
    for (const [connectorId, items] of groups) {
      const connector = connectorsById[connectorId];
      wrap.append(
        el(
          "section",
          { class: "result-group", "aria-label": connectorName(connectorId, connector?.name) },
          el(
            "header",
            { class: "result-group-head" },
            el("h3", {}, connectorName(connectorId, connector?.name)),
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
              { label: "TIPO", render: (row) => el("span", { class: "result-type" }, RESULT_LABELS[row.result_type] || row.result_type) },
              { label: "VALOR", render: (row) => el("code", { class: "result-value" }, G.translateText(row.value)) },
              { label: "DETALHES", render: (row) => el("span", { class: "result-data" }, dataSummary(row.data)) },
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
            rows: items,
          }),
        ),
      );
    }
    return wrap;
  }

  /* ---------------------------------------------------------------- */
  /* View                                                             */
  /* ---------------------------------------------------------------- */

  async function renderMultiSearch(root, params = []) {
    let [connectorData, runs] = await Promise.all([
      api("/api/intel/connectors"),
      api("/api/intel/runs?limit=15"),
    ]);
    await G.loadInvestigations?.();
    const investigations = (state.investigations || []).filter((item) => item.status === "open");
    const connectorsById = Object.fromEntries(connectorData.items.map((item) => [item.connector_id, item]));
    let detected = null;
    let currentRun = null;
    let activeTab = { conectores: "connectors", chaves: "keys" }[params[0]] || "search";
    const keysHost = el("div");
    let detectTimer = null;
    const selected = new Set(connectorData.items.map((item) => item.connector_id));

    const input = el("input", {
      class: "input query-input",
      type: "text",
      id: "multisearch-input",
      autocomplete: "off",
      spellcheck: "false",
      placeholder: "Domínio, IP, CIDR, URL, e-mail, hash, ASN ou CVE",
      "aria-label": "Artefato para consultar",
      maxlength: "2000",
    });
    const detectedNode = el("span", { class: "query-detected", "aria-live": "polite" });
    const caseSelect = el(
      "select",
      { class: "input compact-select", "aria-label": "Associar a uma investigação" },
      el("option", { value: "" }, "Sem investigação"),
      ...investigations.map((item) => el("option", { value: item.id }, item.name)),
    );
    const cacheToggle = el("input", { type: "checkbox", checked: true, id: "multisearch-cache" });
    const runButton = el(
      "button",
      { class: "button button-primary", type: "submit" },
      el("span", { "data-icon": "search", "aria-hidden": "true" }),
      "Consultar",
    );
    const connectorChips = el("div", { class: "connector-chips", role: "group", "aria-label": "Fontes a consultar" });
    const resultArea = el("div", { class: "multisearch-results", "aria-live": "polite" });
    const tabHost = el("div");
    const tabStrip = el("div");

    function chipsFor(type) {
      connectorChips.replaceChildren();
      for (const connector of connectorData.items) {
        const applies = !type || connector.accepts.includes(type);
        const blocked =
          (connector.network && !connectorData.network_allowed) ||
          (connector.contacts_target && !connectorData.target_contact_allowed);
        const checkbox = el("input", {
          type: "checkbox",
          checked: selected.has(connector.connector_id) && applies,
          disabled: !applies,
          onChange: (event) => {
            if (event.target.checked) selected.add(connector.connector_id);
            else selected.delete(connector.connector_id);
          },
        });
        connectorChips.append(
          el(
            "label",
            {
              class: `connector-chip${applies ? "" : " is-unavailable"}${blocked ? " is-blocked" : ""}`,
              "data-tooltip": connectorDescription(connector.connector_id, connector.description),
            },
            checkbox,
            el("span", {}, connectorName(connector.connector_id, connector.name)),
            connector.contacts_target
              ? el("span", { class: "chip-flag is-target" }, blocked ? "alvo off" : "alvo")
              : connector.network
                ? el("span", { class: "chip-flag" }, blocked ? "rede off" : "rede")
                : null,
          ),
        );
      }
    }

    async function detect() {
      const value = input.value.trim();
      if (!value) {
        detected = null;
        detectedNode.replaceChildren();
        chipsFor(null);
        return;
      }
      try {
        detected = await api(`/api/intel/detect?value=${encodeURIComponent(value)}`);
        detectedNode.replaceChildren(
          ...[
            badge(TYPE_LABELS[detected.type] || detected.type, "info"),
            detected.value !== value ? el("code", {}, detected.value) : null,
          ].filter(Boolean),
        );
        chipsFor(detected.type);
      } catch (error) {
        detected = null;
        detectedNode.replaceChildren(el("span", { class: "query-invalid" }, error.message));
        chipsFor(null);
      }
    }

    function showRun(run) {
      currentRun = run;
      const networkSkipped = run.sources.some((item) => item.status === "network-disabled");
      const keyless = run.sources.filter((item) => item.status === "key-missing");
      const caseId = caseSelect.value || run.investigation_id || "";
      const summaryNodes = [
        el(
          "div",
          { class: "run-summary" },
          el(
            "div",
            {},
            el("p", { class: "eyebrow" }, `CONSULTA ${shortId(run.id).toUpperCase()}`),
            el(
              "h2",
              {},
              badge(TYPE_LABELS[run.query_type] || run.query_type, "info"),
              " ",
              el("code", {}, run.query_value),
            ),
            el(
              "p",
              { class: "run-meta" },
              `${formatDate(run.started_at, { time: true })} · ${run.result_count} resultado(s) de ${run.sources.filter((item) => item.status === "ok").length} fonte(s)`,
              run.status === "completed-with-errors" ? " · com erros em fontes" : "",
            ),
          ),
          el(
            "div",
            { class: "page-actions" },
            button("Exportar JSON", () => downloadJson(`garbage-intel-${shortId(run.id)}.json`, run)),
            button(
              "Registrar no caso",
              async () => {
                const investigationId = caseSelect.value || run.investigation_id;
                if (!investigationId) {
                  toast("Escolha uma investigação aberta para registrar os resultados.", "warning");
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
              },
              { variant: caseId ? "button-primary" : "button-secondary", disabled: !run.results.length },
            ),
          ),
        ),
      ];
      if (networkSkipped && !connectorData.network_allowed) {
        summaryNodes.push(
          el(
              "div",
              { class: "notice-bar", role: "note" },
              el("span", {}, "Fontes de rede foram ignoradas porque os conectores de rede estão desativados."),
              button("Ativar rede", () => enableNetwork(() => G.refreshView())),
          ),
        );
      }
      if (keyless.length) {
        summaryNodes.push(
          el(
            "div",
            { class: "notice-bar is-quiet", role: "note" },
            el(
              "span",
              {},
              `${keyless.length} fonte(s) ficaram de fora por falta de chave: ` +
                keyless.map((item) => connectorName(item.connector_id, item.connector_id)).join(", ") + ".",
            ),
            el("a", { class: "button button-secondary button-small", href: "#/multisearch/chaves" }, "Configurar chaves"),
          ),
        );
      }
      summaryNodes.push(
        el(
          "div",
          { class: "multisearch-layout" },
          el(
            "aside",
            { class: "multisearch-sources" },
            el("h3", { class: "side-heading" }, "Fontes"),
            sourceList(run, connectorsById),
          ),
          resultGroups(run, connectorsById, {
            pivot: (value) => {
              input.value = value;
              detect().then(() => submit());
            },
            entity: (row) =>
              G.entityDialog(
                {
                  entity_type: ENTITY_FROM_RESULT[row.result_type],
                  identifier: cleanValue(row),
                  name: cleanValue(row),
                  description: `${RESULT_LABELS[row.result_type] || row.result_type} obtido na consulta multifonte de ${run.query_value}.`,
                  source_reference: row.source_url || `note://garbage/intel-run/${run.id}`,
                  collection_basis: "public",
                },
                {},
              ),
          }),
        ),
      );
      resultArea.replaceChildren(...summaryNodes);
      G.hydrateIcons(resultArea);
    }

    async function submit() {
      const value = input.value.trim();
      if (!value) {
        input.focus();
        return;
      }
      const chosen = [...selected].filter(
        (id) => !detected || connectorsById[id]?.accepts.includes(detected.type),
      );
      if (!chosen.length) {
        toast("Selecione pelo menos uma fonte compatível com este artefato.", "warning");
        return;
      }
      runButton.disabled = true;
      resultArea.replaceChildren(
        loadingBlock(`Consultando ${chosen.length} fonte(s)… fontes de rede podem levar alguns segundos.`),
      );
      try {
        const run = await api("/api/intel/runs", {
          method: "POST",
          body: JSON.stringify({
            value,
            connectors: chosen,
            investigation_id: caseSelect.value || null,
            use_cache: cacheToggle.checked,
          }),
        });
        history.replaceState(null, "", `#/multisearch/${run.id}`);
        showRun(run);
        renderHistory();
      } catch (error) {
        resultArea.replaceChildren(G.inlineError(error.message));
      } finally {
        runButton.disabled = false;
      }
    }

    const historyHost = el("div");
    async function renderHistory() {
      const data = await api("/api/intel/runs?limit=15").catch(() => ({ items: [] }));
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
    const form = el(
      "form",
      {
        class: "query-bar",
        onSubmit: (event) => {
          event.preventDefault();
          submit();
        },
      },
      el("div", { class: "query-field" }, input, detectedNode),
      caseSelect,
      el("label", { class: "inline-check", for: "multisearch-cache" }, cacheToggle, "Usar cache"),
      runButton,
    );

    function connectorsTab() {
      return panel(
        {
          eyebrow: "CONECTORES",
          title: "Status das fontes",
          caption: connectorData.network_allowed ? "Rede ativada" : "Rede desativada",
          actions: connectorData.network_allowed
            ? []
            : [button("Ativar rede", () => enableNetwork(() => G.refreshView()), { variant: "button-primary" })],
        },
        table({
          columns: [
            {
              label: "FONTE",
              render: (row) => el(
                "div",
                { class: "connector-cell" },
                el("strong", {}, connectorName(row.connector_id, row.name)),
                el("span", {}, connectorDescription(row.connector_id, row.description)),
              ),
            },
            { label: "ACEITA", render: (row) => row.accepts.map((type) => TYPE_LABELS[type] || type).join(", ") },
            {
              label: "ACESSO",
              render: (row) =>
                el(
                  "div",
                  { class: "connector-cell" },
                  el("span", {}, row.contacts_target ? "Contata o alvo" : row.network ? "Rede (passivo)" : "Local"),
                  row.key_id
                    ? el(
                        "a",
                        { class: "table-link", href: "#/multisearch/chaves" },
                        row.key_configured ? "Chave salva" : row.requires_key ? "Precisa de chave" : "Chave opcional",
                      )
                    : null,
                ),
            },
            { label: "DISPONIBILIDADE", render: (row) => statusBadgeFor(row.availability) },
            {
              label: "ÚLTIMA EXECUÇÃO",
              render: (row) =>
                row.status
                  ? el(
                      "div",
                      { class: "connector-cell" },
                      statusBadgeFor(row.status.last_status),
                      el(
                        "span",
                        {},
                        `${G.relativeTime(row.status.last_run_at)} · ${G.formatNumber(row.status.last_latency_ms)} ms`,
                      ),
                      row.status.last_error
                        ? el("span", { class: "source-row-error" }, G.translateError(row.status.last_error))
                        : null,
                    )
                  : el("span", { class: "muted" }, "Nunca executado"),
            },
            {
              label: "SUCESSOS / ERROS",
              cellClass: "numeric-col",
              render: (row) => (row.status ? `${row.status.success_count} / ${row.status.error_count}` : "—"),
            },
            {
              label: "LIMITE · CACHE",
              render: (row) =>
                `${row.rate_per_minute}/min · ${row.ttl_seconds ? `${Math.round(row.ttl_seconds / 3600) || 1} h` : "sem cache"}`,
            },
          ],
          rows: connectorData.items,
        }),
      );
    }

    async function keysTab() {
      keysHost.replaceChildren(loadingBlock("Carregando chaves…"));
      let keys;
      try {
        keys = await api("/api/intel/keys");
      } catch (error) {
        keysHost.replaceChildren(G.inlineError(error.message));
        return;
      }
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
          placeholder: provider.configured ? `Substituir a chave salva (${provider.hint})` : "Cole a chave aqui",
          "aria-label": `Chave de API de ${provider.name}`,
        });
        const save = async () => {
          if (!input.value.trim()) return;
          try {
            await api(`/api/intel/keys/${provider.provider_id}`, { method: "PUT", body: JSON.stringify({ key: input.value }) });
            input.value = "";
            toast(`Chave de ${provider.name} salva neste computador.`);
            connectorData = await api("/api/intel/connectors");
            keysTab();
          } catch (error) {
            toast(error.message, "error");
          }
        };
        input.addEventListener("keydown", (event) => {
          if (event.key === "Enter") save();
        });
        return el(
          "div",
          { class: "key-row" },
          el(
            "div",
            { class: "key-info" },
            el("strong", {}, provider.name),
            el("span", {}, PROVIDER_NOTE[provider.provider_id] || provider.note),
            el("span", { class: "muted" }, `Usada por: ${(usedBy[provider.provider_id] || []).join(", ")}`),
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
                    connectorData = await api("/api/intel/connectors");
                    keysTab();
                  } catch (error) {
                    toast(error.message, "error");
                  }
                })
              : null,
          ),
        );
      };
      keysHost.replaceChildren(
        panel(
          {
            eyebrow: "CHAVES DE API",
            title: "Suas contas nos provedores",
            caption: `${keys.items.filter((item) => item.configured).length} de ${keys.total} salvas`,
          },
          el(
            "p",
            { class: "panel-note" },
            "As chaves ficam só no banco local deste workspace. A interface nunca recebe a chave de volta, apenas os 4 últimos caracteres. " +
              "Cada chave vai apenas para o provedor dela, no cabeçalho que ele documenta, e é removida das mensagens de erro.",
          ),
          el("div", { class: "key-list" }, ...keys.items.map(row)),
        ),
      );
    }

    function renderTab() {
      tabStrip.replaceChildren(
        G.tabs({
          items: [
            { key: "search", label: "Pesquisa" },
            { key: "connectors", label: "Conectores", count: connectorData.total },
            { key: "keys", label: "Chaves de API" },
          ],
          active: activeTab,
          onSelect: (key) => {
            activeTab = key;
            renderTab();
          },
        }),
      );
      if (activeTab === "keys") keysTab();
      tabHost.replaceChildren(
        activeTab === "keys"
          ? keysHost
          : activeTab === "connectors"
          ? connectorsTab()
          : el(
              "div",
              {},
              el(
                "section",
                { class: "query-panel" },
                form,
                connectorChips,
              ),
              resultArea,
              panel({ eyebrow: "HISTÓRICO", title: "Consultas recentes" }, historyHost),
            ),
      );
      G.hydrateIcons(tabHost);
    }

    root.append(
      ...[
      pageHeader({
        eyebrow: "INTELIGÊNCIA MULTIFONTE",
        title: "Pesquisa multifonte",
        description:
          "Um artefato consultado em paralelo em todas as fontes compatíveis. Cada resultado guarda a fonte, o hash da resposta e o horário. Correlação não é atribuição.",
      }),
      connectorData.network_allowed
        ? null
        : el(
            "div",
            { class: "notice-bar", role: "note" },
            el(
              "span",
              {},
              "Conectores de rede desativados: só as fontes locais serão consultadas.",
            ),
            button("Ativar rede", () => enableNetwork(() => G.refreshView())),
          ),
      connectorData.network_allowed && !connectorData.target_contact_allowed
        ? el(
            "div",
            { class: "notice-bar is-quiet", role: "note" },
            el(
              "span",
              {},
              "Fontes passivas ativas. Certificado TLS e Impressão digital web acessam o próprio alvo e estão desligados.",
            ),
            button("Permitir contato com o alvo", () => enableTargetContact(() => G.refreshView())),
          )
        : null,
      tabStrip,
      tabHost,
      ].filter(Boolean),
    );
    chipsFor(null);
    renderTab();
    renderHistory();

    const runId = params[0] && /^[0-9a-f-]{36}$/i.test(params[0]) ? params[0] : null;
    if (runId) {
      try {
        const run = await api(`/api/intel/runs/${runId}`);
        input.value = run.query_value;
        await detect();
        showRun(run);
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
  G.connectorLabel = (id) => connectorName(id, id);
  G.resultTypeLabel = (type) => RESULT_LABELS[type] || type;
  G.sourceStatusLabel = (status) => (STATUS_TEXT[status] || [status])[0];
  G.multiSearch = function multiSearch(value) {
    state.pendingMultiSearch = value;
    go("multisearch");
  };
})();
