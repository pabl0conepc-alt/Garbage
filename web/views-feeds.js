"use strict";

/* CTI feeds: TAXII 2.1 servers and collections, and SigmaHQ detection rules. */

(function () {
  const G = window.GARBAGE;
  const { el, api, toast, panel, badge, table, loadingBlock, inlineError, pageHeader, formatDate, go } = G;

  const LEVEL_PT = { critical: "Crítico", high: "Alto", medium: "Médio", low: "Baixo", informational: "Informativo" };
  const STATUS_PT = { stable: "Estável", test: "Teste", experimental: "Experimental", deprecated: "Obsoleta", unsupported: "Sem suporte" };
  G.SIGMA_LEVEL_PT = LEVEL_PT;
  const MITRE_TAXII = "https://attack-taxii.mitre.org/taxii2/";

  function button(label, onClick, options = {}) {
    return el(
      "button",
      { class: `button ${options.variant || "button-secondary"} button-small`, type: "button", disabled: Boolean(options.disabled), onClick },
      label,
    );
  }

  function hashQuery() {
    const query = location.hash.split("?")[1] || "";
    return new URLSearchParams(query);
  }

  /* ---------------------------------------------------------------- */
  /* TAXII                                                             */
  /* ---------------------------------------------------------------- */

  async function renderTaxii(host) {
    let servers = [];
    let current = null; // {server, discovery, root, collections, collection}
    const serversHost = el("div");
    const browseHost = el("div");
    const objectsHost = el("div");

    async function loadServers() {
      try {
        servers = (await api("/api/taxii/servers")).items;
      } catch (error) {
        serversHost.replaceChildren(inlineError(error.message));
        return;
      }
      serversHost.replaceChildren(
        panel(
          {
            eyebrow: "TAXII 2.1",
            title: `Servidores (${servers.length})`,
            actions: [
              button("Adicionar servidor", () => addServer()),
              servers.some((item) => item.discovery_url === MITRE_TAXII)
                ? null
                : button("Adicionar o servidor público do MITRE ATT&CK", () => addServer({ name: "MITRE ATT&CK", discovery_url: MITRE_TAXII })),
            ].filter(Boolean),
          },
          servers.length
            ? table({
                columns: [
                  { label: "NOME", render: (row) => el("strong", {}, row.name) },
                  { label: "DESCOBERTA", render: (row) => el("code", {}, row.discovery_url) },
                  { label: "CREDENCIAIS", render: (row) => (row.has_credentials ? "Basic" : "Público") },
                  { label: "OBJETOS", className: "numeric-col", render: (row) => G.formatNumber(row.object_count) },
                  { label: "ÚLTIMA COLETA", render: (row) => (row.last_pull_at ? formatDate(row.last_pull_at, { time: true }) : "—") },
                  {
                    label: "",
                    render: (row) =>
                      el(
                        "div",
                        { class: "inline-actions" },
                        button("Abrir", () => openServer(row)),
                        button("Remover", () => removeServer(row), { variant: "button-danger" }),
                      ),
                  },
                ],
                rows: servers,
              })
            : el("p", { class: "panel-empty" }, "Nenhum servidor TAXII. Adicione um pela URL de descoberta (por exemplo, o servidor público do MITRE ATT&CK)."),
          el("p", { class: "tool-limit" }, "Credenciais ficam só neste computador, em texto no banco local, como as chaves de API; nunca são devolvidas pela API."),
        ),
      );
    }

    async function addServer(preset = null) {
      const save = (values) => api("/api/taxii/servers", { method: "POST", body: JSON.stringify(values) });
      if (preset) {
        try {
          await save(preset);
        } catch (error) {
          toast(error.message, "error");
          return;
        }
      } else {
        const saved = await G.formDialog({
          title: "Adicionar servidor TAXII",
          eyebrow: "TAXII 2.1",
          fields: [
            { name: "name", label: "Nome", required: true },
            { name: "discovery_url", label: "URL de descoberta (https)", required: true, placeholder: "https://servidor.exemplo/taxii2/" },
            { name: "username", label: "Usuário (opcional)" },
            { name: "password", label: "Senha (opcional)", type: "password" },
          ],
          submitLabel: "Adicionar",
          onSubmit: save,
        });
        if (!saved) return;
      }
      toast("Servidor TAXII adicionado.");
      loadServers();
    }

    async function removeServer(server) {
      const ok = await G.confirm({ title: `Remover ${server.name}?`, message: "O servidor e os objetos já baixados dele são apagados deste workspace.", confirmLabel: "Remover", danger: true });
      if (!ok) return;
      try {
        await api(`/api/taxii/servers/${server.id}`, { method: "DELETE" });
        if (current?.server.id === server.id) {
          current = null;
          browseHost.replaceChildren();
          objectsHost.replaceChildren();
        }
        loadServers();
      } catch (error) {
        toast(error.message, "error");
      }
    }

    async function openServer(server) {
      browseHost.replaceChildren(loadingBlock(`Consultando a descoberta de ${server.name}…`));
      objectsHost.replaceChildren();
      try {
        const discovery = await api(`/api/taxii/servers/${server.id}/discover`);
        current = { server, discovery, root: discovery.default || discovery.api_roots[0] };
        await openRoot(current.root);
      } catch (error) {
        browseHost.replaceChildren(inlineError(error.message));
      }
    }

    async function openRoot(root) {
      current.root = root;
      const rootSelect = el(
        "select",
        { class: "input compact-select", "aria-label": "Raiz da API", onChange: (event) => openRoot(event.target.value) },
        ...current.discovery.api_roots.map((item) => el("option", { value: item, selected: item === root }, item.replace(/^https:\/\/[^/]+/, ""))),
      );
      browseHost.replaceChildren(loadingBlock("Listando coleções…"));
      let result;
      try {
        result = await api(`/api/taxii/servers/${current.server.id}/collections?api_root=${encodeURIComponent(root)}`);
      } catch (error) {
        browseHost.replaceChildren(inlineError(error.message));
        return;
      }
      browseHost.replaceChildren(
        panel(
          { eyebrow: current.discovery.title || current.server.name, title: "Coleções", actions: [rootSelect] },
          current.discovery.description ? el("p", { class: "panel-note" }, current.discovery.description) : null,
          table({
            columns: [
              { label: "COLEÇÃO", render: (row) => el("div", { class: "cell-stack" }, el("strong", {}, row.title || row.id), el("code", {}, row.id)) },
              { label: "DESCRIÇÃO", render: (row) => el("span", { class: "clamp-3" }, row.description || "—") },
              { label: "ACESSO", render: (row) => (row.can_read ? "Leitura" : "Sem leitura") },
              {
                label: "",
                render: (row) =>
                  el(
                    "div",
                    { class: "inline-actions" },
                    button("Baixar objetos", () => pullCollection(row), { disabled: !row.can_read, variant: "button-primary" }),
                    button("Ver baixados", () => showObjects(row)),
                  ),
              },
            ],
            rows: result.items,
            emptyMessage: "Nenhuma coleção nesta raiz.",
          }),
        ),
      );
    }

    async function pullCollection(collection) {
      let values = null;
      const accepted = await G.formDialog({
        title: `Baixar ${collection.title || collection.id}`,
        eyebrow: "COLETA TAXII",
        fields: [
          { name: "max_objects", label: "Máximo de objetos (até 20000)", type: "number", value: "5000", required: true },
          { name: "object_types", label: "Tipos STIX (opcional, separados por vírgula)", placeholder: "indicator, malware" },
          { name: "added_after", label: "Adicionados depois de (opcional, UTC)", placeholder: "2026-01-01T00:00:00Z" },
        ],
        submitLabel: "Baixar",
        onSubmit: (submitted) => {
          const max = Number(submitted.max_objects);
          if (!Number.isInteger(max) || max < 1 || max > 20000) throw new Error("O máximo deve ficar entre 1 e 20000.");
          values = submitted;
        },
      });
      if (!accepted || !values) return;
      objectsHost.replaceChildren(loadingBlock("Baixando objetos página por página…"));
      try {
        const result = await api(`/api/taxii/servers/${current.server.id}/pull`, {
          method: "POST",
          body: JSON.stringify({
            api_root: current.root,
            collection_id: collection.id,
            max_objects: Number(values.max_objects),
            object_types: values.object_types ? values.object_types.split(",").map((item) => item.trim()).filter(Boolean) : null,
            added_after: values.added_after || null,
          }),
        });
        toast(`${G.formatNumber(result.object_count)} objeto(s) em ${result.page_count} página(s)${result.status === "partial" ? ", coleta parcial" : ""}.`);
        loadServers();
        showObjects(collection);
      } catch (error) {
        objectsHost.replaceChildren(inlineError(error.message));
      }
    }

    async function showObjects(collection, filters = {}) {
      const params = new URLSearchParams({ server_id: current.server.id, collection_id: collection.id, limit: "200" });
      if (filters.type) params.set("type", filters.type);
      if (filters.q) params.set("q", filters.q);
      let data;
      try {
        data = await api(`/api/taxii/objects?${params}`);
      } catch (error) {
        objectsHost.replaceChildren(inlineError(error.message));
        return;
      }
      const typeSelect = el(
        "select",
        { class: "input compact-select", "aria-label": "Tipo STIX" },
        el("option", { value: "" }, "Todos os tipos"),
        ...Object.entries(data.types).sort((a, b) => b[1] - a[1]).map(([type, count]) => el("option", { value: type, selected: type === filters.type }, `${type} (${count})`)),
      );
      const search = el("input", { class: "input", type: "search", placeholder: "Filtrar por nome ou padrão", value: filters.q || "" });
      typeSelect.addEventListener("change", () => showObjects(collection, { ...filters, type: typeSelect.value }));
      search.addEventListener("change", () => showObjects(collection, { ...filters, q: search.value }));
      const chosen = new Set();
      const caseSelect = el(
        "select",
        { class: "input compact-select", "aria-label": "Investigação" },
        el("option", { value: "" }, "Escolha a investigação"),
        ...(await G.loadInvestigations()).map((item) => el("option", { value: item.id }, item.name)),
      );
      const sendButton = button("Registrar indicadores no caso", async () => {
        if (!caseSelect.value || !chosen.size) {
          toast("Escolha a investigação e marque indicadores.", "warning");
          return;
        }
        try {
          const result = await api("/api/taxii/objects/to-case", {
            method: "POST",
            body: JSON.stringify({ investigation_id: caseSelect.value, server_id: current.server.id, collection_id: collection.id, object_ids: [...chosen] }),
          });
          toast(`${result.observable_count} observável(is) de ${result.indicator_count} indicador(es) registrados como observação.`);
        } catch (error) {
          toast(error.message, "error");
        }
      });
      objectsHost.replaceChildren(
        panel(
          { eyebrow: "OBJETOS STIX", title: `${collection.title || collection.id} · ${G.formatNumber(data.total)}` },
          el("div", { class: "graph-toolbar" }, typeSelect, search),
          table({
            columns: [
              {
                label: "",
                render: (row) =>
                  row.type === "indicator"
                    ? el("input", {
                        type: "checkbox",
                        "aria-label": `Selecionar ${row.name}`,
                        onChange: (event) => (event.target.checked ? chosen.add(row.object_id) : chosen.delete(row.object_id)),
                      })
                    : null,
              },
              { label: "TIPO", render: (row) => badge(row.type, "neutral") },
              { label: "NOME", render: (row) => el("div", { class: "cell-stack" }, el("strong", {}, row.name), row.pattern ? el("code", { class: "clamp-2" }, row.pattern) : null) },
              { label: "MODIFICADO", render: (row) => (row.modified ? formatDate(row.modified) : "—") },
            ],
            rows: data.items,
            emptyMessage: "Nada baixado desta coleção ainda.",
          }),
          data.total > data.items.length ? el("p", { class: "run-meta" }, `Mostrando ${data.items.length} de ${G.formatNumber(data.total)}; use os filtros.`) : null,
          data.types.indicator
            ? el("div", { class: "graph-toolbar" }, caseSelect, sendButton)
            : null,
          el("p", { class: "tool-limit" }, "Objetos guardados como o servidor publicou. Indicadores enviados ao caso viram uma observação, e o motor de indicadores extrai e correlaciona os valores; nada é verificado automaticamente."),
        ),
      );
    }

    host.replaceChildren(serversHost, browseHost, objectsHost);
    await loadServers();
  }

  /* ---------------------------------------------------------------- */
  /* Sigma                                                             */
  /* ---------------------------------------------------------------- */

  async function renderSigma(host, ruleId) {
    const query = hashQuery();
    const filters = { technique: query.get("technique") || "", q: "", level: "", product: "" };
    const statusHost = el("div");
    const listHost = el("div");
    const ruleHost = el("div");

    async function loadStatus() {
      let status;
      try {
        status = await api("/api/sigma");
      } catch (error) {
        statusHost.replaceChildren(inlineError(error.message));
        return null;
      }
      const refresh = button(status.loaded ? "Atualizar regras" : "Baixar regras do SigmaHQ", async () => {
        refresh.disabled = true;
        refresh.textContent = "Baixando…";
        try {
          await api("/api/sigma/refresh", { method: "POST", body: "{}" });
          toast("Regras Sigma carregadas.");
          await loadStatus();
          loadRules();
        } catch (error) {
          toast(error.message, "error");
          refresh.disabled = false;
        }
      }, { variant: status.loaded ? "button-secondary" : "button-primary" });
      statusHost.replaceChildren(
        panel(
          { eyebrow: "SIGMA", title: status.loaded ? `${G.formatNumber(status.rule_count)} regras · ${status.version}` : "Regras ainda não baixadas", actions: [refresh] },
          status.loaded
            ? G.kvList([
                ["Com técnica ATT&CK", G.formatNumber(status.with_techniques)],
                ["Por nível", Object.entries(status.levels).map(([level, count]) => `${LEVEL_PT[level] || level}: ${count}`).join(" · ")],
                ["Baixadas em", formatDate(status.fetched_at, { time: true })],
                ["SHA-256 do pacote", el("code", { class: "hash" }, status.sha256)],
              ])
            : el("p", { class: "panel-empty" }, "Um download explícito do pacote de regras principais da última versão do SigmaHQ (cerca de 1,4 MB)."),
          el("p", { class: "tool-limit" }, `Regras de detecção do SigmaHQ e de seus autores, sob ${status.license}. São material de referência: o GARBAGE não converte nem executa regras.`),
        ),
      );
      return status;
    }

    async function loadRules() {
      const params = new URLSearchParams({ limit: "200" });
      Object.entries(filters).forEach(([key, value]) => value && params.set(key, value));
      let data;
      try {
        data = await api(`/api/sigma/rules?${params}`);
      } catch (error) {
        listHost.replaceChildren(inlineError(error.message));
        return;
      }
      const search = el("input", { class: "input", type: "search", placeholder: "Título, descrição ou tag", value: filters.q });
      search.addEventListener("change", () => { filters.q = search.value; loadRules(); });
      const technique = el("input", { class: "input compact-select", placeholder: "Técnica (T1059)", value: filters.technique, "aria-label": "Técnica ATT&CK" });
      technique.addEventListener("change", () => { filters.technique = technique.value.trim(); loadRules(); });
      const level = el(
        "select",
        { class: "input compact-select", "aria-label": "Nível" },
        el("option", { value: "" }, "Todos os níveis"),
        ...Object.entries(LEVEL_PT).map(([key, label]) => el("option", { value: key, selected: key === filters.level }, label)),
      );
      level.addEventListener("change", () => { filters.level = level.value; loadRules(); });
      const product = el(
        "select",
        { class: "input compact-select", "aria-label": "Produto" },
        el("option", { value: "" }, "Todos os produtos"),
        ...data.products.map((item) => el("option", { value: item, selected: item === filters.product }, item)),
      );
      product.addEventListener("change", () => { filters.product = product.value; loadRules(); });
      listHost.replaceChildren(
        panel(
          { eyebrow: "REGRAS", title: `${G.formatNumber(data.total)} regra(s)` },
          el("div", { class: "graph-toolbar" }, technique, level, product, search),
          table({
            columns: [
              { label: "REGRA", render: (row) => el("div", { class: "cell-stack" }, el("strong", {}, row.title), el("span", { class: "clamp-2" }, row.description)) },
              { label: "NÍVEL", render: (row) => badge(LEVEL_PT[row.level] || row.level, row.level === "critical" || row.level === "high" ? "warning" : "neutral") },
              { label: "FONTE DE LOG", render: (row) => [row.product, row.category || row.service].filter(Boolean).join(" · ") || "—" },
              { label: "TÉCNICAS", render: (row) => el("div", { class: "chip-list" }, ...row.techniques.slice(0, 4).map((id) => el("a", { class: "table-link", href: `#/attack?technique=${id}` }, id))) },
            ],
            rows: data.items,
            emptyMessage: "Nenhuma regra com esses filtros.",
            onRowClick: (row) => openRule(row.id),
          }),
        ),
      );
    }

    async function openRule(id) {
      history.replaceState(null, "", `#/feeds/sigma/${id}`);
      ruleHost.replaceChildren(loadingBlock("Abrindo regra…"));
      try {
        const rule = await api(`/api/sigma/rules/${id}`);
        ruleHost.replaceChildren(
          panel(
            { eyebrow: "REGRA SIGMA", title: rule.title, actions: [badge(LEVEL_PT[rule.level] || rule.level, "neutral"), badge(STATUS_PT[rule.status] || rule.status, "neutral")] },
            el("p", { class: "prose" }, rule.description),
            G.kvList([
              ["ID", el("code", {}, rule.id)],
              ["Fonte de log", [rule.product, rule.category, rule.service].filter(Boolean).join(" · ") || "—"],
              ["Técnicas", rule.techniques.join(", ") || "—"],
              ["Falsos positivos", rule.falsepositives.join("; ") || "—"],
              ["Criada / alterada", `${rule.date || "—"} / ${rule.modified || "—"}`],
            ]),
            rule.references.length ? el("ul", { class: "attack-list" }, ...rule.references.map((reference) => el("li", {}, G.referenceNode(reference)))) : null,
            el("details", { class: "transform-details", open: true }, el("summary", {}, "YAML da regra"), el("pre", { class: "code-block" }, rule.raw)),
            el("p", { class: "tool-limit" }, `Fonte: SigmaHQ, ${rule.path}. ${rule.license}.`),
          ),
        );
        ruleHost.scrollIntoView({ block: "nearest" });
      } catch (error) {
        ruleHost.replaceChildren(inlineError(error.message));
      }
    }

    host.replaceChildren(statusHost, ruleHost, listHost);
    const status = await loadStatus();
    if (status?.loaded) await loadRules();
    if (ruleId) openRule(ruleId);
  }

  async function renderFeeds(root, params = []) {
    const tab = params[0] === "sigma" ? "sigma" : "taxii";
    const host = el("div");
    root.replaceChildren(
      pageHeader({
        eyebrow: "INTELIGÊNCIA DE AMEAÇAS",
        title: "Feeds CTI",
        description: "Coleções STIX de servidores TAXII 2.1 e regras de detecção Sigma ligadas às técnicas ATT&CK. Tudo é baixado só quando você pede.",
      }),
      G.tabs({
        items: [
          { key: "taxii", label: "TAXII 2.1" },
          { key: "sigma", label: "Regras Sigma" },
        ],
        active: tab,
        onSelect: (key) => go("feeds", key),
      }),
      host,
    );
    if (tab === "sigma") await renderSigma(host, params[1]);
    else await renderTaxii(host);
  }

  G.views.feeds = renderFeeds;
})();
