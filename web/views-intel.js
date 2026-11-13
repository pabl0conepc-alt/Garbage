"use strict";

/* Entity, indicator, evidence, source and report workspaces. */

(function () {
  const G = window.GARBAGE;
  const {
    el, api, toast, confirm, formDialog, pageHeader, panel, badge, statusBadge,
    emptyState, table, loadingBlock, inlineError, formatDate, formatBytes,
    shortId, titleCase, entityTypeLabel, relationshipLabel, indicatorTypeLabel,
    go, state, moduleEnabled,
  } = G;

  function button(label, onClick, options = {}) {
    return el(
      "button",
      {
        class: `button ${options.variant || "button-secondary"} button-small`,
        type: "button",
        disabled: Boolean(options.disabled),
        title: options.title || "",
        onClick,
      },
      label,
    );
  }

  function referenceNode(reference) {
    return G.referenceNode(reference);
  }

  function caseLink(investigationId, name) {
    return el(
      "a",
      { class: "table-link", href: `#/investigations/${investigationId}` },
      name || shortId(investigationId),
    );
  }

  function errorState(title, message, retry) {
    const box = el(
      "div",
      { class: "empty-state" },
      el("span", { class: "empty-icon", "aria-hidden": "true" }, "!"),
      el("h2", {}, title),
      el("p", {}, message),
    );
    if (retry) box.append(button("Tentar novamente", retry, { variant: "button-primary" }));
    return box;
  }

  function typeChip(type) {
    return badge(entityTypeLabel(type), "info");
  }

  /* ================================================================ */
  /* Entities                                                          */
  /* ================================================================ */

  async function renderEntities(root, params) {
    if (params[0]) return renderEntity(root, params[0]);
    const data = await api("/api/entities?limit=500");
    const search = el("input", {
      class: "input",
      type: "search",
      placeholder: "Pesquisar nomes, identificadores ou descrições",
      "aria-label": "Pesquisar entidades",
    });
    const typeFilter = el(
      "select",
      { class: "input compact-select", "aria-label": "Filtrar por tipo de entidade" },
      el("option", { value: "" }, "Todas as categorias"),
      ...G.ENTITY_TYPES.map(([value, label]) => el("option", { value }, label)),
    );
    const host = el("div");
    const count = el("span", { class: "panel-caption" });

    function draw() {
      const query = search.value.trim().toLowerCase();
      const type = typeFilter.value;
      const rows = data.items.filter((entity) => {
        if (type && entity.entity_type !== type) return false;
        return `${entity.name} ${entity.identifier} ${entity.description}`
          .toLowerCase()
          .includes(query);
      });
      count.textContent = `${rows.length} de ${data.total} registros compartilhados`;
      host.replaceChildren(
        table({
          columns: [
            { label: "CATEGORIA", render: (row) => typeChip(row.entity_type) },
            { label: "NOME", render: (row) => el("strong", {}, row.name) },
            {
              label: "IDENTIFICADOR",
              render: (row) =>
                row.identifier
                  ? el("code", { class: "reference-code" }, row.identifier)
                  : el("span", { class: "muted" }, "—"),
            },
            { label: "COLETA", render: (row) => badge(titleCase(row.collection_basis), "neutral") },
            { label: "CONFIANÇA", render: (row) => badge(titleCase(row.confidence), "neutral") },
            { label: "VERIFICAÇÃO", render: (row) => statusBadge(row.verification_status) },
            {
              label: "CASOS",
              className: "numeric-col",
              render: (row) => String(row.investigation_count ?? 0),
            },
            {
              label: "",
              render: (row) => button("Inspecionar", () => go("entities", row.id)),
            },
          ],
          rows,
          emptyMessage: data.items.length
            ? "Nenhuma entidade corresponde a estes filtros."
            : "Nenhuma entidade foi registrada.",
          onRowClick: (row) => go("entities", row.id),
        }),
      );
    }

    root.append(
      pageHeader({
        eyebrow: "REGISTRO DE INTELIGÊNCIA",
        title: "Entidades",
        description:
          "Registros canônicos compartilhados entre casos, o quadro de investigação e o grafo de relacionamentos.",
        actions: [
          button("Registrar entidade", () => G.entityDialog(), {
            variant: "button-primary",
          }),
        ],
      }),
      el(
        "div",
        { class: "metric-grid compact-metrics" },
        G.metric({
          label: "TOTAL DE REGISTROS",
          value: String(data.total),
          foot: "Registro compartilhado",
          icon: "⬡",
          tone: "violet",
        }),
        ...Object.entries(
          data.items.reduce((accumulator, entity) => {
            accumulator[entity.entity_type] = (accumulator[entity.entity_type] || 0) + 1;
            return accumulator;
          }, {}),
        )
          .sort((a, b) => b[1] - a[1])
          .slice(0, 4)
          .map(([type, value]) =>
            G.metric({
              label: entityTypeLabel(type).toUpperCase(),
              value: String(value),
              foot: "Registros",
              icon: "·",
              tone: "blue",
            }),
          ),
      ),
      panel(
        { eyebrow: "REGISTRO", title: "Entidades compartilhadas", actions: [count] },
        el(
          "div",
          { class: "toolbar" },
          el("div", { class: "search-field" }, el("span", { class: "search-field-icon" }, G.icon("search", { size: 14 })), search),
          typeFilter,
        ),
        data.items.length
          ? host
          : emptyState({
              icon: "⬡",
              title: "Nenhuma entidade ainda",
              description:
                "Registre um domínio, endereço, conta, organização ou arquivo para começar a correlacionar.",
              action: button("Registrar entidade", () => G.entityDialog(), {
                variant: "button-primary",
              }),
            }),
      ),
    );
    if (data.items.length) {
      draw();
      search.addEventListener("input", draw);
      typeFilter.addEventListener("change", draw);
    }
  }

  async function renderEntity(root, entityId) {
    let lastOutcome = null;

    async function load() {
      return api(`/api/entities/${entityId}`);
    }

    async function draw() {
      G.setLoading(true);
      let entity;
      try {
        entity = await load();
      } catch (error) {
        root.replaceChildren(
          errorState("Entidade indisponível", error.message, () => draw()),
        );
        G.setLoading(false);
        return;
      }
      G.setLoading(false);
      root.replaceChildren(
        pageHeader({
          eyebrow: "ENTIDADE COMPARTILHADA",
          title: entity.name,
          description: entity.description || "Nenhuma descrição registrada.",
          actions: [
            button("‹ Todas as entidades", () => go("entities")),
            button("Editar", () => G.entityDialog(entity, { onSaved: () => draw() })),
            button("Abrir grafo", () => go("graph")),
            button(
              "Excluir",
              () => G.deleteEntity(entity, () => go("entities")),
              { variant: "button-danger" },
            ),
          ],
        }),
        el(
          "div",
          { class: "case-meta" },
          typeChip(entity.entity_type),
          statusBadge(entity.verification_status),
          el("code", {}, entity.id),
          el("span", {}, `Registrada em ${formatDate(entity.created_at, { time: true })}`),
        ),
        el(
          "div",
          { class: "detail-grid" },
          panel(
            { eyebrow: "PROPRIEDADES", title: "Dados do registro" },
            G.kvList([
              ["Categoria", typeChip(entity.entity_type)],
              ["Identificador", entity.identifier ? el("code", { class: "reference-code" }, entity.identifier) : "—"],
              ["Base de coleta", badge(titleCase(entity.collection_basis), "neutral")],
              ["Confiança", badge(titleCase(entity.confidence), "neutral")],
              ["Verificação", statusBadge(entity.verification_status)],
              ["Fonte", referenceNode(entity.source_reference)],
              ["Criação", formatDate(entity.created_at, { time: true })],
              ["Atualização", formatDate(entity.updated_at, { time: true })],
            ]),
          ),
          panel(
            { eyebrow: "VÍNCULOS COM CASOS", title: `Investigações (${entity.investigations.length})` },
            entity.investigations.length
              ? table({
                  columns: [
                    { label: "CASO", render: (row) => caseLink(row.id, row.name) },
                    { label: "STATUS", render: (row) => statusBadge(row.status) },
                    { label: "VINCULADA EM", render: (row) => formatDate(row.added_at) },
                  ],
                  rows: entity.investigations,
                  emptyMessage: "Não vinculada a um caso.",
                })
              : el("p", { class: "panel-empty" }, "Não vinculada a um caso."),
          ),
          panel(
            { eyebrow: "PROVENIÊNCIA", title: `Fontes (${entity.sources.length})` },
            entity.sources.length
              ? table({
                  columns: [
                    { label: "TÍTULO", render: (row) => el("strong", {}, row.title) },
                    { label: "CATEGORIA", render: (row) => badge(titleCase(row.category), "neutral") },
                    { label: "REFERÊNCIA", render: (row) => referenceNode(row.reference) },
                  ],
                  rows: entity.sources,
                  emptyMessage: "Nenhuma fonte vinculada.",
                })
              : el("p", { class: "panel-empty" }, "Nenhuma fonte vinculada."),
          ),
          panel(
            {
              eyebrow: "RELACIONAMENTOS",
              title: `Relacionamentos (${entity.relationships.length})`,
              actions: [
                button(
                  "Registrar relacionamento",
                  () =>
                    G.relationshipDialog({
                      entities: [entity],
                      onSaved: () => draw(),
                    }),
                  { disabled: true, title: "Registre relacionamentos a partir de um caso com pelo menos duas entidades" },
                ),
              ],
            },
            entity.relationships.length
              ? table({
                  columns: [
                    {
                      label: "DIREÇÃO",
                      render: (row) =>
                        badge(row.direction === "outgoing" ? "Saída" : "Entrada", "neutral"),
                    },
                    {
                      label: "ENTIDADE RELACIONADA",
                      render: (row) =>
                        el(
                          "div",
                          { class: "cell-stack" },
                          el("strong", {}, row.other_name),
                          el("span", {}, entityTypeLabel(row.other_type)),
                        ),
                    },
                    {
                      label: "TIPO",
                      render: (row) => el("span", { class: "relation-type" }, relationshipLabel(row.relationship_type)),
                    },
                    { label: "VERIFICAÇÃO", render: (row) => statusBadge(row.verification_status) },
                    { label: "CONTEXTO", render: (row) => (row.investigation_id ? caseLink(row.investigation_id) : "Compartilhado") },
                  ],
                  rows: entity.relationships,
                  emptyMessage: "Nenhum relacionamento registrado para esta entidade.",
                })
              : el("p", { class: "panel-empty" }, "Nenhum relacionamento registrado."),
          ),
          moduleEnabled("entity-resolution") ? G.entityAliasesPanel(entity.id) : null,
          moduleEnabled("transforms") && moduleEnabled("intel-orchestrator")
            ? G.transformPanel(entity, {
                investigationId: entity.investigations.length === 1 ? entity.investigations[0].id : null,
                lastOutcome,
                onRun: async (outcome) => {
                  lastOutcome = outcome;
                  const top = window.scrollY;
                  await draw();
                  window.scrollTo(0, top);
                },
              })
            : null,
          moduleEnabled("transforms") ? G.transformHistoryPanel(entity.id) : null,
        ),
      );
    }

    await draw();
  }

  /* ================================================================ */
  /* Indicators                                                        */
  /* ================================================================ */

  async function renderIndicators(root) {
    let selectedKey = null;
    let data = null;
    const search = el("input", {
      class: "input",
      type: "search",
      placeholder: "Filtrar indicadores observados",
      "aria-label": "Filtrar indicadores",
    });
    const typeFilter = el(
      "select",
      { class: "input compact-select", "aria-label": "Filtrar tipo de indicador" },
      el("option", { value: "" }, "Todos os tipos de indicador"),
      ...G.INDICATOR_TYPES.map(([value, label]) => el("option", { value }, label)),
    );
    const countLabel = el("span", { class: "panel-caption" });
    const tableHost = el("div");
    const detailHost = el("div", { class: "indicator-detail" });
    const triageText = el("textarea", {
      class: "input triage-input",
      id: "triage-text",
      rows: "4",
      placeholder: "Cole texto de relatório, uma URL neutralizada, hashes ou uma lista de indicadores…",
      "aria-label": "Texto para triagem",
    });
    const triageButton = button("Extrair indicadores", () => runTriage(), {
      variant: "button-primary",
    });
    const triageHost = el("div", { class: "triage-result" });
    const inspectorHost = el("div", { class: "inspector-host" });

    async function load() {
      data = await api("/api/indicators?limit=1000");
    }

    await load();

    if (G.state.pendingIndicatorSearch) {
      search.value = G.state.pendingIndicatorSearch;
      G.state.pendingIndicatorSearch = "";
    }

    function filtered() {
      const query = search.value.trim().toLowerCase();
      const type = typeFilter.value;
      return data.items.filter((item) => {
        if (type && item.type !== type) return false;
        return `${item.value} ${item.type}`.toLowerCase().includes(query);
      });
    }

    function drawDetail(item) {
      if (!item) {
        detailHost.replaceChildren(
          el(
            "p",
            { class: "panel-empty" },
            "Selecione um indicador para inspecionar sua proveniência e registrar uma avaliação analítica.",
          ),
        );
        return;
      }
      const status = el(
        "select",
        { class: "input", "aria-label": "Status de verificação do indicador" },
        ...G.VERIFICATION_STATUSES.map(([value, label]) =>
          el("option", { value, selected: value === item.verification_status }, label),
        ),
      );
      const note = el("textarea", {
        class: "input",
        rows: 3,
        placeholder: "Justificativa e limitações da avaliação",
      });
      note.value = item.assessment_note || "";
      const provenance = el("div", { class: "origin-list" });
      for (const origin of item.origins) {
        provenance.append(
          el(
            "div",
            { class: "origin-item" },
            el(
              "div",
              { class: "origin-heading" },
              badge(titleCase(origin.origin_type), "neutral"),
              el("strong", {}, origin.label || origin.origin_id),
            ),
            el(
              "div",
              { class: "record-meta" },
              origin.investigation_id ? caseLink(origin.investigation_id, origin.investigation_name) : "Workspace",
              el("span", {}, origin.timestamp ? formatDate(origin.timestamp, { time: true }) : "Sem data"),
            ),
            origin.source_reference
              ? el("div", { class: "record-meta" }, "Fonte: ", referenceNode(origin.source_reference))
              : null,
          ),
        );
      }
      detailHost.replaceChildren(
        panel(
          {
            eyebrow: "PROVENIÊNCIA DO INDICADOR",
            title: item.value,
            caption: `${indicatorTypeLabel(item.type)} · ${item.origin_count} ${item.origin_count === 1 ? "origem" : "origens"}`,
          },
          el(
            "div",
            { class: "indicator-summary" },
            G.kvList([
              ["Tipo", badge(indicatorTypeLabel(item.type), "info")],
              ["Primeira ocorrência", item.first_seen ? formatDate(item.first_seen, { time: true }) : "—"],
              ["Última ocorrência", item.last_seen ? formatDate(item.last_seen, { time: true }) : "—"],
              [
                "Casos",
                item.investigations.length
                  ? item.investigations.map((entry) => caseLink(entry.id, entry.name))
                  : "Somente workspace",
              ],
            ]),
          ),
          el("h3", { class: "subheading" }, "Avaliação"),
          el("p", { class: "panel-note" }, "Um indicador não é prova de atividade maliciosa. " +
            "Registre o que o valor sustenta e o que permanece sem verificação."),
          el("div", { class: "field" }, el("label", {}, "Status de verificação"), status),
          el("div", { class: "field" }, el("label", {}, "Nota de avaliação"), note),
          el(
            "div",
            { class: "toolbar-end" },
            moduleEnabled("intel-orchestrator")
              ? button("Pesquisa multifonte", () => G.multiSearch(item.value), { variant: "button-secondary" })
              : null,
            button(
              "Inspecionar valor",
              async () => {
                await inspectIndicator(item.value);
                inspectorHost.scrollIntoView({ behavior: "smooth", block: "center" });
              },
              { variant: "button-secondary" },
            ),
            button(
              "Salvar avaliação",
              async () => {
                try {
                  await api("/api/indicators/assessment", {
                    method: "POST",
                    body: JSON.stringify({
                      indicator_type: item.type,
                      value: item.value,
                      verification_status: status.value,
                      note: note.value,
                    }),
                  });
                  toast("Avaliação do indicador salva.");
                  await load();
                  const refreshed = data.items.find(
                    (entry) => entry.type === item.type && entry.value === item.value,
                  );
                  drawTable();
                  drawDetail(refreshed || null);
                } catch (error) {
                  toast(error.message, "error");
                }
              },
              { variant: "button-primary" },
            ),
          ),
          el("h3", { class: "subheading" }, `Proveniência (${item.origins.length})`),
          item.origins.length ? provenance : el("p", { class: "panel-empty" }, "Nenhuma origem de proveniência disponível."),
        ),
      );
    }

    async function runTriage() {
      const text = triageText.value.trim();
      if (!text) {
        toast("Cole algum texto antes de extrair indicadores.", "error");
        triageText.focus();
        return;
      }
      triageButton.disabled = true;
      triageButton.textContent = "Extraindo…";
      triageHost.replaceChildren(loadingBlock("Extraindo indicadores em memória…"));
      inspectorHost.replaceChildren();
      try {
        const result = await api("/api/intelligence/text", {
          method: "POST",
          body: JSON.stringify({ text }),
        });
        drawTriage(result);
      } catch (error) {
        triageHost.replaceChildren(inlineError(error.message));
      } finally {
        triageButton.disabled = false;
        triageButton.textContent = "Extrair indicadores";
      }
    }

    function drawTriage(result) {
      const summary = el(
        "div",
        { class: "triage-summary" },
        triageMetric("Valores únicos", result.unique_count),
        triageMetric("Ocorrências", result.indicator_count),
        triageMetric("Caracteres", result.characters),
        triageMetric("Entrada neutralizada", result.defanged ? "Sim" : "Não"),
        triageMetric("Truncado", result.truncated ? "Sim" : "Não"),
      );
      const notices = (result.warnings || []).map((warning) =>
        el("p", { class: "inline-notice" }, warning),
      );
      if (!result.items.length) {
        triageHost.replaceChildren(
          summary,
          ...notices,
          el(
            "p",
            { class: "panel-empty" },
            "Nenhum valor reconhecido de IPv4, IPv6, CIDR, domínio, URL, e-mail ou hash foi encontrado.",
          ),
        );
        return;
      }
      triageHost.replaceChildren(
        summary,
        ...notices,
        table({
          columns: [
            { label: "TIPO", render: (row) => badge(indicatorTypeLabel(row.type), "info") },
            {
              label: "VALOR",
              render: (row) => el("code", { class: "indicator-value", title: row.value }, row.value),
            },
            {
              label: "VISTO",
              className: "numeric-col",
              render: (row) => String(row.count),
            },
            {
              label: "CONTEXTO",
              render: (row) => el("span", { class: "triage-context" }, row.contexts[0] || "—"),
            },
            {
              label: "",
              render: (row) => button("Inspecionar", () => inspectIndicator(row.value)),
            },
          ],
          rows: result.items,
          emptyMessage: "Nenhum indicador encontrado.",
          onRowClick: (row) => inspectIndicator(row.value),
        }),
      );
    }

    function triageMetric(label, value) {
      return el(
        "div",
        { class: "triage-metric" },
        el("span", {}, label),
        el("strong", {}, String(value)),
      );
    }

    async function inspectIndicator(value) {
      inspectorHost.replaceChildren(loadingBlock("Inspecionando valor localmente…"));
      try {
        const result = await api(
          `/api/intelligence/inspect?value=${encodeURIComponent(value)}`,
        );
        drawInspector(result);
      } catch (error) {
        inspectorHost.replaceChildren(inlineError(error.message));
      }
    }

    function drawInspector(result) {
      const local = result.local || {};
      const indicator = local.indicator;
      const matchRows = [];
      if (indicator) {
        matchRows.push(
          el(
            "div",
            { class: "inspector-match" },
            badge("Indicador indexado", "success"),
            el("span", {}, `${indicator.origin_count} origem(ns) · ${indicatorTypesLabel(indicator.type)}`),
          ),
        );
      }
      for (const entity of local.entities || []) {
        matchRows.push(
          el(
            "div",
            { class: "inspector-match" },
            badge("Entidade", "info"),
            el("span", {}, entity.name),
            entity.investigation_id ? caseLink(entity.investigation_id) : null,
          ),
        );
      }
      for (const evidence of local.evidence || []) {
        matchRows.push(
          el(
            "div",
            { class: "inspector-match" },
            badge("Evidências", "warning"),
            el("span", {}, evidence.title),
            evidence.investigation_id ? caseLink(evidence.investigation_id, evidence.investigation_name) : null,
          ),
        );
      }
      for (const analysis of local.file_analyses || []) {
        matchRows.push(
          el(
            "div",
            { class: "inspector-match" },
            badge("Análise de arquivo", "neutral"),
            el("span", {}, analysis.file_name),
            el("span", { class: "muted" }, analysis.format),
          ),
        );
      }
      const lookalikeData = local.lookalikes || {};
      const lookalikes = lookalikeData.items?.length
        ? el(
            "div",
            { class: "inspector-related" },
            el("h3", { class: "subheading" }, "Domínios semelhantes locais"),
            el(
              "p",
              { class: "panel-note" },
              "Candidatos por distância de edição a partir apenas de registros locais; não são domínios registrados nem prova de falsificação.",
            ),
            ...lookalikeData.items.map((item) =>
              el(
                "div",
                { class: "inspector-match" },
                badge(`distância ${item.distance}`, item.distance === 1 ? "warning" : "neutral"),
                el("code", {}, item.value),
                el("span", { class: "muted" }, item.reason),
              ),
            ),
            el("p", { class: "tool-limit" }, `${lookalikeData.scanned} candidato(s) local(is) verificado(s) · ${lookalikeData.engine}`),
          )
        : null;
      const cooccurring = (local.cooccurring || []).length
        ? el(
            "div",
            { class: "inspector-related" },
            el("h3", { class: "subheading" }, "Valores coocorrentes"),
            el("p", { class: "panel-note" }, "Valores encontrados nas mesmas observações; isto é coocorrência, não um relacionamento comprovado."),
            ...(local.cooccurring || []).map((item) =>
              el(
                "div",
                { class: "inspector-match" },
                badge(indicatorTypesLabel(item.type), "neutral"),
                el("code", {}, item.value),
                el("span", { class: "muted" }, `${item.count} observação(ões)`),
              ),
            ),
          )
        : null;
      inspectorHost.replaceChildren(
        el(
          "section",
          { class: "tool-result inspector-card" },
          el(
            "div",
            { class: "inspector-heading" },
            el(
              "div",
              {},
              el("p", { class: "eyebrow" }, "INSPETOR DE VALOR LOCAL"),
              el("h3", {}, result.label),
            ),
            el(
              "div",
              { class: "row-actions" },
              badge(`${result.match_count} correspondência(s) local(is)`, result.match_count ? "success" : "neutral"),
              button("Fechar", () => inspectorHost.replaceChildren(), { variant: "button-secondary" }),
            ),
          ),
          el("code", { class: "inspector-canonical" }, result.canonical || result.input),
          kvListFromFacts(result.facts),
          ...(result.warnings || []).map((warning) =>
            el("p", { class: "inline-notice" }, warning),
          ),
          el("h3", { class: "subheading" }, "Correspondências locais exatas"),
          matchRows.length
            ? el("div", { class: "inspector-matches" }, ...matchRows)
            : el("p", { class: "panel-empty" }, "Nenhum registro local corresponde exatamente a este valor. Ele ainda pode existir como texto livre em uma observação."),
          lookalikes,
          cooccurring,
          ...(result.limitations || []).map((limitation) =>
            el("p", { class: "tool-limit" }, G.translateText(limitation)),
          ),
        ),
      );
    }

    function indicatorTypesLabel(type) {
      return indicatorTypeLabel(type);
    }

    function kvListFromFacts(facts) {
      return G.kvList((facts || []).map((fact) => [fact.label, fact.value]));
    }

    function drawTable() {
      const rows = filtered();
      countLabel.textContent = `${rows.length} de ${data.total} indicadores`;
      const columns = [
        { label: "TIPO", render: (row) => badge(indicatorTypeLabel(row.type), "info") },
        {
          label: "VALOR",
          render: (row) => el("code", { class: "indicator-value", title: row.value }, row.value),
        },
        { label: "ORIGENS", className: "numeric-col", render: (row) => String(row.origin_count) },
        {
          label: "CASOS",
          className: "numeric-col",
          render: (row) => String(row.investigations.length),
        },
        {
          label: "PRIMEIRA OCORRÊNCIA",
          render: (row) => (row.first_seen ? formatDate(row.first_seen) : "—"),
        },
        { label: "AVALIAÇÃO", render: (row) => statusBadge(row.verification_status) },
      ];
      tableHost.replaceChildren(
        table({
          columns,
          rows,
          emptyMessage: data.total
            ? "Nenhum indicador corresponde a estes filtros."
            : "Nenhum indicador foi extraído de observações, entidades ou evidências.",
          onRowClick: (row) => {
            selectedKey = `${row.type}:${row.value}`;
            drawDetail(row);
          },
        }),
      );
      if (selectedKey) {
        const item = rows.find((row) => `${row.type}:${row.value}` === selectedKey);
        if (item) drawDetail(item);
      }
    }

    root.append(
      pageHeader({
        eyebrow: "MOTOR DE INDICADORES",
        title: "Pesquisa de inteligência",
        description:
          "Indicadores extraídos do texto das observações, de entidades registradas e de hashes de evidências, unificados por valor exato.",
        actions: [button("Reconstruir índice", () => G.refreshView())],
      }),
      el(
        "div",
        { class: "metric-grid compact-metrics" },
        G.metric({
          label: "INDICADORES ÚNICOS",
          value: String(data.total),
          foot: "Índice por valor exato",
          icon: "⌁",
          tone: "amber",
        }),
        G.metric({
          label: "ORIGENS DE EXTRAÇÃO",
          value: String(data.extraction_count),
          foot: "Ocorrências em texto + registros",
          icon: "▤",
          tone: "blue",
        }),
        G.metric({
          label: "CORRELAÇÕES",
          value: String(data.correlation_count),
          foot: "Valores exatos compartilhados",
          icon: "⟷",
          tone: "violet",
        }),
        G.metric({
          label: "MOTOR",
          value: data.indicator_engine ? "Disponível" : "Indisponível",
          foot: "Extração por expressão regular",
          icon: "◈",
          tone: data.indicator_engine ? "green" : "amber",
        }),
      ),
      panel(
        { eyebrow: "FERRAMENTA", title: "Triagem de texto", caption: "Executado em memória · nada é armazenado" },
        el(
          "p",
          { class: "panel-note" },
          "Cole texto de relatório para extrair valores de IPv4, IPv6, CIDR, domínio, URL, e-mail e hash. A notação neutralizada é restaurada antes da comparação; nenhuma consulta de DNS ou reputação é feita.",
        ),
        el(
          "div",
          { class: "triage-tool" },
          triageText,
          el(
            "div",
            { class: "triage-actions" },
            triageButton,
            el("span", { class: "field-hint" }, "Ctrl/⌘ Enter para executar"),
          ),
        ),
        triageHost,
        inspectorHost,
      ),
      el(
        "div",
        { class: "indicator-layout" },
        panel(
          {
            eyebrow: "ARTEFATOS OBSERVADOS",
            title: "Índice de indicadores",
            actions: [countLabel],
            className: "table-panel",
          },
          el(
            "div",
            { class: "toolbar" },
            el("div", { class: "search-field" }, el("span", { class: "search-field-icon" }, G.icon("search", { size: 14 })), search),
            typeFilter,
          ),
          data.truncated
            ? el(
                "p",
                { class: "inline-notice" },
                "O índice atingiu o limite de análise de 5.000 observações; refine o caso ou reduza o volume de dados.",
              )
            : null,
          tableHost,
        ),
        detailHost,
      ),
    );

    root.append(
      panel(
        {
          eyebrow: "CORROBORAÇÃO",
          title: "Correspondências entre fontes",
          caption: `${data.correlation_count} ${data.correlation_count === 1 ? "valor exato" : "valores exatos"}`,
        },
        el(
          "p",
          { class: "panel-note" },
          "Somente valores observados em mais de um registro são listados. Fontes independentes são contadas por referência de fonte distinta; a contagem de observações sozinha não é corroboração.",
        ),
        data.correlations && data.correlations.length
          ? table({
              columns: [
                { label: "TIPO", render: (row) => badge(indicatorTypeLabel(row.type), "info") },
                {
                  label: "VALOR",
                  render: (row) => el("code", { class: "indicator-value", title: row.value }, row.value),
                },
                {
                  label: "OBSERVAÇÕES",
                  className: "numeric-col",
                  render: (row) => String(row.observation_count),
                },
                {
                  label: "FONTES INDEPENDENTES",
                  className: "numeric-col",
                  render: (row) => String(row.independent_source_count),
                },
                {
                  label: "FORÇA",
                  render: (row) =>
                    badge(
                      titleCase(row.strength),
                      row.strength === "high"
                        ? "success"
                        : row.strength === "medium"
                          ? "info"
                          : row.strength === "low"
                            ? "warning"
                            : "neutral",
                    ),
                },
              ],
              rows: data.correlations,
              emptyMessage: "Nenhum valor foi observado em mais de um registro ainda.",
              onRowClick: (row) => {
                selectedKey = `${row.type}:${row.value}`;
                drawTable();
              },
            })
          : el(
              "p",
              { class: "panel-empty" },
              "Nenhuma correspondência exata entre fontes ainda. Uma única observação, mesmo com vários valores, não é corroboração.",
            ),
        data.correlations_truncated
          ? el("p", { class: "inline-notice" }, "Somente as primeiras 200 correlações são exibidas.")
          : null,
      ),
    );

    drawTable();
    drawDetail(null);
    search.addEventListener("input", drawTable);
    typeFilter.addEventListener("change", drawTable);
    triageText.addEventListener("keydown", (event) => {
      if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
        event.preventDefault();
        runTriage();
      }
    });
  }

  /* ================================================================ */
  /* Evidence                                                          */
  /* ================================================================ */

  async function renderEvidence(root) {
    const data = await api("/api/evidence?limit=500");
    const search = el("input", {
      class: "input",
      type: "search",
      placeholder: "Pesquisar título, nome de arquivo ou SHA-256",
      "aria-label": "Pesquisar evidências",
    });
    const countLabel = el("span", { class: "panel-caption" });
    const host = el("div");

    function draw() {
      const query = search.value.trim().toLowerCase();
      const rows = data.items.filter((row) =>
        `${row.title} ${row.description} ${row.original_name} ${row.sha256} ${row.investigation_name}`
          .toLowerCase()
          .includes(query),
      );
      countLabel.textContent = `${rows.length} de ${data.total} registros`;
      host.replaceChildren(
        table({
          columns: [
            {
              label: "EVIDÊNCIA",
              render: (row) =>
                el(
                  "div",
                  { class: "cell-stack" },
                  el("strong", {}, row.title),
                  el("span", {}, row.original_name || row.evidence_type),
                ),
            },
            { label: "CASO", render: (row) => caseLink(row.investigation_id, row.investigation_name) },
            { label: "TIPO", render: (row) => badge(titleCase(row.evidence_type), "neutral") },
            {
              label: "SHA-256",
              render: (row) =>
                el("code", { class: "hash", title: row.sha256 }, row.sha256 ? row.sha256.slice(0, 16) : "—"),
            },
            { label: "TAMANHO", render: (row) => formatBytes(row.size_bytes) },
            {
              label: "INTEGRIDADE",
              render: (row) =>
                statusBadge(row.integrity_status === "unverified" ? "not-verified" : row.integrity_status),
            },
            { label: "REGISTRO", render: (row) => formatDate(row.recorded_at) },
            {
              label: "AÇÕES",
              render: (row) =>
                el(
                  "div",
                  { class: "row-actions" },
                  row.has_file
                    ? el(
                        "a",
                        {
                          class: "button button-secondary button-small",
                          href: `/api/evidence/${row.id}/download`,
                        },
                        "Baixar",
                      )
                    : null,
                  row.has_file
                    ? button("Verificar", async () => {
                        try {
                          const result = await api(`/api/evidence/${row.id}/verify`, {
                            method: "POST",
                            body: JSON.stringify({}),
                          });
                          toast(
                            result.matches ? "O hash confere." : `Integridade: ${G.statusLabel(result.integrity_status)}.`,
                            result.matches ? "success" : "error",
                          );
                          G.refreshView();
                        } catch (error) {
                          toast(error.message, "error");
                        }
                      })
                    : null,
                ),
            },
          ],
          rows,
          emptyMessage: data.items.length
            ? "Nenhuma evidência corresponde a esta pesquisa."
            : "Não há registros de evidência.",
          onRowClick: (row) => go("investigations", row.investigation_id),
        }),
      );
    }

    root.append(
      pageHeader({
        eyebrow: "GERENCIADOR DE EVIDÊNCIAS",
        title: "Evidências",
        description:
          "Cópias com hash e referências do analista. Os originais são preservados; arquivos armazenados nunca são executados.",
        actions: [
          button("Adicionar evidência", () => G.evidenceDialog(), {
            variant: "button-primary",
          }),
        ],
      }),
      panel(
        { eyebrow: "ARMAZENAMENTO ÍNTEGRO", title: "Registros de evidência", actions: [countLabel] },
        el(
          "div",
          { class: "toolbar" },
          el("div", { class: "search-field" }, el("span", { class: "search-field-icon" }, G.icon("search", { size: 14 })), search),
        ),
        data.items.length
          ? host
          : emptyState({
              icon: "▣",
              title: "Nenhum registro de evidência",
              description:
                "Anexe um arquivo (máximo de 4 MiB) ou registre uma referência com seu hash.",
              action: button("Adicionar evidência", () => G.evidenceDialog(), {
                variant: "button-primary",
              }),
            }),
      ),
    );
    if (data.items.length) {
      draw();
      search.addEventListener("input", draw);
    }
  }

  /* ================================================================ */
  /* Sources                                                           */
  /* ================================================================ */

  async function renderSources(root, params) {
    if (params[0]) return renderSource(root, params[0]);
    const data = await api("/api/sources?limit=500");
    const search = el("input", {
      class: "input",
      type: "search",
      placeholder: "Pesquisar títulos, referências ou notas",
      "aria-label": "Pesquisar fontes",
    });
    const categoryFilter = el(
      "select",
      { class: "input compact-select", "aria-label": "Filtrar categoria da fonte" },
      el("option", { value: "" }, "Todas as categorias"),
      ...G.SOURCE_CATEGORIES.map(([value, label]) => el("option", { value }, label)),
    );
    const countLabel = el("span", { class: "panel-caption" });
    const host = el("div");

    function draw() {
      const query = search.value.trim().toLowerCase();
      const category = categoryFilter.value;
      const rows = data.items.filter((row) => {
        if (category && row.category !== category) return false;
        return `${row.title} ${row.reference} ${row.description}`.toLowerCase().includes(query);
      });
      countLabel.textContent = `${rows.length} de ${data.total} fontes`;
      host.replaceChildren(
        table({
          columns: [
            {
              label: "FONTE",
              render: (row) =>
                el(
                  "div",
                  { class: "cell-stack" },
                  el("strong", {}, row.title),
                  el("span", {}, row.description || "Sem descrição"),
                ),
            },
            { label: "CATEGORIA", render: (row) => badge(titleCase(row.category), "neutral") },
            { label: "REFERÊNCIA", render: (row) => referenceNode(row.reference) },
            {
              label: "CASOS",
              className: "numeric-col",
              render: (row) => String(row.investigation_count),
            },
            { label: "ACESSO", render: (row) => formatDate(row.accessed_at) },
            { label: "VERIFICAÇÃO", render: (row) => statusBadge(row.verification_status) },
            { label: "", render: (row) => button("Inspecionar", () => go("sources", row.id)) },
          ],
          rows,
          emptyMessage: data.items.length
            ? "Nenhuma fonte corresponde a estes filtros."
            : "Nenhuma fonte foi registrada.",
          onRowClick: (row) => go("sources", row.id),
        }),
      );
    }

    root.append(
      pageHeader({
        eyebrow: "PROVENIÊNCIA",
        title: "Fontes",
        description:
          "Cada observação, entidade e relatório aponta para uma fonte registrada e a data de acesso.",
        actions: [
          button("Registrar fonte", () => G.sourceDialog(), {
            variant: "button-primary",
          }),
        ],
      }),
      panel(
        { eyebrow: "REGISTRO DE FONTES", title: "Fontes consultadas", actions: [countLabel] },
        el(
          "div",
          { class: "toolbar" },
          el("div", { class: "search-field" }, el("span", { class: "search-field-icon" }, G.icon("search", { size: 14 })), search),
          categoryFilter,
        ),
        data.items.length
          ? host
          : emptyState({
              icon: "⛁",
              title: "Nenhuma fonte registrada",
              description: "Registre uma URL, documento ou nota do analista antes de citá-la em um caso.",
              action: button("Registrar fonte", () => G.sourceDialog(), {
                variant: "button-primary",
              }),
            }),
      ),
    );
    if (data.items.length) {
      draw();
      search.addEventListener("input", draw);
      categoryFilter.addEventListener("change", draw);
    }
  }

  async function renderSource(root, sourceId) {
    async function load() {
      return api(`/api/sources/${sourceId}`);
    }

    async function draw() {
      G.setLoading(true);
      let source;
      try {
        source = await load();
      } catch (error) {
        root.replaceChildren(
          errorState("Fonte indisponível", error.message, () => draw()),
        );
        G.setLoading(false);
        return;
      }
      G.setLoading(false);
      root.replaceChildren(
        pageHeader({
          eyebrow: "REGISTRO DA FONTE",
          title: source.title,
          description: source.description || "Nenhuma descrição registrada.",
          actions: [
            button("‹ Todas as fontes", () => go("sources")),
            button("Editar", () => G.sourceDialog(source, { onSaved: () => draw() })),
            button(
              "Excluir",
              async () => {
                if (
                  !(await confirm({
                    title: "Excluir fonte",
                    message: `Excluir "${source.title}" do registro compartilhado?`,
                    confirmLabel: "Excluir fonte",
                    danger: true,
                  }))
                )
                  return;
                try {
                  await api(`/api/sources/${source.id}`, { method: "DELETE" });
                  toast("Fonte excluída.");
                  go("sources");
                } catch (error) {
                  toast(error.message, "error");
                }
              },
              { variant: "button-danger" },
            ),
          ],
        }),
        el(
          "div",
          { class: "case-meta" },
          badge(titleCase(source.category), "neutral"),
          statusBadge(source.verification_status),
          el("code", {}, source.id),
          el("span", {}, `Acessada em ${formatDate(source.accessed_at, { time: true })}`),
        ),
        el(
          "div",
          { class: "detail-grid" },
          panel(
            { eyebrow: "PROPRIEDADES", title: "Dados da fonte" },
            G.kvList([
              ["Referência", referenceNode(source.reference)],
              ["Categoria", badge(titleCase(source.category), "neutral")],
              ["Acesso", formatDate(source.accessed_at, { time: true })],
              ["Verificação", statusBadge(source.verification_status)],
              ["Criação", formatDate(source.created_at, { time: true })],
              ["Atualização", formatDate(source.updated_at, { time: true })],
            ]),
          ),
          panel(
            { eyebrow: "VÍNCULOS COM CASOS", title: `Investigações (${source.investigations.length})` },
            source.investigations.length
              ? table({
                  columns: [
                    { label: "CASO", render: (row) => caseLink(row.id, row.name) },
                    { label: "STATUS", render: (row) => statusBadge(row.status) },
                    { label: "VINCULADA EM", render: (row) => formatDate(row.added_at) },
                  ],
                  rows: source.investigations,
                  emptyMessage: "Não vinculada a um caso.",
                })
              : el("p", { class: "panel-empty" }, "Não vinculada a um caso."),
          ),
          panel(
            { eyebrow: "VÍNCULOS COM ENTIDADES", title: `Entidades (${source.entities.length})` },
            source.entities.length
              ? table({
                  columns: [
                    { label: "ENTIDADE", render: (row) => el("strong", {}, row.name) },
                    { label: "CATEGORIA", render: (row) => typeChip(row.entity_type) },
                    { label: "VINCULADA EM", render: (row) => formatDate(row.added_at) },
                  ],
                  rows: source.entities,
                  emptyMessage: "Não vinculada a uma entidade.",
                })
              : el("p", { class: "panel-empty" }, "Não vinculada a uma entidade."),
          ),
        ),
      );
    }

    await draw();
  }

  /* ================================================================ */
  /* Reports                                                           */
  /* ================================================================ */

  async function renderReports(root) {
    const investigations = await G.loadInvestigations(true);
    const rows = investigations;
    const formats = [
      ["html", "HTML"],
      ["json", "JSON"],
      ["csv", "CSV"],
      ["markdown", "Markdown"],
      ["stix", "STIX 2.1"],
      ["misp", "MISP"],
      ["iocs", "IOCs"],
    ];
    root.append(
      pageHeader({
        eyebrow: "RELATÓRIOS",
        title: "Central de relatórios",
        description:
          "Toda exportação é gerada a partir do caso atual. Inferências e base de coleta permanecem identificadas.",
      }),
      el(
        "div",
        { class: "notice" },
        "Relatórios descrevem observações com fonte, não fatos confirmados. " +
          "Revise a seção de limitações antes de distribuir uma exportação.",
      ),
      panel(
        { eyebrow: "RELATÓRIOS DE CASOS", title: "Gerar exportações", caption: `${rows.length} casos` },
        rows.length
          ? table({
              columns: [
                {
                  label: "CASO",
                  render: (row) =>
                    el(
                      "div",
                      { class: "cell-stack" },
                      el("strong", {}, row.name),
                      el("span", {}, row.description || "Sem descrição"),
                    ),
                },
                { label: "STATUS", render: (row) => statusBadge(row.status) },
                {
                  label: "REGISTROS",
                  render: (row) =>
                    `${row.observation_count} obs · ${row.entity_count} ent · ${row.evidence_count} evid`,
                },
                { label: "ATUALIZAÇÃO", render: (row) => formatDate(row.updated_at) },
                {
                  label: "EXPORTAR",
                  render: (row) =>
                    el(
                      "div",
                      { class: "row-actions" },
                      ...formats.map(([format, label]) =>
                        el(
                          "a",
                          {
                            class: "button button-secondary button-small",
                            href: `/api/investigations/${row.id}/export?format=${format}`,
                            download: "",
                          },
                          label,
                        ),
                      ),
                      el(
                        "a",
                        {
                          class: "button button-secondary button-small",
                          href: `/reports/${row.id}`,
                          target: "_blank",
                          rel: "noopener",
                        },
                        "Imprimir",
                      ),
                    ),
                },
              ],
              rows,
              emptyMessage: "Crie um caso antes de gerar relatórios.",
            })
          : emptyState({
              icon: "▤",
              title: "Nenhum caso para relatar",
              description: "As exportações ficam disponíveis quando existe uma investigação.",
              action: button("Criar investigação", () => G.newInvestigation(), {
                variant: "button-primary",
              }),
            }),
      ),
      panel(
        { eyebrow: "MÉTODO", title: "O que os relatórios incluem" },
        el(
          "ul",
          { class: "plain-list" },
          el("li", {}, "Escopo, status do caso e data de geração."),
          el("li", {}, "Fontes com referências e datas de acesso."),
          el("li", {}, "Observações identificadas pela base de coleta."),
          el("li", {}, "Entidades, relacionamentos e seu status de verificação."),
          el("li", {}, "Hashes, tamanhos e verificações de integridade das evidências."),
          el("li", {}, "Indicadores extraídos e correlações por valor exato."),
          el("li", {}, "Limitações analíticas e a distinção entre inferência e confirmação."),
        ),
      ),
    );
  }

  G.views.entities = renderEntities;
  G.views.indicators = renderIndicators;
  G.views.evidence = renderEvidence;
  G.views.sources = renderSources;
  G.views.reports = renderReports;
})();
