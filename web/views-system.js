"use strict";

/* Module manager, settings, system diagnostics and CISA KEV. */

(function () {
  const G = window.GARBAGE;
  const {
    el, api, toast, confirm, pageHeader, panel, metric, badge, statusBadge,
    emptyState, table, loadingBlock, inlineError, formatDate, formatBytes,
    titleCase, go,
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

  /* ================================================================ */
  /* Module manager                                                    */
  /* ================================================================ */

  async function renderModules(root) {
    const data = await api("/api/modules");
    const available = data.items.filter((item) => item.state === "available").length;
    const disabled = data.items.filter((item) => item.state === "disabled").length;
    const categories = [...new Set(data.items.map((item) => item.category))];

    async function setState(module, target) {
      try {
        await api(`/api/modules/${encodeURIComponent(module.module_id)}`, {
          method: "PATCH",
          body: JSON.stringify({ state: target }),
        });
        toast(`${G.moduleLabel(module.module_id, module.name)}: ${target === "enabled" ? "ativado" : "desativado"}.`);
        await G.reloadModules();
        G.refreshView();
      } catch (error) {
        toast(error.message, "error");
      }
    }

    const sections = categories.map((category) => {
      const modules = data.items.filter((item) => item.category === category);
      return panel(
        {
          eyebrow: "CATEGORIA",
          title: G.moduleCategory(category),
          caption: `${modules.length} registrados`,
          className: "module-section",
        },
        el(
          "div",
          { class: "module-list" },
          ...modules.map((module) =>
            el(
              "article",
              {
                class: `module-row ${module.state === "planned" ? "is-planned" : ""}`,
              },
              el(
                "div",
                { class: "module-identity" },
                el(
                  "div",
                  { class: "module-title" },
                  el("strong", {}, G.moduleLabel(module.module_id, module.name)),
                  module.core ? badge("Essencial", "info") : null,
                  badge(titleCase(module.state), module.state),
                ),
                el("p", {}, G.moduleDescription(module.module_id, module.description)),
                el(
                  "div",
                  { class: "module-meta" },
                  el("code", {}, module.module_id),
                  el("span", {}, `v${module.version}`),
                  module.updated_at
                    ? el("span", {}, `atualizado em ${formatDate(module.updated_at)}`)
                    : null,
                ),
              ),
              el(
                "div",
                { class: "module-actions" },
                module.state === "planned"
                  ? badge("Não implementado", "warning")
                  : module.core
                    ? el("span", { class: "panel-note" }, "Obrigatório")
                    : button(
                        module.state === "enabled" ? "Desativar" : "Ativar",
                        () =>
                          setState(
                            module,
                            module.state === "enabled" ? "disabled" : "enabled",
                          ),
                        { variant: module.state === "enabled" ? "button-secondary" : "button-primary" },
                      ),
              ),
            ),
          ),
        ),
      );
    });

    root.append(
      pageHeader({
        eyebrow: "REGISTRO DE MÓDULOS",
        title: "Gerenciador de módulos",
        description:
          "O estado de cada recurso é aplicado pela API. Módulos planejados não estão implementados e não podem ser ativados.",
        actions: [button("Atualizar", () => G.refreshView())],
      }),
      el(
        "div",
        { class: "metric-grid compact-metrics" },
        metric({
          label: "ATIVADOS",
          value: String(data.enabled),
          foot: "Atendendo solicitações",
          icon: "◈",
          tone: "green",
        }),
        metric({
          label: "DISPONÍVEIS",
          value: String(available),
          foot: "Prontos para ativar",
          icon: "○",
          tone: "blue",
        }),
        metric({
          label: "DESATIVADOS",
          value: String(disabled),
          foot: "A API retorna 409",
          icon: "⊘",
          tone: "amber",
        }),
        metric({
          label: "PLANEJADOS",
          value: String(data.planned),
          foot: "Documentados, não construídos",
          icon: "◇",
          tone: "violet",
        }),
      ),
      el(
        "div",
        { class: "notice" },
        "Desativar um módulo altera a API e a navegação imediatamente. " +
          "Módulos essenciais não podem ser desativados.",
      ),
      ...sections,
      panel(
        { eyebrow: "CONTRATOS", title: "Interface dos módulos" },
        el(
          "p",
          { class: "panel-note" },
          "Cada módulo declara identificador, nome, descrição, categoria, versão e estado. " +
            "Módulos planejados permanecem visíveis para que a distância entre a interface e o backend fique explícita.",
        ),
        el(
          "ul",
          { class: "plain-list" },
          el("li", {}, "Ativado: as rotas da API aceitam solicitações e a tela está disponível."),
          el("li", {}, "Disponível / desativado: a implementação existe, mas a API rejeita suas rotas."),
          el("li", {}, "Planejado: sem implementação no backend; não pode ser ativado."),
        ),
      ),
    );
  }

  /* ================================================================ */
  /* Settings                                                          */
  /* ================================================================ */

  function settingsControl(source, value) {
    const [label, description] = G.settingText(source.key, source.label, source.description);
    const entry = { ...source, label, description };
    if (entry.type === "boolean") {
      const input = el("input", {
        type: "checkbox",
        role: "switch",
        checked: value === "true",
        "aria-label": entry.label,
      });
      return el(
        "label",
        { class: "switch-row" },
        input,
        el(
          "span",
          {},
          el("strong", {}, entry.label),
          el("small", {}, entry.description),
        ),
      );
    }
    if (entry.type === "choice") {
      return el(
        "div",
        { class: "field" },
        el("label", {}, entry.label),
        el(
          "select",
          { class: "input", "data-setting": entry.key, "aria-label": entry.label },
          ...entry.options.map((option) =>
            el(
              "option",
              { value: option, selected: option === value },
              titleCase(option),
            ),
          ),
        ),
        el("p", { class: "field-hint" }, entry.description),
      );
    }
    return el(
      "div",
      { class: "field" },
      el("label", {}, entry.label),
      el("input", {
        class: "input",
        type: "number",
        value,
        min: entry.minimum,
        max: entry.maximum,
        "data-setting": entry.key,
        "aria-label": entry.label,
      }),
      el("p", { class: "field-hint" }, entry.description),
    );
  }

  async function renderSettings(root) {
    const [settings, system] = await Promise.all([
      api("/api/settings"),
      api("/api/system").catch(() => null),
    ]);
    const controls = new Map();
    const fields = settings.schema.map((entry) => {
      const control = settingsControl(entry, settings.values[entry.key]);
      controls.set(entry.key, control);
      return control;
    });

    async function save() {
      const payload = {};
      for (const entry of settings.schema) {
        const control = controls.get(entry.key);
        const input = control.matches("input, select")
          ? control
          : control.querySelector("input, select");
        if (!input) continue;
        if (entry.type === "boolean") {
          payload[entry.key] = input.checked ? "true" : "false";
        } else {
          payload[entry.key] = input.value;
        }
      }
      try {
        const result = await api("/api/settings", {
          method: "PATCH",
          body: JSON.stringify(payload),
        });
        G.state.settings = result.values;
        G.applySettings(result.values);
        toast("Configurações salvas.");
      } catch (error) {
        toast(error.message, "error");
      }
    }

    const runtimeEntries = system?.runtime ? Object.entries(system.runtime) : [];
    root.append(
      pageHeader({
        eyebrow: "CONFIGURAÇÃO DO WORKSPACE",
        title: "Configurações",
        description:
          "As preferências de interface são salvas no SQLite. Os padrões de relatório e pesquisa afetam as saídas reais.",
        actions: [button("Salvar configurações", save, { variant: "button-primary" })],
      }),
      el(
        "div",
        { class: "settings-layout" },
        panel(
          { eyebrow: "INTERFACE E PADRÕES", title: "Preferências" },
          el("div", { class: "settings-fields" }, ...fields),
          el(
            "div",
            { class: "toolbar-end" },
            button("Salvar configurações", save, { variant: "button-primary" }),
          ),
        ),
        el(
          "div",
          { class: "settings-side" },
          panel(
            { eyebrow: "EXECUÇÃO", title: "Diagnóstico do sistema" },
            system
              ? G.kvList([
                  ["Versão do aplicativo", system.version],
                  ["Versão do esquema", String(system.schema_version)],
                  [
                    "Banco de dados",
                    `${system.database.name} · ${formatBytes(system.database.size_bytes)}`,
                  ],
                  [
                    "Armazenamento",
                    system.database.file_backed ? "SQLite em arquivo" : "Em memória",
                  ],
                  [
                    "Python",
                    system.runtime?.python?.version
                      ? `${system.runtime.python.version} (mínimo ${system.runtime.python.minimum || "—"}${system.runtime.python.supported === false ? ", não suportado" : ""})`
                      : "—",
                  ],
                  [
                    "Plataforma",
                    system.runtime?.platform?.system
                      ? [system.runtime.platform.system, system.runtime.platform.distribution].filter(Boolean).join(" · ")
                      : "—",
                  ],
                  [
                    "SQLite",
                    system.runtime?.sqlite_version
                      ? String(system.runtime.sqlite_version)
                      : "—",
                  ],
                  [
                    "FTS5",
                    system.runtime?.fts5 === undefined ? "—" : system.runtime.fts5 ? "Disponível" : "Indisponível",
                  ],
                ])
              : el("p", { class: "panel-empty" }, "O diagnóstico do sistema está indisponível."),
          ),
          panel(
            { eyebrow: "MOTOR NATIVO", title: "Aceleradores opcionais" },
            system?.native
              ? G.kvList([
                  [
                    "Análise de arquivos em C",
                    system.native.engines.c_file_intelligence
                      ? "Carregado"
                      : "Alternativa em Python",
                  ],
                  [
                    "Métricas de grafo em C++",
                    system.native.engines.cpp_graph_metrics
                      ? "Carregado"
                      : "Alternativa em Python",
                  ],
                  [
                    "Similaridade em Rust",
                    system.native.engines.rust_similarity
                      ? "Carregado"
                      : "Alternativa em Python",
                  ],
                  ["Diretório de build", system.native.directory],
                ])
              : el("p", { class: "panel-empty" }, "O status nativo está indisponível."),
          ),
          panel(
            { eyebrow: "CONTAGENS", title: "Registros armazenados" },
            system
              ? G.kvList(
                  Object.entries(system.counts).map(([key, value]) => [
                    titleCase(key),
                    String(value),
                  ]),
                )
              : el("p", { class: "panel-empty" }, "Sem diagnósticos."),
          ),
          panel(
            { eyebrow: "EXTENSÕES", title: "Integrações" },
            system && system.integrations.length
              ? el(
                  "ul",
                  { class: "plain-list" },
                  ...system.integrations.map((integration) =>
                    el(
                      "li",
                      {},
                      el("strong", {}, integration.module_id),
                      ` · ${G.translateText(integration.mode)}`,
                    ),
                  ),
                )
              : el("p", { class: "panel-empty" }, "Nenhuma integração registrada."),
          ),
          runtimeEntries.length
            ? panel(
                { eyebrow: "DETALHES DO DIAGNÓSTICO", title: "Campos de execução" },
                el(
                  "pre",
                  { class: "code-block" },
                  runtimeEntries
                    .map(([key, value]) => `${key}: ${String(value)}`)
                    .join("\n"),
                ),
              )
            : null,
        ),
      ),
      system
        ? panel(
            { eyebrow: "MIGRAÇÕES", title: "Histórico do esquema", caption: `${system.migrations.length} aplicadas` },
            table({
              columns: [
                { label: "VERSÃO", className: "numeric-col", render: (row) => String(row.version) },
                { label: "DESCRIÇÃO", render: (row) => G.translateText(row.description) },
                { label: "APLICADA EM", render: (row) => formatDate(row.applied_at, { time: true }) },
              ],
              rows: system.migrations,
              emptyMessage: "Nenhuma migração registrada.",
            }),
          )
        : null,
    );
  }

  /* ================================================================ */
  /* CISA KEV                                                          */
  /* ================================================================ */

  async function renderKev(root) {
    let data = null;
    let error = null;
    try {
      data = await api("/api/intel/cisa-kev?limit=100");
    } catch (caught) {
      error = caught;
    }
    if (!data) {
      root.append(
        pageHeader({
          eyebrow: "INTELIGÊNCIA DE AMEAÇAS",
          title: "CISA KEV",
          description:
            "Metadados de vulnerabilidades exploradas conhecidas do catálogo público da CISA.",
        }),
        error && error.status === 404
          ? panel(
              { eyebrow: "CONECTOR", title: "Nenhum snapshot local do KEV" },
              emptyState({
                icon: "☰",
                title: "Atualize o catálogo público",
                description:
                  "O cache do KEV está vazio. O GARBAGE faz uma única solicitação HTTPS explícita à CISA e armazena um snapshot validado e com hash. Não há consultas em segundo plano.",
                action: button(
                  "Atualizar CISA KEV",
                  () => refresh(root, true),
                  { variant: "button-primary" },
                ),
              }),
            )
          : panel(
              { eyebrow: "CONECTOR", title: "Conector do KEV indisponível" },
              errorState(
                "A solicitação ao CISA KEV falhou",
                error?.message || "O conector não retornou dados.",
                () => G.refreshView(),
              ),
            ),
      );
      return;
    }

    const search = el("input", {
      class: "input",
      type: "search",
      placeholder: "Filtrar por CVE, fornecedor, produto ou descrição",
      "aria-label": "Filtrar entradas do CISA KEV",
    });
    const host = el("div");
    function draw() {
      const query = search.value.trim().toLowerCase();
      const rows = data.items.filter((item) =>
        `${item.cve_id} ${item.vendor_project} ${item.product} ${item.vulnerability_name} ${item.short_description}`
          .toLowerCase()
          .includes(query),
      );
      host.replaceChildren(
        table({
          columns: [
            { label: "CVE", render: (row) => el("code", {}, row.cve_id) },
            {
              label: "PRODUTO",
              render: (row) =>
                el(
                  "div",
                  { class: "cell-stack" },
                  el("strong", {}, row.product),
                  el("span", {}, row.vendor_project),
                ),
            },
            {
              label: "VULNERABILIDADE",
              render: (row) =>
                el(
                  "div",
                  { class: "cell-stack" },
                  el("span", {}, row.vulnerability_name),
                  el("span", { class: "muted" }, row.short_description),
                ),
            },
            { label: "INCLUSÃO", render: (row) => formatDate(row.date_added) },
            { label: "PRAZO", render: (row) => formatDate(row.due_date) },
            {
              label: "RANSOMWARE",
              render: (row) =>
                badge(titleCase(row.ransomware_use || "unknown"), row.ransomware_use === "Known" ? "danger" : "neutral"),
            },
          ],
          rows,
          emptyMessage: "Nenhuma entrada do KEV corresponde a este filtro.",
        }),
      );
    }

    root.append(
      pageHeader({
        eyebrow: "INTELIGÊNCIA DE AMEAÇAS",
        title: "CISA KEV",
        description:
          "Metadados de exploração por fornecedor e produto, exibidos exatamente como publicados pela CISA. Não constar no KEV não implica segurança.",
        actions: [button("Atualizar catálogo", () => refresh(root, false))],
      }),
      el(
        "div",
        { class: "metric-grid compact-metrics" },
        metric({
          label: "ENTRADAS DO CATÁLOGO",
          value: String(data.count),
          foot: "Snapshot validado",
          icon: "☰",
          tone: "amber",
        }),
        metric({
          label: "CORRESPONDENTES",
          value: String(data.matched),
          foot: "Filtro local",
          icon: "⌕",
          tone: "blue",
        }),
        metric({
          label: "VERSÃO DO CATÁLOGO",
          value: data.catalog_version,
          foot: "Fonte CISA",
          icon: "◈",
          tone: "violet",
        }),
        metric({
          label: "SNAPSHOT",
          value: formatDate(data.fetched_at),
          foot: "Atualização explícita",
          icon: "◷",
          tone: "green",
        }),
      ),
      panel(
        { eyebrow: "PROVENIÊNCIA", title: "Integridade do snapshot" },
        G.kvList([
          ["Fonte", el("a", { class: "reference-link", href: data.source_url, target: "_blank", rel: "noopener noreferrer" }, data.source_url)],
          ["Atualização na fonte", formatDate(data.source_updated_at, { time: true })],
          ["Obtido em", formatDate(data.fetched_at, { time: true })],
          ["SHA-256", el("code", { class: "hash" }, data.sha256)],
        ]),
      ),
      panel(
        { eyebrow: "CATÁLOGO DE VULNERABILIDADES", title: "Vulnerabilidades exploradas conhecidas", actions: [el("span", { class: "panel-caption" }, `${data.items.length} exibidas`)] },
        el("div", { class: "toolbar" }, el("div", { class: "search-field" }, el("span", { class: "search-field-icon" }, G.icon("search", { size: 14 })), search)),
        data.items.length ? host : emptyState({ icon: "☰", title: "Nenhuma entrada no snapshot" }),
      ),
    );
    draw();
    search.addEventListener("input", draw);
  }

  async function refresh(root, initial) {
    const original = root.querySelector(".page-header") || root;
    G.setLoading(true);
    try {
      const result = await api("/api/intel/cisa-kev/refresh", {
        method: "POST",
        body: JSON.stringify({ force: !initial }),
      });
      toast(`CISA KEV atualizado: ${result.count} entradas.`);
      await renderKev(root);
    } catch (error) {
      toast(error.message, "error");
      if (!initial) G.refreshView();
    } finally {
      G.setLoading(false);
    }
  }

  G.views.modules = renderModules;
  G.views.settings = renderSettings;
  G.views.kev = renderKev;
})();
