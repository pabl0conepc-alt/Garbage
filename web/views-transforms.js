"use strict";

/* Transforms on an entity, its enrichment history, and entity resolution. */

(function () {
  const G = window.GARBAGE;
  const {
    el, api, toast, panel, badge, statusBadge, table, loadingBlock, inlineError,
    formatDate, entityTypeLabel, pageHeader,
  } = G;

  const KIND_TEXT = { pivot: "Pivô", enrichment: "Enriquecimento" };
  const AVAILABILITY_TEXT = {
    ready: "Pronta",
    "network-disabled": "Rede desativada",
    "target-contact-disabled": "Contato com o alvo desativado",
    "key-missing": "Sem chave",
    "module-disabled": "Módulo desativado",
  };
  const ARTIFACT_TEXT = {
    domain: "domínio", ipv4: "IPv4", ipv6: "IPv6", cidr: "CIDR", url: "URL", email: "e-mail",
    md5: "MD5", sha1: "SHA-1", sha256: "SHA-256", asn: "ASN", cve: "CVE",
  };

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

  function seconds(ms) {
    if (ms === null || ms === undefined) return "";
    if (ms < 1000) return `${ms} ms`;
    return `${(ms / 1000).toLocaleString(G.LOCALE, { maximumFractionDigits: 1 })} s`;
  }

  function transformName(id) {
    return G.connectorLabel ? G.connectorLabel(id) : id;
  }

  function estimateText(item) {
    if (item.estimate_ms === null) return "sem histórico de tempo";
    return `~${seconds(item.estimate_ms)} (média de ${item.estimate_samples})`;
  }

  function outputText(item) {
    if (!item.outputs.length) return "Acrescenta fatos ao histórico; não cria entidades";
    const types = [...new Set(item.outputs.map((output) => entityTypeLabel(output.entity_type)))];
    return `Gera: ${types.join(", ")}`;
  }

  /* One log event in Portuguese. */
  function eventText(event) {
    switch (event.event) {
      case "input":
        return `Entrada: ${ARTIFACT_TEXT[event.type] || event.type} ${event.value}`;
      case "source": {
        const parts = [`Fonte: ${G.sourceStatusLabel ? G.sourceStatusLabel(event.status) : event.status}`];
        parts.push(`${event.count} resultado(s)`);
        if (event.cached) parts.push("do cache");
        else if (event.elapsed_ms) parts.push(seconds(event.elapsed_ms));
        if (event.error) parts.push(G.translateError(event.error));
        return parts.join(" · ");
      }
      case "limit":
        return `Limite aplicado: ${event.kept} de ${event.found} resultado(s) viraram entidades`;
      case "not-promoted":
        return `${event.count} resultado(s) poderiam virar entidades (criação desligada nos parâmetros)`;
      case "promoted":
        return `${event.created} nova(s), ${event.reused} reaproveitada(s), ${event.relationships} relacionamento(s) novo(s)${event.skipped ? `, ${event.skipped} ignorado(s)` : ""}`;
      default:
        return event.event;
    }
  }

  function logList(log) {
    return el("ol", { class: "transform-log" }, ...log.map((event) => el("li", {}, eventText(event))));
  }

  /* ---------------------------------------------------------------- */
  /* Transform runner                                                  */
  /* ---------------------------------------------------------------- */

  function transformPanel(entity, { investigationId = null, onRun = null, compact = false, lastOutcome = null } = {}) {
    const body = el("div", { class: "transform-body" }, loadingBlock("Carregando transformações…"));
    const container = compact
      ? el("div", { class: "transform-panel is-compact" }, body)
      : panel(
          {
            eyebrow: "TRANSFORMAÇÕES",
            title: "Executar a partir desta entidade",
            className: "transform-panel span-2",
          },
          body,
        );

    async function load() {
      let listing;
      try {
        listing = await api(`/api/transforms?entity_id=${encodeURIComponent(entity.id)}`);
      } catch (error) {
        body.replaceChildren(inlineError(error.message));
        return;
      }
      if (!listing.artifact) {
        body.replaceChildren(
          el("p", { class: "panel-empty" }, G.translateError(listing.unsupported_reason) || "Nenhuma transformação se aplica a esta entidade."),
        );
        return;
      }
      draw(listing);
    }

    function draw(listing) {
      const rows = listing.items.map((item) => {
        const ready = item.availability === "ready";
        const check = el("input", { type: "checkbox", disabled: !ready, checked: ready && item.kind === "pivot" && !item.contacts_target });
        return { item, check };
      });
      const useCache = el("input", { type: "checkbox", checked: true });
      const promote = el("input", { type: "checkbox", checked: true });
      const limit = el("input", { class: "input transform-limit", type: "number", min: "1", max: "50", value: "25", "aria-label": "Máximo de entidades novas" });
      const results = el("div", { class: "transform-results", "aria-live": "polite" }, lastOutcome ? runSummary(lastOutcome) : null);
      const runButton = el("button", { class: "button button-primary", type: "button" }, "Executar");
      const count = () => rows.filter((row) => row.check.checked).length;
      const syncButton = () => {
        runButton.textContent = `Executar ${count()} transformação(ões)`;
        runButton.disabled = count() === 0;
      };
      rows.forEach((row) => row.check.addEventListener("change", syncButton));
      syncButton();

      function select(predicate) {
        rows.forEach((row) => {
          if (!row.check.disabled) row.check.checked = predicate(row.item);
        });
        syncButton();
      }

      runButton.addEventListener("click", async () => {
        const chosen = rows.filter((row) => row.check.checked).map((row) => row.item.transform_id);
        const max = Number(limit.value);
        if (!Number.isInteger(max) || max < 1 || max > 50) {
          toast("O máximo de entidades novas deve ficar entre 1 e 50.", "warning");
          return;
        }
        runButton.disabled = true;
        results.replaceChildren(loadingBlock(`Executando ${chosen.length} transformação(ões) sobre ${listing.artifact.value}…`));
        try {
          const outcome = await api("/api/transforms/run", {
            method: "POST",
            body: JSON.stringify({
              entity_id: entity.id,
              transforms: chosen,
              investigation_id: investigationId,
              parameters: { use_cache: useCache.checked, promote: promote.checked, max_new_entities: max },
            }),
          });
          results.replaceChildren(runSummary(outcome));
          toast(`${outcome.created_count} entidade(s) nova(s) e ${outcome.relationship_count} relacionamento(s).`);
          if (onRun) onRun(outcome);
        } catch (error) {
          results.replaceChildren(inlineError(error.message));
        } finally {
          syncButton();
        }
      });

      const list = el(
        "div",
        { class: "transform-list" },
        ...rows.map(({ item, check }) =>
          el(
            "label",
            { class: `transform-row${check.disabled ? " is-unavailable" : ""}` },
            check,
            el(
              "span",
              { class: "transform-main" },
              el("strong", {}, transformName(item.transform_id)),
              el("span", { class: "transform-meta" }, outputText(item)),
            ),
            el(
              "span",
              { class: "transform-side" },
              badge(KIND_TEXT[item.kind], "neutral"),
              item.availability === "ready"
                ? el("span", { class: "transform-meta" }, estimateText(item))
                : badge(AVAILABILITY_TEXT[item.availability] || item.availability, "warning"),
            ),
          ),
        ),
      );

      body.replaceChildren(
        el(
          "p",
          { class: "run-meta" },
          `Entrada: ${ARTIFACT_TEXT[listing.artifact.type] || listing.artifact.type} `,
          el("code", {}, listing.artifact.value),
          ` · ${listing.items.length} transformação(ões) aceitam este tipo`,
        ),
        el(
          "div",
          { class: "transform-toolbar" },
          button("Só pivôs prontos", () => select((item) => item.kind === "pivot" && !item.contacts_target)),
          button("Todas as prontas", () => select(() => true)),
          button("Limpar", () => select(() => false)),
        ),
        list,
        el(
          "div",
          { class: "transform-params" },
          el("label", { class: "check-field" }, useCache, "Usar cache das fontes"),
          el("label", { class: "check-field" }, promote, "Criar entidades e relacionamentos a partir dos resultados"),
          el("label", { class: "check-field" }, "Máx. de entidades novas", limit),
        ),
        el(
          "p",
          { class: "transform-note" },
          "Relacionamentos criados ficam como \"possível\" e não verificados, citando a fonte. Fontes de rede seguem as travas da Pesquisa multifonte.",
        ),
        el("div", { class: "transform-actions" }, runButton),
        results,
      );
    }

    load();
    return container;
  }

  function runSummary(outcome) {
    return el(
      "div",
      { class: "transform-summary" },
      ...outcome.items.map((item) =>
        el(
          "div",
          { class: "transform-result" },
          el(
            "div",
            { class: "transform-result-head" },
            el("strong", {}, transformName(item.transform_id)),
            badge(G.sourceStatusLabel ? G.sourceStatusLabel(item.status) : item.status, G.sourceStatusTone ? G.sourceStatusTone(item.status) : "neutral"),
            el("span", { class: "transform-meta" }, seconds(item.duration_ms)),
          ),
          logList(item.log),
          item.created_entities.length
            ? el(
                "p",
                { class: "transform-created" },
                "Novas: ",
                ...item.created_entities.flatMap((created, index) => [
                  index ? ", " : "",
                  el("a", { class: "table-link", href: `#/entities/${created.id}` }, created.name),
                ]),
              )
            : null,
        ),
      ),
    );
  }

  function transformDialog(entity, { investigationId = null, onDone = null } = {}) {
    let changed = false;
    const dialog = el("dialog", { class: "app-dialog pivot-dialog", "aria-label": `Transformações de ${entity.name}` });
    dialog.append(
      el(
        "div",
        { class: "dialog-form" },
        el(
          "div",
          { class: "dialog-heading" },
          el("div", {}, el("p", { class: "eyebrow" }, "TRANSFORMAÇÕES"), el("h2", {}, entity.name)),
        ),
        el("div", { class: "pivot-body" }, transformPanel(entity, { investigationId, compact: true, onRun: () => { changed = true; } })),
        el(
          "div",
          { class: "dialog-actions" },
          el("button", { class: "button button-secondary", type: "button", onClick: () => dialog.close() }, "Fechar"),
        ),
      ),
    );
    document.body.append(dialog);
    dialog.addEventListener("close", () => {
      dialog.remove();
      if (changed && onDone) onDone();
    });
    dialog.showModal();
  }

  /* ---------------------------------------------------------------- */
  /* History and aliases                                               */
  /* ---------------------------------------------------------------- */

  function historyPanel(entityId) {
    const body = el("div", {}, loadingBlock("Carregando histórico…"));
    const box = panel({ eyebrow: "ENRIQUECIMENTO", title: "Histórico de transformações", className: "span-2" }, body);
    api(`/api/entities/${entityId}/transforms`)
      .then((history) => {
        if (!history.items.length) {
          body.replaceChildren(el("p", { class: "panel-empty" }, "Nenhuma transformação executada nesta entidade."));
          return;
        }
        body.replaceChildren(
          table({
            columns: [
              { label: "QUANDO", render: (row) => formatDate(row.started_at, { time: true }) },
              { label: "TRANSFORMAÇÃO", render: (row) => el("strong", {}, transformName(row.transform_id)) },
              { label: "FONTE", render: (row) => badge(G.sourceStatusLabel ? G.sourceStatusLabel(row.status) : row.status, G.sourceStatusTone ? G.sourceStatusTone(row.status) : "neutral") },
              { label: "RESULTADOS", render: (row) => String(row.result_count) },
              { label: "NOVAS", render: (row) => `${row.created_count} entidade(s), ${row.relationship_count} relação(ões)` },
              { label: "DURAÇÃO", render: (row) => seconds(row.duration_ms) },
              {
                label: "LOG",
                render: (row) => el("details", { class: "transform-details" }, el("summary", {}, "Ver"), logList(row.log)),
              },
            ],
            rows: history.items,
            emptyMessage: "Nenhuma transformação executada.",
          }),
          history.total > history.items.length
            ? el("p", { class: "run-meta" }, `Mostrando ${history.items.length} de ${history.total}.`)
            : null,
        );
      })
      .catch((error) => body.replaceChildren(inlineError(error.message)));
    return box;
  }

  function aliasesPanel(entityId) {
    const body = el("div", {});
    const box = panel({ eyebrow: "RESOLUÇÃO", title: "Entidades fundidas nesta" }, body);
    box.hidden = true;
    api(`/api/entities/${entityId}/aliases`)
      .then((aliases) => {
        if (!aliases.items.length) return;
        box.hidden = false;
        body.replaceChildren(
          table({
            columns: [
              { label: "NOME", render: (row) => el("strong", {}, row.name) },
              { label: "CATEGORIA", render: (row) => entityTypeLabel(row.entity_type) },
              { label: "IDENTIFICADOR", render: (row) => (row.identifier ? el("code", {}, row.identifier) : "—") },
              { label: "NÍVEL", render: (row) => LEVEL_TEXT[row.level] || "—" },
              { label: "NOTA", render: (row) => row.note || "—" },
              { label: "FUNDIDA EM", render: (row) => formatDate(row.created_at, { time: true }) },
            ],
            rows: aliases.items,
            emptyMessage: "",
          }),
        );
      })
      .catch(() => {});
    return box;
  }

  /* ---------------------------------------------------------------- */
  /* Entity resolution view                                            */
  /* ---------------------------------------------------------------- */

  const LEVEL_TEXT = { exact: "Exata", probable: "Provável", weak: "Fraca" };

  function ruleText(item) {
    const detail = item.detail || {};
    switch (item.rule) {
      case "same-artifact":
        return `Mesmo artefato depois de normalizado: ${ARTIFACT_TEXT[detail.artifact_type] || detail.artifact_type} ${detail.value}`;
      case "www-prefix":
        return `Mesmo domínio com e sem "www.": ${detail.domain}`;
      case "url-variant":
        return "Mesma URL com esquema, \"www.\", porta padrão ou barra final diferentes";
      case "same-label-other-suffix":
        return `Mesmo nome sob outro sufixo: ${(detail.values || []).join(" e ")}. Pode ser a mesma organização ou um registro oportunista.`;
      case "organization-name":
        return `Mesmo nome de organização sem sufixo jurídico, acentos e pontuação: "${detail.normalized}"`;
      case "similar-organization-name":
        return `Nomes de organização parecidos (semelhança de ${Math.round((detail.ratio || 0) * 100)}%)`;
      default:
        return item.rule;
    }
  }

  function entityCard(entity, onKeep) {
    return el(
      "div",
      { class: "resolution-entity" },
      el("a", { class: "table-link", href: `#/entities/${entity.id}` }, el("strong", {}, entity.name)),
      el("span", { class: "transform-meta" }, entityTypeLabel(entity.entity_type)),
      entity.identifier ? el("code", {}, entity.identifier) : null,
      el(
        "span",
        { class: "transform-meta" },
        `${entity.relationship_count} relacionamento(s) · ${entity.case_count} caso(s)`,
      ),
      statusBadge(entity.verification_status),
      el(
        "button",
        {
          class: "button button-secondary button-small",
          type: "button",
          "aria-label": `Manter esta: ${entity.name} (${entityTypeLabel(entity.entity_type)}), fundindo a outra nela`,
          onClick: onKeep,
        },
        "Manter esta",
      ),
    );
  }

  async function renderResolution(root) {
    let level = "";
    let investigationId = "";
    const listBox = el("div", { class: "resolution-list" });
    const tabsBox = el("div", {});
    const caseSelect = el("select", { class: "input", "aria-label": "Escopo" }, el("option", { value: "" }, "Todo o workspace"));
    try {
      const cases = await G.loadInvestigations();
      (Array.isArray(cases) ? cases : cases.items || []).forEach((item) =>
        caseSelect.append(el("option", { value: item.id }, item.name)),
      );
    } catch (error) {
      /* the scope menu just stays workspace-wide */
    }
    caseSelect.addEventListener("change", () => {
      investigationId = caseSelect.value;
      load();
    });

    root.replaceChildren(
      pageHeader({
        eyebrow: "ANÁLISE",
        title: "Resolução de entidades",
        description:
          "Possíveis duplicatas em três níveis. Nada é fundido sem sua decisão, e semelhança não é atribuição. Pessoas, nomes de usuário e perfis ficam de fora.",
      }),
      el("div", { class: "resolution-toolbar" }, tabsBox, el("label", { class: "field inline-field" }, el("span", {}, "Escopo"), caseSelect)),
      listBox,
    );

    async function decide(item, action) {
      const [first, second] = item.entities;
      if (action === "distinct") {
        try {
          await api("/api/resolution/dismiss", {
            method: "POST",
            body: JSON.stringify({ first: first.id, second: second.id, level: item.level, rule: item.rule }),
          });
          toast("Par marcado como distinto; não será sugerido de novo.");
          load();
        } catch (error) {
          toast(error.message, "error");
        }
        return;
      }
      const keep = action === "keep-first" ? first : second;
      const merge = action === "keep-first" ? second : first;
      const describe = (entity) => `"${entity.name}" (${entityTypeLabel(entity.entity_type).toLowerCase()})`;
      const ok = await G.confirm({
        title: `Fundir ${describe(merge)} em ${describe(keep)}?`,
        message: `Os relacionamentos, casos, fontes e elementos de quadro de "${merge.name}" passam para "${keep.name}". "${merge.name}" é excluída e fica registrada como alias. A fusão fica no registro de atividades e não pode ser desfeita automaticamente.`,
        confirmLabel: "Fundir",
        danger: true,
      });
      if (!ok) return;
      try {
        const result = await api("/api/resolution/merge", {
          method: "POST",
          body: JSON.stringify({ keep_id: keep.id, merge_id: merge.id, level: item.level }),
        });
        const moved = result.moved;
        toast(`Fundida. ${moved.relationships} relacionamento(s) movido(s), ${moved.dropped_relationships} duplicado(s) removido(s), ${moved.cases} caso(s) vinculado(s).`);
        load();
      } catch (error) {
        toast(error.message, "error");
      }
    }

    async function load() {
      listBox.replaceChildren(loadingBlock("Procurando candidatos…"));
      const params = new URLSearchParams();
      if (level) params.set("level", level);
      if (investigationId) params.set("investigation_id", investigationId);
      let data;
      try {
        data = await api(`/api/resolution/candidates?${params}`);
      } catch (error) {
        listBox.replaceChildren(inlineError(error.message));
        return;
      }
      const all = data.counts.exact + data.counts.probable + data.counts.weak;
      tabsBox.replaceChildren(
        G.tabs({
          items: [
            { key: "", label: "Todos", count: all },
            { key: "exact", label: "Exatos", count: data.counts.exact },
            { key: "probable", label: "Prováveis", count: data.counts.probable },
            { key: "weak", label: "Fracos", count: data.counts.weak },
          ],
          active: level,
          onSelect: (key) => {
            level = key;
            load();
          },
        }),
      );
      const meta = el(
        "p",
        { class: "run-meta" },
        `${data.scanned} entidade(s) comparadas${data.truncated ? " (limite atingido)" : ""} · ${data.dismissed} par(es) já marcados como distintos`,
      );
      if (!data.items.length) {
        listBox.replaceChildren(meta, G.emptyState({ icon: "merge", title: "Nenhum candidato", description: "Nenhuma entidade parece duplicada neste escopo." }));
        return;
      }
      listBox.replaceChildren(
        meta,
        ...data.items.map((item) =>
          el(
            "article",
            { class: `resolution-card level-${item.level}` },
            el(
              "div",
              { class: "resolution-head" },
              badge(LEVEL_TEXT[item.level], item.level === "weak" ? "neutral" : "info"),
              el("p", {}, ruleText(item)),
            ),
            el(
              "div",
              { class: "resolution-pair" },
              entityCard(item.entities[0], () => decide(item, "keep-first")),
              el("span", { class: "resolution-vs", "aria-hidden": "true" }, "≈"),
              entityCard(item.entities[1], () => decide(item, "keep-second")),
            ),
            el(
              "div",
              { class: "resolution-actions" },
              button("São entidades distintas", () => decide(item, "distinct")),
            ),
          ),
        ),
      );
    }

    load();
  }

  G.transformPanel = transformPanel;
  G.transformDialog = transformDialog;
  G.transformHistoryPanel = historyPanel;
  G.entityAliasesPanel = aliasesPanel;
  G.views.resolution = renderResolution;
})();
