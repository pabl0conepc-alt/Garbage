"use strict";

/* MITRE ATT&CK: offline matrix, technique details and case mapping. */

(function () {
  const G = window.GARBAGE;
  const { el, api, toast, pageHeader, panel, badge, emptyState, formatDate } = G;

  const ORIGIN_LABEL = { "file-analysis": "análise de arquivo", "intel-source": "fonte de inteligência" };
  const KIND_LABEL = { technique: "Técnica", group: "Grupo", software: "Software", mitigation: "Mitigação" };

  /* Backend reasons are short English clauses; keep the subject, translate
     the stock phrases. */
  const REASON_PT = [
    [/VBA macro code is present/, "há código de macro VBA"],
    [/macros run automatically when the document is opened/, "as macros rodam sozinhas ao abrir o documento"],
    [/the PDF declares JavaScript or a launch action/, "o PDF declara JavaScript ou ação de execução"],
    [/a shortcut launches a script host or downloader/, "um atalho chama interpretador de scripts ou baixador"],
    [/the shortcut invokes a command interpreter/, "o atalho chama um interpretador de comandos"],
    [/shortcut arguments are hidden behind whitespace/, "argumentos do atalho escondidos por espaços"],
    [/executables are delivered inside a disc image/, "executáveis entregues dentro de imagem de disco"],
    [/an Equation Editor object is embedded/, "há objeto do Editor de Equações"],
    [/the document references a remote template/, "o documento aponta para modelo remoto"],
    [/a DDE field is present/, "há campo DDE"],
    [/a packaged file is embedded in the document/, "há arquivo empacotado no documento"],
    [/the installer declares custom actions/, "o instalador declara ações personalizadas"],
    [/executable headers are embedded in another file/, "há executável embutido em outro arquivo"],
    [/high entropy is consistent with packing/, "entropia alta compatível com empacotamento"],
    [/macro source mentions PowerShell or another interpreter/, "a macro cita PowerShell ou outro interpretador"],
    [/macro source can download content/, "a macro pode baixar conteúdo"],
    [/macro source uses obfuscation helpers/, "a macro usa funções de ofuscação"],
    [/macro source declares native API calls/, "a macro declara chamadas de API nativas"],
    [/macro source starts processes/, "a macro inicia processos"],
    [/^(.+) lists it for (.+)$/, "$1 aponta para $2"],
  ];
  const reasonText = (text) => REASON_PT.reduce((value, [pattern, replacement]) => value.replace(pattern, replacement), String(text));

  function button(label, onClick, options = {}) {
    return el("button", { class: `button ${options.variant || "button-secondary"} button-small`, type: "button", disabled: Boolean(options.disabled), onClick }, label);
  }

  async function renderAttack(root, params = []) {
    let status = await api("/api/attack");
    const investigations = await G.loadInvestigations();
    let investigationId = params[0] || "";
    let matrix = null;
    let suggestions = [];
    let filter = "";
    let selected = null;

    const caseSelect = el(
      "select",
      { class: "input compact-select", "aria-label": "Investigação" },
      el("option", { value: "" }, "Sem investigação (só consulta)"),
      ...investigations.map((item) => el("option", { value: item.id }, item.name)),
    );
    caseSelect.value = investigationId;
    const searchInput = el("input", { class: "input", type: "search", placeholder: "Filtrar por ID ou nome (ex.: T1059, phishing)", "aria-label": "Filtrar técnicas" });
    const matrixHost = el("div", { class: "attack-matrix-host" });
    const sideHost = el("aside", { class: "attack-side" });
    const statusHost = el("div");

    caseSelect.addEventListener("change", () => {
      investigationId = caseSelect.value;
      history.replaceState(null, "", investigationId ? `#/attack/${investigationId}` : "#/attack");
      load();
    });
    let timer = null;
    searchInput.addEventListener("input", () => {
      clearTimeout(timer);
      timer = setTimeout(() => {
        filter = searchInput.value.trim().toLowerCase();
        drawMatrix();
      }, 150);
    });

    async function refresh() {
      const confirmed = await G.confirm({
        title: "Baixar o MITRE ATT&CK",
        message: "Baixa o bundle oficial Enterprise ATT&CK (cerca de 55 MB) do repositório mitre-attack/attack-stix-data no GitHub e guarda uma cópia compacta no workspace. Nenhum dado do caso é enviado.",
        confirmLabel: "Baixar",
      });
      if (!confirmed) return;
      statusHost.replaceChildren(G.loadingBlock("Baixando e processando o ATT&CK…"));
      try {
        status = await api("/api/attack/refresh", { method: "POST", body: "{}" });
        toast(`ATT&CK ${status.version} carregado: ${status.counts.techniques} técnicas e ${status.counts.subtechniques} subtécnicas.`);
        await load();
      } catch (error) {
        toast(error.message, "error");
        drawStatus();
      }
    }

    function drawStatus() {
      statusHost.replaceChildren(
        status.loaded
          ? el(
              "div",
              { class: "notice-bar is-quiet attack-status" },
              el(
                "span",
                {},
                `Enterprise ATT&CK ${status.version} · ${status.counts.techniques} técnicas, ${status.counts.subtechniques} subtécnicas, ` +
                  `${status.counts.groups} grupos, ${status.counts.software} softwares, ${status.counts.mitigations} mitigações · atualizado ${formatDate(status.fetched_at)}`,
              ),
              button("Atualizar", refresh),
            )
          : null,
      );
    }

    async function load() {
      drawStatus();
      if (!status.loaded) {
        matrixHost.replaceChildren(
          emptyState({
            icon: "matrix",
            title: "ATT&CK ainda não foi baixado",
            description: "O GARBAGE guarda uma cópia local do Enterprise ATT&CK para consultar sem rede e mapear técnicas nos casos.",
            action: button("Baixar ATT&CK", refresh, { variant: "button-primary" }),
          }),
        );
        sideHost.replaceChildren();
        return;
      }
      const query = investigationId ? `?investigation_id=${investigationId}` : "";
      try {
        [matrix, suggestions] = await Promise.all([
          api(`/api/attack/matrix${query}`),
          investigationId ? api(`/api/investigations/${investigationId}/techniques/suggestions`).then((data) => data.items) : Promise.resolve([]),
        ]);
      } catch (error) {
        matrixHost.replaceChildren(G.inlineError(error.message));
        return;
      }
      drawMatrix();
      drawSide();
    }

    function matches(cell) {
      if (!filter) return true;
      const text = `${cell.id} ${cell.name} ${cell.subtechniques.map((sub) => `${sub.id} ${sub.name}`).join(" ")}`.toLowerCase();
      return text.includes(filter);
    }

    function drawMatrix() {
      if (!matrix) return;
      const suggested = new Set(suggestions.filter((item) => !item.linked).map((item) => item.id.split(".")[0]));
      const grid = el("div", { class: "attack-matrix", role: "grid", "aria-label": "Matriz ATT&CK" });
      for (const tactic of matrix.tactics) {
        const cells = tactic.techniques.filter(matches);
        const linkedHere = tactic.techniques.filter((cell) => cell.linked || cell.linked_subtechniques).length;
        grid.append(
          el(
            "section",
            { class: "attack-column", role: "rowgroup" },
            el(
              "header",
              { class: "attack-tactic" },
              el("strong", {}, tactic.name),
              el("span", {}, `${tactic.techniques.length} técnicas${linkedHere ? ` · ${linkedHere} no caso` : ""}`),
            ),
            ...cells.map((cell) =>
              el(
                "button",
                {
                  type: "button",
                  class: `attack-cell${cell.linked || cell.linked_subtechniques ? " is-linked" : ""}${suggested.has(cell.id) ? " is-suggested" : ""}${selected === cell.id ? " is-selected" : ""}`,
                  title: `${cell.id} · ${cell.name}`,
                  onClick: () => openTechnique(cell.id),
                },
                el("span", { class: "attack-cell-name" }, cell.name),
                el(
                  "span",
                  { class: "attack-cell-meta" },
                  cell.id,
                  cell.subtechniques.length ? ` · ${cell.linked_subtechniques ? `${cell.linked_subtechniques}/` : ""}${cell.subtechniques.length} sub` : "",
                ),
              ),
            ),
          ),
        );
      }
      matrixHost.replaceChildren(
        el(
          "div",
          { class: "attack-legend" },
          el("span", {}, el("i", { class: "attack-key is-linked" }), "Vinculada ao caso"),
          el("span", {}, el("i", { class: "attack-key is-suggested" }), "Sugerida pelos achados"),
          el("span", { class: "muted" }, "Clique numa técnica para detalhes, grupos, softwares e mitigações."),
        ),
        el("div", { class: "attack-scroll" }, grid),
      );
    }

    async function openTechnique(id) {
      selected = id;
      drawMatrix();
      sideHost.replaceChildren(G.loadingBlock("Carregando técnica…"));
      let detail;
      try {
        detail = await api(`/api/attack/techniques/${id}`);
      } catch (error) {
        sideHost.replaceChildren(G.inlineError(error.message));
        return;
      }
      const linked = detail.cases.some((item) => item.investigation_id === investigationId);
      const note = el("input", { class: "input", type: "text", maxlength: "1000", placeholder: "Nota (opcional): por que se aplica", "aria-label": "Nota do vínculo" });
      const list = (items, empty) =>
        items.length
          ? el(
              "ul",
              { class: "attack-related" },
              ...items.slice(0, 25).map((item) =>
                el("li", {}, el("a", { class: "table-link", href: item.url, target: "_blank", rel: "noopener noreferrer" }, `${item.id} ${item.name}`), item.aliases ? el("span", { class: "muted" }, ` (${item.aliases.split(",").slice(0, 3).join(", ")})`) : null),
              ),
              items.length > 25 ? el("li", { class: "muted" }, `e mais ${items.length - 25}`) : null,
            )
          : el("p", { class: "panel-empty" }, empty);
      sideHost.replaceChildren(
        panel(
          { eyebrow: `${detail.id} · ${detail.tactics.map((name) => matrix.tactics.find((item) => item.shortname === name)?.name || name).join(", ")}`, title: detail.name },
          el("p", { class: "attack-description" }, detail.description || "Sem descrição."),
          G.kvList([
            ["Plataformas", detail.platforms.join(", ")],
            ["Detecção", detail.detection],
            ["Referência", el("a", { class: "table-link", href: detail.url, target: "_blank", rel: "noopener noreferrer" }, "attack.mitre.org")],
          ]),
          detail.family.length > 1
            ? el("div", { class: "chip-list" }, ...detail.family.map((item) => el("button", { type: "button", class: `chip-button${item.id === detail.id ? " is-active" : ""}`, onClick: () => openTechnique(item.id) }, `${item.id} ${item.name}`)))
            : null,
          investigationId
            ? el(
                "div",
                { class: "attack-link-box" },
                linked
                  ? button("Remover do caso", async () => {
                      await api(`/api/investigations/${investigationId}/techniques/${detail.id}`, { method: "DELETE" });
                      toast(`${detail.id} removida do caso.`);
                      await load();
                      openTechnique(detail.id);
                    })
                  : el(
                      "div",
                      { class: "attack-link-form" },
                      note,
                      button("Vincular ao caso", async () => {
                        try {
                          await api(`/api/investigations/${investigationId}/techniques`, { method: "POST", body: JSON.stringify({ technique_id: detail.id, note: note.value }) });
                          toast(`${detail.id} vinculada ao caso.`);
                          await load();
                          openTechnique(detail.id);
                        } catch (error) {
                          toast(error.message, "error");
                        }
                      }, { variant: "button-primary" }),
                    ),
              )
            : el("p", { class: "panel-note" }, "Escolha uma investigação para vincular técnicas."),
          G.sectionHeading("Grupos que usam", `${detail.groups.length}`),
          list(detail.groups, "Nenhum grupo registrado."),
          G.sectionHeading("Softwares que usam", `${detail.software.length}`),
          list(detail.software, "Nenhum software registrado."),
          G.sectionHeading("Mitigações", `${detail.mitigations.length}`),
          list(detail.mitigations, "Nenhuma mitigação registrada."),
          el("p", { class: "tool-limit" }, "Uso por grupos e softwares vem dos relatos públicos compilados pelo MITRE. Ver a mesma técnica num caso não indica o mesmo autor."),
        ),
      );
    }

    function drawSide() {
      if (selected) return;
      const linkedItems = [];
      for (const tactic of matrix.tactics) {
        for (const cell of tactic.techniques) {
          if (cell.linked) linkedItems.push({ id: cell.id, name: cell.name, tactic: tactic.name });
          for (const sub of cell.subtechniques) if (sub.linked) linkedItems.push({ id: sub.id, name: `${cell.name}: ${sub.name}`, tactic: tactic.name });
        }
      }
      const unique = [...new Map(linkedItems.map((item) => [item.id, item])).values()];
      sideHost.replaceChildren(
        investigationId
          ? panel(
              { eyebrow: "CASO", title: `${unique.length} técnica(s) vinculada(s)` },
              unique.length
                ? el("ul", { class: "attack-related" }, ...unique.map((item) => el("li", {}, el("button", { type: "button", class: "link-button", onClick: () => openTechnique(item.id) }, `${item.id} ${item.name}`), el("span", { class: "muted" }, ` · ${item.tactic}`))))
                : el("p", { class: "panel-empty" }, "Nenhuma técnica vinculada a este caso."),
              G.sectionHeading("Sugestões", `${suggestions.filter((item) => !item.linked).length}`),
              suggestions.filter((item) => !item.linked).length
                ? el(
                    "div",
                    { class: "attack-suggestions" },
                    ...suggestions
                      .filter((item) => !item.linked)
                      .map((item) =>
                        el(
                          "article",
                          { class: "attack-suggestion" },
                          el("header", {}, el("button", { type: "button", class: "link-button", onClick: () => openTechnique(item.id) }, `${item.id} ${item.name}`), ...item.origins.map((origin) => badge(ORIGIN_LABEL[origin] || origin, "neutral"))),
                          el("ul", {}, ...item.reasons.map((reason) => el("li", {}, reasonText(reason)))),
                          button("Aceitar", async () => {
                            try {
                              await api(`/api/investigations/${investigationId}/techniques`, {
                                method: "POST",
                                body: JSON.stringify({ technique_id: item.id, note: item.reasons.map(reasonText).join("; ").slice(0, 990), source: "suggestion" }),
                              });
                              toast(`${item.id} vinculada a partir da sugestão.`);
                              await load();
                            } catch (error) {
                              toast(error.message, "error");
                            }
                          }),
                        ),
                      ),
                  )
                : el("p", { class: "panel-empty" }, "Sem sugestões: analise arquivos ou rode consultas multifonte no caso."),
              el("p", { class: "tool-limit" }, "Sugestões vêm de achados estáticos e de técnicas citadas por fontes. São pistas para o analista, não atribuição."),
            )
          : panel({ eyebrow: "COMO USAR", title: "Mapeie técnicas no caso" }, el("p", { class: "panel-note" }, "Escolha uma investigação para ver as técnicas vinculadas e as sugestões tiradas dos arquivos analisados e das fontes consultadas. Sem caso, a matriz serve de consulta.")),
      );
    }

    root.append(
      pageHeader({
        eyebrow: "INTELIGÊNCIA DE AMEAÇAS",
        title: "MITRE ATT&CK",
        description: "Matriz Enterprise offline, com detalhes de cada técnica e o mapeamento das técnicas observadas em cada caso.",
      }),
      statusHost,
      el("div", { class: "attack-toolbar" }, caseSelect, el("div", { class: "search-field" }, el("span", { class: "search-field-icon" }, G.icon("search", { size: 14 })), searchInput)),
      el("div", { class: "attack-layout" }, matrixHost, sideHost),
    );
    await load();
  }

  G.views.attack = renderAttack;
})();
