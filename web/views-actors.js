"use strict";

/* Threat actors: ATT&CK group profiles and the groups whose reported
 * techniques overlap a case. Overlap is a lead, never an attribution. */

(function () {
  const G = window.GARBAGE;
  const { el, api, pageHeader, panel, badge, table, emptyState, loadingBlock, inlineError, go } = G;

  const TACTIC_PT = {
    reconnaissance: "Reconhecimento",
    "resource-development": "Desenvolvimento de recursos",
    "initial-access": "Acesso inicial",
    execution: "Execução",
    persistence: "Persistência",
    "privilege-escalation": "Escalada de privilégios",
    "defense-evasion": "Evasão de defesas",
    "credential-access": "Acesso a credenciais",
    discovery: "Descoberta",
    "lateral-movement": "Movimento lateral",
    collection: "Coleta",
    "command-and-control": "Comando e controle",
    exfiltration: "Exfiltração",
    impact: "Impacto",
    other: "Outras",
  };
  const CAVEAT = "Sobreposição de técnicas não é atribuição: grupos compartilham métodos, as técnicas são públicas e o MITRE lista só o que foi relatado.";

  function techniqueLink(item) {
    return el("a", { class: "table-link", href: `#/attack?technique=${encodeURIComponent(item.id)}` }, el("code", {}, item.id), ` ${item.name || ""}`);
  }

  async function ensureLoaded(root) {
    const status = await api("/api/attack");
    if (status.loaded) return true;
    root.append(
      emptyState({
        icon: "matrix",
        title: "ATT&CK ainda não foi baixado",
        description: "Os perfis de atores vêm da base offline do MITRE ATT&CK. Baixe-a na tela do ATT&CK.",
        action: el("a", { class: "button button-primary button-small", href: "#/attack" }, "Abrir MITRE ATT&CK"),
      }),
    );
    return false;
  }

  async function renderList(root) {
    const results = el("div");
    const overlapHost = el("div");
    const search = el("input", { class: "input", type: "search", placeholder: "Nome, alias ou ID (ex.: APT29, Cozy Bear, G0016)", "aria-label": "Pesquisar grupos" });
    const caseSelect = el(
      "select",
      { class: "input compact-select", "aria-label": "Investigação para comparar" },
      el("option", { value: "" }, "Escolha uma investigação"),
      ...(await G.loadInvestigations()).filter((item) => !item.archived_at).map((item) => el("option", { value: item.id }, item.name)),
    );

    async function loadGroups() {
      let data;
      try {
        data = await api(`/api/attack/groups?q=${encodeURIComponent(search.value.trim())}`);
      } catch (error) {
        results.replaceChildren(inlineError(error.message));
        return;
      }
      results.replaceChildren(
        panel(
          { eyebrow: "GRUPOS", title: `${data.items.length} de ${data.total} grupos`, caption: "Ordenados pelo número de técnicas relatadas" },
          table({
            columns: [
              { label: "GRUPO", render: (row) => el("div", { class: "cell-stack" }, el("strong", {}, row.name), el("span", {}, row.aliases.slice(0, 4).join(", ") || "—")) },
              { label: "ID", render: (row) => el("code", {}, row.id) },
              { label: "TÉCNICAS", className: "numeric-col", cellClass: "numeric-col", render: (row) => String(row.technique_count) },
              { label: "SOFTWARE", className: "numeric-col", cellClass: "numeric-col", render: (row) => (row.software_count ? String(row.software_count) : "—") },
            ],
            rows: data.items,
            emptyMessage: "Nenhum grupo encontrado.",
            onRowClick: (row) => go("actors", row.id),
          }),
        ),
      );
    }

    async function loadOverlap() {
      if (!caseSelect.value) {
        overlapHost.replaceChildren(el("p", { class: "panel-empty" }, "Escolha uma investigação para ver os grupos com técnicas em comum."));
        return;
      }
      overlapHost.replaceChildren(loadingBlock("Comparando técnicas…"));
      let data;
      try {
        data = await api(`/api/investigations/${caseSelect.value}/actors?limit=10`);
      } catch (error) {
        overlapHost.replaceChildren(inlineError(error.message));
        return;
      }
      if (!data.case_techniques) {
        overlapHost.replaceChildren(
          el("p", { class: "panel-empty" }, "Esta investigação ainda não tem técnicas ATT&CK. Vincule técnicas na tela do ATT&CK ou aceite sugestões."),
        );
        return;
      }
      overlapHost.replaceChildren(
        data.weak ? el("p", { class: "tool-limit" }, `Só ${data.case_techniques} técnica(s) no caso: com tão pouco, muitos grupos empatam e o ranking diz pouco.`) : null,
        table({
          columns: [
            { label: "GRUPO", render: (row) => el("div", { class: "cell-stack" }, el("strong", {}, row.name), el("span", {}, row.id)) },
            { label: "COBERTURA", className: "numeric-col", cellClass: "numeric-col", render: (row) => `${Math.round(row.score * 100)}%` },
            { label: "EM COMUM", render: (row) => el("span", {}, `${row.shared_count} de ${data.case_techniques}`, el("span", { class: "muted" }, ` · repertório ${row.group_technique_count}`)) },
            {
              label: "TÉCNICAS",
              render: (row) =>
                el("div", { class: "actor-shared" }, ...row.shared.map((item) => el("code", { title: item.exact ? item.name : `${item.name} (mesma família)` }, item.exact ? item.id : `${item.id}~`))),
            },
          ],
          rows: data.items,
          emptyMessage: "Nenhum grupo usa as técnicas deste caso.",
          onRowClick: (row) => go("actors", row.id),
        }),
        el("p", { class: "tool-limit" }, `${CAVEAT} Cobertura pesa mais as técnicas raras; "~" marca técnica da mesma família (pai ou subtécnica).`),
      );
    }

    let timer = null;
    search.addEventListener("input", () => {
      window.clearTimeout(timer);
      timer = window.setTimeout(loadGroups, 250);
    });
    caseSelect.addEventListener("change", loadOverlap);

    root.append(
      panel(
        { eyebrow: "CASO", title: "Grupos com técnicas em comum" },
        el("div", { class: "inline-actions" }, caseSelect),
        overlapHost,
      ),
      el("div", { class: "toolbar-row" }, search),
      results,
    );
    loadOverlap();
    await loadGroups();
  }

  async function renderProfile(root, groupId) {
    let data;
    try {
      data = await api(`/api/attack/groups/${encodeURIComponent(groupId)}`);
    } catch (error) {
      root.append(inlineError(error.message));
      return;
    }
    const coverage = data.detection.techniques ? Math.round((data.detection.techniques_with_rules / data.detection.techniques) * 100) : 0;
    root.append(
      el(
        "div",
        { class: "actor-facts" },
        el("div", {}, el("span", { class: "eyebrow" }, "TÉCNICAS"), el("strong", {}, String(data.technique_count))),
        el("div", {}, el("span", { class: "eyebrow" }, "SOFTWARE"), el("strong", {}, data.software_known ? String(data.software.length) : "—")),
        el("div", {}, el("span", { class: "eyebrow" }, "COM REGRA SIGMA"), el("strong", {}, `${data.detection.techniques_with_rules}/${data.detection.techniques}`), el("span", { class: "muted" }, ` ${coverage}%`)),
        el("div", {}, el("span", { class: "eyebrow" }, "CASOS COM TÉCNICAS EM COMUM"), el("strong", {}, String(data.cases.length))),
      ),
      panel(
        { eyebrow: "PERFIL", title: data.name, caption: data.aliases.length ? `Também chamado: ${data.aliases.join(", ")}` : "" },
        el("p", {}, data.description || "Sem descrição."),
        el("p", { class: "tool-limit" }, "Texto e relações publicados pelo MITRE ATT&CK. ", el("a", { href: data.url, target: "_blank", rel: "noopener noreferrer" }, "Ver no site do MITRE")),
      ),
      panel(
        { eyebrow: "TÉCNICAS POR TÁTICA", title: `${data.technique_count} técnicas relatadas`, caption: "O número ao lado é a quantidade de regras Sigma locais para a técnica" },
        data.tactics.length
          ? el(
              "div",
              { class: "actor-tactics" },
              ...data.tactics.map((tactic) =>
                el(
                  "section",
                  { class: "actor-tactic" },
                  el("h3", {}, TACTIC_PT[tactic.shortname] || tactic.name, el("span", { class: "muted" }, ` · ${tactic.techniques.length}`)),
                  el(
                    "ul",
                    {},
                    ...tactic.techniques.map((item) =>
                      el("li", {}, techniqueLink(item), item.sigma_rules ? badge(`${item.sigma_rules} Sigma`, "neutral") : el("span", { class: "muted" }, " · sem regra")),
                    ),
                  ),
                ),
              ),
            )
          : el("p", { class: "panel-empty" }, "Nenhuma técnica relatada."),
      ),
      panel(
        { eyebrow: "DEFESA", title: "Mitigações que mais cobrem este grupo", caption: "Quantas técnicas do grupo cada mitigação cobre (direto ou pela técnica pai)" },
        table({
          columns: [
            { label: "MITIGAÇÃO", render: (row) => el("a", { class: "table-link", href: row.url, target: "_blank", rel: "noopener noreferrer" }, el("code", {}, row.id), ` ${row.name}`) },
            { label: "COBRE", className: "numeric-col", cellClass: "numeric-col", render: (row) => `${row.covered} de ${data.technique_count}` },
          ],
          rows: data.mitigations,
          emptyMessage: "Nenhuma mitigação mapeada.",
        }),
      ),
      panel(
        { eyebrow: "SOFTWARE", title: "Software relatado" },
        !data.software_known
          ? el("p", { class: "panel-empty" }, "A base ATT&CK local foi baixada antes de o GARBAGE guardar a relação grupo → software. Atualize o ATT&CK para ver esta lista.")
          : data.software.length
            ? table({
                columns: [
                  { label: "SOFTWARE", render: (row) => el("a", { class: "table-link", href: row.url, target: "_blank", rel: "noopener noreferrer" }, el("code", {}, row.id), ` ${row.name}`) },
                  { label: "TÉCNICAS", className: "numeric-col", cellClass: "numeric-col", render: (row) => String(row.technique_count) },
                ],
                rows: data.software,
              })
            : el("p", { class: "panel-empty" }, "Nenhum software relatado para este grupo."),
      ),
      panel(
        { eyebrow: "CASOS", title: "Investigações com técnicas em comum" },
        table({
          columns: [
            { label: "INVESTIGAÇÃO", render: (row) => el("a", { class: "table-link", href: `#/investigations/${row.investigation_id}` }, row.investigation_name) },
            { label: "TÉCNICAS EM COMUM", className: "numeric-col", cellClass: "numeric-col", render: (row) => String(row.shared) },
          ],
          rows: data.cases,
          emptyMessage: "Nenhuma investigação tem técnicas deste grupo.",
        }),
        el("p", { class: "tool-limit" }, CAVEAT),
      ),
    );
  }

  async function renderActors(root, params = []) {
    const groupId = params[0] || "";
    root.replaceChildren(
      pageHeader({
        eyebrow: "INTELIGÊNCIA DE AMEAÇAS",
        title: groupId ? "Perfil de ator" : "Atores de ameaça",
        description: groupId
          ? "O que o MITRE ATT&CK publica sobre o grupo, com as defesas e detecções que isso indica."
          : "Grupos do MITRE ATT&CK e quais deles têm técnicas em comum com uma investigação.",
        actions: groupId ? [el("a", { class: "button button-secondary button-small", href: "#/actors" }, "Todos os grupos")] : [],
      }),
    );
    try {
      if (!(await ensureLoaded(root))) return;
    } catch (error) {
      root.append(inlineError(error.message));
      return;
    }
    if (groupId) await renderProfile(root, groupId);
    else await renderList(root);
  }

  G.views.actors = renderActors;
})();
