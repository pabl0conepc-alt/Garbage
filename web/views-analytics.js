"use strict";

/* Analytics dashboard: counts across the workspace or one investigation. */

(function () {
  const G = window.GARBAGE;
  const { el, api, pageHeader, metric, panel } = G;
  const C = G.charts;

  const PERIODS = [
    [7, "7 dias"],
    [30, "30 dias"],
    [90, "90 dias"],
    [365, "12 meses"],
  ];

  /* Activity actions keep the same colour whatever is in the period. */
  const ACTIONS = [
    ["create", "Criações"],
    ["update", "Edições"],
    ["link", "Vínculos"],
    ["intel-run", "Consultas multifonte"],
    ["analysis", "Análises de arquivo"],
    ["evidence", "Evidências"],
    ["observation", "Observações"],
  ];
  const ACTION_SLOT = Object.fromEntries(ACTIONS.map(([key], index) => [key, index]));
  const ACTION_LABEL = Object.fromEntries(ACTIONS);

  /* Status colours are reserved and always paired with a label. */
  const STATUS = [
    ["ok", "var(--viz-good)"],
    ["empty", "var(--viz-neutral)"],
    ["error", "var(--viz-critical)"],
    ["rate-limited", "var(--viz-warning)"],
    ["key-missing", "var(--viz-serious)"],
  ];
  const LEVEL_COLOR = { warning: "var(--viz-warning)", note: "var(--viz-neutral)", info: "var(--viz-1)" };
  const LEVEL_LABEL = { warning: "Alerta", note: "Nota", info: "Informação" };
  const VERIFICATION_LABEL = { verified: "Verificado", "not-verified": "Não verificado", disputed: "Contestado", "false-positive": "Falso positivo" };
  const FINDING_LABEL = {
    "vba-macros": "Macros VBA", "vba-autoexec": "Macro automática", "vba-suspicious-keywords": "Palavras-chave suspeitas em macro",
    "yara-match": "Regra YARA", "yara-error": "Erro em regra YARA", "embedded-executable": "Executável embutido",
    "embedded-private-key": "Chave privada embutida", "high-entropy": "Entropia alta", "extension-mismatch": "Extensão divergente",
    "structural-note": "Nota estrutural", "executable-static-only": "Executável (análise estática)", "pdf-active-content": "PDF com conteúdo ativo",
    "pdf-encrypted": "PDF criptografado", "lnk-command": "Atalho com comando de risco", "lnk-padded-arguments": "Atalho com argumentos ocultos",
    "lnk-tracker": "Atalho com máquina de origem", "iso-executable-content": "ISO com executáveis", "rtf-objects": "RTF com objetos",
    "rtf-equation-editor": "Editor de Equações", "rtf-remote-template": "Modelo remoto", "rtf-auto-update": "Objeto com atualização automática",
    "rtf-dde": "Campo DDE", "rtf-package": "Pacote embutido", "msi-custom-actions": "Ações personalizadas de MSI",
    "ole-embedded-objects": "Objetos OLE embutidos", "legacy-ole": "OLE legado",
  };
  const FORMAT_LABEL = {
    pdf: "PDF", zip: "ZIP", docx: "Word (OOXML)", xlsx: "Excel (OOXML)", pptx: "PowerPoint (OOXML)", doc: "Word 97-2003",
    xls: "Excel 97-2003", ppt: "PowerPoint 97-2003", msi: "MSI", lnk: "Atalho LNK", iso: "ISO", rtf: "RTF", pe: "PE",
    elf: "ELF", macho: "Mach-O", jpeg: "JPEG", png: "PNG", text: "Texto", unknown: "Não reconhecido",
  };

  const label = (map) => (row) => map[row.key] || row.key || "—";

  async function renderAnalytics(root, params = []) {
    let investigationId = params[0] || "";
    let days = 30;
    let data = null;
    const content = el("div", { class: "analytics-content" });

    const investigations = await G.loadInvestigations();
    const caseSelect = el(
      "select",
      { class: "input compact-select", "aria-label": "Investigação" },
      el("option", { value: "" }, "Todo o workspace"),
      ...investigations.map((item) => el("option", { value: item.id }, item.name)),
    );
    caseSelect.value = investigationId;
    caseSelect.addEventListener("change", () => {
      investigationId = caseSelect.value;
      history.replaceState(null, "", investigationId ? `#/analytics/${investigationId}` : "#/analytics");
      load();
    });
    const periodGroup = el("div", { class: "segmented", role: "radiogroup", "aria-label": "Período das séries temporais" });
    function drawPeriods() {
      periodGroup.replaceChildren(
        ...PERIODS.map(([value, text]) =>
          el(
            "button",
            {
              type: "button",
              role: "radio",
              class: `segmented-option${value === days ? " is-active" : ""}`,
              "aria-checked": String(value === days),
              onClick: () => {
                days = value;
                drawPeriods();
                load();
              },
            },
            text,
          ),
        ),
      );
    }
    drawPeriods();

    async function load() {
      content.classList.add("is-refreshing");
      try {
        const query = new URLSearchParams({ days: String(days) });
        if (investigationId) query.set("investigation_id", investigationId);
        data = await api(`/api/analytics?${query}`);
        draw();
      } catch (error) {
        content.replaceChildren(G.inlineError(error.message));
      } finally {
        content.classList.remove("is-refreshing");
      }
    }

    function draw() {
      const totals = data.totals;
      const activity = data.activity.series
        .map((item) => ({
          key: item.key,
          label: ACTION_LABEL[item.key] || "Outras ações",
          values: item.values,
          slot: ACTION_SLOT[item.key] ?? ACTIONS.length,
        }))
        .reduce((merged, item) => {
          const target = merged.find((entry) => entry.slot === item.slot);
          if (target) target.values = target.values.map((value, index) => value + item.values[index]);
          else merged.push({ ...item, values: [...item.values] });
          return merged;
        }, [])
        .sort((a, b) => a.slot - b.slot)
        .map((item) => ({ ...item, color: C.seriesColor(item.slot) }));
      const activityTotal = activity.reduce((sum, item) => sum + item.values.reduce((a, b) => a + b, 0), 0);
      const runsTotal = data.intel_runs_by_day.reduce((a, b) => a + b, 0);
      const dayColumns = [{ label: "DIA", value: (row) => G.formatDate(`${row.day}T12:00:00`) }];

      const sources = data.sources.slice(0, 14);
      const statusSegments = STATUS.map(([key, color]) => ({
        label: G.sourceStatusLabel(key),
        color,
        value: (row) => row.statuses[key] || 0,
      }));

      content.replaceChildren(
        el(
          "div",
          { class: "metric-grid analytics-metrics" },
          metric({ label: "RESULTADOS DE FONTES", value: C.number.format(totals.intel_results), foot: `${C.number.format(totals.intel_runs)} consultas multifonte`, icon: "◎" }),
          metric({ label: "ENTIDADES", value: C.number.format(totals.entities), foot: `${C.number.format(totals.relationships)} relacionamento(s)` }),
          metric({ label: "OBSERVAÇÕES", value: C.number.format(totals.observations), foot: `${C.number.format(totals.evidence)} evidência(s)` }),
          metric({ label: "ARQUIVOS ANALISADOS", value: C.number.format(totals.file_analyses), foot: `${C.number.format(data.finding_levels.reduce((a, b) => a + b.count, 0))} achados estáticos` }),
        ),
        el(
          "div",
          { class: "analytics-grid" },
          C.card({
            eyebrow: "ATIVIDADE",
            title: "O que foi feito no período",
            caption: `${C.number.format(activityTotal)} ações desde ${G.formatDate(`${data.since}T12:00:00`)}`,
            legend: activity.length > 1 ? C.legend(activity.map((item) => ({ label: item.label, color: item.color, line: true }))) : null,
            empty: activityTotal ? "" : "Nenhuma ação registrada neste período.",
            chart: () => C.timeSeries({ days: data.activity.days, series: activity }),
            table: () =>
              C.dataTable(
                [...dayColumns, ...activity.map((item) => ({ label: item.label.toUpperCase(), numeric: true, value: (row) => C.number.format(row.values[item.key]) }))],
                data.activity.days
                  .map((day, index) => ({ day, values: Object.fromEntries(activity.map((item) => [item.key, item.values[index]])) }))
                  .filter((row) => Object.values(row.values).some(Boolean)),
              ),
          }),
          C.card({
            eyebrow: "PESQUISA MULTIFONTE",
            title: "Consultas por dia",
            caption: `${C.number.format(runsTotal)} no período`,
            empty: runsTotal ? "" : "Nenhuma consulta multifonte neste período.",
            chart: () => C.timeSeries({ days: data.activity.days, series: [{ label: "Consultas", values: data.intel_runs_by_day, color: C.seriesColor(3) }] }),
            table: () =>
              C.dataTable(
                [...dayColumns, { label: "CONSULTAS", numeric: true, value: (row) => C.number.format(row.count) }],
                data.activity.days.map((day, index) => ({ day, count: data.intel_runs_by_day[index] })).filter((row) => row.count),
              ),
          }),
          C.card({
            eyebrow: "FONTES",
            title: "Resultados por fonte",
            caption: "Total de fatos devolvidos",
            empty: sources.length ? "" : "Nenhuma consulta multifonte ainda.",
            chart: () => C.bars({ rows: sources, label: (row) => G.connectorLabel(row.key), value: (row) => row.results, unit: "resultados" }),
            table: () =>
              C.dataTable(
                [
                  { label: "FONTE", value: (row) => G.connectorLabel(row.key) },
                  { label: "RESULTADOS", numeric: true, value: (row) => C.number.format(row.results) },
                  { label: "CONSULTAS", numeric: true, value: (row) => C.number.format(row.runs) },
                ],
                data.sources,
              ),
          }),
          C.card({
            eyebrow: "SAÚDE DAS FONTES",
            title: "Desfecho por consulta",
            caption: "Cada consulta conta uma vez por fonte",
            legend: C.legend(statusSegments.map((segment) => ({ label: segment.label, color: segment.color }))),
            empty: sources.length ? "" : "Nenhuma consulta multifonte ainda.",
            chart: () => C.stackedBars({ rows: sources, label: (row) => G.connectorLabel(row.key), segments: statusSegments }),
            table: () =>
              C.dataTable(
                [{ label: "FONTE", value: (row) => G.connectorLabel(row.key) }, ...statusSegments.map((segment) => ({ label: segment.label.toUpperCase(), numeric: true, value: (row) => C.number.format(segment.value(row)) }))],
                data.sources,
              ),
          }),
          C.card({
            eyebrow: "RESULTADOS",
            title: "Tipos de fato mais encontrados",
            empty: data.result_types.length ? "" : "Nenhum resultado ainda.",
            chart: () => C.bars({ rows: data.result_types, label: (row) => G.resultTypeLabel(row.key), value: (row) => row.count }),
            table: () => C.dataTable([{ label: "TIPO", value: (row) => G.resultTypeLabel(row.key) }, { label: "OCORRÊNCIAS", numeric: true, value: (row) => C.number.format(row.count) }], data.result_types),
          }),
          C.card({
            eyebrow: "ENTIDADES",
            title: "Entidades por tipo",
            empty: data.entity_types.length ? "" : "Nenhuma entidade registrada.",
            chart: () => C.bars({ rows: data.entity_types, label: (row) => G.entityTypeLabel(row.key), value: (row) => row.count }),
            table: () => C.dataTable([{ label: "TIPO", value: (row) => G.entityTypeLabel(row.key) }, { label: "ENTIDADES", numeric: true, value: (row) => C.number.format(row.count) }], data.entity_types),
          }),
          C.card({
            eyebrow: "RELACIONAMENTOS",
            title: "Relacionamentos por tipo",
            caption: data.relationship_verification.map((row) => `${VERIFICATION_LABEL[row.key] || row.key}: ${row.count}`).join(" · "),
            empty: data.relationship_types.length ? "" : "Nenhum relacionamento registrado.",
            chart: () => C.bars({ rows: data.relationship_types, label: (row) => G.relationshipLabel(row.key), value: (row) => row.count }),
            table: () => C.dataTable([{ label: "TIPO", value: (row) => G.relationshipLabel(row.key) }, { label: "RELACIONAMENTOS", numeric: true, value: (row) => C.number.format(row.count) }], data.relationship_types),
          }),
          C.card({
            eyebrow: "ANÁLISE DE ARQUIVOS",
            title: "Achados estáticos",
            caption: data.finding_levels.map((row) => `${LEVEL_LABEL[row.key] || row.key}: ${row.count}`).join(" · "),
            empty: data.finding_codes.length ? "" : "Nenhum arquivo analisado ainda.",
            chart: () => C.bars({ rows: data.finding_codes, label: label(FINDING_LABEL), value: (row) => row.count }),
            table: () => C.dataTable([{ label: "ACHADO", value: label(FINDING_LABEL) }, { label: "OCORRÊNCIAS", numeric: true, value: (row) => C.number.format(row.count) }], data.finding_codes),
          }),
          C.card({
            eyebrow: "ANÁLISE DE ARQUIVOS",
            title: "Formatos analisados",
            empty: data.file_formats.length ? "" : "Nenhum arquivo analisado ainda.",
            chart: () => C.bars({ rows: data.file_formats, label: label(FORMAT_LABEL), value: (row) => row.count }),
            table: () => C.dataTable([{ label: "FORMATO", value: label(FORMAT_LABEL) }, { label: "ANÁLISES", numeric: true, value: (row) => C.number.format(row.count) }], data.file_formats),
          }),
        ),
        el(
          "p",
          { class: "tool-limit" },
          "Contagens de registros do workspace. Cada número pode ser conferido nas telas de origem; volume de resultados não mede gravidade nem atribuição.",
        ),
      );
      G.hydrateIcons?.(content);
    }

    root.append(
      pageHeader({
        eyebrow: "ANÁLISE",
        title: "Painel analítico",
        description: "Visão consolidada do que foi coletado, analisado e relacionado, por investigação e por período.",
      }),
      el("div", { class: "analytics-filters" }, caseSelect, periodGroup),
      content,
    );
    content.replaceChildren(G.loadingBlock("Calculando…"));
    await load();
  }

  G.views.analytics = renderAnalytics;
})();
