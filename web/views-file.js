"use strict";

/* File intelligence: bounded static analysis of analyst-supplied files. */

(function () {
  const G = window.GARBAGE;
  const {
    el, api, toast, pageHeader, panel, metric, badge, emptyState, table,
    loadingBlock, inlineError, formatDate, formatBytes, shortId, titleCase, go,
  } = G;

  const MAX_BYTES = 4 * 1024 * 1024;

  function button(label, onClick, options = {}) {
    return el(
      "button",
      {
        class: `button ${options.variant || "button-secondary"} button-small`,
        type: "button",
        disabled: Boolean(options.disabled),
        onClick,
      },
      label,
    );
  }

  function fileToBase64(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onerror = () => reject(new Error("Não foi possível ler o arquivo selecionado."));
      reader.onload = () => {
        const result = String(reader.result || "");
        const comma = result.indexOf(",");
        resolve(comma >= 0 ? result.slice(comma + 1) : result);
      };
      reader.readAsDataURL(file);
    });
  }

  function flattenMetadata(value, prefix = "", pairs = []) {
    if (value === null || value === undefined || value === "") return pairs;
    if (Array.isArray(value)) {
      for (const item of value) {
        if (item && typeof item === "object" && "key" in item && "value" in item) {
          pairs.push([titleCase(item.key), String(item.value)]);
        } else if (typeof item !== "object") {
          pairs.push([prefix || "Valor", String(item)]);
        }
      }
      return pairs;
    }
    if (typeof value === "object") {
      for (const [key, item] of Object.entries(value)) {
        flattenMetadata(item, prefix ? `${prefix} · ${titleCase(key)}` : titleCase(key), pairs);
      }
      return pairs;
    }
    pairs.push([prefix || "Valor", String(value)]);
    return pairs;
  }

  async function renderFiles(root) {
    let investigations = [];
    let selectedFile = null;
    let analysis = null;
    let analyses = { items: [], total: 0 };
    let busy = false;

    try {
      investigations = await G.loadInvestigations();
    } catch (error) {
      // History and analysis still work without a case list.
    }

    const fileInput = el("input", {
      type: "file",
      "aria-label": "Arquivo para análise",
      onChange: (event) => {
        selectedFile = event.target.files?.[0] || null;
        updateSelection();
      },
    });
    const dropZone = el(
      "div",
      { class: "drop-zone", tabindex: "0" },
      el("span", { class: "drop-icon", "aria-hidden": "true" }, "▧"),
      el("strong", {}, "Escolha um arquivo ou solte-o aqui"),
      el("span", {}, "Máximo de 4 MiB. Somente inspeção estática: nada é executado ou extraído."),
      fileInput,
    );
    dropZone.addEventListener("dragover", (event) => {
      event.preventDefault();
      dropZone.classList.add("is-dragging");
    });
    dropZone.addEventListener("dragleave", () => dropZone.classList.remove("is-dragging"));
    dropZone.addEventListener("drop", (event) => {
      event.preventDefault();
      dropZone.classList.remove("is-dragging");
      const file = event.dataTransfer?.files?.[0];
      if (file) {
        selectedFile = file;
        updateSelection();
      }
    });

    const caseSelect = el(
      "select",
      { class: "input", "aria-label": "Associar a análise a uma investigação" },
      el("option", { value: "" }, "Somente histórico do workspace"),
      ...investigations.map((investigation) =>
        el("option", { value: investigation.id }, investigation.name),
      ),
    );
    const selectedLabel = el("p", { class: "file-selection" }, "Nenhum arquivo selecionado.");
    const analyzeButton = button("Analisar arquivo", () => analyse(), {
      variant: "button-primary",
      disabled: true,
    });

    function updateSelection() {
      if (!selectedFile) {
        selectedLabel.textContent = "Nenhum arquivo selecionado.";
        analyzeButton.disabled = true;
        return;
      }
      selectedLabel.replaceChildren(
        el("strong", {}, selectedFile.name),
        el("span", {}, `${formatBytes(selectedFile.size)} · ${selectedFile.type || "tipo desconhecido"}`),
      );
      analyzeButton.disabled = busy || selectedFile.size > MAX_BYTES;
      if (selectedFile.size > MAX_BYTES) {
        toast("O arquivo excede o limite de análise de 4 MiB.", "error");
      }
    }

    async function analyse() {
      if (!selectedFile || busy) return;
      if (selectedFile.size > MAX_BYTES) {
        toast("O arquivo excede o limite de análise de 4 MiB.", "error");
        return;
      }
      busy = true;
      analyzeButton.disabled = true;
      analyzeButton.textContent = "Analisando…";
      try {
        const content_base64 = await fileToBase64(selectedFile);
        analysis = await api("/api/intelligence/files", {
          method: "POST",
          body: JSON.stringify({
            filename: selectedFile.name,
            content_base64,
            ...(caseSelect.value ? { investigation_id: caseSelect.value } : {}),
          }),
        });
        toast(`Analisado: ${analysis.file_name} · ${analysis.format_label}.`);
        await loadHistory();
        drawResult();
      } catch (error) {
        toast(error.message, "error");
      } finally {
        busy = false;
        analyzeButton.disabled = !selectedFile;
        analyzeButton.textContent = "Analisar arquivo";
      }
    }

    async function loadHistory() {
      try {
        analyses = await api("/api/intelligence/files?limit=50");
      } catch (error) {
        analyses = { items: [], total: 0 };
      }
      drawHistory();
    }

    async function openAnalysis(id) {
      try {
        analysis = await api(`/api/intelligence/files/${id}`);
        drawResult();
      } catch (error) {
        toast(error.message, "error");
      }
    }

    async function attachEvidence() {
      if (!analysis?.investigation_id) return;
      if (!selectedFile || selectedFile.size > MAX_BYTES) {
        toast("Selecione novamente o arquivo original para anexá-lo como evidência.", "error");
        return;
      }
      try {
        await api(`/api/investigations/${analysis.investigation_id}/evidence`, {
          method: "POST",
          body: JSON.stringify({
            title: analysis.file_name,
            evidence_type: "file",
            description:
              "Anexado pela Análise de arquivos após análise estática. O arquivo não foi executado.",
            source_reference: "note://file-intelligence",
            original_name: selectedFile.name,
            content_base64: await fileToBase64(selectedFile),
          }),
        });
        toast("Evidência adicionada com seu próprio registro de integridade SHA-256.");
      } catch (error) {
        toast(error.message, "error");
      }
    }

    const resultHost = el("div", { class: "file-result" });
    const historyHost = el("div");

    function drawResult() {
      if (!analysis) {
        resultHost.replaceChildren(
          emptyState({
            icon: "▧",
            title: "Nenhuma análise selecionada",
            description:
              "Escolha um arquivo autorizado dentro do limite. O GARBAGE identifica estrutura e metadados sem executá-lo ou descompactá-lo.",
          }),
        );
        return;
      }
      const findings = (analysis.findings || []).map((finding) =>
        el(
          "div",
          { class: `file-finding level-${finding.level}` },
          badge(titleCase(finding.level), finding.level === "warning" ? "warning" : finding.level === "note" ? "neutral" : "info"),
          el("span", {}, G.translateText(finding.message)),
        ),
      );
      const indicators = analysis.indicators || [];
      const structure = analysis.structure || {};
      const metadataPairs = flattenMetadata(analysis.metadata || {});
      const hashRows = G.kvList([
        ["SHA-256", el("code", { class: "hash" }, analysis.hashes.sha256)],
        ["SHA-1", el("code", { class: "hash" }, analysis.hashes.sha1)],
        ["MD5", el("code", { class: "hash" }, analysis.hashes.md5)],
        ["Assinatura (magic bytes)", el("code", {}, analysis.magic_hex)],
        ["Entropia", `${analysis.entropy} / 8`],
      ]);

      const sections = [];
      if (structure.entries?.length) {
        sections.push(
          panel(
            {
              eyebrow: "ESTRUTURA DO PACOTE",
              title: `Membros (${structure.entry_count})`,
              caption: "Somente listados; nunca extraídos",
            },
            table({
              columns: [
                { label: "NOME", render: (row) => el("code", { class: "reference-code" }, row.name) },
                { label: "TAMANHO", render: (row) => formatBytes(row.size_bytes) },
                {
                  label: "TAXA",
                  className: "numeric-col",
                  render: (row) => (row.ratio === null ? "—" : `${row.ratio}×`),
                },
                {
                  label: "SINALIZADORES",
                  render: (row) =>
                    el(
                      "div",
                      { class: "row-actions" },
                      row.path_traversal ? badge("Travessia de caminho", "warning") : null,
                      row.encrypted ? badge("Criptografado", "neutral") : null,
                    ),
                },
              ],
              rows: structure.entries,
              emptyMessage: "Nenhum membro.",
            }),
          ),
        );
      }
      if (structure.header) {
        const header = structure.header;
        sections.push(
          panel(
            { eyebrow: "CABEÇALHO BINÁRIO", title: analysis.format_label },
            G.kvList(
              Object.entries(header)
                .filter(([, value]) => value !== "" && value !== null && !Array.isArray(value))
                .map(([key, value]) => [titleCase(key), String(value)]),
            ),
            header.segments?.length
              ? table({
                  columns: [
                    { label: "SEGMENTO", render: (row) => el("code", {}, row.name || "—") },
                    { label: "TAMANHO VM", render: (row) => formatBytes(row.vm_size || 0) },
                    { label: "TAMANHO NO ARQUIVO", render: (row) => formatBytes(row.file_size || 0) },
                  ],
                  rows: header.segments,
                })
              : null,
            header.architectures?.length
              ? table({
                  columns: [
                    { label: "ARQUITETURA", render: (row) => row.cpu },
                    { label: "DESLOCAMENTO", render: (row) => `0x${Number(row.offset).toString(16)}` },
                    { label: "TAMANHO", render: (row) => formatBytes(row.size) },
                  ],
                  rows: header.architectures,
                })
              : null,
          ),
        );
      }
      if (analysis.hardening?.checks?.length) {
        const hardening = analysis.hardening;
        const tone = (status) =>
          status === "enabled"
            ? "success"
            : status === "missing"
              ? "warning"
              : "neutral";
        sections.push(
          panel(
            {
              eyebrow: "PROTEÇÕES DO BINÁRIO",
              title: `${hardening.enabled_count} ativas · ${hardening.missing_count} não encontradas`,
              caption: `${hardening.detail} · ${hardening.engine}`,
            },
            el(
              "div",
              { class: "file-findings" },
              ...hardening.checks.map((check) =>
                el(
                  "div",
                  { class: "file-finding" },
                  badge(titleCase(check.status), tone(check.status)),
                  el(
                    "div",
                    {},
                    el("strong", {}, check.label),
                    el("p", { class: "panel-note" }, check.detail),
                  ),
                ),
              ),
            ),
            ...(hardening.limitations || []).map((limit) =>
              el("p", { class: "tool-limit" }, G.translateText(limit)),
            ),
          ),
        );
      }
      if (structure.sections?.length) {
        sections.push(
          panel(
            { eyebrow: "SEÇÕES", title: `${structure.sections.length} analisadas` },
            table({
              columns: [
                { label: "SEÇÃO", render: (row) => el("code", {}, row.name || "—") },
                { label: "TIPO", render: (row) => String(row.type) },
                { label: "DESLOCAMENTO", render: (row) => `0x${Number(row.offset).toString(16)}` },
                { label: "TAMANHO", render: (row) => formatBytes(row.size_bytes) },
              ],
              rows: structure.sections,
            }),
          ),
        );
      }
      if (structure.gzip) {
        sections.push(
          panel(
            { eyebrow: "FLUXO GZIP", title: "Prévia de descompressão limitada" },
            G.kvList(
              Object.entries(structure.gzip).map(([key, value]) => [
                titleCase(key),
                typeof value === "boolean" ? (value ? "Sim" : "Não") : String(value),
              ]),
            ),
            el(
              "p",
              { class: "panel-note" },
              "A prévia é limitada a 1 MiB e nunca é gravada em disco.",
            ),
          ),
        );
      }
      if (structure.image) {
        sections.push(
          panel(
            { eyebrow: "ESTRUTURA DA IMAGEM", title: "Dimensões" },
            G.kvList(Object.entries(structure.image).map(([key, value]) => [titleCase(key), String(value)])),
          ),
        );
      }
      if (structure.version || structure.approximate_page_count !== undefined) {
        sections.push(
          panel(
            { eyebrow: "ESTRUTURA DO PDF", title: "Dados do documento" },
            G.kvList(
              Object.entries(structure).map(([key, value]) => [titleCase(key), String(value)]),
            ),
          ),
        );
      }
      if (analysis.imports?.length) {
        sections.push(
          panel(
            { eyebrow: "IMPORTAÇÕES ESTÁTICAS", title: `${analysis.imports.length} referenciadas` },
            el("div", { class: "chip-list" }, ...analysis.imports.map((item) => el("code", {}, item))),
          ),
        );
      }

      resultHost.replaceChildren(
        el(
          "div",
          { class: "result-heading" },
          el(
            "div",
            {},
            el("p", { class: "eyebrow" }, "ANÁLISE ESTÁTICA"),
            el("h2", {}, analysis.file_name),
            el(
              "div",
              { class: "case-meta" },
              badge(analysis.format_label, "info"),
              badge(analysis.media_type, "neutral"),
              el("span", {}, formatBytes(analysis.size_bytes)),
              analysis.investigation_id
                ? el("a", { class: "table-link", href: `#/investigations/${analysis.investigation_id}` }, "Abrir caso")
                : el("span", {}, "Histórico do workspace"),
              el("span", {}, formatDate(analysis.created_at, { time: true })),
            ),
          ),
          el(
            "div",
            { class: "row-actions" },
            analysis.investigation_id
              ? button("Anexar como evidência", attachEvidence, { variant: "button-primary" })
              : null,
            button("Limpar", () => {
              analysis = null;
              drawResult();
            }),
          ),
        ),
        el(
          "div",
          { class: "metric-grid compact-metrics" },
          metric({
            label: "FORMATO",
            value: analysis.format_label,
            foot: analysis.media_type,
            icon: "▧",
            tone: "blue",
          }),
          metric({
            label: "TAMANHO",
            value: formatBytes(analysis.size_bytes),
            foot: `${analysis.strings.count} strings amostradas`,
            icon: "◫",
            tone: "violet",
          }),
          metric({
            label: "ENTROPIA",
            value: String(analysis.entropy),
            foot: "Bits por byte",
            icon: "◈",
            tone: analysis.entropy >= 7.2 ? "amber" : "green",
          }),
          metric({
            label: "INDICADORES",
            value: String(indicators.length),
            foot: "Correspondências sintáticas em strings",
            icon: "⌁",
            tone: "amber",
          }),
        ),
        panel({ eyebrow: "ACHADOS", title: "Observações estáticas" }, ...findings),
        el(
          "div",
          { class: "detail-grid" },
          panel({ eyebrow: "INTEGRIDADE", title: "Hashes" }, hashRows),
          panel(
            { eyebrow: "METADADOS", title: "Propriedades extraídas" },
            metadataPairs.length
              ? G.kvList(metadataPairs.slice(0, 80))
              : el("p", { class: "panel-empty" }, "Nenhum metadado extraído."),
          ),
        ),
        ...sections,
        panel(
          {
            eyebrow: "INDICADORES EMBUTIDOS",
            title: `Correspondências sintáticas (${indicators.length})`,
            caption: "Sem verificação de reputação",
          },
          indicators.length
            ? table({
                columns: [
                  { label: "TIPO", render: (row) => badge(G.indicatorTypeLabel(row.type), "info") },
                  { label: "VALOR", render: (row) => el("code", { class: "reference-code" }, row.value) },
                  { label: "NOTA", render: (row) => row.note },
                ],
                rows: indicators,
              })
            : el("p", { class: "panel-empty" }, "Nenhum indicador corresponde às strings extraídas."),
        ),
        panel(
          {
            eyebrow: "STRINGS",
            title: `Amostra (${analysis.strings.count})`,
            caption: analysis.strings.truncated ? "truncado no limite" : "complete sample",
          },
          el(
            "pre",
            { class: "code-block strings-block" },
            analysis.strings.items
              .map((item) => `0x${item.offset.toString(16).padStart(6, "0")}  ${item.value}`)
              .join("\n") || "Nenhuma string imprimível.",
          ),
        ),
        panel(
          { eyebrow: "LIMITAÇÕES", title: "Limites analíticos" },
          el(
            "ul",
            { class: "plain-list" },
            ...analysis.limitations.map((limitation) => el("li", {}, G.translateText(limitation))),
          ),
        ),
        el(
          "details",
          { class: "raw-details" },
          el("summary", {}, "Estrutura bruta (JSON)"),
          el("pre", { class: "code-block" }, JSON.stringify(analysis.structure, null, 2)),
        ),
      );
    }

    function drawHistory() {
      historyHost.replaceChildren(
        panel(
          {
            eyebrow: "HISTÓRICO",
            title: "Registros de análise",
            caption: `${analyses.items.length} de ${analyses.total}`,
          },
          analyses.items.length
            ? table({
                columns: [
                  {
                    label: "ARQUIVO",
                    render: (row) =>
                      el(
                        "div",
                        { class: "cell-stack" },
                        el("strong", {}, row.file_name),
                        el("span", {}, row.format),
                      ),
                  },
                  { label: "TAMANHO", render: (row) => formatBytes(row.size_bytes) },
                  {
                    label: "SHA-256",
                    render: (row) => el("code", { class: "hash" }, row.sha256.slice(0, 16)),
                  },
                  {
                    label: "CASO",
                    render: (row) =>
                      row.investigation_id
                        ? el("a", { class: "table-link", href: `#/investigations/${row.investigation_id}` }, row.investigation_name || shortId(row.investigation_id))
                        : "Workspace",
                  },
                  { label: "ANÁLISE", render: (row) => formatDate(row.created_at) },
                  { label: "", render: (row) => button("Abrir", () => openAnalysis(row.id)) },
                ],
                rows: analyses.items,
                emptyMessage: "Nenhum arquivo foi analisado ainda.",
                onRowClick: (row) => openAnalysis(row.id),
              })
            : el("p", { class: "panel-empty" }, "Nenhum histórico ainda."),
        ),
      );
    }

    root.append(
      pageHeader({
        eyebrow: "ANÁLISE DE ARQUIVOS",
        title: "Análise estática de arquivos",
        description:
          "Identifique formato, hashes, metadados, estrutura de pacotes, cabeçalhos binários e indicadores embutidos sem execução.",
        actions: [button("Atualizar histórico", () => loadHistory())],
      }),
      el(
        "div",
        { class: "notice" },
        "Nada é executado, emulado ou extraído automaticamente. A análise é limitada e somente leitura; " +
          "indicadores embutidos são correspondências sintáticas, não resultados de reputação.",
      ),
      el(
        "div",
        { class: "file-layout" },
        panel(
          { eyebrow: "ENTRADA", title: "Analisar um arquivo" },
          dropZone,
          selectedLabel,
          el(
            "div",
            { class: "field" },
            el("label", {}, "Associar a uma investigação (opcional)"),
            caseSelect,
          ),
          el("div", { class: "toolbar-end" }, analyzeButton),
        ),
        panel(
          { eyebrow: "ESCOPO", title: "Analisadores estáticos suportados" },
          el(
            "ul",
            { class: "plain-list" },
            el("li", {}, "Metadados de PDF, declarações de conteúdo ativo e contagem aproximada de páginas."),
            el("li", {}, "Diretórios centrais de ZIP/OOXML/EPUB/JAR/APK, travessia de caminho e sinalizadores de macro."),
            el("li", {}, "Cabeçalhos TAR e prévia de descompressão GZIP limitada."),
            el("li", {}, "Dimensões de PNG, JPEG, GIF, WebP e BMP."),
            el("li", {}, "Cabeçalhos, seções, importações e arquitetura de ELF, PE e Mach-O."),
            el("li", {}, "Strings ASCII/UTF-16, entropia e SHA-256/SHA-1/MD5."),
          ),
          el(
            "p",
            { class: "panel-note" },
            "Suporte mais profundo a formatos está no roadmap. Formatos não suportados são identificados, não presumidos.",
          ),
        ),
      ),
      resultHost,
      historyHost,
    );

    drawResult();
    await loadHistory();
  }

  G.views.files = renderFiles;
})();
