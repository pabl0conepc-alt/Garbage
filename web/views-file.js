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
      reader.onerror = () => reject(new Error("Unable to read the selected file."));
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
          pairs.push([prefix || "Value", String(item)]);
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
    pairs.push([prefix || "Value", String(value)]);
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
      "aria-label": "File to analyse",
      onChange: (event) => {
        selectedFile = event.target.files?.[0] || null;
        updateSelection();
      },
    });
    const dropZone = el(
      "div",
      { class: "drop-zone", tabindex: "0" },
      el("span", { class: "drop-icon", "aria-hidden": "true" }, "▧"),
      el("strong", {}, "Choose a file or drop it here"),
      el("span", {}, "Maximum 4 MiB. Static inspection only: nothing is executed or extracted."),
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
      { class: "input", "aria-label": "Associate analysis with an investigation" },
      el("option", { value: "" }, "Workspace history only"),
      ...investigations.map((investigation) =>
        el("option", { value: investigation.id }, investigation.name),
      ),
    );
    const selectedLabel = el("p", { class: "file-selection" }, "No file selected.");
    const analyzeButton = button("Analyse file", () => analyse(), {
      variant: "button-primary",
      disabled: true,
    });

    function updateSelection() {
      if (!selectedFile) {
        selectedLabel.textContent = "No file selected.";
        analyzeButton.disabled = true;
        return;
      }
      selectedLabel.replaceChildren(
        el("strong", {}, selectedFile.name),
        el("span", {}, `${formatBytes(selectedFile.size)} · ${selectedFile.type || "unknown type"}`),
      );
      analyzeButton.disabled = busy || selectedFile.size > MAX_BYTES;
      if (selectedFile.size > MAX_BYTES) {
        toast("The file exceeds the 4 MiB analysis limit.", "error");
      }
    }

    async function analyse() {
      if (!selectedFile || busy) return;
      if (selectedFile.size > MAX_BYTES) {
        toast("The file exceeds the 4 MiB analysis limit.", "error");
        return;
      }
      busy = true;
      analyzeButton.disabled = true;
      analyzeButton.textContent = "Analysing…";
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
        toast(`Analysed ${analysis.file_name} · ${analysis.format_label}.`);
        await loadHistory();
        drawResult();
      } catch (error) {
        toast(error.message, "error");
      } finally {
        busy = false;
        analyzeButton.disabled = !selectedFile;
        analyzeButton.textContent = "Analyse file";
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
        toast("Re-select the original file to attach it as evidence.", "error");
        return;
      }
      try {
        await api(`/api/investigations/${analysis.investigation_id}/evidence`, {
          method: "POST",
          body: JSON.stringify({
            title: analysis.file_name,
            evidence_type: "file",
            description:
              "Attached from File Intelligence after static analysis. The file was not executed.",
            source_reference: "note://file-intelligence",
            original_name: selectedFile.name,
            content_base64: await fileToBase64(selectedFile),
          }),
        });
        toast("Evidence added with its own SHA-256 integrity record.");
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
            title: "No analysis selected",
            description:
              "Choose a bounded, authorized file. GARBAGE identifies structure and metadata without executing or unpacking it.",
          }),
        );
        return;
      }
      const findings = (analysis.findings || []).map((finding) =>
        el(
          "div",
          { class: `file-finding level-${finding.level}` },
          badge(titleCase(finding.level), finding.level === "warning" ? "warning" : finding.level === "note" ? "neutral" : "info"),
          el("span", {}, finding.message),
        ),
      );
      const indicators = analysis.indicators || [];
      const structure = analysis.structure || {};
      const metadataPairs = flattenMetadata(analysis.metadata || {});
      const hashRows = G.kvList([
        ["SHA-256", el("code", { class: "hash" }, analysis.hashes.sha256)],
        ["SHA-1", el("code", { class: "hash" }, analysis.hashes.sha1)],
        ["MD5", el("code", { class: "hash" }, analysis.hashes.md5)],
        ["Magic bytes", el("code", {}, analysis.magic_hex)],
        ["Entropy", `${analysis.entropy} / 8`],
      ]);

      const sections = [];
      if (structure.entries?.length) {
        sections.push(
          panel(
            {
              eyebrow: "ARCHIVE STRUCTURE",
              title: `Members (${structure.entry_count})`,
              caption: "Listed only; never extracted",
            },
            table({
              columns: [
                { label: "NAME", render: (row) => el("code", { class: "reference-code" }, row.name) },
                { label: "SIZE", render: (row) => formatBytes(row.size_bytes) },
                {
                  label: "RATIO",
                  className: "numeric-col",
                  render: (row) => (row.ratio === null ? "—" : `${row.ratio}×`),
                },
                {
                  label: "FLAGS",
                  render: (row) =>
                    el(
                      "div",
                      { class: "row-actions" },
                      row.path_traversal ? badge("Traversal", "warning") : null,
                      row.encrypted ? badge("Encrypted", "neutral") : null,
                    ),
                },
              ],
              rows: structure.entries,
              emptyMessage: "No members.",
            }),
          ),
        );
      }
      if (structure.header) {
        const header = structure.header;
        sections.push(
          panel(
            { eyebrow: "BINARY HEADER", title: analysis.format_label },
            G.kvList(
              Object.entries(header)
                .filter(([, value]) => value !== "" && value !== null && !Array.isArray(value))
                .map(([key, value]) => [titleCase(key), String(value)]),
            ),
            header.segments?.length
              ? table({
                  columns: [
                    { label: "SEGMENT", render: (row) => el("code", {}, row.name || "—") },
                    { label: "VM SIZE", render: (row) => formatBytes(row.vm_size || 0) },
                    { label: "FILE SIZE", render: (row) => formatBytes(row.file_size || 0) },
                  ],
                  rows: header.segments,
                })
              : null,
            header.architectures?.length
              ? table({
                  columns: [
                    { label: "ARCHITECTURE", render: (row) => row.cpu },
                    { label: "OFFSET", render: (row) => `0x${Number(row.offset).toString(16)}` },
                    { label: "SIZE", render: (row) => formatBytes(row.size) },
                  ],
                  rows: header.architectures,
                })
              : null,
          ),
        );
      }
      if (structure.sections?.length) {
        sections.push(
          panel(
            { eyebrow: "SECTIONS", title: `${structure.sections.length} parsed` },
            table({
              columns: [
                { label: "SECTION", render: (row) => el("code", {}, row.name || "—") },
                { label: "TYPE", render: (row) => String(row.type) },
                { label: "OFFSET", render: (row) => `0x${Number(row.offset).toString(16)}` },
                { label: "SIZE", render: (row) => formatBytes(row.size_bytes) },
              ],
              rows: structure.sections,
            }),
          ),
        );
      }
      if (structure.gzip) {
        sections.push(
          panel(
            { eyebrow: "GZIP STREAM", title: "Bounded decompression preview" },
            G.kvList(
              Object.entries(structure.gzip).map(([key, value]) => [
                titleCase(key),
                typeof value === "boolean" ? (value ? "Yes" : "No") : String(value),
              ]),
            ),
            el(
              "p",
              { class: "panel-note" },
              "The preview is capped at 1 MiB and is never written to disk.",
            ),
          ),
        );
      }
      if (structure.image) {
        sections.push(
          panel(
            { eyebrow: "IMAGE STRUCTURE", title: "Dimensions" },
            G.kvList(Object.entries(structure.image).map(([key, value]) => [titleCase(key), String(value)])),
          ),
        );
      }
      if (structure.version || structure.approximate_page_count !== undefined) {
        sections.push(
          panel(
            { eyebrow: "PDF STRUCTURE", title: "Document facts" },
            G.kvList(
              Object.entries(structure).map(([key, value]) => [titleCase(key), String(value)]),
            ),
          ),
        );
      }
      if (analysis.imports?.length) {
        sections.push(
          panel(
            { eyebrow: "STATIC IMPORTS", title: `${analysis.imports.length} referenced` },
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
            el("p", { class: "eyebrow" }, "STATIC ANALYSIS"),
            el("h2", {}, analysis.file_name),
            el(
              "div",
              { class: "case-meta" },
              badge(analysis.format_label, "info"),
              badge(analysis.media_type, "neutral"),
              el("span", {}, formatBytes(analysis.size_bytes)),
              analysis.investigation_id
                ? el("a", { class: "table-link", href: `#/investigations/${analysis.investigation_id}` }, "Open case")
                : el("span", {}, "Workspace history"),
              el("span", {}, formatDate(analysis.created_at, { time: true })),
            ),
          ),
          el(
            "div",
            { class: "row-actions" },
            analysis.investigation_id
              ? button("Attach as evidence", attachEvidence, { variant: "button-primary" })
              : null,
            button("Clear", () => {
              analysis = null;
              drawResult();
            }),
          ),
        ),
        el(
          "div",
          { class: "metric-grid compact-metrics" },
          metric({
            label: "FORMAT",
            value: analysis.format_label,
            foot: analysis.media_type,
            icon: "▧",
            tone: "blue",
          }),
          metric({
            label: "SIZE",
            value: formatBytes(analysis.size_bytes),
            foot: `${analysis.strings.count} strings sampled`,
            icon: "◫",
            tone: "violet",
          }),
          metric({
            label: "ENTROPY",
            value: String(analysis.entropy),
            foot: "Bits per byte",
            icon: "◈",
            tone: analysis.entropy >= 7.2 ? "amber" : "green",
          }),
          metric({
            label: "INDICATORS",
            value: String(indicators.length),
            foot: "Syntactic string matches",
            icon: "⌁",
            tone: "amber",
          }),
        ),
        panel({ eyebrow: "FINDINGS", title: "Static observations" }, ...findings),
        el(
          "div",
          { class: "detail-grid" },
          panel({ eyebrow: "INTEGRITY", title: "Digests" }, hashRows),
          panel(
            { eyebrow: "METADATA", title: "Extracted properties" },
            metadataPairs.length
              ? G.kvList(metadataPairs.slice(0, 80))
              : el("p", { class: "panel-empty" }, "No metadata extracted."),
          ),
        ),
        ...sections,
        panel(
          {
            eyebrow: "EMBEDDED INDICATORS",
            title: `Syntactic matches (${indicators.length})`,
            caption: "Not reputation-checked",
          },
          indicators.length
            ? table({
                columns: [
                  { label: "TYPE", render: (row) => badge(G.indicatorTypeLabel(row.type), "info") },
                  { label: "VALUE", render: (row) => el("code", { class: "reference-code" }, row.value) },
                  { label: "NOTE", render: (row) => row.note },
                ],
                rows: indicators,
              })
            : el("p", { class: "panel-empty" }, "No indicators matched the extracted strings."),
        ),
        panel(
          {
            eyebrow: "STRINGS",
            title: `Sample (${analysis.strings.count})`,
            caption: analysis.strings.truncated ? "truncated at limit" : "complete sample",
          },
          el(
            "pre",
            { class: "code-block strings-block" },
            analysis.strings.items
              .map((item) => `0x${item.offset.toString(16).padStart(6, "0")}  ${item.value}`)
              .join("\n") || "No printable strings.",
          ),
        ),
        panel(
          { eyebrow: "LIMITATIONS", title: "Analytical limits" },
          el(
            "ul",
            { class: "plain-list" },
            ...analysis.limitations.map((limitation) => el("li", {}, limitation)),
          ),
        ),
        el(
          "details",
          { class: "raw-details" },
          el("summary", {}, "Raw structure (JSON)"),
          el("pre", { class: "code-block" }, JSON.stringify(analysis.structure, null, 2)),
        ),
      );
    }

    function drawHistory() {
      historyHost.replaceChildren(
        panel(
          {
            eyebrow: "HISTORY",
            title: "Analysis records",
            caption: `${analyses.items.length} of ${analyses.total}`,
          },
          analyses.items.length
            ? table({
                columns: [
                  {
                    label: "FILE",
                    render: (row) =>
                      el(
                        "div",
                        { class: "cell-stack" },
                        el("strong", {}, row.file_name),
                        el("span", {}, row.format),
                      ),
                  },
                  { label: "SIZE", render: (row) => formatBytes(row.size_bytes) },
                  {
                    label: "SHA-256",
                    render: (row) => el("code", { class: "hash" }, row.sha256.slice(0, 16)),
                  },
                  {
                    label: "CASE",
                    render: (row) =>
                      row.investigation_id
                        ? el("a", { class: "table-link", href: `#/investigations/${row.investigation_id}` }, row.investigation_name || shortId(row.investigation_id))
                        : "Workspace",
                  },
                  { label: "ANALYSED", render: (row) => formatDate(row.created_at) },
                  { label: "", render: (row) => button("Open", () => openAnalysis(row.id)) },
                ],
                rows: analyses.items,
                emptyMessage: "No files have been analysed yet.",
                onRowClick: (row) => openAnalysis(row.id),
              })
            : el("p", { class: "panel-empty" }, "No history yet."),
        ),
      );
    }

    root.append(
      pageHeader({
        eyebrow: "FILE INTELLIGENCE",
        title: "Static file analysis",
        description:
          "Identify format, hashes, metadata, archive structure, binary headers and embedded indicators without execution.",
        actions: [button("↻ Refresh history", () => loadHistory())],
      }),
      el(
        "div",
        { class: "notice" },
        "Nothing is executed, emulated or automatically extracted. Analysis is bounded and read-only; " +
          "embedded indicators are syntactic matches, not reputation results.",
      ),
      el(
        "div",
        { class: "file-layout" },
        panel(
          { eyebrow: "INPUT", title: "Analyse a file" },
          dropZone,
          selectedLabel,
          el(
            "div",
            { class: "field" },
            el("label", {}, "Associate with investigation (optional)"),
            caseSelect,
          ),
          el("div", { class: "toolbar-end" }, analyzeButton),
        ),
        panel(
          { eyebrow: "SCOPE", title: "Supported static parsers" },
          el(
            "ul",
            { class: "plain-list" },
            el("li", {}, "PDF metadata, active-content declarations and approximate page count."),
            el("li", {}, "ZIP/OOXML/EPUB/JAR/APK central directories, traversal and macro flags."),
            el("li", {}, "TAR headers and GZIP bounded decompression preview."),
            el("li", {}, "PNG, JPEG, GIF, WebP and BMP dimensions."),
            el("li", {}, "ELF, PE and Mach-O headers, sections, imports and architecture."),
            el("li", {}, "ASCII/UTF-16 strings, entropy and SHA-256/SHA-1/MD5."),
          ),
          el(
            "p",
            { class: "panel-note" },
            "Deeper format support is tracked in the roadmap. Unsupported formats are identified, not guessed.",
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
