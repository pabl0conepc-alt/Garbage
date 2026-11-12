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
    if (retry) box.append(button("Retry", retry, { variant: "button-primary" }));
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
      placeholder: "Search names, identifiers or descriptions",
      "aria-label": "Search entities",
    });
    const typeFilter = el(
      "select",
      { class: "input compact-select", "aria-label": "Filter by entity type" },
      el("option", { value: "" }, "All categories"),
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
      count.textContent = `${rows.length} of ${data.total} shared records`;
      host.replaceChildren(
        table({
          columns: [
            { label: "CATEGORY", render: (row) => typeChip(row.entity_type) },
            { label: "NAME", render: (row) => el("strong", {}, row.name) },
            {
              label: "IDENTIFIER",
              render: (row) =>
                row.identifier
                  ? el("code", { class: "reference-code" }, row.identifier)
                  : el("span", { class: "muted" }, "—"),
            },
            { label: "COLLECTION", render: (row) => badge(titleCase(row.collection_basis), "neutral") },
            { label: "CONFIDENCE", render: (row) => badge(titleCase(row.confidence), "neutral") },
            { label: "VERIFICATION", render: (row) => statusBadge(row.verification_status) },
            {
              label: "CASES",
              className: "numeric-col",
              render: (row) => String(row.investigation_count ?? 0),
            },
            {
              label: "",
              render: (row) => button("Inspect", () => go("entities", row.id)),
            },
          ],
          rows,
          emptyMessage: data.items.length
            ? "No entities match these filters."
            : "No entities have been registered.",
          onRowClick: (row) => go("entities", row.id),
        }),
      );
    }

    root.append(
      pageHeader({
        eyebrow: "INTELLIGENCE REGISTRY",
        title: "Entities",
        description:
          "Canonical records shared across cases, the investigation board and the relationship graph.",
        actions: [
          button("＋ Register entity", () => G.entityDialog(), {
            variant: "button-primary",
          }),
        ],
      }),
      el(
        "div",
        { class: "metric-grid compact-metrics" },
        G.metric({
          label: "TOTAL RECORDS",
          value: String(data.total),
          foot: "Shared registry",
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
              foot: "Records",
              icon: "·",
              tone: "blue",
            }),
          ),
      ),
      panel(
        { eyebrow: "REGISTRY", title: "Shared entities", actions: [count] },
        el(
          "div",
          { class: "toolbar" },
          el("div", { class: "search-field" }, el("span", { "aria-hidden": "true" }, "⌕"), search),
          typeFilter,
        ),
        data.items.length
          ? host
          : emptyState({
              icon: "⬡",
              title: "No entities yet",
              description:
                "Register a domain, address, account, organization or file to start correlating.",
              action: button("Register entity", () => G.entityDialog(), {
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
          errorState("Entity unavailable", error.message, () => draw()),
        );
        G.setLoading(false);
        return;
      }
      G.setLoading(false);
      root.replaceChildren(
        pageHeader({
          eyebrow: "SHARED ENTITY",
          title: entity.name,
          description: entity.description || "No description recorded.",
          actions: [
            button("‹ All entities", () => go("entities")),
            button("Edit", () => G.entityDialog(entity, { onSaved: () => draw() })),
            button("Open graph", () => go("graph")),
            button(
              "Delete",
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
          el("span", {}, `Registered ${formatDate(entity.created_at, { time: true })}`),
        ),
        el(
          "div",
          { class: "detail-grid" },
          panel(
            { eyebrow: "PROPERTIES", title: "Record data" },
            G.kvList([
              ["Category", typeChip(entity.entity_type)],
              ["Identifier", entity.identifier ? el("code", { class: "reference-code" }, entity.identifier) : "—"],
              ["Collection basis", badge(titleCase(entity.collection_basis), "neutral")],
              ["Confidence", badge(titleCase(entity.confidence), "neutral")],
              ["Verification", statusBadge(entity.verification_status)],
              ["Source", referenceNode(entity.source_reference)],
              ["Created", formatDate(entity.created_at, { time: true })],
              ["Updated", formatDate(entity.updated_at, { time: true })],
            ]),
          ),
          panel(
            { eyebrow: "CASE LINKS", title: `Investigations (${entity.investigations.length})` },
            entity.investigations.length
              ? table({
                  columns: [
                    { label: "CASE", render: (row) => caseLink(row.id, row.name) },
                    { label: "STATUS", render: (row) => statusBadge(row.status) },
                    { label: "LINKED", render: (row) => formatDate(row.added_at) },
                  ],
                  rows: entity.investigations,
                  emptyMessage: "Not linked to a case.",
                })
              : el("p", { class: "panel-empty" }, "Not linked to a case."),
          ),
          panel(
            { eyebrow: "PROVENANCE", title: `Sources (${entity.sources.length})` },
            entity.sources.length
              ? table({
                  columns: [
                    { label: "TITLE", render: (row) => el("strong", {}, row.title) },
                    { label: "CATEGORY", render: (row) => badge(titleCase(row.category), "neutral") },
                    { label: "REFERENCE", render: (row) => referenceNode(row.reference) },
                  ],
                  rows: entity.sources,
                  emptyMessage: "No sources linked.",
                })
              : el("p", { class: "panel-empty" }, "No sources linked."),
          ),
          panel(
            {
              eyebrow: "RELATIONSHIP ENGINE",
              title: `Relationships (${entity.relationships.length})`,
              actions: [
                button(
                  "＋ Record relationship",
                  () =>
                    G.relationshipDialog({
                      entities: [entity],
                      onSaved: () => draw(),
                    }),
                  { disabled: true, title: "Record relationships from a case with at least two entities" },
                ),
              ],
            },
            entity.relationships.length
              ? table({
                  columns: [
                    {
                      label: "DIRECTION",
                      render: (row) =>
                        badge(row.direction === "outgoing" ? "Outgoing" : "Incoming", "neutral"),
                    },
                    {
                      label: "RELATED ENTITY",
                      render: (row) =>
                        el(
                          "div",
                          { class: "cell-stack" },
                          el("strong", {}, row.other_name),
                          el("span", {}, entityTypeLabel(row.other_type)),
                        ),
                    },
                    {
                      label: "TYPE",
                      render: (row) => el("span", { class: "relation-type" }, relationshipLabel(row.relationship_type)),
                    },
                    { label: "VERIFICATION", render: (row) => statusBadge(row.verification_status) },
                    { label: "CONTEXT", render: (row) => (row.investigation_id ? caseLink(row.investigation_id) : "Shared") },
                  ],
                  rows: entity.relationships,
                  emptyMessage: "No relationships recorded for this entity.",
                })
              : el("p", { class: "panel-empty" }, "No relationships recorded."),
          ),
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
      placeholder: "Filter observed indicators",
      "aria-label": "Filter indicators",
    });
    const typeFilter = el(
      "select",
      { class: "input compact-select", "aria-label": "Filter indicator type" },
      el("option", { value: "" }, "All indicator types"),
      ...G.INDICATOR_TYPES.map(([value, label]) => el("option", { value }, label)),
    );
    const countLabel = el("span", { class: "panel-caption" });
    const tableHost = el("div");
    const detailHost = el("div", { class: "indicator-detail" });

    async function load() {
      data = await api("/api/indicators?limit=1000");
    }

    await load();

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
            "Select an indicator to inspect its provenance and record an analytical assessment.",
          ),
        );
        return;
      }
      const status = el(
        "select",
        { class: "input", "aria-label": "Indicator verification status" },
        ...G.VERIFICATION_STATUSES.map(([value, label]) =>
          el("option", { value, selected: value === item.verification_status }, label),
        ),
      );
      const note = el("textarea", {
        class: "input",
        rows: 3,
        placeholder: "Assessment rationale and limitations",
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
              el("span", {}, origin.timestamp ? formatDate(origin.timestamp, { time: true }) : "No timestamp"),
            ),
            origin.source_reference
              ? el("div", { class: "record-meta" }, "Source: ", referenceNode(origin.source_reference))
              : null,
          ),
        );
      }
      detailHost.replaceChildren(
        panel(
          {
            eyebrow: "INDICATOR PROVENANCE",
            title: item.value,
            caption: `${indicatorTypeLabel(item.type)} · ${item.origin_count} origin${item.origin_count === 1 ? "" : "s"}`,
          },
          el(
            "div",
            { class: "indicator-summary" },
            G.kvList([
              ["Type", badge(indicatorTypeLabel(item.type), "info")],
              ["First seen", item.first_seen ? formatDate(item.first_seen, { time: true }) : "—"],
              ["Last seen", item.last_seen ? formatDate(item.last_seen, { time: true }) : "—"],
              [
                "Cases",
                item.investigations.length
                  ? item.investigations.map((entry) => caseLink(entry.id, entry.name))
                  : "Workspace only",
              ],
            ]),
          ),
          el("h3", { class: "subheading" }, "Assessment"),
          el("p", { class: "panel-note" }, "An indicator is not proof of malicious activity. " +
            "Record what the value supports and what remains unverified."),
          el("div", { class: "field" }, el("label", {}, "Verification status"), status),
          el("div", { class: "field" }, el("label", {}, "Assessment note"), note),
          el(
            "div",
            { class: "toolbar-end" },
            button(
              "Save assessment",
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
                  toast("Indicator assessment saved.");
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
          el("h3", { class: "subheading" }, `Provenance (${item.origins.length})`),
          item.origins.length ? provenance : el("p", { class: "panel-empty" }, "No provenance origins available."),
        ),
      );
    }

    function drawTable() {
      const rows = filtered();
      countLabel.textContent = `${rows.length} of ${data.total} indicators`;
      const columns = [
        { label: "TYPE", render: (row) => badge(indicatorTypeLabel(row.type), "info") },
        {
          label: "VALUE",
          render: (row) => el("code", { class: "indicator-value", title: row.value }, row.value),
        },
        { label: "ORIGINS", className: "numeric-col", render: (row) => String(row.origin_count) },
        {
          label: "CASES",
          className: "numeric-col",
          render: (row) => String(row.investigations.length),
        },
        {
          label: "FIRST SEEN",
          render: (row) => (row.first_seen ? formatDate(row.first_seen) : "—"),
        },
        { label: "ASSESSMENT", render: (row) => statusBadge(row.verification_status) },
      ];
      tableHost.replaceChildren(
        table({
          columns,
          rows,
          emptyMessage: data.total
            ? "No indicators match these filters."
            : "No indicators have been extracted from observations, entities or evidence.",
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
        eyebrow: "INDICATOR ENGINE",
        title: "Intelligence search",
        description:
          "Indicators extracted from observation text, registered entities and evidence digests, unified by exact value.",
        actions: [button("↻ Rebuild index", () => G.refreshView())],
      }),
      el(
        "div",
        { class: "metric-grid compact-metrics" },
        G.metric({
          label: "UNIQUE INDICATORS",
          value: String(data.total),
          foot: "Exact-value index",
          icon: "⌁",
          tone: "amber",
        }),
        G.metric({
          label: "EXTRACTION ORIGINS",
          value: String(data.extraction_count),
          foot: "Text matches + records",
          icon: "▤",
          tone: "blue",
        }),
        G.metric({
          label: "CORRELATIONS",
          value: String(data.correlation_count),
          foot: "Shared exact values",
          icon: "⟷",
          tone: "violet",
        }),
        G.metric({
          label: "ENGINE",
          value: data.indicator_engine ? "Online" : "Offline",
          foot: "Regex extraction",
          icon: "◈",
          tone: data.indicator_engine ? "green" : "amber",
        }),
      ),
      el(
        "div",
        { class: "indicator-layout" },
        panel(
          {
            eyebrow: "OBSERVED ARTIFACTS",
            title: "Indicator index",
            actions: [countLabel],
            className: "table-panel",
          },
          el(
            "div",
            { class: "toolbar" },
            el("div", { class: "search-field" }, el("span", { "aria-hidden": "true" }, "⌕"), search),
            typeFilter,
          ),
          data.truncated
            ? el(
                "p",
                { class: "inline-notice" },
                "The index reached its 5,000-observation analysis limit; refine the case or reduce data volume.",
              )
            : null,
          tableHost,
        ),
        detailHost,
      ),
    );

    drawTable();
    drawDetail(null);
    search.addEventListener("input", drawTable);
    typeFilter.addEventListener("change", drawTable);
  }

  /* ================================================================ */
  /* Evidence                                                          */
  /* ================================================================ */

  async function renderEvidence(root) {
    const data = await api("/api/evidence?limit=500");
    const search = el("input", {
      class: "input",
      type: "search",
      placeholder: "Search title, file name or SHA-256",
      "aria-label": "Search evidence",
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
      countLabel.textContent = `${rows.length} of ${data.total} records`;
      host.replaceChildren(
        table({
          columns: [
            {
              label: "EVIDENCE",
              render: (row) =>
                el(
                  "div",
                  { class: "cell-stack" },
                  el("strong", {}, row.title),
                  el("span", {}, row.original_name || row.evidence_type),
                ),
            },
            { label: "CASE", render: (row) => caseLink(row.investigation_id, row.investigation_name) },
            { label: "TYPE", render: (row) => badge(titleCase(row.evidence_type), "neutral") },
            {
              label: "SHA-256",
              render: (row) =>
                el("code", { class: "hash", title: row.sha256 }, row.sha256 ? row.sha256.slice(0, 16) : "—"),
            },
            { label: "SIZE", render: (row) => formatBytes(row.size_bytes) },
            {
              label: "INTEGRITY",
              render: (row) =>
                statusBadge(row.integrity_status === "unverified" ? "not-verified" : row.integrity_status),
            },
            { label: "RECORDED", render: (row) => formatDate(row.recorded_at) },
            {
              label: "ACTIONS",
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
                        "Download",
                      )
                    : null,
                  row.has_file
                    ? button("Verify", async () => {
                        try {
                          const result = await api(`/api/evidence/${row.id}/verify`, {
                            method: "POST",
                            body: JSON.stringify({}),
                          });
                          toast(
                            result.matches ? "Digest matches." : `Integrity ${result.integrity_status}.`,
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
            ? "No evidence matches this search."
            : "No evidence records exist.",
          onRowClick: (row) => go("investigations", row.investigation_id),
        }),
      );
    }

    root.append(
      pageHeader({
        eyebrow: "EVIDENCE MANAGER",
        title: "Evidence",
        description:
          "Hashed copies and analyst references. Originals are preserved; stored files are never executed.",
        actions: [
          button("＋ Add evidence", () => G.evidenceDialog(), {
            variant: "button-primary",
          }),
        ],
      }),
      panel(
        { eyebrow: "INTEGRITY STORE", title: "Evidence records", actions: [countLabel] },
        el(
          "div",
          { class: "toolbar" },
          el("div", { class: "search-field" }, el("span", { "aria-hidden": "true" }, "⌕"), search),
        ),
        data.items.length
          ? host
          : emptyState({
              icon: "▣",
              title: "No evidence records",
              description:
                "Attach a file (maximum 4 MiB) or record a reference with its hash.",
              action: button("Add evidence", () => G.evidenceDialog(), {
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
      placeholder: "Search titles, references or notes",
      "aria-label": "Search sources",
    });
    const categoryFilter = el(
      "select",
      { class: "input compact-select", "aria-label": "Filter source category" },
      el("option", { value: "" }, "All categories"),
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
      countLabel.textContent = `${rows.length} of ${data.total} sources`;
      host.replaceChildren(
        table({
          columns: [
            {
              label: "SOURCE",
              render: (row) =>
                el(
                  "div",
                  { class: "cell-stack" },
                  el("strong", {}, row.title),
                  el("span", {}, row.description || "No description"),
                ),
            },
            { label: "CATEGORY", render: (row) => badge(titleCase(row.category), "neutral") },
            { label: "REFERENCE", render: (row) => referenceNode(row.reference) },
            {
              label: "CASES",
              className: "numeric-col",
              render: (row) => String(row.investigation_count),
            },
            { label: "ACCESSED", render: (row) => formatDate(row.accessed_at) },
            { label: "VERIFICATION", render: (row) => statusBadge(row.verification_status) },
            { label: "", render: (row) => button("Inspect", () => go("sources", row.id)) },
          ],
          rows,
          emptyMessage: data.items.length
            ? "No sources match these filters."
            : "No sources have been registered.",
          onRowClick: (row) => go("sources", row.id),
        }),
      );
    }

    root.append(
      pageHeader({
        eyebrow: "PROVENANCE",
        title: "Sources",
        description:
          "Every observation, entity and report points back to a recorded source and access time.",
        actions: [
          button("＋ Register source", () => G.sourceDialog(), {
            variant: "button-primary",
          }),
        ],
      }),
      panel(
        { eyebrow: "SOURCE REGISTRY", title: "Consulted sources", actions: [countLabel] },
        el(
          "div",
          { class: "toolbar" },
          el("div", { class: "search-field" }, el("span", { "aria-hidden": "true" }, "⌕"), search),
          categoryFilter,
        ),
        data.items.length
          ? host
          : emptyState({
              icon: "⛁",
              title: "No sources registered",
              description: "Record a URL, document or analyst note before citing it in a case.",
              action: button("Register source", () => G.sourceDialog(), {
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
          errorState("Source unavailable", error.message, () => draw()),
        );
        G.setLoading(false);
        return;
      }
      G.setLoading(false);
      root.replaceChildren(
        pageHeader({
          eyebrow: "SOURCE RECORD",
          title: source.title,
          description: source.description || "No description recorded.",
          actions: [
            button("‹ All sources", () => go("sources")),
            button("Edit", () => G.sourceDialog(source, { onSaved: () => draw() })),
            button(
              "Delete",
              async () => {
                if (
                  !(await confirm({
                    title: "Delete source",
                    message: `Delete "${source.title}" from the shared registry?`,
                    confirmLabel: "Delete source",
                    danger: true,
                  }))
                )
                  return;
                try {
                  await api(`/api/sources/${source.id}`, { method: "DELETE" });
                  toast("Source deleted.");
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
          el("span", {}, `Accessed ${formatDate(source.accessed_at, { time: true })}`),
        ),
        el(
          "div",
          { class: "detail-grid" },
          panel(
            { eyebrow: "PROPERTIES", title: "Source data" },
            G.kvList([
              ["Reference", referenceNode(source.reference)],
              ["Category", badge(titleCase(source.category), "neutral")],
              ["Accessed", formatDate(source.accessed_at, { time: true })],
              ["Verification", statusBadge(source.verification_status)],
              ["Created", formatDate(source.created_at, { time: true })],
              ["Updated", formatDate(source.updated_at, { time: true })],
            ]),
          ),
          panel(
            { eyebrow: "CASE LINKS", title: `Investigations (${source.investigations.length})` },
            source.investigations.length
              ? table({
                  columns: [
                    { label: "CASE", render: (row) => caseLink(row.id, row.name) },
                    { label: "STATUS", render: (row) => statusBadge(row.status) },
                    { label: "LINKED", render: (row) => formatDate(row.added_at) },
                  ],
                  rows: source.investigations,
                  emptyMessage: "Not linked to a case.",
                })
              : el("p", { class: "panel-empty" }, "Not linked to a case."),
          ),
          panel(
            { eyebrow: "ENTITY LINKS", title: `Entities (${source.entities.length})` },
            source.entities.length
              ? table({
                  columns: [
                    { label: "ENTITY", render: (row) => el("strong", {}, row.name) },
                    { label: "CATEGORY", render: (row) => typeChip(row.entity_type) },
                    { label: "LINKED", render: (row) => formatDate(row.added_at) },
                  ],
                  rows: source.entities,
                  emptyMessage: "Not linked to an entity.",
                })
              : el("p", { class: "panel-empty" }, "Not linked to an entity."),
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
    ];
    root.append(
      pageHeader({
        eyebrow: "REPORT ENGINE",
        title: "Reports",
        description:
          "Every export is generated from the live case file. Inference and collection basis remain labelled.",
      }),
      el(
        "div",
        { class: "notice" },
        "Reports describe sourced observations, not confirmed facts. " +
          "Review the limitations section before distributing an export.",
      ),
      panel(
        { eyebrow: "CASE REPORTS", title: "Generate exports", caption: `${rows.length} cases` },
        rows.length
          ? table({
              columns: [
                {
                  label: "CASE",
                  render: (row) =>
                    el(
                      "div",
                      { class: "cell-stack" },
                      el("strong", {}, row.name),
                      el("span", {}, row.description || "No description"),
                    ),
                },
                { label: "STATUS", render: (row) => statusBadge(row.status) },
                {
                  label: "RECORDS",
                  render: (row) =>
                    `${row.observation_count} obs · ${row.entity_count} ent · ${row.evidence_count} evid`,
                },
                { label: "UPDATED", render: (row) => formatDate(row.updated_at) },
                {
                  label: "EXPORT",
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
                        "Print",
                      ),
                    ),
                },
              ],
              rows,
              emptyMessage: "Create a case before generating reports.",
            })
          : emptyState({
              icon: "▤",
              title: "No cases to report",
              description: "Report exports become available when an investigation exists.",
              action: button("Create investigation", () => G.newInvestigation(), {
                variant: "button-primary",
              }),
            }),
      ),
      panel(
        { eyebrow: "METHOD", title: "What the report engine includes" },
        el(
          "ul",
          { class: "plain-list" },
          el("li", {}, "Scope, case status and generation timestamp."),
          el("li", {}, "Sources with references and access times."),
          el("li", {}, "Observations labelled by collection basis."),
          el("li", {}, "Entities, relationships and their verification status."),
          el("li", {}, "Evidence digests, sizes and recorded integrity checks."),
          el("li", {}, "Extracted indicators and exact-value correlations."),
          el("li", {}, "Analytical limitations and the distinction between inference and confirmation."),
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
