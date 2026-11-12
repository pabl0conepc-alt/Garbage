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
    if (retry) box.append(button("Retry", retry, { variant: "button-primary" }));
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
        toast(`${module.name} ${target === "enabled" ? "enabled" : "disabled"}.`);
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
          eyebrow: category.toUpperCase(),
          title: `${category} modules`,
          caption: `${modules.length} registered`,
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
                  el("strong", {}, module.name),
                  module.core ? badge("Core", "info") : null,
                  badge(titleCase(module.state), module.state),
                ),
                el("p", {}, module.description),
                el(
                  "div",
                  { class: "module-meta" },
                  el("code", {}, module.module_id),
                  el("span", {}, `v${module.version}`),
                  module.updated_at
                    ? el("span", {}, `updated ${formatDate(module.updated_at)}`)
                    : null,
                ),
              ),
              el(
                "div",
                { class: "module-actions" },
                module.state === "planned"
                  ? badge("Not implemented", "warning")
                  : module.core
                    ? el("span", { class: "panel-note" }, "Required")
                    : button(
                        module.state === "enabled" ? "Disable" : "Enable",
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
        eyebrow: "MODULE REGISTRY",
        title: "Module manager",
        description:
          "Capability state is enforced by the API. Planned modules are not implemented and cannot be enabled.",
        actions: [button("↻ Refresh", () => G.refreshView())],
      }),
      el(
        "div",
        { class: "metric-grid compact-metrics" },
        metric({
          label: "ENABLED",
          value: String(data.enabled),
          foot: "Serving requests",
          icon: "◈",
          tone: "green",
        }),
        metric({
          label: "AVAILABLE",
          value: String(available),
          foot: "Ready to enable",
          icon: "○",
          tone: "blue",
        }),
        metric({
          label: "DISABLED",
          value: String(disabled),
          foot: "API returns 409",
          icon: "⊘",
          tone: "amber",
        }),
        metric({
          label: "PLANNED",
          value: String(data.planned),
          foot: "Documented, not built",
          icon: "◇",
          tone: "violet",
        }),
      ),
      el(
        "div",
        { class: "notice" },
        "Disabling a module changes the API and navigation immediately. " +
          "Core workflow modules cannot be disabled.",
      ),
      ...sections,
      panel(
        { eyebrow: "CONTRACTS", title: "Module interface" },
        el(
          "p",
          { class: "panel-note" },
          "Every module declares an identifier, name, description, category, version and state. " +
            "Planned modules remain visible so the gap between the interface and the backend is explicit.",
        ),
        el(
          "ul",
          { class: "plain-list" },
          el("li", {}, "Enabled: the API routes accept requests and the view is available."),
          el("li", {}, "Available / disabled: the implementation exists but the API rejects its routes."),
          el("li", {}, "Planned: no backend implementation; it cannot be enabled."),
        ),
      ),
    );
  }

  /* ================================================================ */
  /* Settings                                                          */
  /* ================================================================ */

  function settingsControl(entry, value) {
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
        toast("Settings saved.");
      } catch (error) {
        toast(error.message, "error");
      }
    }

    const runtimeEntries = system?.runtime ? Object.entries(system.runtime) : [];
    root.append(
      pageHeader({
        eyebrow: "WORKSPACE CONFIGURATION",
        title: "Settings",
        description:
          "Interface preferences are persisted in SQLite. Report and search defaults affect real outputs.",
        actions: [button("Save settings", save, { variant: "button-primary" })],
      }),
      el(
        "div",
        { class: "settings-layout" },
        panel(
          { eyebrow: "INTERFACE & DEFAULTS", title: "Preferences" },
          el("div", { class: "settings-fields" }, ...fields),
          el(
            "div",
            { class: "toolbar-end" },
            button("Save settings", save, { variant: "button-primary" }),
          ),
        ),
        el(
          "div",
          { class: "settings-side" },
          panel(
            { eyebrow: "RUNTIME", title: "System diagnostics" },
            system
              ? G.kvList([
                  ["Application version", system.version],
                  ["Schema version", String(system.schema_version)],
                  [
                    "Database",
                    `${system.database.name} · ${formatBytes(system.database.size_bytes)}`,
                  ],
                  [
                    "Storage",
                    system.database.file_backed ? "File-backed SQLite" : "In-memory",
                  ],
                  ["Python", system.runtime?.python || "—"],
                  ["Platform", system.runtime?.platform || "—"],
                  [
                    "SQLite",
                    system.runtime?.sqlite_version
                      ? String(system.runtime.sqlite_version)
                      : "—",
                  ],
                  [
                    "FTS5",
                    system.runtime?.fts5 ? "Available" : "Unavailable",
                  ],
                ])
              : el("p", { class: "panel-empty" }, "System diagnostics are unavailable."),
          ),
          panel(
            { eyebrow: "NATIVE ENGINE", title: "Optional accelerators" },
            system?.native
              ? G.kvList([
                  [
                    "C file intelligence",
                    system.native.engines.c_file_intelligence
                      ? "Loaded"
                      : "Python fallback",
                  ],
                  [
                    "C++ graph metrics",
                    system.native.engines.cpp_graph_metrics
                      ? "Loaded"
                      : "Python fallback",
                  ],
                  [
                    "Rust similarity",
                    system.native.engines.rust_similarity
                      ? "Loaded"
                      : "Python fallback",
                  ],
                  ["Build directory", system.native.directory],
                ])
              : el("p", { class: "panel-empty" }, "Native status is unavailable."),
          ),
          panel(
            { eyebrow: "COUNTS", title: "Stored records" },
            system
              ? G.kvList(
                  Object.entries(system.counts).map(([key, value]) => [
                    titleCase(key),
                    String(value),
                  ]),
                )
              : el("p", { class: "panel-empty" }, "No diagnostics."),
          ),
          panel(
            { eyebrow: "EXTENSIONS", title: "Integrations" },
            system && system.integrations.length
              ? el(
                  "ul",
                  { class: "plain-list" },
                  ...system.integrations.map((integration) =>
                    el(
                      "li",
                      {},
                      el("strong", {}, integration.module_id),
                      ` · ${integration.mode}`,
                    ),
                  ),
                )
              : el("p", { class: "panel-empty" }, "No integrations registered."),
          ),
          runtimeEntries.length
            ? panel(
                { eyebrow: "DIAGNOSTIC DETAIL", title: "Runtime fields" },
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
            { eyebrow: "MIGRATIONS", title: "Schema history", caption: `${system.migrations.length} applied` },
            table({
              columns: [
                { label: "VERSION", className: "numeric-col", render: (row) => String(row.version) },
                { label: "DESCRIPTION", render: (row) => row.description },
                { label: "APPLIED", render: (row) => formatDate(row.applied_at, { time: true }) },
              ],
              rows: system.migrations,
              emptyMessage: "No migrations recorded.",
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
          eyebrow: "THREAT INTELLIGENCE",
          title: "CISA KEV",
          description:
            "Known Exploited Vulnerabilities metadata from the public CISA catalog.",
        }),
        error && error.status === 404
          ? panel(
              { eyebrow: "CONNECTOR", title: "No local KEV snapshot" },
              emptyState({
                icon: "☰",
                title: "Refresh the public catalog",
                description:
                  "The KEV cache is empty. GARBAGE performs one explicit HTTPS request to CISA and stores a validated, hashed snapshot. No background polling occurs.",
                action: button(
                  "Refresh CISA KEV",
                  () => refresh(root, true),
                  { variant: "button-primary" },
                ),
              }),
            )
          : panel(
              { eyebrow: "CONNECTOR", title: "KEV connector unavailable" },
              errorState(
                "CISA KEV request failed",
                error?.message || "The connector did not return data.",
                () => G.refreshView(),
              ),
            ),
      );
      return;
    }

    const search = el("input", {
      class: "input",
      type: "search",
      placeholder: "Filter by CVE, vendor, product or description",
      "aria-label": "Filter CISA KEV entries",
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
              label: "PRODUCT",
              render: (row) =>
                el(
                  "div",
                  { class: "cell-stack" },
                  el("strong", {}, row.product),
                  el("span", {}, row.vendor_project),
                ),
            },
            {
              label: "VULNERABILITY",
              render: (row) =>
                el(
                  "div",
                  { class: "cell-stack" },
                  el("span", {}, row.vulnerability_name),
                  el("span", { class: "muted" }, row.short_description),
                ),
            },
            { label: "ADDED", render: (row) => formatDate(row.date_added) },
            { label: "DUE", render: (row) => formatDate(row.due_date) },
            {
              label: "RANSOMWARE",
              render: (row) =>
                badge(titleCase(row.ransomware_use || "unknown"), row.ransomware_use === "Known" ? "danger" : "neutral"),
            },
          ],
          rows,
          emptyMessage: "No KEV entries match this filter.",
        }),
      );
    }

    root.append(
      pageHeader({
        eyebrow: "THREAT INTELLIGENCE",
        title: "CISA KEV",
        description:
          "Vendor and product exploitation metadata, shown exactly as published by CISA. Absence from KEV does not imply safety.",
        actions: [button("↻ Refresh catalog", () => refresh(root, false))],
      }),
      el(
        "div",
        { class: "metric-grid compact-metrics" },
        metric({
          label: "CATALOG ENTRIES",
          value: String(data.count),
          foot: "Validated snapshot",
          icon: "☰",
          tone: "amber",
        }),
        metric({
          label: "MATCHED",
          value: String(data.matched),
          foot: "Local filter",
          icon: "⌕",
          tone: "blue",
        }),
        metric({
          label: "CATALOG VERSION",
          value: data.catalog_version,
          foot: "CISA source",
          icon: "◈",
          tone: "violet",
        }),
        metric({
          label: "SNAPSHOT",
          value: formatDate(data.fetched_at),
          foot: "Explicit refresh",
          icon: "◷",
          tone: "green",
        }),
      ),
      panel(
        { eyebrow: "PROVENANCE", title: "Snapshot integrity" },
        G.kvList([
          ["Source", el("a", { class: "reference-link", href: data.source_url, target: "_blank", rel: "noopener noreferrer" }, data.source_url)],
          ["Source updated", formatDate(data.source_updated_at, { time: true })],
          ["Fetched", formatDate(data.fetched_at, { time: true })],
          ["SHA-256", el("code", { class: "hash" }, data.sha256)],
        ]),
      ),
      panel(
        { eyebrow: "VULNERABILITY CATALOG", title: "Known exploited vulnerabilities", actions: [el("span", { class: "panel-caption" }, `${data.items.length} shown`)] },
        el("div", { class: "toolbar" }, el("div", { class: "search-field" }, el("span", { "aria-hidden": "true" }, "⌕"), search)),
        data.items.length ? host : emptyState({ icon: "☰", title: "No entries in the snapshot" }),
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
      toast(`CISA KEV refreshed: ${result.count} entries.`);
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
