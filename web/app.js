"use strict";

/* GARBAGE workstation core: API client, components, router and search. */

const G = (window.GARBAGE = window.GARBAGE || {});
G.views = G.views || {};

const statusNode = document.querySelector("#status");
const loadingNode = document.querySelector("#loading-state");
const viewRoot = document.querySelector("#view-root");
const searchDialog = document.querySelector("#search-dialog");
const searchInput = document.querySelector("#global-search-input");
const searchResults = document.querySelector("#global-search-results");
const searchButton = document.querySelector("#global-search-button");
const newInvestigationButton = document.querySelector("#new-investigation-button");

G.NAV = [
  {
    label: "WORKSPACE",
    items: [
      { view: "overview", label: "Overview", icon: "◫" },
      { view: "investigations", label: "Investigations", icon: "⌕", module: "investigations" },
      { view: "activity", label: "Activity timeline", icon: "◷", module: "activity-log" },
    ],
  },
  {
    label: "INTELLIGENCE",
    items: [
      { view: "entities", label: "Entity intelligence", icon: "⬡", module: "entities" },
      { view: "indicators", label: "IOC analyzer", icon: "⌁", module: "indicator-engine" },
      { view: "files", label: "File intelligence", icon: "▧", module: "file-intelligence" },
    ],
  },
  {
    label: "ANALYSIS",
    items: [
      { view: "board", label: "Investigation board", icon: "▦", module: "investigation-board" },
      { view: "graph", label: "Relationship graph", icon: "⟷", module: "relationship-graph" },
    ],
  },
  {
    label: "EVIDENCE",
    items: [
      { view: "evidence", label: "Evidence manager", icon: "▤", module: "evidence" },
      { view: "sources", label: "Source manager", icon: "⛁", module: "source-manager" },
    ],
  },
  {
    label: "THREAT INTELLIGENCE",
    items: [
      { view: "kev", label: "CISA KEV", icon: "☰", module: "cisa-kev" },
    ],
  },
  {
    label: "OUTPUT",
    items: [
      { view: "reports", label: "Report center", icon: "⎙", module: "report-center" },
    ],
  },
  {
    label: "SYSTEM",
    items: [
      { view: "modules", label: "Module manager", icon: "⊞", module: "module-manager" },
      { view: "settings", label: "Settings", icon: "⚙", module: "settings" },
    ],
  },
];

G.VIEW_LABELS = Object.fromEntries(
  G.NAV.flatMap((group) => group.items.map((item) => [item.view, item.label])),
);

G.ENTITY_TYPES = [
  ["person", "Person"],
  ["username", "Username"],
  ["profile", "Public profile"],
  ["domain", "Domain"],
  ["ipv4", "IPv4 address"],
  ["ipv6", "IPv6 address"],
  ["email", "Email"],
  ["organization", "Organization"],
  ["file", "File"],
  ["image", "Image"],
  ["hash", "Hash"],
  ["url", "URL"],
  ["ioc", "Indicator"],
  ["other", "Other"],
];
G.ENTITY_TYPE_LABELS = Object.fromEntries(G.ENTITY_TYPES);
G.RELATIONSHIP_TYPES = [
  ["associated-with", "Associated with"],
  ["belongs-to", "Belongs to"],
  ["references", "References"],
  ["hosted-on", "Hosted on"],
  ["derived-from", "Derived from"],
  ["related-to", "Related to"],
  ["connected-to", "Connected to"],
  ["communicates-with", "Communicates with"],
  ["owns", "Owns"],
  ["uses", "Uses"],
];
G.RELATIONSHIP_TYPE_LABELS = Object.fromEntries(G.RELATIONSHIP_TYPES);
G.COLLECTION_BASES = [
  ["public", "Public"],
  ["authorized", "Authorized"],
  ["user-provided", "User-provided"],
];
G.CONFIDENCE_LEVELS = [
  ["unconfirmed", "Unconfirmed"],
  ["possible", "Possible"],
  ["probable", "Probable"],
  ["confirmed", "Confirmed"],
];
G.VERIFICATION_STATUSES = [
  ["not-verified", "Not verified"],
  ["verified", "Verified"],
  ["disputed", "Disputed"],
  ["false-positive", "False positive"],
];
G.SOURCE_CATEGORIES = [
  ["website", "Website"],
  ["documentation", "Documentation"],
  ["api", "API"],
  ["public-database", "Public database"],
  ["report", "Report"],
  ["file", "File"],
  ["other", "Other"],
];
G.EVIDENCE_TYPES = [
  ["file", "File"],
  ["document", "Document"],
  ["image", "Image"],
  ["hash", "Hash reference"],
  ["note", "Analyst note"],
  ["url", "URL reference"],
];
G.INDICATOR_TYPE_LABELS = {
  ipv4: "IPv4 address",
  ipv6: "IPv6 address",
  domain: "Domain",
  url: "URL",
  email: "Email",
  md5: "MD5",
  sha1: "SHA-1",
  sha256: "SHA-256",
  username: "Username",
};
G.INDICATOR_TYPES = Object.entries(G.INDICATOR_TYPE_LABELS);

G.state = {
  modules: null,
  settings: null,
  investigations: [],
  currentView: "",
  currentParams: [],
  searchIndex: -1,
  pendingIndicatorSearch: "",
};
G.cleanupFns = [];

/* ------------------------------------------------------------------ */
/* DOM helpers                                                        */
/* ------------------------------------------------------------------ */

function append(parent, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    parent.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
}

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key === "dataset") Object.assign(node.dataset, value);
    else if (key === "value") node.value = value;
    else if (key === "checked") node.checked = Boolean(value);
    else if (key === "hidden") node.hidden = Boolean(value);
    else if (key === "disabled") node.disabled = Boolean(value);
    else if (key.startsWith("on") && typeof value === "function") {
      node.addEventListener(key.slice(2).toLowerCase(), value);
    } else if (value === true) node.setAttribute(key, "");
    else node.setAttribute(key, String(value));
  }
  append(node, children);
  return node;
}

function svgEl(tag, attrs = {}, ...children) {
  const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "text") node.textContent = value;
    else if (key === "class") node.setAttribute("class", value);
    else node.setAttribute(key, String(value));
  }
  append(node, children);
  return node;
}

G.el = el;
G.svgEl = svgEl;

/* ------------------------------------------------------------------ */
/* Formatting                                                         */
/* ------------------------------------------------------------------ */

function formatDate(value, options = {}) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: options.dateStyle || "medium",
    ...(options.time ? { timeStyle: "short" } : {}),
    timeZone: "UTC",
  }).format(date);
}

function relativeTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  const seconds = Math.round((Date.now() - date.getTime()) / 1000);
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} h ago`;
  if (seconds < 172800) return "yesterday";
  if (seconds < 604800) return `${Math.floor(seconds / 86400)} days ago`;
  return formatDate(value);
}

function formatBytes(value) {
  const bytes = Number(value) || 0;
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MiB`;
}

function shortId(value) {
  if (!value) return "—";
  return String(value).slice(0, 8);
}

function titleCase(value) {
  return String(value || "")
    .replace(/[-_]/g, " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function entityTypeLabel(value) {
  return G.ENTITY_TYPE_LABELS[value] || titleCase(value);
}

function relationshipLabel(value) {
  return G.RELATIONSHIP_TYPE_LABELS[value] || titleCase(value);
}

function indicatorTypeLabel(value) {
  return G.INDICATOR_TYPE_LABELS[value] || titleCase(value);
}

G.formatDate = formatDate;
G.relativeTime = relativeTime;
G.formatBytes = formatBytes;
G.shortId = shortId;
G.titleCase = titleCase;
G.entityTypeLabel = entityTypeLabel;
G.relationshipLabel = relationshipLabel;
G.indicatorTypeLabel = indicatorTypeLabel;

/* ------------------------------------------------------------------ */
/* API and feedback                                                   */
/* ------------------------------------------------------------------ */

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (options.body) headers["Content-Type"] = "application/json";
  const response = await fetch(path, { ...options, headers });
  const contentType = response.headers.get("Content-Type") || "";
  let payload = null;
  if (contentType.includes("application/json")) {
    payload = await response.json();
  }
  if (!response.ok) {
    const error = new Error(payload?.error || `Request failed (${response.status})`);
    error.status = response.status;
    error.code = payload?.code;
    throw error;
  }
  return payload;
}

let toastTimer = null;
function toast(message, tone = "success") {
  statusNode.textContent = message;
  statusNode.dataset.tone = tone;
  statusNode.classList.add("is-visible");
  clearTimeout(toastTimer);
  toastTimer = window.setTimeout(
    () => statusNode.classList.remove("is-visible"),
    tone === "error" ? 9000 : 4200,
  );
}

function setLoading(loading) {
  loadingNode.classList.toggle("is-loading", loading);
  loadingNode.setAttribute("aria-hidden", String(!loading));
}

function moduleEnabled(moduleId) {
  if (!moduleId) return true;
  const item = G.state.modules?.items?.find((entry) => entry.module_id === moduleId);
  if (!item) return true;
  return item.state === "enabled";
}

function applySettings(values = G.state.settings) {
  if (!values) return;
  document.documentElement.dataset.theme = values["interface.theme"] || "dark";
  document.documentElement.dataset.density = values["interface.density"] || "comfortable";
  document.documentElement.dataset.reduceMotion =
    values["interface.reduce_motion"] === "true" ? "true" : "false";
}

G.api = api;
G.toast = toast;
G.setLoading = setLoading;
G.moduleEnabled = moduleEnabled;
G.applySettings = applySettings;

/* ------------------------------------------------------------------ */
/* Shared components                                                  */
/* ------------------------------------------------------------------ */

const STATUS_TONES = {
  open: "success",
  closed: "neutral",
  cancelled: "danger",
  enabled: "success",
  disabled: "neutral",
  available: "info",
  planned: "warning",
  error: "danger",
  verified: "success",
  "not-verified": "neutral",
  disputed: "warning",
  "false-positive": "danger",
  unconfirmed: "neutral",
  possible: "info",
  probable: "warning",
  confirmed: "success",
};

function badge(text, tone = "neutral") {
  return el("span", { class: `badge badge-${tone}` }, text);
}

function statusBadge(value) {
  return badge(titleCase(value), STATUS_TONES[value] || "neutral");
}

function pageHeader({ eyebrow, title, description, actions = [] }) {
  return el(
    "div",
    { class: "page-heading" },
    el(
      "div",
      { class: "page-heading-copy" },
      eyebrow ? el("p", { class: "eyebrow" }, eyebrow) : null,
      el("h1", {}, title),
      description ? el("p", { class: "page-description" }, description) : null,
    ),
    actions.length ? el("div", { class: "page-actions" }, actions) : null,
  );
}

function panel({ eyebrow, title, caption, actions = [], className = "" }, ...children) {
  const heading =
    title || eyebrow || actions.length
      ? el(
          "div",
          { class: "panel-heading" },
          el(
            "div",
            {},
            eyebrow ? el("p", { class: "eyebrow" }, eyebrow) : null,
            title ? el("h2", {}, title) : null,
          ),
          el(
            "div",
            { class: "panel-heading-side" },
            caption ? el("span", { class: "panel-caption" }, caption) : null,
            actions.length ? el("div", { class: "panel-actions" }, actions) : null,
          ),
        )
      : null;
  return el(
    "section",
    { class: `panel ${className}`.trim() },
    heading,
    el("div", { class: "panel-body" }, children),
  );
}

function metric({ label, value, foot, icon, tone = "blue" }) {
  return el(
    "article",
    { class: "metric-card" },
    el(
      "div",
      { class: "metric-top" },
      el("span", {}, label),
      icon ? el("span", { class: `metric-icon tone-${tone}`, "aria-hidden": "true" }, icon) : null,
    ),
    el("div", { class: "metric-value" }, value),
    foot ? el("div", { class: "metric-foot" }, foot) : null,
  );
}

function emptyState({ icon = "◫", title, description, action = null }) {
  return el(
    "div",
    { class: "empty-state" },
    el("span", { class: "empty-icon", "aria-hidden": "true" }, icon),
    el("h3", {}, title),
    description ? el("p", {}, description) : null,
    action || null,
  );
}

function errorState({ title = "Unable to load this view", message, retry = null }) {
  return el(
    "div",
    { class: "error-state", role: "alert" },
    el("span", { class: "error-icon", "aria-hidden": "true" }, "!"),
    el("h3", {}, title),
    el("p", {}, message || "The local API returned an error."),
    retry
      ? el("button", { class: "button button-secondary", type: "button", onClick: retry }, "Try again")
      : null,
  );
}

function dataTable({ columns, rows, emptyMessage = "No records.", onRowClick = null }) {
  const table = el("table", { class: "data-table" });
  table.append(
    el(
      "thead",
      {},
      el(
        "tr",
        {},
        ...columns.map((column) =>
          el("th", { scope: "col", class: column.className || "" }, column.label),
        ),
      ),
    ),
  );
  const tbody = el("tbody");
  if (!rows.length) {
    tbody.append(
      el(
        "tr",
        {},
        el("td", { class: "table-empty", colspan: String(columns.length) }, emptyMessage),
      ),
    );
  }
  for (const row of rows) {
    const tr = el("tr");
    if (onRowClick) {
      tr.classList.add("is-clickable");
      tr.tabIndex = 0;
      tr.addEventListener("click", (event) => {
        if (event.target.closest("button, a, input, select")) return;
        onRowClick(row);
      });
      tr.addEventListener("keydown", (event) => {
        if (event.key === "Enter" && event.target === tr) onRowClick(row);
      });
    }
    for (const column of columns) {
      const td = el("td", { class: column.cellClass || "" });
      append(td, [column.render(row)]);
      tr.append(td);
    }
    tbody.append(tr);
  }
  table.append(tbody);
  return el("div", { class: "table-scroll" }, table);
}

function tabs({ items, active, onSelect }) {
  return el(
    "div",
    { class: "tabs", role: "tablist" },
    ...items.map((item) =>
      el(
        "button",
        {
          class: `tab${item.key === active ? " is-active" : ""}`,
          type: "button",
          role: "tab",
          "aria-selected": String(item.key === active),
          onClick: () => onSelect(item.key),
        },
        item.label,
        item.count !== undefined && item.count !== null
          ? el("span", { class: "tab-count" }, String(item.count))
          : null,
      ),
    ),
  );
}

function sectionHeading(title, caption = null) {
  return el(
    "div",
    { class: "subsection-heading" },
    el("h3", {}, title),
    caption ? el("span", { class: "panel-caption" }, caption) : null,
  );
}

function kvList(pairs) {
  const dl = el("dl", { class: "kv-list" });
  for (const [key, value] of pairs) {
    if (value === null || value === undefined || value === "") continue;
    dl.append(el("dt", {}, key), el("dd", {}, value));
  }
  return dl;
}

function loadingBlock(message = "Loading…") {
  return el("div", { class: "loading-block", role: "status" }, el("span", { class: "spinner", "aria-hidden": "true" }), message);
}

function inlineError(message) {
  return el("p", { class: "inline-error", role: "alert" }, message);
}

G.pageHeader = pageHeader;
G.panel = panel;
G.metric = metric;
G.badge = badge;
G.statusBadge = statusBadge;
G.emptyState = emptyState;
G.errorState = errorState;
G.table = dataTable;
G.tabs = tabs;
G.sectionHeading = sectionHeading;
G.kvList = kvList;
G.loadingBlock = loadingBlock;
G.inlineError = inlineError;
G.titleCase = titleCase;

/* ------------------------------------------------------------------ */
/* Dialogs                                                            */
/* ------------------------------------------------------------------ */

function fieldLabel(field) {
  return el(
    "span",
    { class: "field-label" },
    field.label,
    field.optional ? el("span", { class: "optional-label" }, "OPTIONAL") : null,
  );
}

function fieldControl(field) {
  if (field.type === "textarea") {
    const textarea = el("textarea", {
      name: field.name,
      rows: field.rows || 4,
      placeholder: field.placeholder || "",
      maxlength: field.maxlength || "",
    });
    textarea.value = field.value || "";
    return textarea;
  }
  if (field.type === "select") {
    const select = el("select", { name: field.name });
    for (const option of field.options || []) {
      const value = Array.isArray(option) ? option[0] : option;
      const label = Array.isArray(option) ? option[1] : titleCase(option);
      select.append(el("option", { value }, label));
    }
    select.value = field.value !== undefined ? String(field.value) : "";
    return select;
  }
  if (field.type === "checkbox") {
    return el("input", {
      type: "checkbox",
      name: field.name,
      checked: Boolean(field.value),
    });
  }
  if (field.type === "file") {
    return el("input", {
      type: "file",
      name: field.name,
      accept: field.accept || "",
    });
  }
  const input = el("input", {
    type: field.type || "text",
    name: field.name,
    placeholder: field.placeholder || "",
    maxlength: field.maxlength || "",
    min: field.min !== undefined ? field.min : "",
    max: field.max !== undefined ? field.max : "",
    step: field.step || "",
    autocomplete: "off",
  });
  input.value = field.value !== undefined && field.value !== null ? String(field.value) : "";
  return input;
}

function fieldNode(field) {
  if (field.type === "checkbox") {
    return el(
      "label",
      { class: "check-field" },
      fieldControl(field),
      el("span", {}, field.label),
      field.hint ? el("span", { class: "field-hint" }, field.hint) : null,
    );
  }
  return el(
    "label",
    { class: "field" },
    fieldLabel(field),
    fieldControl(field),
    field.hint ? el("span", { class: "field-hint" }, field.hint) : null,
  );
}

function readForm(form, fields) {
  const values = {};
  for (const field of fields) {
    const control = form.elements.namedItem(field.name);
    if (!control) continue;
    if (field.type === "checkbox") values[field.name] = Boolean(control.checked);
    else if (field.type === "file") values[field.name] = control.files?.[0] || null;
    else values[field.name] = control.value;
  }
  return values;
}

function formDialog({
  eyebrow = "",
  title,
  description = "",
  fields = [],
  submitLabel = "Save",
  danger = false,
  onSubmit,
}) {
  return new Promise((resolve) => {
    const errorNode = el("p", { class: "form-error", role: "alert", hidden: true });
    const submitButton = el(
      "button",
      { class: `button ${danger ? "button-danger" : "button-primary"}`, type: "submit" },
      submitLabel,
    );
    const form = el(
      "form",
      { class: "dialog-form", novalidate: true },
      el(
        "div",
        { class: "dialog-heading" },
        el(
          "div",
          {},
          eyebrow ? el("p", { class: "eyebrow" }, eyebrow) : null,
          el("h2", {}, title),
          description ? el("p", { class: "dialog-description" }, description) : null,
        ),
        el(
          "button",
          {
            class: "icon-button",
            type: "button",
            "aria-label": "Close dialog",
            onClick: () => dialog.close("cancel"),
          },
          "×",
        ),
      ),
      ...fields.map(fieldNode),
      errorNode,
      el(
        "div",
        { class: "dialog-actions" },
        el(
          "button",
          {
            class: "button button-secondary",
            type: "button",
            onClick: () => dialog.close("cancel"),
          },
          "Cancel",
        ),
        submitButton,
      ),
    );
    const dialog = el("dialog", { class: "app-dialog", "aria-label": title }, form);
    document.body.append(dialog);
    dialog.addEventListener("close", () => {
      dialog.remove();
      resolve(dialog.returnValue === "submitted");
    });
    dialog.addEventListener("click", (event) => {
      if (event.target === dialog) dialog.close("cancel");
    });
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      errorNode.hidden = true;
      const values = readForm(form, fields);
      const missing = fields.filter((field) => {
        if (!field.required) return false;
        if (field.type === "checkbox") return !values[field.name];
        if (field.type === "file") return !values[field.name];
        return !String(values[field.name] ?? "").trim();
      });
      if (missing.length) {
        errorNode.textContent = `Required: ${missing.map((field) => field.label).join(", ")}`;
        errorNode.hidden = false;
        return;
      }
      submitButton.disabled = true;
      try {
        await onSubmit?.(values, form, dialog);
        dialog.close("submitted");
      } catch (error) {
        errorNode.textContent = error.message;
        errorNode.hidden = false;
      } finally {
        submitButton.disabled = false;
      }
    });
    dialog.showModal();
  });
}

function confirmDialog({ title, message, confirmLabel = "Confirm", danger = false }) {
  return new Promise((resolve) => {
    let confirmed = false;
    const dialog = el(
      "dialog",
      { class: "app-dialog confirm-dialog", "aria-label": title },
      el(
        "div",
        { class: "dialog-form" },
        el(
          "div",
          { class: "dialog-heading" },
          el("div", {}, el("p", { class: "eyebrow" }, "CONFIRM ACTION"), el("h2", {}, title)),
        ),
        el("p", { class: "confirm-message" }, message),
        el(
          "div",
          { class: "dialog-actions" },
          el(
            "button",
            { class: "button button-secondary", type: "button", onClick: () => dialog.close() },
            "Cancel",
          ),
          el(
            "button",
            {
              class: `button ${danger ? "button-danger" : "button-primary"}`,
              type: "button",
              onClick: () => {
                confirmed = true;
                dialog.close();
              },
            },
            confirmLabel,
          ),
        ),
      ),
    );
    document.body.append(dialog);
    dialog.addEventListener("close", () => {
      dialog.remove();
      resolve(confirmed);
    });
    dialog.showModal();
  });
}

G.formDialog = formDialog;
G.confirm = confirmDialog;

/* ------------------------------------------------------------------ */
/* Navigation                                                         */
/* ------------------------------------------------------------------ */

function renderNav() {
  const container = document.querySelector("#nav-groups");
  container.replaceChildren();
  for (const group of G.NAV) {
    const items = group.items.filter((item) => moduleEnabled(item.module));
    if (!items.length) continue;
    const section = el("section", { class: "nav-section" });
    section.append(el("div", { class: "nav-section-label" }, group.label));
    for (const item of items) {
      section.append(
        el(
          "a",
          { class: "nav-link", href: `#/${item.view}`, dataset: { view: item.view } },
          el("span", { class: "nav-icon", "aria-hidden": "true" }, item.icon),
          el("span", { class: "nav-label" }, item.label),
        ),
      );
    }
    container.append(section);
  }
}

function renderShellState() {
  renderNav();
  if (newInvestigationButton) {
    newInvestigationButton.hidden = !moduleEnabled("investigations");
  }
  if (searchButton) {
    searchButton.hidden = !moduleEnabled("global-search");
  }
}

function markActiveNav(view) {
  document.querySelectorAll(".nav-link").forEach((link) => {
    const active = link.dataset.view === view;
    link.classList.toggle("is-active", active);
    if (active) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  });
}

function setBreadcrumb(view) {
  const label = G.VIEW_LABELS[view] || titleCase(view);
  document.querySelector("#page-breadcrumb").textContent = label;
}

function go(...parts) {
  const target = `#/${parts.filter(Boolean).join("/")}`;
  if (location.hash === target) route();
  else location.hash = target;
}

async function route() {
  if (!G.views) return;
  for (const cleanup of G.cleanupFns.splice(0)) {
    try {
      cleanup();
    } catch {
      /* cleanup is best effort */
    }
  }
  const raw = location.hash.replace(/^#\/?/, "");
  const segments = raw.split("/").filter(Boolean);
  const candidate = segments[0] || "overview";
  const view = G.views[candidate] ? candidate : "overview";
  const params = segments.slice(1);
  G.state.currentView = view;
  G.state.currentParams = params;
  markActiveNav(view);
  setBreadcrumb(view);
  setLoading(true);
  viewRoot.replaceChildren();
  try {
    await G.views[view](viewRoot, params);
  } catch (error) {
    viewRoot.replaceChildren(
      errorState({
        title: "This view could not be loaded",
        message: error.message,
        retry: () => route(),
      }),
    );
  } finally {
    setLoading(false);
    viewRoot.focus({ preventScroll: true });
  }
  window.scrollTo({ top: 0, behavior: "auto" });
}

G.go = go;
G.refreshView = route;
G.reloadModules = async function reloadModules() {
  G.state.modules = await api("/api/modules");
  renderShellState();
};
G.loadInvestigations = async function loadInvestigations(force = false) {
  if (G.state.investigations.length && !force) return G.state.investigations;
  G.state.investigations = await api("/api/investigations");
  return G.state.investigations;
};
G.invalidateInvestigations = function invalidateInvestigations() {
  G.state.investigations = [];
};

G.newInvestigation = async function newInvestigation() {
  await formDialog({
    eyebrow: "NEW CASE",
    title: "Create investigation",
    description: "Open a case file. Observations stay sourced and unverified.",
    fields: [
      {
        name: "name",
        label: "Investigation name",
        required: true,
        maxlength: 200,
        placeholder: "e.g. Suspicious infrastructure review",
      },
      {
        name: "description",
        label: "Description",
        type: "textarea",
        rows: 3,
        placeholder: "Scope, context, or analyst objective",
      },
    ],
    submitLabel: "Create investigation",
    onSubmit: async (values) => {
      const created = await api("/api/investigations", {
        method: "POST",
        body: JSON.stringify(values),
      });
      G.invalidateInvestigations();
      toast("Investigation created.");
      go("investigations", created.id);
    },
  });
};

/* ------------------------------------------------------------------ */
/* Global search                                                      */
/* ------------------------------------------------------------------ */

let searchTimer = null;

function renderSearchHint(message = "Type at least two characters to search local records.") {
  searchResults.replaceChildren(el("p", { class: "search-hint" }, message));
  G.state.searchIndex = -1;
}

function navigateSearchItem(item) {
  if (item.view === "entities" && item.entity_id) go("entities", item.entity_id);
  else if (item.view === "sources" && item.source_id) go("sources", item.source_id);
  else if (item.view === "evidence" && item.investigation_id) go("evidence", item.investigation_id);
  else if (item.view === "investigations" && item.investigation_id)
    go("investigations", item.investigation_id);
  else go(item.view);
}

function renderSearchResults(data) {
  searchResults.replaceChildren();
  G.state.searchIndex = -1;
  if (data.message) {
    renderSearchHint(data.message);
    return;
  }
  const groups = (data.groups || []).filter((group) => group.items.length);
  if (!groups.length) {
    renderSearchHint("No matching local records.");
    return;
  }
  for (const group of groups) {
    const section = el(
      "section",
      { class: "search-group" },
      el(
        "div",
        { class: "search-group-label" },
        el("span", {}, group.label),
        el("span", { class: "search-group-total" }, String(group.total)),
      ),
    );
    for (const item of group.items) {
      section.append(
        el(
          "button",
          {
            class: "search-result",
            type: "button",
            onClick: () => {
              searchDialog.close();
              navigateSearchItem(item);
            },
          },
          el("span", { class: "search-result-title" }, item.title),
          el("span", { class: "search-result-subtitle" }, item.subtitle),
        ),
      );
    }
    searchResults.append(section);
  }
}

async function runSearch(query) {
  try {
    const data = await api(`/api/search?q=${encodeURIComponent(query)}`);
    if (searchInput.value.trim() !== query) return;
    renderSearchResults(data);
  } catch (error) {
    if (searchInput.value.trim() !== query) return;
    searchResults.replaceChildren(inlineError(error.message));
  }
}

function moveSearchSelection(delta) {
  const buttons = [...searchResults.querySelectorAll(".search-result")];
  if (!buttons.length) return;
  const current = G.state.searchIndex;
  G.state.searchIndex = (current + delta + buttons.length) % buttons.length;
  buttons.forEach((button, index) => button.classList.toggle("is-active", index === G.state.searchIndex));
  buttons[G.state.searchIndex].scrollIntoView({ block: "nearest" });
}

function openSearch() {
  if (!moduleEnabled("global-search")) {
    toast("Global search is disabled in the module manager.", "error");
    return;
  }
  searchInput.value = "";
  renderSearchHint();
  searchDialog.showModal();
  window.setTimeout(() => searchInput.focus(), 20);
}

G.openSearch = openSearch;

/* ------------------------------------------------------------------ */
/* Boot                                                               */
/* ------------------------------------------------------------------ */

function bindShell() {
  if (bindShell.bound) return;
  bindShell.bound = true;
  document.querySelector("#nav-groups").addEventListener("click", () => {
    /* native anchors handle navigation; active state follows hashchange */
  });
  newInvestigationButton.addEventListener("click", () => {
    G.newInvestigation().catch((error) => toast(error.message, "error"));
  });
  searchButton.addEventListener("click", openSearch);
  searchDialog.addEventListener("click", (event) => {
    if (event.target === searchDialog) searchDialog.close();
  });
  searchInput.addEventListener("input", () => {
    clearTimeout(searchTimer);
    const query = searchInput.value.trim();
    if (query.length < 2) {
      renderSearchHint();
      return;
    }
    searchResults.replaceChildren(loadingBlock("Searching local records…"));
    searchTimer = window.setTimeout(() => runSearch(query), 220);
  });
  searchInput.addEventListener("keydown", (event) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      moveSearchSelection(1);
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      moveSearchSelection(-1);
    } else if (event.key === "Enter") {
      event.preventDefault();
      const buttons = [...searchResults.querySelectorAll(".search-result")];
      if (!buttons.length) return;
      buttons[Math.max(0, G.state.searchIndex)].click();
    }
  });
  document.addEventListener("keydown", (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
      event.preventDefault();
      openSearch();
    }
  });
}

async function boot() {
  bindShell();
  if (!boot.retryBound) {
    boot.retryBound = true;
    window.addEventListener("hashchange", () => {
      route();
    });
  }
  try {
    const [modules, settings] = await Promise.all([api("/api/modules"), api("/api/settings")]);
    G.state.modules = modules;
    G.state.settings = settings.values;
    applySettings();
    renderShellState();
    if (!location.hash) {
      history.replaceState(null, "", "#/overview");
    }
    await route();
  } catch (error) {
    document.querySelector("#nav-groups").replaceChildren();
    viewRoot.replaceChildren(
      errorState({
        title: "The local workspace is unavailable",
        message: `${error.message}. Start the server with "python3 -m garbage_intel serve" and retry.`,
        retry: () => boot(),
      }),
    );
  }
}

document.addEventListener("DOMContentLoaded", () => {
  boot();
});
