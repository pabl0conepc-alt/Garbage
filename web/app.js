"use strict";

const status = document.querySelector("#status");
const loadingState = document.querySelector("#loading-state");
const investigationDialog = document.querySelector("#investigation-dialog");
const observationDialog = document.querySelector("#observation-dialog");
const investigationForm = document.querySelector("#investigation-form");
const observationForm = document.querySelector("#observation-form");
const detailPanel = document.querySelector("#investigation-detail");
const timelineSelect = document.querySelector("#timeline-investigation-select");
const kevRecords = document.querySelector("#kev-records");
const state = {
  investigations: [],
  reports: new Map(),
  selectedInvestigationId: "",
  kevLoaded: false,
};

const COLLECTION_BASES = [
  { key: "public", label: "Public", color: "blue" },
  { key: "authorized", label: "Authorized", color: "violet" },
  { key: "user-provided", label: "User-provided", color: "amber" },
];
const INDICATOR_TYPES = [
  { key: "ipv4", label: "IPv4 address", color: "blue" },
  { key: "domain", label: "Domain", color: "violet" },
  { key: "md5", label: "MD5", color: "amber" },
  { key: "sha1", label: "SHA-1", color: "green" },
  { key: "sha256", label: "SHA-256", color: "red" },
];

async function request(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...options.headers,
    },
  });
  const result = await response.json();
  if (!response.ok) {
    const error = new Error(result.error || `Request failed (${response.status})`);
    error.status = response.status;
    throw error;
  }
  return result;
}

function element(tagName, className, text) {
  const node = document.createElement(tagName);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function showStatus(message, isError = false) {
  status.textContent = message;
  status.dataset.tone = isError ? "error" : "success";
  status.classList.add("is-visible");
  status.setAttribute("aria-live", isError ? "assertive" : "polite");
  window.clearTimeout(showStatus.timeoutId);
  if (message) {
    showStatus.timeoutId = window.setTimeout(
      () => status.classList.remove("is-visible"),
      isError ? 9000 : 4500,
    );
  }
}

function setLoading(loading) {
  loadingState.classList.toggle("is-loading", loading);
  loadingState.setAttribute("aria-hidden", String(!loading));
}

function formatDate(value, options = {}) {
  if (!value) return "Unknown date";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Unknown date";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: options.dateStyle || "medium",
    ...(options.time ? { timeStyle: "short" } : {}),
    timeZone: "UTC",
  }).format(date);
}

function relativeDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Unknown date";
  const days = Math.floor((Date.now() - date.getTime()) / 86_400_000);
  if (days < 0) return formatDate(value);
  if (days === 0) return "Today";
  if (days === 1) return "Yesterday";
  if (days < 7) return `${days} days ago`;
  return formatDate(value);
}

function selectedCase() {
  return state.investigations.find(
    (investigation) => investigation.id === state.selectedInvestigationId,
  );
}

function reportFor(investigationId) {
  return state.reports.get(investigationId);
}

function updateSelects() {
  const timelineValue = timelineSelect.value;
  timelineSelect.replaceChildren();
  const placeholder = element("option", "", "Choose an investigation");
  placeholder.value = "";
  timelineSelect.append(placeholder);
  for (const investigation of state.investigations) {
    const option = element(
      "option",
      "",
      `${investigation.name} · ${investigation.status}`,
    );
    option.value = investigation.id;
    timelineSelect.append(option);
  }
  if (state.investigations.some((item) => item.id === timelineValue)) {
    timelineSelect.value = timelineValue;
  } else if (state.selectedInvestigationId) {
    timelineSelect.value = state.selectedInvestigationId;
  }
  document.querySelector("#nav-investigation-count").textContent =
    state.investigations.length.toLocaleString();
}

async function loadWorkspace({ quiet = false } = {}) {
  if (!quiet) setLoading(true);
  try {
    const investigations = await request("/api/investigations");
    const reports = await Promise.all(
      investigations.map(async (investigation) => {
        const report = await request(
          `/api/investigations/${encodeURIComponent(investigation.id)}/report`,
        );
        return [investigation.id, report];
      }),
    );
    state.investigations = investigations;
    state.reports = new Map(reports);
    if (!investigations.some((item) => item.id === state.selectedInvestigationId)) {
      state.selectedInvestigationId = investigations[0]?.id || "";
    }
    updateSelects();
    renderOverview();
    renderInvestigationTable();
    if (!detailPanel.hidden && state.selectedInvestigationId) {
      renderCaseDetail(state.selectedInvestigationId);
    }
    if (document.querySelector("#view-timeline").hidden === false) {
      await loadTimeline();
    }
    if (!quiet) showStatus("Workspace data refreshed.");
  } catch (error) {
    showStatus(`Unable to load workspace data: ${error.message}`, true);
    throw error;
  } finally {
    if (!quiet) setLoading(false);
  }
}

function allObservations() {
  return [...state.reports.values()].flatMap((report) =>
    report.observations.map((observation) => ({
      ...observation,
      investigation_id: report.investigation.id,
      investigation_name: report.investigation.name,
    })),
  );
}

function allIndicators() {
  return [...state.reports.values()].flatMap((report) => report.indicators);
}

function allCorrelations() {
  return [...state.reports.values()].flatMap((report) => report.correlations);
}

function renderOverview() {
  const observations = allObservations();
  const openCount = state.investigations.filter(
    (investigation) => investigation.status === "open",
  ).length;
  document.querySelector("#metric-open").textContent = openCount.toLocaleString();
  document.querySelector("#metric-observations").textContent =
    observations.length.toLocaleString();
  document.querySelector("#metric-indicators").textContent =
    allIndicators().length.toLocaleString();
  document.querySelector("#metric-correlations").textContent =
    allCorrelations().length.toLocaleString();
  document.querySelector("#metric-open-foot").textContent =
    `${state.investigations.length.toLocaleString()} total investigations`;
  renderActivityChart(observations);
  renderBasisChart(observations);
  renderIndicatorMix(allIndicators());
  renderRecentInvestigations();
}

function renderActivityChart(observations) {
  const chart = document.querySelector("#activity-chart");
  chart.replaceChildren();
  const today = new Date();
  const points = [];
  for (let daysAgo = 6; daysAgo >= 0; daysAgo -= 1) {
    const date = new Date(Date.UTC(
      today.getUTCFullYear(),
      today.getUTCMonth(),
      today.getUTCDate() - daysAgo,
    ));
    const key = date.toISOString().slice(0, 10);
    points.push({
      key,
      label: new Intl.DateTimeFormat(undefined, {
        weekday: "short",
        timeZone: "UTC",
      }).format(date),
      count: observations.filter(
        (observation) => observation.observed_at?.slice(0, 10) === key,
      ).length,
    });
  }
  const total = points.reduce((sum, point) => sum + point.count, 0);
  document.querySelector("#activity-total").textContent =
    `${total.toLocaleString()} ${total === 1 ? "record" : "records"}`;
  if (observations.length === 0) {
    chart.append(
      element("div", "chart-empty", "Record observations to see evidence activity."),
    );
    return;
  }

  const namespace = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(namespace, "svg");
  svg.setAttribute("viewBox", "0 0 640 190");
  svg.setAttribute("role", "img");
  svg.setAttribute(
    "aria-label",
    `Observation counts for the last seven days: ${points
      .map((point) => `${point.label} ${point.count}`)
      .join(", ")}`,
  );
  const max = Math.max(1, ...points.map((point) => point.count));
  const baseline = 150;
  const top = 18;
  for (let line = 0; line < 4; line += 1) {
    const y = top + ((baseline - top) / 3) * line;
    const guide = document.createElementNS(namespace, "line");
    guide.setAttribute("x1", "38");
    guide.setAttribute("x2", "625");
    guide.setAttribute("y1", String(y));
    guide.setAttribute("y2", String(y));
    guide.setAttribute("class", "chart-guide");
    svg.append(guide);
  }
  points.forEach((point, index) => {
    const x = 56 + index * 82;
    const height = point.count === 0 ? 3 : Math.max(8, (point.count / max) * 112);
    const bar = document.createElementNS(namespace, "rect");
    bar.setAttribute("x", String(x));
    bar.setAttribute("y", String(baseline - height));
    bar.setAttribute("width", "38");
    bar.setAttribute("height", String(height));
    bar.setAttribute("rx", "6");
    bar.setAttribute("class", point.count ? "chart-bar" : "chart-bar is-empty");
    const tooltip = document.createElementNS(namespace, "title");
    tooltip.textContent = `${point.key}: ${point.count} observations`;
    bar.append(tooltip);
    svg.append(bar);
    const countLabel = document.createElementNS(namespace, "text");
    countLabel.setAttribute("x", String(x + 19));
    countLabel.setAttribute("y", String(baseline - height - 8));
    countLabel.setAttribute("text-anchor", "middle");
    countLabel.setAttribute("class", "chart-count");
    countLabel.textContent = String(point.count);
    svg.append(countLabel);
    const dayLabel = document.createElementNS(namespace, "text");
    dayLabel.setAttribute("x", String(x + 19));
    dayLabel.setAttribute("y", "177");
    dayLabel.setAttribute("text-anchor", "middle");
    dayLabel.setAttribute("class", "chart-day");
    dayLabel.textContent = point.label;
    svg.append(dayLabel);
  });
  chart.append(svg);
}

function renderBasisChart(observations) {
  const chart = document.querySelector("#basis-chart");
  const legend = document.querySelector("#basis-legend");
  chart.replaceChildren();
  legend.replaceChildren();
  const counts = Object.fromEntries(
    COLLECTION_BASES.map(({ key }) => [
      key,
      observations.filter((item) => item.collection_basis === key).length,
    ]),
  );
  const total = observations.length;
  const segmented = element("div", "basis-segments");
  for (const basis of COLLECTION_BASES) {
    const count = counts[basis.key];
    if (count === 0 || total === 0) continue;
    const width = Math.max(5, Math.round((count / total) * 20) * 5);
    const segment = element(
      "span",
      `basis-segment basis-${basis.color} width-${width}`,
    );
    segment.setAttribute("aria-label", `${basis.label}: ${count}`);
    segmented.append(segment);
  }
  if (total === 0) segmented.classList.add("is-empty");
  chart.append(segmented);
  for (const basis of COLLECTION_BASES) {
    const item = element("div", "basis-legend-item");
    const label = element("span", "basis-name");
    label.append(element("i", `legend-square legend-${basis.color}`));
    label.append(document.createTextNode(basis.label));
    item.append(label, element("strong", "", counts[basis.key].toLocaleString()));
    legend.append(item);
  }
  const totalLabel = element("div", "basis-total");
  totalLabel.append(element("span", "", "Total sourced observations"));
  totalLabel.append(element("strong", "", total.toLocaleString()));
  chart.append(totalLabel);
}

function renderIndicatorMix(indicators) {
  const container = document.querySelector("#indicator-mix");
  container.replaceChildren();
  if (indicators.length === 0) {
    container.append(
      element("div", "chart-empty", "Indicators appear here when patterns are found in observations."),
    );
    return;
  }
  const counts = Object.fromEntries(
    INDICATOR_TYPES.map(({ key }) => [
      key,
      indicators.filter((indicator) => indicator.type === key).length,
    ]),
  );
  for (const item of INDICATOR_TYPES) {
    const count = counts[item.key];
    if (!count) continue;
    const row = element("div", "indicator-row");
    const heading = element("div", "indicator-row-heading");
    heading.append(
      element("span", "indicator-label", item.label),
      element("strong", "", count.toLocaleString()),
    );
    const track = element("div", "indicator-track");
    const width = Math.max(5, Math.round((count / indicators.length) * 20) * 5);
    const fill = element("span", `indicator-fill fill-${item.color} width-${width}`);
    track.append(fill);
    row.append(heading, track);
    container.append(row);
  }
}

function renderRecentInvestigations() {
  const container = document.querySelector("#recent-investigations");
  container.replaceChildren();
  const recent = [...state.investigations]
    .sort((a, b) => b.created_at.localeCompare(a.created_at))
    .slice(0, 5);
  if (recent.length === 0) {
    container.append(
      element("div", "chart-empty", "New investigations will appear here."),
    );
    return;
  }
  for (const investigation of recent) {
    const report = reportFor(investigation.id);
    const row = element("button", "recent-item");
    row.type = "button";
    row.addEventListener("click", () => openInvestigation(investigation.id));
    const mark = element("span", "case-avatar", investigation.name.slice(0, 1).toUpperCase());
    const copy = element("span", "recent-copy");
    copy.append(
      element("strong", "", investigation.name),
      element("small", "", `${report.observations.length} observations · ${relativeDate(investigation.created_at)}`),
    );
    row.append(
      mark,
      copy,
      element("span", `status-badge status-${investigation.status}`, investigation.status),
      element("span", "row-chevron", "›"),
    );
    container.append(row);
  }
}

function renderInvestigationTable() {
  const rows = document.querySelector("#investigation-rows");
  const empty = document.querySelector("#investigation-empty");
  rows.replaceChildren();
  const query = document.querySelector("#investigation-search").value.trim().toLocaleLowerCase();
  const investigations = [...state.investigations]
    .sort((a, b) => b.created_at.localeCompare(a.created_at))
    .filter((investigation) =>
      `${investigation.name} ${investigation.description} ${investigation.status}`
        .toLocaleLowerCase()
        .includes(query),
    );
  document.querySelector("#investigation-result-count").textContent =
    `${investigations.length.toLocaleString()} ${investigations.length === 1 ? "investigation" : "investigations"}`;
  empty.hidden = investigations.length > 0;
  document.querySelector(".table-scroll").hidden =
    state.investigations.length === 0;
  if (investigations.length === 0 && state.investigations.length > 0) {
    const row = document.createElement("tr");
    const cell = element("td", "filter-empty", "No investigations match this search.");
    cell.colSpan = 6;
    row.append(cell);
    rows.append(row);
    return;
  }
  for (const investigation of investigations) {
    const report = reportFor(investigation.id);
    const row = document.createElement("tr");
    const nameCell = document.createElement("td");
    const name = element("strong", "table-case-name", investigation.name);
    const description = element(
      "span",
      "table-case-description",
      investigation.description || "No description provided",
    );
    nameCell.append(name, description);
    const statusCell = document.createElement("td");
    statusCell.append(
      element("span", `status-badge status-${investigation.status}`, investigation.status),
    );
    const createdCell = element("td", "muted-cell", formatDate(investigation.created_at));
    const observationCell = element(
      "td",
      "numeric-cell",
      report.observations.length.toLocaleString(),
    );
    const indicatorCell = element(
      "td",
      "numeric-cell",
      report.indicators.length.toLocaleString(),
    );
    const actionCell = document.createElement("td");
    const openButton = element("button", "text-button", "Open case →");
    openButton.type = "button";
    openButton.addEventListener("click", () => openInvestigation(investigation.id));
    actionCell.append(openButton);
    row.append(nameCell, statusCell, createdCell, observationCell, indicatorCell, actionCell);
    rows.append(row);
  }
}

function openInvestigation(investigationId) {
  state.selectedInvestigationId = investigationId;
  updateSelects();
  renderCaseDetail(investigationId);
  detailPanel.hidden = false;
  setView("investigations");
  detailPanel.scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderCaseDetail(investigationId) {
  const report = reportFor(investigationId);
  if (!report) return;
  const { investigation, observations, indicators, correlations } = report;
  detailPanel.replaceChildren();
  const heading = element("div", "case-detail-heading");
  const titleGroup = element("div", "");
  const eyebrow = element("p", "eyebrow", "INVESTIGATION FILE");
  const title = element("h2", "", investigation.name);
  titleGroup.append(eyebrow, title);
  const actions = element("div", "case-actions");
  const recordButton = element("button", "button button-primary button-small", "＋ Record observation");
  recordButton.type = "button";
  recordButton.disabled = investigation.status !== "open";
  recordButton.addEventListener("click", openObservationDialog);
  const statusButton = element(
    "button",
    "button button-secondary button-small",
    investigation.status === "open" ? "Close investigation" : "Reopen investigation",
  );
  statusButton.type = "button";
  statusButton.addEventListener("click", () => toggleInvestigationStatus(investigation));
  const printableReport = element("a", "button button-secondary button-small", "Printable report");
  printableReport.href = `/reports/${encodeURIComponent(investigation.id)}`;
  printableReport.target = "_blank";
  printableReport.rel = "noopener";
  actions.append(recordButton, statusButton, printableReport);
  heading.append(titleGroup, actions);

  const summary = element("p", "case-description", investigation.description || "No description provided.");
  const stats = element("div", "case-stat-grid");
  stats.append(
    caseStat("Status", investigation.status, `status-text-${investigation.status}`),
    caseStat("Observations", observations.length.toLocaleString()),
    caseStat("Indicators", indicators.length.toLocaleString()),
    caseStat("Correlations", correlations.length.toLocaleString()),
  );
  const observationHeading = element("div", "subsection-heading");
  observationHeading.append(
    element("h3", "", "Evidence observations"),
    element("span", "panel-caption", `${observations.length} total`),
  );
  const observationList = element("div", "observation-list");
  if (observations.length === 0) {
    observationList.append(
      element("div", "chart-empty", "No observations have been recorded for this investigation."),
    );
  } else {
    [...observations].reverse().slice(0, 8).forEach((observation) => {
      const item = element("article", "observation-item");
      const titleLine = element("div", "observation-heading");
      titleLine.append(
        element("strong", "", observation.title),
        element("span", "collection-chip", observation.collection_basis),
      );
      item.append(
        titleLine,
        element("p", "observation-content", observation.content),
        element("div", "observation-meta", `Observed ${formatDate(observation.observed_at, { time: true })} · Source: ${observation.source_reference}`),
      );
      observationList.append(item);
    });
  }
  detailPanel.append(heading, summary, stats, observationHeading, observationList);
}

function caseStat(label, value, valueClass = "") {
  const item = element("div", "case-stat");
  item.append(element("span", "", label), element("strong", valueClass, value));
  return item;
}

async function toggleInvestigationStatus(investigation) {
  const nextStatus = investigation.status === "open" ? "closed" : "open";
  try {
    await request(`/api/investigations/${encodeURIComponent(investigation.id)}`, {
      method: "PATCH",
      body: JSON.stringify({ status: nextStatus }),
    });
    await loadWorkspace({ quiet: true });
    showStatus(`Investigation ${nextStatus}.`);
  } catch (error) {
    showStatus(`Unable to update investigation: ${error.message}`, true);
  }
}

async function loadTimeline() {
  const investigationId = timelineSelect.value;
  const eventsContainer = document.querySelector("#timeline-events");
  const empty = document.querySelector("#timeline-empty");
  eventsContainer.replaceChildren();
  const investigation = state.investigations.find((item) => item.id === investigationId);
  document.querySelector("#timeline-case-name").textContent =
    investigation?.name || "Select an investigation";
  document.querySelector("#timeline-event-count").textContent = "";
  if (!investigationId) {
    empty.hidden = true;
    eventsContainer.append(
      element("div", "chart-empty", "Choose an investigation to load its chronological activity."),
    );
    return;
  }
  try {
    const timeline = await request(
      `/api/investigations/${encodeURIComponent(investigationId)}/timeline`,
    );
    document.querySelector("#timeline-event-count").textContent =
      `${timeline.events.length} ${timeline.events.length === 1 ? "event" : "events"}`;
    empty.hidden = timeline.events.length > 0;
    if (timeline.events.length === 0) return;
    for (const event of [...timeline.events].reverse()) {
      const item = element("article", "timeline-event");
      const marker = element(
        "span",
        `timeline-marker marker-${event.type === "observation" ? "observation" : event.type === "status_changed" ? "status" : "created"}`,
      );
      const body = element("div", "timeline-event-body");
      const header = element("div", "timeline-event-header");
      header.append(
        element("h3", "", event.title),
        element("time", "", formatDate(event.occurred_at, { time: true })),
      );
      body.append(header);
      if (event.collection_basis) {
        body.append(
          element("span", "collection-chip", event.collection_basis),
        );
      }
      if (event.source_reference) {
        body.append(element("p", "timeline-source", `Source: ${event.source_reference}`));
      }
      item.append(marker, body);
      eventsContainer.append(item);
    }
  } catch (error) {
    empty.hidden = false;
    document.querySelector("#timeline-empty h3").textContent = "Timeline unavailable";
    document.querySelector("#timeline-empty p").textContent = error.message;
  }
}

function setView(viewName) {
  const views = ["overview", "investigations", "timeline", "kev"];
  for (const view of views) {
    document.querySelector(`#view-${view}`).hidden = view !== viewName;
  }
  document.querySelectorAll(".nav-link").forEach((link) => {
    const active = link.dataset.view === viewName;
    link.classList.toggle("is-active", active);
    if (active) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  });
  document.querySelector("#page-breadcrumb").textContent =
    { overview: "Overview", investigations: "Investigations", timeline: "Activity timeline", kev: "CISA KEV" }[viewName];
  if (viewName === "timeline") loadTimeline();
  if (viewName === "kev" && !state.kevLoaded) loadKevCatalog();
}

async function loadKevCatalog(search = "") {
  const query = new URLSearchParams({ search, limit: "25" });
  try {
    const catalog = await request(`/api/intel/cisa-kev?${query}`);
    state.kevLoaded = true;
    renderKevCatalog(catalog, search);
  } catch (error) {
    if (error.status === 404) {
      state.kevLoaded = false;
      renderKevEmpty("No cached catalog", "Refresh CISA KEV to fetch a local copy. Page load does not contact CISA.");
      return;
    }
    showStatus(`Unable to read the cached CISA catalog: ${error.message}`, true);
    renderKevEmpty("Catalog unavailable", error.message);
  }
}

function renderKevCatalog(catalog, search = "") {
  kevRecords.replaceChildren();
  document.querySelector("#kev-empty").hidden = true;
  document.querySelector("#kev-result-count").textContent =
    `${catalog.matched.toLocaleString()} matching ${catalog.matched === 1 ? "record" : "records"}`;
  document.querySelector("#kev-snapshot-meta").textContent =
    `Version ${catalog.catalog_version} · ${catalog.count.toLocaleString()} entries · released ${formatDate(catalog.source_updated_at)} · fetched ${formatDate(catalog.fetched_at, { time: true })}`;
  if (catalog.items.length === 0) {
    renderKevEmpty(search ? "No matching vulnerabilities" : "No records to display", search ? "Try a different search term. The catalog remains cached locally." : "The cached catalog contains no records.");
    return;
  }
  for (const vulnerability of catalog.items) {
    const card = element("article", "kev-record");
    const head = element("div", "kev-record-header");
    const identifier = element("a", "cve-id", vulnerability.cve_id);
    identifier.href = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(vulnerability.cve_id)}`;
    identifier.target = "_blank";
    identifier.rel = "noopener noreferrer";
    const dateAdded = element("span", "kev-date-added", `Added ${formatDate(vulnerability.date_added)}`);
    head.append(identifier, dateAdded);
    const title = element("h3", "", vulnerability.vulnerability_name);
    const product = element("p", "kev-product", `${vulnerability.vendor_project} · ${vulnerability.product}`);
    const description = element("p", "kev-description", vulnerability.short_description);
    const footer = element("div", "kev-record-footer");
    footer.append(
      element("span", "kev-due-date", `Due ${formatDate(vulnerability.due_date)}`),
      element("span", "kev-ransomware", `Ransomware use: ${vulnerability.ransomware_use}`),
    );
    const action = element("p", "kev-action");
    action.append(element("strong", "", "Required action "), document.createTextNode(vulnerability.required_action));
    card.append(head, title, product, description, action, footer);
    kevRecords.append(card);
  }
  if (catalog.matched > catalog.items.length) {
    kevRecords.append(
      element("p", "kev-truncated", `Showing ${catalog.items.length} of ${catalog.matched} matches. Refine your search to narrow the results.`),
    );
  }
}

function renderKevEmpty(title, description) {
  kevRecords.replaceChildren();
  document.querySelector("#kev-result-count").textContent = "";
  const empty = document.querySelector("#kev-empty");
  empty.hidden = false;
  document.querySelector("#kev-empty-title").textContent = title;
  document.querySelector("#kev-empty-description").textContent = description;
}

function openObservationDialog() {
  const investigation = selectedCase();
  if (!investigation || investigation.status !== "open") return;
  document.querySelector("#observation-case-name").textContent = investigation.name;
  observationForm.reset();
  document.querySelector("#observation-form-error").hidden = true;
  observationDialog.showModal();
}

document.querySelectorAll(".nav-link").forEach((button) => {
  button.addEventListener("click", () => setView(button.dataset.view));
});

document.querySelectorAll("[data-open-view]").forEach((button) => {
  button.addEventListener("click", () => setView(button.dataset.openView));
});

document.querySelector("#new-investigation-button").addEventListener("click", () => {
  investigationForm.reset();
  document.querySelector("#investigation-form-error").hidden = true;
  investigationDialog.showModal();
});

document.querySelectorAll("[data-create-investigation]").forEach((button) => {
  button.addEventListener("click", () => {
    setView("investigations");
    investigationForm.reset();
    document.querySelector("#investigation-form-error").hidden = true;
    investigationDialog.showModal();
  });
});

document.querySelectorAll("[data-close-dialog]").forEach((button) => {
  button.addEventListener("click", () => button.closest("dialog").close());
});

investigationForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const submitButton = investigationForm.querySelector('[type="submit"]');
  submitButton.disabled = true;
  document.querySelector("#investigation-form-error").hidden = true;
  const data = Object.fromEntries(new FormData(investigationForm));
  try {
    const investigation = await request("/api/investigations", {
      method: "POST",
      body: JSON.stringify(data),
    });
    investigationDialog.close();
    await loadWorkspace({ quiet: true });
    openInvestigation(investigation.id);
    showStatus("Investigation created.");
  } catch (error) {
    const formError = document.querySelector("#investigation-form-error");
    formError.textContent = `Unable to create investigation: ${error.message}`;
    formError.hidden = false;
  } finally {
    submitButton.disabled = false;
  }
});

observationForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const investigation = selectedCase();
  if (!investigation || investigation.status !== "open") {
    observationDialog.close();
    showStatus("Reopen the investigation before recording evidence.", true);
    return;
  }
  const submitButton = observationForm.querySelector('[type="submit"]');
  submitButton.disabled = true;
  const data = Object.fromEntries(new FormData(observationForm));
  document.querySelector("#observation-form-error").hidden = true;
  if (!data.observed_at) delete data.observed_at;
  try {
    await request(
      `/api/investigations/${encodeURIComponent(investigation.id)}/observations`,
      { method: "POST", body: JSON.stringify(data) },
    );
    observationDialog.close();
    await loadWorkspace({ quiet: true });
    showStatus("Observation recorded.");
  } catch (error) {
    const formError = document.querySelector("#observation-form-error");
    formError.textContent = `Unable to record observation: ${error.message}`;
    formError.hidden = false;
  } finally {
    submitButton.disabled = false;
  }
});

document.querySelector("#refresh-button").addEventListener("click", async () => {
  const button = document.querySelector("#refresh-button");
  button.disabled = true;
  try {
    await loadWorkspace();
  } catch {
    // loadWorkspace already displays a visible error.
  } finally {
    button.disabled = false;
  }
});

document.querySelector("#investigation-search").addEventListener("input", renderInvestigationTable);

timelineSelect.addEventListener("change", loadTimeline);

document.querySelector("#kev-search-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  await loadKevCatalog(document.querySelector("#kev-search").value);
});

document.querySelector("#kev-refresh-button").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  button.classList.add("is-loading");
  try {
    const catalog = await request("/api/intel/cisa-kev/refresh", {
      method: "POST",
      body: JSON.stringify({}),
    });
    await loadKevCatalog(document.querySelector("#kev-search").value);
    const label = catalog.refresh_status.replaceAll("_", " ");
    showStatus(`CISA KEV ${label} · ${catalog.count.toLocaleString()} catalog records.`);
  } catch (error) {
    showStatus(`CISA KEV refresh failed: ${error.message}`, true);
  } finally {
    button.disabled = false;
    button.classList.remove("is-loading");
  }
});

loadWorkspace().catch(() => {
  document.querySelector("#metric-open").textContent = "—";
  document.querySelector("#metric-observations").textContent = "—";
  document.querySelector("#metric-indicators").textContent = "—";
  document.querySelector("#metric-correlations").textContent = "—";
});
