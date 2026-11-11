"use strict";

const status = document.querySelector("#status");
const investigationSelect = document.querySelector("#investigation-select");
const reportOutput = document.querySelector("#report");
const htmlReportLink = document.querySelector("#html-report-link");
const statusToggle = document.querySelector("#status-toggle");

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
    throw new Error(result.error || `Request failed (${response.status})`);
  }
  return result;
}

function showStatus(message, isError = false) {
  status.textContent = message;
  status.setAttribute("aria-live", isError ? "assertive" : "polite");
}

function selectedInvestigationId() {
  return investigationSelect.value;
}

async function loadInvestigations(selectId) {
  const investigations = await request("/api/investigations");
  investigationSelect.replaceChildren();
  for (const investigation of investigations) {
    const option = document.createElement("option");
    option.value = investigation.id;
    option.textContent = `${investigation.name} (${investigation.status})`;
    investigationSelect.append(option);
  }
  if (selectId) investigationSelect.value = selectId;
  const hasSelection = Boolean(selectedInvestigationId());
  const current = investigations.find(
    (investigation) => investigation.id === selectedInvestigationId(),
  );
  document.querySelector("#report-button").disabled = !hasSelection;
  document.querySelector("#timeline-button").disabled = !hasSelection;
  document.querySelector("#observation-form button").disabled =
    current?.status !== "open";
  statusToggle.disabled = !hasSelection;
  statusToggle.textContent =
    !current || current.status === "open"
      ? "Close investigation"
      : "Reopen investigation";
  htmlReportLink.href = hasSelection
    ? `/reports/${encodeURIComponent(selectedInvestigationId())}`
    : "/";
  htmlReportLink.setAttribute("aria-disabled", String(!hasSelection));
  htmlReportLink.tabIndex = hasSelection ? 0 : -1;
  return investigations;
}

async function showReport() {
  const id = selectedInvestigationId();
  if (!id) throw new Error("Create or select an investigation first.");
  const report = await request(`/api/investigations/${encodeURIComponent(id)}/report`);
  reportOutput.textContent = JSON.stringify(report, null, 2);
}

document.querySelector("#investigation-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = Object.fromEntries(new FormData(form));
  try {
    const investigation = await request("/api/investigations", {
      method: "POST",
      body: JSON.stringify(data),
    });
    form.reset();
    await loadInvestigations(investigation.id);
    await showReport();
    showStatus("Investigation created.");
  } catch (error) {
    showStatus(error.message, true);
  }
});

document.querySelector("#observation-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = Object.fromEntries(new FormData(form));
  if (!data.observed_at) delete data.observed_at;
  try {
    await request(
      `/api/investigations/${encodeURIComponent(selectedInvestigationId())}/observations`,
      { method: "POST", body: JSON.stringify(data) },
    );
    form.reset();
    await loadInvestigations(selectedInvestigationId());
    await showReport();
    showStatus("Observation recorded.");
  } catch (error) {
    showStatus(error.message, true);
  }
});

document.querySelector("#report-button").addEventListener("click", async () => {
  try {
    await showReport();
    showStatus("Report loaded.");
  } catch (error) {
    showStatus(error.message, true);
  }
});

document.querySelector("#timeline-button").addEventListener("click", async () => {
  try {
    const id = selectedInvestigationId();
    if (!id) throw new Error("Create or select an investigation first.");
    const timeline = await request(
      `/api/investigations/${encodeURIComponent(id)}/timeline`,
    );
    reportOutput.textContent = JSON.stringify(timeline, null, 2);
    showStatus("Timeline loaded.");
  } catch (error) {
    showStatus(error.message, true);
  }
});

statusToggle.addEventListener("click", async () => {
  const id = selectedInvestigationId();
  try {
    const report = await request(`/api/investigations/${encodeURIComponent(id)}/report`);
    const nextStatus =
      report.investigation.status === "open" ? "closed" : "open";
    await request(`/api/investigations/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: JSON.stringify({ status: nextStatus }),
    });
    await loadInvestigations(id);
    await showReport();
    showStatus(`Investigation ${nextStatus}.`);
  } catch (error) {
    showStatus(error.message, true);
  }
});

investigationSelect.addEventListener("change", async () => {
  try {
    await loadInvestigations(selectedInvestigationId());
    await showReport();
    showStatus("Report loaded.");
  } catch (error) {
    showStatus(error.message, true);
  }
});

function showKevCatalog(catalog) {
  const { items, ...provenance } = catalog;
  document.querySelector("#kev-output").textContent = JSON.stringify(
    { provenance, items },
    null,
    2,
  );
}

document.querySelector("#kev-refresh-button").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    const catalog = await request("/api/intel/cisa-kev/refresh", {
      method: "POST",
      body: JSON.stringify({}),
    });
    showKevCatalog(catalog);
    showStatus(`CISA KEV ${catalog.refresh_status}; ${catalog.count} records.`);
  } catch (error) {
    showStatus(error.message, true);
  } finally {
    button.disabled = false;
  }
});

document.querySelector("#kev-search-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const query = new URLSearchParams({
    search: document.querySelector("#kev-search").value,
    limit: "25",
  });
  try {
    const catalog = await request(`/api/intel/cisa-kev?${query}`);
    showKevCatalog(catalog);
    showStatus(`${catalog.matched} cached CISA KEV records matched.`);
  } catch (error) {
    showStatus(error.message, true);
  }
});

loadInvestigations()
  .then(() => showStatus("Ready. This interface is only available on this machine."))
  .catch((error) => showStatus(error.message, true));
