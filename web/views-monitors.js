"use strict";

/* Monitoring: saved queries on a schedule, their differences, and the
 * notification bell in the top bar. */

(function () {
  const G = window.GARBAGE;
  const { el, api, toast, panel, badge, table, loadingBlock, inlineError, pageHeader, formatDate, relativeTime, go } = G;

  const STATUS = {
    baseline: ["Primeira execução", "neutral"],
    unchanged: ["Sem mudanças", "neutral"],
    changed: ["Mudou", "warning"],
    error: ["Falhou", "danger"],
    "": ["Ainda não rodou", "neutral"],
  };
  const INTERVALS = [[15, "15 min"], [60, "1 hora"], [360, "6 horas"], [1440, "1 dia"], [10080, "1 semana"]];
  const TYPE_TEXT = { domain: "domínio", ipv4: "IPv4", ipv6: "IPv6", cidr: "CIDR", url: "URL", email: "e-mail", md5: "MD5", sha1: "SHA-1", sha256: "SHA-256", asn: "ASN", cve: "CVE" };

  function button(label, onClick, options = {}) {
    return el("button", { class: `button ${options.variant || "button-secondary"} button-small`, type: "button", disabled: Boolean(options.disabled), title: options.title || "", onClick }, label);
  }

  function label(item) {
    const known = G.connectorLabel ? G.connectorLabel(item.connector_id) : "";
    return known && known !== item.connector_id ? known : item.name;
  }

  function intervalText(minutes) {
    const known = INTERVALS.find(([value]) => value === minutes);
    if (known) return known[1];
    return minutes % 1440 === 0 ? `${minutes / 1440} dia(s)` : minutes % 60 === 0 ? `${minutes / 60} h` : `${minutes} min`;
  }

  function diffList(items, sign) {
    if (!items.length) return null;
    return el(
      "ul",
      { class: `monitor-diff ${sign === "+" ? "is-added" : "is-removed"}` },
      ...items.slice(0, 50).map((item) =>
        el("li", {}, el("span", { class: "monitor-sign", "aria-hidden": "true" }, sign), el("code", {}, item.value), el("span", { class: "muted" }, ` · ${G.resultTypeLabel ? G.resultTypeLabel(item.result_type) : item.result_type} · ${G.connectorLabel ? G.connectorLabel(item.connector_id) : item.connector_id}`)),
      ),
      items.length > 50 ? el("li", { class: "muted" }, `e mais ${items.length - 50}`) : null,
    );
  }

  async function renderMonitors(root, params = []) {
    let selected = params[0] || "";
    let connectorData = null;
    const listHost = el("div");
    const historyHost = el("div");
    const formHost = el("div");

    async function loadConnectors() {
      if (!connectorData) connectorData = await api("/api/intel/connectors");
      return connectorData;
    }

    async function drawForm() {
      const data = await loadConnectors();
      const name = el("input", { class: "input", maxlength: 120, placeholder: "ex.: Subdomínios do alvo", "aria-label": "Nome do monitor" });
      const value = el("input", { class: "input", placeholder: "Domínio, IP, URL, hash, ASN ou CVE", "aria-label": "Artefato" });
      const interval = el("select", { class: "input compact-select", "aria-label": "Intervalo" }, ...INTERVALS.map(([minutes, label]) => el("option", { value: minutes, selected: minutes === 1440 }, `A cada ${label}`)));
      const caseSelect = el("select", { class: "input compact-select", "aria-label": "Investigação" }, el("option", { value: "" }, "Sem investigação"),
        ...(await G.loadInvestigations()).filter((item) => !item.archived_at).map((item) => el("option", { value: item.id }, item.name)));
      const chips = el("div", { class: "monitor-sources" }, el("p", { class: "panel-empty" }, "Digite o artefato para ver as fontes compatíveis."));
      const chosen = new Set();
      let detectedType = "";
      let timer = null;
      value.addEventListener("input", () => {
        window.clearTimeout(timer);
        timer = window.setTimeout(async () => {
          chips.replaceChildren();
          chosen.clear();
          if (!value.value.trim()) return;
          try {
            detectedType = (await api(`/api/intel/detect?value=${encodeURIComponent(value.value.trim())}`)).type;
          } catch (error) {
            chips.replaceChildren(el("p", { class: "panel-empty" }, error.message));
            return;
          }
          const usable = data.items.filter((item) => item.accepts.includes(detectedType));
          chips.append(
            el("p", { class: "run-meta" }, `Tipo: ${TYPE_TEXT[detectedType] || detectedType}. Fontes de rede seguem as travas da Pesquisa multifonte.`),
            ...usable.map((item) => {
              const box = el("input", { type: "checkbox", "aria-label": label(item), onChange: (event) => (event.target.checked ? chosen.add(item.connector_id) : chosen.delete(item.connector_id)) });
              return el("label", { class: `connector-chip${item.availability === "ready" ? "" : " is-blocked"}`, title: item.availability }, box, el("span", {}, label(item)));
            }),
          );
        }, 350);
      });
      const create = button("Criar monitor", async () => {
        try {
          const created = await api("/api/monitors", {
            method: "POST",
            body: JSON.stringify({ name: name.value, value: value.value.trim(), connectors: [...chosen], interval_minutes: Number(interval.value), investigation_id: caseSelect.value || null }),
          });
          toast(`Monitor "${created.name}" criado; a primeira execução vira a linha de base.`);
          selected = created.id;
          loadList();
        } catch (error) {
          toast(error.message, "error");
        }
      }, { variant: "button-primary" });
      formHost.replaceChildren(
        panel(
          { eyebrow: "NOVO MONITOR", title: "Vigiar um artefato" },
          el("div", { class: "monitor-form" }, el("label", { class: "field" }, el("span", {}, "Nome"), name), el("label", { class: "field" }, el("span", {}, "Artefato"), value), el("label", { class: "field" }, el("span", {}, "Intervalo"), interval), el("label", { class: "field" }, el("span", {}, "Investigação"), caseSelect)),
          chips,
          el("div", { class: "inline-actions" }, create),
          el("p", { class: "tool-limit" }, "Roda enquanto o servidor do GARBAGE está ligado. Cada execução é comparada com a anterior por fonte, tipo e valor; mudanças e falhas geram notificação no sino."),
        ),
      );
    }

    async function loadList() {
      let data;
      try {
        data = await api("/api/monitors");
      } catch (error) {
        listHost.replaceChildren(inlineError(error.message));
        return;
      }
      const scheduler = data.scheduler;
      listHost.replaceChildren(
        panel(
          {
            eyebrow: "MONITORES",
            title: `${data.total} monitor(es)`,
            caption: scheduler.running ? `Agendador ativo · última verificação ${scheduler.last_tick ? relativeTime(scheduler.last_tick) : "agora"}` : "Agendador parado: inicie com 'garbage serve'",
          },
          table({
            columns: [
              { label: "MONITOR", render: (row) => el("div", { class: "cell-stack" }, el("strong", {}, row.name), el("span", {}, `${TYPE_TEXT[row.query_type] || row.query_type} · `, el("code", {}, row.query_value))) },
              { label: "FONTES", className: "numeric-col", render: (row) => String(row.connectors.length) },
              { label: "INTERVALO", render: (row) => intervalText(row.interval_minutes) },
              { label: "ÚLTIMA", render: (row) => el("div", { class: "cell-stack" }, badge(...(STATUS[row.last_status] || [row.last_status, "neutral"])), row.last_run_at ? el("span", {}, relativeTime(row.last_run_at)) : null) },
              { label: "PRÓXIMA", render: (row) => (row.enabled ? formatDate(row.next_run_at, { time: true }) : "Pausado") },
              {
                label: "",
                render: (row) =>
                  el(
                    "div",
                    { class: "inline-actions" },
                    button("Rodar agora", async (event) => {
                      event.stopPropagation();
                      const trigger = event.currentTarget;
                      trigger.disabled = true;
                      trigger.textContent = "Rodando…";
                      try {
                        const result = await api(`/api/monitors/${row.id}/run`, { method: "POST", body: "{}" });
                        toast(`${row.name}: ${STATUS[result.status]?.[0] || result.status}${result.status === "changed" ? ` (+${result.added_count} / −${result.removed_count})` : ""}.`);
                        selected = row.id;
                        loadList();
                      } catch (error) {
                        toast(error.message, "error");
                        trigger.disabled = false;
                        trigger.textContent = "Rodar agora";
                      }
                    }),
                    button(row.enabled ? "Pausar" : "Retomar", async (event) => {
                      event.stopPropagation();
                      await api(`/api/monitors/${row.id}`, { method: "PATCH", body: JSON.stringify({ enabled: !row.enabled }) }).catch((error) => toast(error.message, "error"));
                      loadList();
                    }),
                    button("Excluir", async (event) => {
                      event.stopPropagation();
                      if (!(await G.confirm({ title: `Excluir ${row.name}?`, message: "O monitor e o histórico de diferenças são apagados. As consultas já feitas continuam na Pesquisa multifonte.", confirmLabel: "Excluir", danger: true }))) return;
                      await api(`/api/monitors/${row.id}`, { method: "DELETE" }).catch((error) => toast(error.message, "error"));
                      if (selected === row.id) selected = "";
                      loadList();
                    }, { variant: "button-danger" }),
                  ),
              },
            ],
            rows: data.items,
            emptyMessage: "Nenhum monitor. Crie um abaixo.",
            onRowClick: (row) => {
              selected = row.id;
              loadHistory();
            },
          }),
        ),
      );
      loadHistory();
    }

    async function loadHistory() {
      if (!selected) {
        historyHost.replaceChildren();
        return;
      }
      historyHost.replaceChildren(loadingBlock("Carregando histórico…"));
      let data;
      try {
        data = await api(`/api/monitors/${selected}/runs`);
      } catch (error) {
        historyHost.replaceChildren(inlineError(error.message));
        return;
      }
      historyHost.replaceChildren(
        panel(
          { eyebrow: "HISTÓRICO", title: data.monitor.name, caption: `${data.items.length} execução(ões) recentes` },
          data.items.length
            ? el(
                "div",
                { class: "monitor-runs" },
                ...data.items.map((run) =>
                  el(
                    "article",
                    { class: `monitor-run status-${run.status}` },
                    el(
                      "div",
                      { class: "monitor-run-head" },
                      badge(...(STATUS[run.status] || [run.status, "neutral"])),
                      el("span", {}, formatDate(run.started_at, { time: true })),
                      el("span", { class: "muted" }, run.trigger === "schedule" ? "agendada" : "manual"),
                      run.status === "changed" ? el("span", {}, `+${run.added_count} / −${run.removed_count}`) : null,
                      run.intel_run_id ? el("a", { class: "table-link", href: `#/multisearch/${run.intel_run_id}` }, "Ver consulta") : null,
                    ),
                    run.error ? el("p", { class: "inline-error-text" }, G.translateError(run.error)) : null,
                    diffList(run.added, "+"),
                    diffList(run.removed, "−"),
                  ),
                ),
              )
            : el("p", { class: "panel-empty" }, "Ainda não rodou. Use \"Rodar agora\" ou aguarde o agendador."),
        ),
      );
    }

    root.replaceChildren(
      pageHeader({
        eyebrow: "INTELIGÊNCIA",
        title: "Monitoramento",
        description: "Consultas multifonte salvas que rodam de novo sozinhas e mostram o que apareceu e o que sumiu desde a última vez.",
      }),
      listHost,
      historyHost,
      formHost,
    );
    await loadList();
    drawForm();
  }

  /* Notification bell -------------------------------------------------- */

  const wrap = document.querySelector("#notify-wrap");
  const toggle = document.querySelector("#notify-toggle");
  const count = document.querySelector("#notify-count");
  const menu = document.querySelector("#notify-menu");

  async function refreshBell() {
    if (!wrap) return;
    const enabled = G.moduleEnabled && G.moduleEnabled("monitoring");
    wrap.hidden = !enabled;
    if (!enabled) return;
    try {
      const data = await api("/api/notifications?unread=1&limit=1");
      count.hidden = data.unread === 0;
      count.textContent = data.unread > 99 ? "99+" : String(data.unread);
      toggle.setAttribute("aria-label", `Notificações de monitoramento: ${data.unread} não lida(s)`);
    } catch (error) {
      count.hidden = true;
    }
  }

  async function openMenu() {
    const open = menu.hidden;
    menu.hidden = !open;
    toggle.setAttribute("aria-expanded", String(open));
    if (!open) return;
    menu.replaceChildren(loadingBlock("Carregando…"));
    let data;
    try {
      data = await api("/api/notifications?limit=15");
    } catch (error) {
      menu.replaceChildren(inlineError(error.message));
      return;
    }
    menu.replaceChildren(
      el("div", { class: "notify-head" }, el("strong", {}, "Notificações"), data.unread ? button("Marcar todas como lidas", async () => { await api("/api/notifications/read", { method: "POST", body: JSON.stringify({ ids: "all" }) }); menu.hidden = true; refreshBell(); }) : null),
      data.items.length
        ? el(
            "div",
            { class: "notify-list" },
            ...data.items.map((item) =>
              el(
                "button",
                {
                  class: `notify-item${item.read_at ? "" : " is-unread"}`,
                  type: "button",
                  onClick: async () => {
                    menu.hidden = true;
                    await api("/api/notifications/read", { method: "POST", body: JSON.stringify({ ids: [item.id] }) }).catch(() => {});
                    refreshBell();
                    go("monitors", item.monitor_id);
                  },
                },
                el("strong", {}, item.title.replace(/: (\d+) new, (\d+) gone$/, ": +$1 / −$2").replace(/: the run failed$/, ": a execução falhou")),
                item.body ? el("span", {}, G.translateError(item.body)) : null,
                el("span", { class: "muted" }, relativeTime(item.created_at)),
              ),
            ),
          )
        : el("p", { class: "panel-empty" }, "Nenhuma notificação."),
    );
  }

  if (toggle) {
    toggle.addEventListener("click", (event) => {
      event.stopPropagation();
      openMenu();
    });
    document.addEventListener("click", (event) => {
      if (!menu.hidden && !wrap.contains(event.target)) {
        menu.hidden = true;
        toggle.setAttribute("aria-expanded", "false");
      }
    });
    document.addEventListener("keydown", (event) => {
      if (event.key !== "Escape" || menu.hidden) return;
      menu.hidden = true;
      toggle.setAttribute("aria-expanded", "false");
      if (wrap.contains(document.activeElement)) toggle.focus();
    });
    window.setTimeout(refreshBell, 1500);
    window.setInterval(refreshBell, 60_000);
  }

  G.refreshNotifications = refreshBell;
  G.views.monitors = renderMonitors;
})();
