"use strict";

/* Watchlists: identifiers re-checked on a schedule, with change alerts. */

(function () {
  const G = window.GARBAGE;
  const { el, api, toast, pageHeader, panel, badge, table, loadingBlock, formatDate } = G;

  const INTERVALS = [
    [60, "A cada hora"],
    [360, "A cada 6 horas"],
    [1440, "Diariamente"],
    [10080, "Semanalmente"],
  ];
  const intervalLabel = (minutes) => (INTERVALS.find(([value]) => value === minutes) || [0, `${minutes} min`])[1];

  function button(label, onClick, variant = "button-secondary") {
    return el("button", { class: `button ${variant} button-small`, type: "button", onClick }, label);
  }

  async function renderWatchlist(root) {
    const listHost = el("div");
    const alertsHost = el("div");

    const valueInput = el("input", {
      class: "input",
      type: "text",
      placeholder: "Domínio, IP, e-mail, user:<nome>, discord:<id>…",
      "aria-label": "Identificador para monitorar",
      maxlength: "2000",
    });
    const labelInput = el("input", { class: "input", type: "text", placeholder: "Rótulo (opcional)", "aria-label": "Rótulo", maxlength: "120" });
    const intervalSelect = el(
      "select",
      { class: "input compact-select", "aria-label": "Frequência" },
      ...INTERVALS.map(([value, label]) => el("option", { value: String(value), selected: value === 1440 }, label)),
    );

    async function add(event) {
      event.preventDefault();
      try {
        await api("/api/watchlist", {
          method: "POST",
          body: JSON.stringify({ value: valueInput.value, label: labelInput.value, interval_minutes: Number(intervalSelect.value) }),
        });
        valueInput.value = "";
        labelInput.value = "";
        toast("Identificador adicionado. A primeira verificação cria a linha de base.");
        await refresh();
      } catch (error) {
        toast(error.message, "error");
      }
    }

    async function act(path, options, message) {
      try {
        const result = await api(path, options);
        if (message) toast(typeof message === "function" ? message(result) : message);
        await refresh();
      } catch (error) {
        toast(error.message, "error");
      }
    }

    function drawWatches(data) {
      listHost.replaceChildren(
        table({
          columns: [
            { label: "IDENTIFICADOR", render: (w) => el("span", {}, el("strong", {}, w.label || w.value), w.label ? el("small", { class: "muted" }, ` ${w.value}`) : null) },
            { label: "TIPO", render: (w) => badge(w.query_type, "info") },
            { label: "FREQUÊNCIA", render: (w) => intervalLabel(w.interval_minutes) },
            {
              label: "ÚLTIMA VERIFICAÇÃO",
              render: (w) =>
                w.last_error
                  ? el("span", { class: "muted-text" }, `Erro: ${w.last_error}`)
                  : w.last_checked_at
                    ? formatDate(w.last_checked_at)
                    : "Ainda não verificado",
            },
            { label: "AVISOS", render: (w) => (w.warnings.length ? badge(w.warnings.join("; "), "warning") : "—") },
            {
              label: "",
              render: (w) =>
                el(
                  "div",
                  { class: "row-actions" },
                  button("Verificar agora", () =>
                    act(`/api/watchlist/${w.id}/check`, { method: "POST" }, (r) =>
                      r.baseline ? "Linha de base criada." : r.alerts.length ? `${r.alerts.length} alerta(s) novo(s).` : "Nada mudou.",
                    ),
                  ),
                  button(w.enabled ? "Pausar" : "Retomar", () =>
                    act(`/api/watchlist/${w.id}`, { method: "PATCH", body: JSON.stringify({ enabled: !w.enabled }) }),
                  ),
                  button("Remover", () => {
                    if (confirm(`Parar de monitorar ${w.value}? Os alertas dele também serão apagados.`)) {
                      act(`/api/watchlist/${w.id}`, { method: "DELETE" }, "Removido.");
                    }
                  }),
                ),
            },
          ],
          rows: data.items,
          emptyMessage: "Nenhum identificador monitorado.",
        }),
      );
    }

    function changeList(items, tone) {
      return items.map((item) => el("li", {}, badge(item.connector, tone), ` ${item.type}: `, el("code", {}, item.value)));
    }

    function drawAlerts(data) {
      if (!data.items.length) {
        alertsHost.replaceChildren(el("p", { class: "panel-empty" }, "Nenhum alerta ainda."));
        return;
      }
      alertsHost.replaceChildren(
        ...data.items.map((alert) =>
          el(
            "details",
            { class: `watch-alert${alert.read ? "" : " unread"}` },
            el(
              "summary",
              {},
              badge(alert.kind === "expiry" ? "Expiração" : "Mudança", alert.kind === "expiry" ? "warning" : "info"),
              " ",
              el("strong", {}, alert.summary),
              el("small", { class: "muted" }, ` · ${formatDate(alert.created_at)}`),
            ),
            alert.details.warnings ? el("ul", {}, ...alert.details.warnings.map((text) => el("li", {}, text))) : null,
            alert.details.added?.length ? el("div", {}, el("p", {}, "Novo:"), el("ul", {}, ...changeList(alert.details.added, "success"))) : null,
            alert.details.removed?.length ? el("div", {}, el("p", {}, "Sumiu:"), el("ul", {}, ...changeList(alert.details.removed, "neutral"))) : null,
            alert.run_id ? el("a", { class: "table-link", href: `#/multisearch/${alert.run_id}` }, "Abrir a consulta completa") : null,
          ),
        ),
      );
    }

    async function refresh() {
      const [watches, alerts] = await Promise.all([api("/api/watchlist"), api("/api/watchlist/alerts")]);
      drawWatches(watches);
      drawAlerts(alerts);
      unreadBadge.textContent = watches.unread_alerts ? `${watches.unread_alerts} não lido(s)` : "";
    }

    const unreadBadge = el("span", { class: "muted" });
    root.replaceChildren(
      pageHeader({
        eyebrow: "INTELIGÊNCIA",
        title: "Monitoramento",
        description:
          "Identificadores seus ou que você tem autorização para acompanhar, consultados de novo em todas as fontes compatíveis. Cada verificação é comparada com a anterior; mudanças e certificados ou domínios perto de expirar viram alertas (e vão para o webhook, se configurado). Exige acesso à rede nas Configurações.",
      }),
      panel(
        { eyebrow: "NOVO", title: "Monitorar identificador" },
        el("form", { class: "query-panel watch-form", onSubmit: add }, valueInput, labelInput, intervalSelect, el("button", { class: "button button-primary", type: "submit" }, "Adicionar")),
      ),
      panel({ eyebrow: "LISTA", title: "Identificadores monitorados" }, listHost),
      panel(
        {
          eyebrow: "ALERTAS",
          title: "Alertas recentes",
          actions: [unreadBadge, button("Marcar todos como lidos", () => act("/api/watchlist/alerts/read", { method: "POST", body: "{}" }))],
        },
        alertsHost,
      ),
    );
    listHost.replaceChildren(loadingBlock("Carregando…"));
    try {
      await refresh();
    } catch (error) {
      listHost.replaceChildren(G.inlineError(error.message));
    }
  }

  G.views.watchlist = renderWatchlist;
})();
