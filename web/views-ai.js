"use strict";

/* AI investigator: a model plans multi-source queries; GARBAGE runs them. */

(function () {
  const G = window.GARBAGE;
  const { el, api, toast, pageHeader, panel, badge, table, loadingBlock, formatDate, go } = G;
  const STATUS = { running: ["Em andamento", "info"], done: ["Concluída", "success"], error: ["Erro", "danger"] };
  const STEP_STATUS = { ok: "success", rejected: "warning", skipped: "neutral" };

  function button(label, onClick, variant = "button-secondary") {
    return el("button", { class: `button ${variant} button-small`, type: "button", onClick }, label);
  }

  /* The report is model output: shown as text, never as HTML. Headings and
     bullets are styled by line prefix only. */
  function reportView(text) {
    return el(
      "div",
      { class: "ai-report" },
      ...text.split("\n").map((line) => {
        const heading = line.match(/^#{1,4}\s+(.*)/);
        if (heading) return el("h3", {}, heading[1]);
        if (/^\s*[-*]\s+/.test(line)) return el("p", { class: "ai-bullet" }, line.replace(/^\s*[-*]\s+/, "• "));
        return line.trim() ? el("p", {}, line) : null;
      }),
    );
  }

  async function renderAi(root, params = []) {
    const investigations = await G.loadInvestigations();
    const configHost = el("div");
    const listHost = el("div");
    const detailHost = el("div");
    let poll = null;

    const question = el("textarea", {
      class: "input",
      rows: "4",
      placeholder: "Ex.: O que dá para saber sobre a infraestrutura de exemplo.com e quem opera os IPs dela?",
      "aria-label": "Pergunta da investigação",
      maxlength: "4000",
    });
    const caseSelect = el(
      "select",
      { class: "input compact-select", "aria-label": "Investigação" },
      el("option", { value: "" }, "Sem investigação"),
      ...investigations.map((item) => el("option", { value: item.id }, item.name)),
    );
    const stepsInput = el("input", { class: "input compact-select", type: "number", min: "1", max: "10", value: "6", "aria-label": "Máximo de consultas" });

    function drawConfig(config) {
      const ready = config.provider !== "disabled" && config.model;
      configHost.replaceChildren(
        G.kvList([
          ["Provedor", ready ? badge(config.provider, "info") : badge("não configurado", "warning")],
          ["Endpoint", config.base_url || null],
          ["Modelo", config.model || null],
          ["Onde roda", config.provider === "disabled" ? null : config.local ? "Nesta máquina ou na rede local" : "Serviço externo: a pergunta e os resultados das consultas são enviados a ele"],
          ["Chave", config.has_key ? "Salva" : "Nenhuma (normal para Ollama e LM Studio)"],
        ]),
        el(
          "div",
          { class: "row-actions" },
          el("a", { class: "button button-secondary button-small", href: "#/settings" }, "Configurar modelo"),
          el("a", { class: "button button-secondary button-small", href: "#/multisearch/chaves" }, "Chave de API"),
          button("Testar conexão", async () => {
            toast("Testando…");
            const r = await api("/api/ai/test", { method: "POST" });
            toast(r.ok ? `Modelo respondeu: ${r.reply}` : r.error, r.ok ? "success" : "error");
          }),
        ),
      );
    }

    async function showSession(id) {
      clearTimeout(poll);
      const s = await api(`/api/ai/sessions/${id}`);
      const [label, tone] = STATUS[s.status] || [s.status, "neutral"];
      detailHost.replaceChildren(
        panel(
          { eyebrow: "SESSÃO", title: s.question.slice(0, 140), caption: `${s.model} · ${formatDate(s.created_at)}` },
          el("p", {}, badge(label, tone), s.error ? el("span", { class: "muted-text" }, ` ${s.error}`) : null),
          table({
            columns: [
              { label: "#", render: (step) => String(step.index) },
              { label: "CONSULTA", render: (step) => el("code", {}, step.value) },
              { label: "MOTIVO", render: (step) => step.reason || "—" },
              { label: "RESULTADO", render: (step) => badge(step.status === "ok" ? `${step.findings} achados` : step.note || step.status, STEP_STATUS[step.status] || "neutral") },
            ],
            rows: s.steps,
            emptyMessage: s.status === "running" ? "Planejando a primeira consulta…" : "Nenhuma consulta executada.",
            onRowClick: (step) => step.run_id && go("multisearch", step.run_id),
          }),
          s.report ? panel({ eyebrow: "RELATÓRIO", title: "Relatório do analista (gerado por IA)", caption: "Confira as evidências nas consultas antes de usar" }, reportView(s.report)) : null,
        ),
      );
      if (s.status === "running") poll = setTimeout(() => showSession(id).then(loadList), 2500);
    }

    async function loadList() {
      const data = await api("/api/ai/sessions");
      drawConfig(data.config);
      listHost.replaceChildren(
        table({
          columns: [
            { label: "PERGUNTA", render: (s) => s.question.slice(0, 90) },
            { label: "STATUS", render: (s) => badge(...(STATUS[s.status] || [s.status, "neutral"])) },
            { label: "MODELO", render: (s) => s.model },
            { label: "INÍCIO", render: (s) => formatDate(s.created_at) },
          ],
          rows: data.items,
          emptyMessage: "Nenhuma investigação ainda.",
          onRowClick: (s) => showSession(s.id),
        }),
      );
    }

    async function start(event) {
      event.preventDefault();
      const steps = Number(stepsInput.value) || 6;
      if (!confirm(`Iniciar? O modelo vai pedir até ${steps} consultas multifonte. Fontes com chave paga ou limite diário podem consumir cota, e, com um provedor externo, a pergunta e os resultados são enviados a ele.`)) return;
      try {
        const s = await api("/api/ai/sessions", {
          method: "POST",
          body: JSON.stringify({ question: question.value, investigation_id: caseSelect.value || null, max_steps: steps }),
        });
        question.value = "";
        await loadList();
        showSession(s.id);
      } catch (error) {
        toast(error.message, "error");
      }
    }

    root.replaceChildren(
      pageHeader({
        eyebrow: "INTELIGÊNCIA",
        title: "Investigador IA",
        description:
          "Um modelo de linguagem planeja as consultas e encadeia os pivôs; o GARBAGE executa cada uma pelas fontes normais, com as mesmas permissões de rede e chaves. O relatório separa evidência, inferência e hipótese. Funciona com modelos locais (Ollama, LM Studio, llama.cpp, vLLM) ou APIs compatíveis com OpenAI (OpenRouter, OpenAI…) e Anthropic.",
      }),
      panel({ eyebrow: "MODELO", title: "Configuração atual" }, configHost),
      panel(
        { eyebrow: "NOVA", title: "Nova investigação" },
        el("form", { class: "query-panel ai-form", onSubmit: start }, question,
          el("div", { class: "watch-form" }, caseSelect, el("label", { class: "field-hint" }, "Máx. de consultas "), stepsInput,
            el("button", { class: "button button-primary", type: "submit" }, "Investigar"))),
      ),
      detailHost,
      panel({ eyebrow: "HISTÓRICO", title: "Investigações anteriores" }, listHost),
    );
    listHost.replaceChildren(loadingBlock("Carregando…"));
    try {
      await loadList();
      if (params[0]) showSession(params[0]);
    } catch (error) {
      listHost.replaceChildren(G.inlineError(error.message));
    }
  }

  G.views.ai = renderAi;
})();
