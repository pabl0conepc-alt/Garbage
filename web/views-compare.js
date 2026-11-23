"use strict";

/* Two saved multi-source runs side by side, with an explainable score. */

(function () {
  const G = window.GARBAGE;
  const { el, api, pageHeader, panel, badge, table, loadingBlock, formatDate } = G;

  const LEVEL = { strong: ["forte", "danger"], moderate: ["moderada", "warning"], weak: ["fraca", "info"], none: ["nenhuma", "neutral"] };
  const SIGNAL = {
    "same-name": ["Mesmo nome", "O mesmo nome ou identificador aparece nos dois."],
    "normalised-name": ["Nome igual após normalizar", "Os nomes batem depois de tirar separadores, números finais e leetspeak."],
    "similar-name": ["Nome parecido", "Os nomes são muito parecidos."],
    "same-image": ["Mesma imagem", "Os dois usam a mesma URL de avatar, skin ou banner."],
    "same-sites": ["Mesmos sites", "O nome existe nos mesmos sites (nomes comuns coincidem com frequência)."],
    "shared-links": ["Links em comum", "Os dois apontam para os mesmos hosts pouco comuns."],
    "similar-text": ["Bio parecida", "Bios ou descrições compartilham boa parte das palavras."],
    "shared-values": ["Outros achados iguais", "IPs, servidores de nome, certificados, grupos…"],
  };

  async function renderCompare(root) {
    const pickA = el("select", { class: "input", "aria-label": "Primeira consulta" });
    const pickB = el("select", { class: "input", "aria-label": "Segunda consulta" });
    const output = el("div");

    async function run(event) {
      event.preventDefault();
      output.replaceChildren(loadingBlock("Comparando…"));
      try {
        const r = await api("/api/intel/compare", { method: "POST", body: JSON.stringify({ run_a: pickA.value, run_b: pickB.value }) });
        const [label, tone] = LEVEL[r.level];
        output.replaceChildren(
          panel(
            { eyebrow: "RESULTADO", title: `${r.a.query_value}  ×  ${r.b.query_value}`, caption: `Pontuação ${r.score}/100` },
            el("p", {}, badge(`Correspondência ${label}`, tone)),
            table({
              columns: [
                { label: "SINAL", render: (x) => (SIGNAL[x.signal] || [x.signal])[0] },
                { label: "PESO", cellClass: "numeric-col", render: (x) => `+${x.weight}` },
                { label: "POR QUÊ", render: (x) => (SIGNAL[x.signal] || [null, x.detail])[1] },
                { label: "VALORES", render: (x) => x.evidence.join(", ") },
              ],
              rows: r.signals,
              emptyMessage: "Nenhum sinal em comum.",
            }),
            el("p", { class: "tool-limit" }, "Isto é uma pista para revisão manual, não uma identificação. Nomes comuns, hospedagem compartilhada e avatares padrão geram coincidências."),
          ),
        );
      } catch (error) {
        output.replaceChildren(G.inlineError(error.message));
      }
    }

    root.replaceChildren(
      pageHeader({
        eyebrow: "PESQUISA",
        title: "Comparar consultas",
        description: "Duas consultas salvas lado a lado, por exemplo user:alice e user:alice_99, ou um perfil da Steam e um do Roblox. Cada sinal mostra o peso e os valores que o geraram.",
      }),
      panel(
        { eyebrow: "ESCOLHA", title: "Consultas" },
        el("form", { class: "query-panel watch-form", onSubmit: run }, pickA, pickB, el("button", { class: "button button-primary", type: "submit" }, "Comparar")),
      ),
      output,
    );
    const data = await api("/api/intel/runs?limit=100");
    const options = data.items.map((item) => [item.id, `${item.query_type} · ${item.query_value} · ${formatDate(item.started_at)}`]);
    for (const pick of [pickA, pickB]) pick.replaceChildren(...options.map(([id, text]) => el("option", { value: id }, text)));
    if (options.length > 1) pickB.value = options[1][0];
    else output.replaceChildren(el("p", { class: "panel-empty" }, "Faça pelo menos duas consultas para comparar."));
  }

  G.views.compare = renderCompare;
})();
