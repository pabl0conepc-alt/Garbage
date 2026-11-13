"use strict";

/* Relationship graph over the shared entity and relationship records. */

(function () {
  const G = window.GARBAGE;
  const {
    el, svgEl, api, toast, pageHeader, panel, badge, emptyState, loadingBlock,
    formatDate, titleCase, entityTypeLabel, relationshipLabel, statusBadge, go,
  } = G;

  const SIZE_MODES = {
    degree: "Tamanho por conexões",
    betweenness: "Tamanho por intermediação",
    harmonic: "Tamanho por proximidade",
    uniform: "Tamanho uniforme",
  };
  const TYPE_LAYER_CLASS = {
    person: "people",
    username: "accounts",
    profile: "accounts",
    email: "accounts",
    organization: "groups",
    domain: "domains",
    url: "domains",
    ipv4: "ips",
    ipv6: "ips",
    file: "files",
    image: "files",
    hash: "files",
    ioc: "other",
    other: "other",
  };
  const TYPE_COLORS = {
    person: "#C5A36B",
    username: "#C5A36B",
    profile: "#B08F5A",
    email: "#B08F5A",
    organization: "#A592B5",
    domain: "#829EB7",
    url: "#829EB7",
    ipv4: "#79A98A",
    ipv6: "#79A98A",
    file: "#CE7777",
    image: "#CE7777",
    hash: "#CE7777",
    ioc: "#C5A36B",
    other: "#8A939B",
  };
  /* Community colours: the validated categorical slots (style.css --viz-N).
     The seven largest communities get a slot; the rest share a neutral
     "other" colour instead of recycling hues. */
  const COMMUNITY_COLORS = ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#008300", "#9085e9"];
  const OTHER_COMMUNITY = "#6b7178";
  const PIVOT_TYPES = {
    "dns-a": ["ipv4", "hosted-on"], "dns-aaaa": ["ipv6", "hosted-on"], "dns-ns": ["domain", "associated-with"],
    "dns-cname": ["domain", "references"], "dns-mx": ["domain", "associated-with"], nameserver: ["domain", "associated-with"],
    "ct-name": ["domain", "related-to"], "cert-san": ["domain", "related-to"], organization: ["organization", "belongs-to"],
    "abuse-contact": ["email", "associated-with"], "archive-capture": ["url", "references"], "http-redirect": ["url", "references"],
    lookalike: ["domain", "related-to"], asn: ["other", "belongs-to"], "as-name": ["organization", "belongs-to"], cidr: ["other", "belongs-to"],
  };
  const PIVOT_LABELS = {
    "dns-a": "DNS A", "dns-aaaa": "DNS AAAA", "dns-ns": "DNS NS", "dns-cname": "DNS CNAME", "dns-mx": "DNS MX",
    nameserver: "Servidor de nomes", "ct-name": "Nome em certificado", "cert-san": "SAN do certificado",
    organization: "Organização", "abuse-contact": "Contato de abuso", "archive-capture": "Captura arquivada",
    "http-redirect": "Redirecionamento", lookalike: "Domínio semelhante", asn: "ASN", "as-name": "Nome do AS", cidr: "CIDR",
  };

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

  function typeLayerClass(type) {
    return `layer-${TYPE_LAYER_CLASS[type] || "other"}`;
  }

  function updatePath(source, target, radiusOf) {
    const dx = target.x - source.x;
    const dy = target.y - source.y;
    const distance = Math.max(1, Math.hypot(dx, dy));
    const radius = radiusOf(source);
    const targetRadius = radiusOf(target) + 3;
    const x1 = source.x + (dx / distance) * radius;
    const y1 = source.y + (dy / distance) * radius;
    const x2 = target.x - (dx / distance) * targetRadius;
    const y2 = target.y - (dy / distance) * targetRadius;
    return `M ${x1} ${y1} L ${x2} ${y2}`;
  }

  async function renderGraph(root, params) {
    let investigationId = params[0] || "";
    let entityType = "";
    let query = "";
    let layout = "force";
    let graph = { nodes: [], edges: [], investigation: null };
    let selectedId = null;
    let focusedId = null;
    let visibleTypes = null;
    let nodes = [];
    let edges = [];
    let viewport = { x: 0, y: 0, zoom: 1 };
    let panning = null;
    let dragging = null;
    let searchTimer = null;
    let requestToken = 0;
    let colorMode = "type";
    let pathIds = new Set();
    let pathEdgeIds = new Set();
    let sizeMode = "degree";
    let focusDepth = 1;
    let edgeLabels = false;
    let hoverId = null;
    let viewMode = "graph";
    let communityColor = new Map();

    const canvas = el("div", { class: "graph-canvas", tabindex: "0" });
    const svg = svgEl("svg", {
      class: "graph-svg",
      width: "100%",
      height: "100%",
      role: "img",
      "aria-label": "Grafo de relacionamentos entre entidades",
    });
    const legendHost = el("div", { class: "graph-legend" });
    const defs = svgEl("defs");
    const arrow = svgEl("marker", {
      id: "graph-arrow",
      viewBox: "0 0 10 10",
      refX: "9",
      refY: "5",
      markerWidth: "7",
      markerHeight: "7",
      orient: "auto-start-reverse",
    });
    arrow.append(svgEl("path", { d: "M 0 1 L 9 5 L 0 9 z", class: "graph-arrow-head" }));
    defs.append(arrow);
    svg.append(defs);
    const view = svgEl("g", { class: "graph-viewport" });
    const edgeLayer = svgEl("g", { class: "graph-edges" });
    const nodeLayer = svgEl("g", { class: "graph-nodes" });
    const labelLayer = svgEl("g", { class: "graph-labels" });
    view.append(edgeLayer, nodeLayer, labelLayer);
    svg.append(view);
    canvas.append(svg);
    const inspector = el("aside", { class: "graph-inspector" });
    const shell = el(
      "div",
      { class: "graph-shell" },
      el(
        "div",
        { class: "graph-stage" },
        canvas,
        el(
          "div",
          { class: "graph-controls" },
          button("−", () => zoomBy(0.85), { title: "Diminuir zoom" }),
          button("＋", () => zoomBy(1.18), { title: "Aumentar zoom" }),
          button("Ajustar", () => fit(), { title: "Ajustar grafo à tela" }),
          button("Exportar SVG", () => exportSvg(), { title: "Baixar o grafo visível como SVG" }),
          button("Redefinir", () => {
            focusedId = null;
            selectedId = null;
            viewport = { x: 0, y: 0, zoom: 1 };
            applyTransform();
            render();
          }),
        ),
        legendHost,
      ),
      inspector,
    );

    const caseSelect = el(
      "select",
      { class: "input compact-select", "aria-label": "Filtrar grafo por investigação" },
      el("option", { value: "" }, "Todas as investigações"),
      ...(await G.loadInvestigations()).map((item) =>
        el("option", { value: item.id }, item.name),
      ),
    );
    caseSelect.value = investigationId;

    const typeSelect = el(
      "select",
      { class: "input compact-select", "aria-label": "Filtrar grafo por tipo de entidade" },
      el("option", { value: "" }, "Todos os tipos de entidade"),
      ...G.ENTITY_TYPES.map(([value, label]) => el("option", { value }, label)),
    );
    const search = el("input", {
      class: "input",
      type: "search",
      placeholder: "Filtrar entidades por nome ou identificador",
      "aria-label": "Pesquisar entidades no grafo",
    });
    const colorSelect = el(
      "select",
      { class: "input compact-select", "aria-label": "Cor dos nós" },
      el("option", { value: "type" }, "Cor por tipo"),
      el("option", { value: "community" }, "Cor por comunidade"),
    );
    colorSelect.addEventListener("change", () => {
      colorMode = colorSelect.value;
      render();
    });
    const layoutSelect = el(
      "select",
      { class: "input compact-select", "aria-label": "Layout do grafo" },
      ...Object.entries(G.graphLayouts).map(([key, item]) => el("option", { value: key }, item.label)),
    );
    const sizeSelect = el(
      "select",
      { class: "input compact-select", "aria-label": "Tamanho dos nós" },
      ...Object.entries(SIZE_MODES).map(([key, text]) => el("option", { value: key }, text)),
    );
    sizeSelect.addEventListener("change", () => {
      sizeMode = sizeSelect.value;
      render();
    });
    const depthSelect = el(
      "select",
      { class: "input compact-select", "aria-label": "Alcance do foco" },
      el("option", { value: "1" }, "Foco: 1 salto"),
      el("option", { value: "2" }, "Foco: 2 saltos"),
      el("option", { value: "3" }, "Foco: 3 saltos"),
    );
    depthSelect.addEventListener("change", () => {
      focusDepth = Number(depthSelect.value);
      render();
    });
    const edgeLabelToggle = el("input", { type: "checkbox", id: "graph-edge-labels" });
    edgeLabelToggle.addEventListener("change", () => {
      edgeLabels = edgeLabelToggle.checked;
      render();
    });
    const viewTabs = el("div", { class: "graph-view-tabs" });
    const altHost = el("div", { class: "graph-alt", hidden: true });

    async function loadGraph() {
      const token = ++requestToken;
      canvas.classList.add("is-loading");
      const parameters = new URLSearchParams();
      if (investigationId) parameters.set("investigation_id", investigationId);
      if (entityType) parameters.set("entity_type", entityType);
      if (query.trim()) parameters.set("search", query.trim());
      try {
        const data = await api(`/api/graph?${parameters}`);
        if (token !== requestToken) return;
        graph = data;
        nodes = data.nodes.map((node) => ({ ...node, degree: 0 }));
        const byId = new Map(nodes.map((node) => [node.id, node]));
        edges = data.edges.filter(
          (edge) => byId.has(edge.source_entity_id) && byId.has(edge.target_entity_id),
        );
        for (const edge of edges) {
          byId.get(edge.source_entity_id).degree += 1;
          byId.get(edge.target_entity_id).degree += 1;
        }
        if (selectedId && !byId.has(selectedId)) selectedId = null;
        pathIds = new Set();
        pathEdgeIds = new Set();
        if (focusedId && !byId.has(focusedId)) focusedId = null;
        if (query.trim() || investigationId || entityType) {
          rememberQuery();
        }
        rankCommunities();
        layoutNodes();
        fit();
        render();
      } catch (error) {
        if (token !== requestToken) return;
        inspector.replaceChildren(
          panel({ eyebrow: "GRAFO", title: "Não foi possível montar o grafo" }, G.inlineError(error.message)),
        );
      } finally {
        if (token === requestToken) canvas.classList.remove("is-loading");
      }
    }

    function rememberQuery() {
      const history = (G.state.graphHistory = G.state.graphHistory || []);
      const entry = {
        investigationId,
        entityType,
        query: query.trim(),
        investigation:
          G.state.investigations.find((item) => item.id === investigationId)?.name || "",
      };
      const key = JSON.stringify(entry);
      const next = [entry, ...history.filter((item) => JSON.stringify(item) !== key)].slice(0, 8);
      G.state.graphHistory = next;
    }

    function layoutNodes() {
      if (!nodes.length) return;
      const width = Math.max(640, canvas.clientWidth || 960);
      const height = Math.max(480, canvas.clientHeight || 620);
      (G.graphLayouts[layout] || G.graphLayouts.force).run(nodes, edges, {
        width,
        height,
        rootId: selectedId,
        analytics: graph.analytics,
      });
    }

    function radiusOf(node) {
      const metrics = graph.analytics?.nodes?.[node.id];
      if (sizeMode === "uniform") return 11;
      if (sizeMode === "betweenness" && metrics) return 8 + Math.sqrt(metrics.betweenness) * 26;
      if (sizeMode === "harmonic" && metrics) return 7 + metrics.harmonic * 16;
      return 10 + Math.min(12, node.degree * 1.6);
    }

    function rankCommunities() {
      const sizes = new Map();
      for (const node of nodes) {
        const id = graph.analytics?.nodes?.[node.id]?.community;
        if (id !== undefined) sizes.set(id, (sizes.get(id) || 0) + 1);
      }
      communityColor = new Map(
        [...sizes.entries()]
          .sort((a, b) => b[1] - a[1] || a[0] - b[0])
          .map(([id, size], rank) => [id, size > 1 && rank < COMMUNITY_COLORS.length ? COMMUNITY_COLORS[rank] : OTHER_COMMUNITY]),
      );
    }

    function visibleNodeSet() {
      const types = visibleTypes || new Set(graph.nodes.map((node) => node.entity_type));
      const set = new Set(
        graph.nodes.filter((node) => types.has(node.entity_type)).map((node) => node.id),
      );
      if (focusedId && set.has(focusedId)) {
        const neighbors = new Set([focusedId]);
        let frontier = [focusedId];
        for (let hop = 0; hop < focusDepth; hop += 1) {
          const next = [];
          for (const edge of graph.edges) {
            for (const [from, to] of [[edge.source_entity_id, edge.target_entity_id], [edge.target_entity_id, edge.source_entity_id]]) {
              if (frontier.includes(from) && !neighbors.has(to)) {
                neighbors.add(to);
                next.push(to);
              }
            }
          }
          frontier = next;
        }
        for (const id of [...set]) if (!neighbors.has(id)) set.delete(id);
      }
      return set;
    }

    function applyTransform() {
      view.setAttribute(
        "transform",
        `translate(${viewport.x} ${viewport.y}) scale(${viewport.zoom})`,
      );
    }

    function nodeColor(node) {
      if (colorMode === "community") {
        const metrics = graph.analytics?.nodes?.[node.id];
        if (metrics) return communityColor.get(metrics.community) || OTHER_COMMUNITY;
      }
      return TYPE_COLORS[node.entity_type] || TYPE_COLORS.other;
    }

    function percent(value) {
      return `${(Number(value || 0) * 100).toFixed(1)}%`;
    }

    async function showPath(fromId, toId) {
      try {
        const parameters = new URLSearchParams({ from: fromId, to: toId });
        if (investigationId) parameters.set("investigation_id", investigationId);
        const result = await api(`/api/graph/path?${parameters}`);
        pathIds = new Set(result.path.map((item) => item.id));
        pathEdgeIds = new Set(result.hops.map((hop) => hop.relationship_id).filter(Boolean));
        if (!result.path.length) toast("Não há caminho de relacionamentos entre essas entidades.", "warning");
        else toast(`Caminho de ${result.length} salto(s): ${result.path.map((item) => item.name).join(" → ")}`);
        render();
      } catch (error) {
        toast(error.message, "error");
      }
    }

    async function pivotDialog(node) {
      const value = node.identifier || node.name;
      const dialog = el("dialog", { class: "app-dialog pivot-dialog", "aria-label": `Pivotar a partir de ${node.name}` });
      const body = el("div", { class: "pivot-body" }, loadingBlock(`Consultando fontes sobre ${value}…`));
      const submit = el("button", { class: "button button-primary", type: "button", disabled: true }, "Adicionar ao grafo");
      dialog.append(
        el(
          "div",
          { class: "dialog-form" },
          el(
            "div",
            { class: "dialog-heading" },
            el(
              "div",
              {},
              el("p", { class: "eyebrow" }, "PIVÔ"),
              el("h2", {}, node.name),
              el("p", { class: "dialog-description" }, "Escolha quais resultados viram entidades ligadas a este nó. Cada relacionamento fica como \"possível\" e não verificado, citando a fonte."),
            ),
          ),
          body,
          el(
            "div",
            { class: "dialog-actions" },
            el("button", { class: "button button-secondary", type: "button", onClick: () => dialog.close() }, "Cancelar"),
            submit,
          ),
        ),
      );
      document.body.append(dialog);
      dialog.addEventListener("close", () => dialog.remove());
      dialog.showModal();
      let run;
      try {
        run = await api("/api/intel/runs", {
          method: "POST",
          body: JSON.stringify({ value, investigation_id: investigationId || null }),
        });
      } catch (error) {
        body.replaceChildren(G.inlineError(error.message));
        return;
      }
      const self = String(value).toLowerCase();
      const candidates = run.results.filter((item) => {
        if (!PIVOT_TYPES[item.result_type] || item.data?.null_mx) return false;
        const clean = String(item.value).replace(/^\d+\s+/, "").replace(/^\*\./, "").replace(/\.$/, "").toLowerCase();
        return clean && clean !== self;
      });
      if (!candidates.length) {
        const skipped = run.sources.filter((item) => item.status === "network-disabled" || item.status === "target-contact-disabled").length;
        body.replaceChildren(
          el("p", { class: "panel-empty" }, skipped
            ? "Nenhum resultado aproveitável. Fontes de rede estão desativadas: ative-as na Pesquisa multifonte."
            : "Nenhuma fonte retornou resultados que possam virar entidades."),
        );
        return;
      }
      const rows = candidates.map((item) => {
        const [entityType, relationship] = PIVOT_TYPES[item.result_type];
        const check = el("input", { type: "checkbox", checked: ["dns-a", "dns-aaaa", "dns-ns", "dns-mx", "asn", "organization"].includes(item.result_type) });
        const typeSelect = el("select", { class: "input compact-select", "aria-label": "Categoria da entidade" },
          ...G.ENTITY_TYPES.map(([key, label]) => el("option", { value: key, selected: key === entityType }, label)));
        const relSelect = el("select", { class: "input compact-select", "aria-label": "Tipo de relacionamento" },
          ...G.RELATIONSHIP_TYPES.map(([key, label]) => el("option", { value: key, selected: key === relationship }, label)));
        return { item, check, typeSelect, relSelect };
      });
      body.replaceChildren(
        el("p", { class: "run-meta" }, `${run.result_count} resultado(s) de ${run.sources.filter((item) => item.status === "ok").length} fonte(s) · ${candidates.length} podem virar entidades`),
        el(
          "div",
          { class: "pivot-list" },
          ...rows.map(({ item, check, typeSelect, relSelect }) =>
            el(
              "label",
              { class: "pivot-row" },
              check,
              el("span", { class: "pivot-kind" }, PIVOT_LABELS[item.result_type] || item.result_type),
              el("code", { class: "pivot-value" }, item.value),
              typeSelect,
              relSelect,
            ),
          ),
        ),
      );
      submit.disabled = false;
      submit.addEventListener("click", async () => {
        const items = rows
          .filter((row) => row.check.checked)
          .map((row) => ({ result_id: row.item.id, entity_type: row.typeSelect.value, relationship_type: row.relSelect.value }));
        if (!items.length) {
          toast("Selecione pelo menos um resultado.", "warning");
          return;
        }
        submit.disabled = true;
        try {
          const result = await api(`/api/intel/runs/${run.id}/promote`, {
            method: "POST",
            body: JSON.stringify({ source_entity_id: node.id, investigation_id: investigationId || null, items }),
          });
          toast(`${result.created_entities.length} entidade(s) nova(s), ${result.reused_entities.length} reaproveitada(s), ${result.relationships.length} relacionamento(s).`);
          dialog.close();
          await loadGraph();
        } catch (error) {
          submit.disabled = false;
          toast(error.message, "error");
        }
      });
    }

    /* Alternative views ------------------------------------------- */

    function visibleSubgraph() {
      const visible = visibleNodeSet();
      const shown = nodes.filter((node) => visible.has(node.id));
      const links = edges.filter((edge) => visible.has(edge.source_entity_id) && visible.has(edge.target_entity_id));
      return { shown, links };
    }

    function selectFromView(id) {
      selectedId = id;
      viewMode = "graph";
      renderViewTabs();
      render();
    }

    function renderViewTabs() {
      viewTabs.replaceChildren(
        G.tabs({
          items: [
            { key: "graph", label: "Grafo" },
            { key: "matrix", label: "Matriz" },
            { key: "timeline", label: "Linha do tempo" },
          ],
          active: viewMode,
          onSelect: (key) => {
            viewMode = key;
            renderViewTabs();
          },
        }),
      );
      shell.hidden = viewMode !== "graph";
      altHost.hidden = viewMode === "graph";
      if (viewMode === "graph") return;
      const { shown, links } = visibleSubgraph();
      if (!shown.length) {
        altHost.replaceChildren(el("p", { class: "panel-empty" }, "Nenhuma entidade no grafo atual."));
        return;
      }
      if (viewMode === "matrix") {
        const result = G.graphViews.matrix({ nodes: shown, edges: links, analytics: graph.analytics, onSelect: selectFromView });
        altHost.replaceChildren(
          panel(
            {
              eyebrow: "MATRIZ DE ADJACÊNCIA",
              title: `${shown.length} entidades · ${links.length} relacionamentos`,
              caption: result.truncated ? "Mostrando as 150 entidades mais conectadas" : "Linhas e colunas agrupadas por comunidade",
            },
            result.legend,
            result.element,
            el("p", { class: "tool-limit" }, "Cada célula é um relacionamento registrado, nas duas direções. Blocos na diagonal são comunidades; clique numa célula para ver a entidade no grafo."),
          ),
        );
        return;
      }
      altHost.replaceChildren(
        panel(
          { eyebrow: "LINHA DO TEMPO", title: "Quando cada registro entrou no grafo", caption: "Data de registro no workspace, não data do fato" },
          G.charts.legend([
            { label: "Entidade", color: "var(--viz-1)" },
            { label: "Relacionamento", color: "var(--viz-2)" },
          ]),
          G.graphViews.timeline({ nodes: shown, edges: links, onSelect: selectFromView }),
        ),
      );
    }

    /* Standalone SVG of what is on screen, with computed styles inlined. */
    function exportSvg() {
      const { shown } = visibleSubgraph();
      if (!shown.length) {
        toast("Não há nada visível para exportar.", "warning");
        return;
      }
      if (hoverId) {
        hoverId = null;
        render();
      }
      const margin = 60;
      const minX = Math.min(...shown.map((node) => node.x)) - margin;
      const minY = Math.min(...shown.map((node) => node.y)) - margin;
      const width = Math.max(...shown.map((node) => node.x)) + margin - minX;
      const height = Math.max(...shown.map((node) => node.y)) + margin - minY;
      const copy = svg.cloneNode(true);
      const inline = (source, target) => {
        if (source.nodeType !== 1) return;
        const style = getComputedStyle(source);
        const properties = ["fill", "stroke", "stroke-width", "stroke-dasharray", "opacity", "font-size", "font-family", "font-weight"];
        target.setAttribute("style", properties.map((name) => `${name}:${style.getPropertyValue(name)}`).join(";"));
        [...source.children].forEach((child, index) => inline(child, target.children[index]));
      };
      inline(svg, copy);
      copy.querySelector(".graph-viewport").removeAttribute("transform");
      copy.setAttribute("xmlns", "http://www.w3.org/2000/svg");
      copy.setAttribute("viewBox", `${minX} ${minY} ${width} ${height}`);
      copy.setAttribute("width", String(Math.round(width)));
      copy.setAttribute("height", String(Math.round(height)));
      const background = document.createElementNS("http://www.w3.org/2000/svg", "rect");
      background.setAttribute("x", minX);
      background.setAttribute("y", minY);
      background.setAttribute("width", width);
      background.setAttribute("height", height);
      background.setAttribute("fill", getComputedStyle(canvas).backgroundColor || "#15181B");
      copy.insertBefore(background, copy.firstChild.nextSibling);
      const blob = new Blob([new XMLSerializer().serializeToString(copy)], { type: "image/svg+xml" });
      const url = URL.createObjectURL(blob);
      const link = el("a", { href: url, download: `grafo-${new Date().toISOString().slice(0, 10)}.svg` });
      document.body.append(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      toast("SVG do grafo exportado.");
    }

    function render() {
      applyTransform();
      const visible = visibleNodeSet();
      const visibleNodes = nodes.filter((node) => visible.has(node.id));
      const visibleEdges = edges.filter(
        (edge) =>
          visible.has(edge.source_entity_id) && visible.has(edge.target_entity_id),
      );
      edgeLayer.replaceChildren();
      nodeLayer.replaceChildren();
      labelLayer.replaceChildren();
      const byId = new Map(nodes.map((node) => [node.id, node]));

      for (const edge of visibleEdges) {
        const source = byId.get(edge.source_entity_id);
        const target = byId.get(edge.target_entity_id);
        if (!source || !target) continue;
        const near = hoverId && (edge.source_entity_id === hoverId || edge.target_entity_id === hoverId);
        const path = svgEl("path", {
          d: updatePath(source, target, radiusOf),
          class: `graph-edge verification-${edge.verification_status || "not-verified"}${pathEdgeIds.has(edge.id) ? " is-path" : ""}${near ? " is-near" : ""}`,
          "data-id": edge.id,
          "marker-end": "url(#graph-arrow)",
        });
        path.append(
          svgEl("title", {}, `${source.name} — ${relationshipLabel(edge.relationship_type)} → ${target.name}`),
        );
        edgeLayer.append(path);
        if (edgeLabels) {
          labelLayer.append(
            svgEl(
              "text",
              {
                x: (source.x + target.x) / 2,
                y: (source.y + target.y) / 2 - 4,
                "text-anchor": "middle",
                class: `graph-edge-label${near ? " is-near" : ""}`,
                "data-edge": edge.id,
              },
              relationshipLabel(edge.relationship_type),
            ),
          );
        }
      }
      const neighbourIds = new Set(hoverId ? [hoverId] : []);
      if (hoverId) {
        for (const edge of visibleEdges) {
          if (edge.source_entity_id === hoverId) neighbourIds.add(edge.target_entity_id);
          if (edge.target_entity_id === hoverId) neighbourIds.add(edge.source_entity_id);
        }
      }
      svg.classList.toggle("has-hover", Boolean(hoverId));

      for (const node of visibleNodes) {
        const radius = radiusOf(node);
        const group = svgEl("g", {
          class: `graph-node type-${node.entity_type}${node.id === selectedId ? " is-selected" : ""}${pathIds.has(node.id) ? " is-path" : ""}${neighbourIds.has(node.id) ? " is-near" : ""}`,
          transform: `translate(${node.x} ${node.y})`,
          tabindex: "0",
          role: "button",
          "aria-label": `${entityTypeLabel(node.entity_type)}: ${node.name}`,
          "data-id": node.id,
        });
        const circle = svgEl("circle", {
          r: radius,
          fill: nodeColor(node),
          class: "graph-node-circle",
        });
        circle.append(svgEl("title", {}, `${node.name} · ${entityTypeLabel(node.entity_type)}`));
        group.append(circle);
        group.addEventListener("click", (event) => {
          event.stopPropagation();
          selectedId = node.id;
          render();
        });
        group.addEventListener("keydown", (event) => {
          if (event.key === "Enter" || event.key === " ") {
            selectedId = node.id;
            render();
          }
        });
        group.addEventListener("pointerenter", () => {
          if (dragging || panning) return;
          hoverId = node.id;
          render();
        });
        group.addEventListener("pointerleave", () => {
          if (hoverId !== node.id) return;
          hoverId = null;
          render();
        });
        group.addEventListener("pointerdown", (event) => {
          if (event.button !== 0) return;
          event.stopPropagation();
          event.preventDefault();
          group.setPointerCapture(event.pointerId);
          dragging = {
            node,
            group,
            pointerId: event.pointerId,
            startX: event.clientX,
            startY: event.clientY,
            originX: node.x,
            originY: node.y,
            moved: false,
          };
          group.classList.add("is-dragging");
          canvas.focus({ preventScroll: true });
        });
        nodeLayer.append(group);
        const label = svgEl(
          "text",
          {
            x: node.x,
            y: node.y + radius + 14,
            "text-anchor": "middle",
            class: `graph-node-label${neighbourIds.has(node.id) ? " is-near" : ""}`,
            "data-id": node.id,
          },
          node.name.length > 26 ? `${node.name.slice(0, 24)}…` : node.name,
        );
        labelLayer.append(label);
      }
      canvas.classList.toggle("is-empty", nodes.length === 0);
      legendHost.replaceChildren(legend());
      renderInspector();
    }

    function updateGeometry() {
      const byId = new Map(nodes.map((node) => [node.id, node]));
      for (const group of nodeLayer.querySelectorAll(".graph-node")) {
        const node = byId.get(group.dataset.id);
        if (!node) continue;
        group.setAttribute("transform", `translate(${node.x} ${node.y})`);
      }
      for (const label of labelLayer.querySelectorAll(".graph-node-label")) {
        const id = label.dataset.id;
        const node = byId.get(id);
        if (!node) continue;
        const radius = radiusOf(node);
        label.setAttribute("x", node.x);
        label.setAttribute("y", node.y + radius + 14);
      }
      for (const path of edgeLayer.querySelectorAll(".graph-edge")) {
        const edge = edges.find((item) => item.id === path.dataset.id);
        if (!edge) continue;
        const source = byId.get(edge.source_entity_id);
        const target = byId.get(edge.target_entity_id);
        if (source && target) path.setAttribute("d", updatePath(source, target, radiusOf));
      }
      for (const text of labelLayer.querySelectorAll(".graph-edge-label")) {
        const edge = edges.find((item) => item.id === text.dataset.edge);
        const source = edge && byId.get(edge.source_entity_id);
        const target = edge && byId.get(edge.target_entity_id);
        if (!source || !target) continue;
        text.setAttribute("x", (source.x + target.x) / 2);
        text.setAttribute("y", (source.y + target.y) / 2 - 4);
      }
    }

    function zoomBy(factor) {
      const rect = canvas.getBoundingClientRect();
      const pointerX = rect.width / 2;
      const pointerY = rect.height / 2;
      const worldX = (pointerX - viewport.x) / viewport.zoom;
      const worldY = (pointerY - viewport.y) / viewport.zoom;
      viewport.zoom = Math.min(4, Math.max(0.15, viewport.zoom * factor));
      viewport.x = pointerX - worldX * viewport.zoom;
      viewport.y = pointerY - worldY * viewport.zoom;
      applyTransform();
    }

    function fit() {
      if (!nodes.length) {
        viewport = { x: 0, y: 0, zoom: 1 };
        applyTransform();
        return;
      }
      const minX = Math.min(...nodes.map((node) => node.x)) - 80;
      const minY = Math.min(...nodes.map((node) => node.y)) - 80;
      const maxX = Math.max(...nodes.map((node) => node.x)) + 80;
      const maxY = Math.max(...nodes.map((node) => node.y)) + 80;
      const rect = canvas.getBoundingClientRect();
      const width = Math.max(1, maxX - minX);
      const height = Math.max(1, maxY - minY);
      const zoom = Math.min(
        1.4,
        Math.max(0.15, Math.min((rect.width || 960) / width, (rect.height || 620) / height)),
      );
      viewport.zoom = Number(zoom.toFixed(3));
      viewport.x = Math.round(((rect.width || 960) - width * zoom) / 2 - minX * zoom);
      viewport.y = Math.round(((rect.height || 620) - height * zoom) / 2 - minY * zoom);
      applyTransform();
    }

    function renderInspector() {
      if (selectedId) {
        const node = nodes.find((item) => item.id === selectedId);
        if (!node) {
          selectedId = null;
          return renderInspector();
        }
        const related = edges
          .filter(
            (edge) =>
              edge.source_entity_id === node.id || edge.target_entity_id === node.id,
          )
          .map((edge) => {
            const outgoing = edge.source_entity_id === node.id;
            const otherId = outgoing ? edge.target_entity_id : edge.source_entity_id;
            const other = nodes.find((item) => item.id === otherId);
            return { edge, outgoing, other };
          })
          .filter((item) => item.other);
        inspector.replaceChildren(
          panel(
            {
              eyebrow: "INSPETOR DE NÓ",
              title: node.name,
              actions: [statusBadge(node.verification_status)],
            },
            G.kvList([
              ["Categoria", badge(entityTypeLabel(node.entity_type), "info")],
              ["Identificador", node.identifier || "—"],
              ["Confiança", titleCase(node.confidence)],
              ["Relacionamentos", String(node.degree)],
            ]),
            graph.analytics?.nodes?.[node.id]
              ? el(
                  "div",
                  {},
                  el("h3", { class: "subheading" }, "Posição no grafo"),
                  G.kvList([
                    ["Centralidade de grau", percent(graph.analytics.nodes[node.id].degree)],
                    ["Intermediação", percent(graph.analytics.nodes[node.id].betweenness)],
                    ["Proximidade harmônica", percent(graph.analytics.nodes[node.id].harmonic)],
                    [
                      "Comunidade",
                      `#${graph.analytics.nodes[node.id].community + 1} · ${graph.analytics.nodes[node.id].community_size} entidade(s)`,
                    ],
                  ]),
                )
              : null,
            node.description ? el("p", { class: "prose" }, node.description) : null,
            el(
              "div",
              { class: "inspector-actions" },
              button("Abrir registro da entidade", () => go("entities", node.id), {
                variant: "button-primary",
              }),
              G.moduleEnabled("intel-orchestrator") && (node.identifier || node.name)
                ? button("Pivotar", () => pivotDialog(node))
                : null,
              button(
                focusedId === node.id ? "Limpar foco" : "Focar vizinhança",
                () => {
                  focusedId = focusedId === node.id ? null : node.id;
                  render();
                },
              ),
              button("Reorganizar a partir deste nó", () => {
                if (!["hierarchical", "radial"].includes(layout)) {
                  layout = "radial";
                  layoutSelect.value = layout;
                }
                layoutNodes();
                fit();
                render();
              }, { title: "Layout radial ou hierárquico com este nó no centro ou no topo" }),
            ),
            nodes.length > 1
              ? el(
                  "div",
                  { class: "field" },
                  el("label", {}, "Caminho até"),
                  el(
                    "select",
                    {
                      class: "input",
                      "aria-label": "Mostrar caminho até outra entidade",
                      onChange: (event) => {
                        if (event.target.value) showPath(node.id, event.target.value);
                        else {
                          pathIds = new Set();
                          pathEdgeIds = new Set();
                          render();
                        }
                      },
                    },
                    el("option", { value: "" }, "Escolha uma entidade"),
                    ...nodes
                      .filter((item) => item.id !== node.id)
                      .sort((a, b) => a.name.localeCompare(b.name))
                      .map((item) => el("option", { value: item.id }, item.name)),
                  ),
                )
              : null,
            el("h3", { class: "subheading" }, `Relacionamentos (${related.length})`),
            related.length
              ? el(
                  "div",
                  { class: "graph-relation-list" },
                  ...related.map(({ edge, outgoing, other }) =>
                    el(
                      "div",
                      { class: "graph-relation" },
                      el(
                        "div",
                        { class: "graph-relation-heading" },
                        el("span", { class: "relation-direction" }, outgoing ? "→" : "←"),
                        el(
                          "button",
                          {
                            class: "link-button",
                            type: "button",
                            onClick: () => {
                              selectedId = other.id;
                              render();
                            },
                          },
                          other.name,
                        ),
                      ),
                      el(
                        "div",
                        { class: "record-meta" },
                        el("span", {}, relationshipLabel(edge.relationship_type)),
                        statusBadge(edge.verification_status),
                        edge.investigation_id
                          ? el(
                              "a",
                              { class: "table-link", href: `#/investigations/${edge.investigation_id}` },
                              "Caso",
                            )
                          : null,
                      ),
                      edge.description ? el("p", { class: "panel-note" }, edge.description) : null,
                    ),
                  ),
                )
              : el("p", { class: "panel-empty" }, "Nenhum relacionamento registrado para esta entidade."),
          ),
          panel(
            { eyebrow: "FILTROS", title: "Camadas de entidades" },
            el(
              "div",
              { class: "graph-type-list" },
              ...typeLegendNodes(),
            ),
            button("Mostrar todas as camadas", () => {
              visibleTypes = null;
              render();
            }),
          ),
        );
        return;
      }
      const components = countComponents();
      const graphMetrics = graph.metrics || {};
      const hub = nodes.find((node) => node.id === graphMetrics.max_degree_node);
      const metricRows = [
        ["Investigação", graph.investigation ? graph.investigation.name : "Todos os casos"],
        ["Entidades exibidas", String(nodes.length)],
        ["Relacionamentos exibidos", String(edges.length)],
        ["Componentes conectados", String(components)],
      ];
      if (graphMetrics.density !== undefined) {
        metricRows.push(
          ["Densidade", `${(Number(graphMetrics.density) * 100).toFixed(1)}%`],
          ["Entidades isoladas", String(graphMetrics.isolates ?? 0)],
          [
            "Maior grau",
            `${graphMetrics.max_degree ?? 0}${hub ? ` · ${hub.name}` : ""}`,
          ],
          ["Vínculos recíprocos", String(graphMetrics.reciprocal_edges ?? 0)],
        );
      }
      metricRows.push([
        "Layout",
        (G.graphLayouts[layout] || G.graphLayouts.force).label,
      ]);
      if (graphMetrics.engine) {
        metricRows.push(["Motor de métricas", graphMetrics.engine]);
      }
      const analytics = graph.analytics;
      if (analytics && nodes.length) {
        metricRows.push(
          ["Comunidades", String(analytics.communities)],
          ["Modularidade", Number(analytics.modularity).toFixed(3)],
        );
      }
      const bridges = analytics
        ? nodes
            .map((node) => ({ node, value: analytics.nodes[node.id]?.betweenness || 0 }))
            .filter((item) => item.value > 0)
            .sort((a, b) => b.value - a.value)
            .slice(0, 5)
        : [];
      inspector.replaceChildren(
        ...[
        panel(
          { eyebrow: "GRAFO DE RELACIONAMENTOS", title: "Visão geral do grafo" },
          G.kvList(metricRows),
          nodes.length
            ? el(
                "p",
                { class: "panel-note" },
                "Relacionamentos continuam sendo registros do analista. Uma linha indica uma associação registrada, não prova de coordenação.",
              )
            : null,
        ),
        bridges.length
          ? panel(
              { eyebrow: "ANÁLISE", title: "Entidades-ponte" },
              el(
                "div",
                { class: "graph-relation-list" },
                ...bridges.map(({ node, value }) =>
                  el(
                    "div",
                    { class: "graph-relation" },
                    el("button", { class: "link-button", type: "button", onClick: () => { selectedId = node.id; render(); } }, node.name),
                    el("span", { class: "record-meta" }, `intermediação ${percent(value)}`),
                  ),
                ),
              ),
              el("p", { class: "panel-note" }, "Entidades que mais aparecem nos caminhos mais curtos entre outras. Indicam ligação estrutural, não papel real."),
            )
          : null,
        panel(
          { eyebrow: "CAMADAS", title: "Tipos de entidade" },
          el("div", { class: "graph-type-list" }, ...typeLegendNodes()),
          button("Mostrar todas as camadas", () => {
            visibleTypes = null;
            render();
          }),
        ),
        historyPanel(),
        ].filter(Boolean),
      );
    }

    function typeLegendNodes() {
      const types = [...new Set(nodes.map((node) => node.entity_type))].sort();
      if (!types.length) {
        return [el("p", { class: "panel-empty" }, "Nenhuma entidade no grafo atual.")];
      }
      return types.map((type) => {
        const count = nodes.filter((node) => node.entity_type === type).length;
        const checked = !visibleTypes || visibleTypes.has(type);
        return el(
          "label",
          { class: "layer-toggle" },
          el("input", {
            type: "checkbox",
            checked,
            onChange: (event) => {
              if (!visibleTypes) {
                visibleTypes = new Set(types);
              }
              if (event.target.checked) visibleTypes.add(type);
              else visibleTypes.delete(type);
              render();
            },
          }),
          el("span", { class: `layer-swatch ${typeLayerClass(type)}` }),
          `${entityTypeLabel(type)} (${count})`,
        );
      });
    }

    function historyPanel() {
      const history = G.state.graphHistory || [];
      return panel(
        { eyebrow: "HISTÓRICO", title: "Consultas recentes ao grafo" },
        history.length
          ? el(
              "div",
              { class: "query-history" },
              ...history.map((entry) =>
                button(
                  `${entry.investigation || "Todos os casos"} · ${entry.query || entry.entityType || "grafo completo"}`,
                  () => {
                    investigationId = entry.investigationId || "";
                    entityType = entry.entityType || "";
                    query = entry.query || "";
                    caseSelect.value = investigationId;
                    typeSelect.value = entityType;
                    search.value = query;
                    loadGraph();
                  },
                ),
              ),
            )
          : el("p", { class: "panel-empty" }, "Consultas filtradas ao grafo aparecem aqui."),
      );
    }

    function countComponents() {
      const adjacency = new Map(nodes.map((node) => [node.id, []]));
      for (const edge of edges) {
        adjacency.get(edge.source_entity_id)?.push(edge.target_entity_id);
        adjacency.get(edge.target_entity_id)?.push(edge.source_entity_id);
      }
      const seen = new Set();
      let count = 0;
      for (const node of nodes) {
        if (seen.has(node.id)) continue;
        count += 1;
        const stack = [node.id];
        while (stack.length) {
          const current = stack.pop();
          if (seen.has(current)) continue;
          seen.add(current);
          for (const neighbor of adjacency.get(current) || []) {
            if (!seen.has(neighbor)) stack.push(neighbor);
          }
        }
      }
      return count;
    }

    function legend() {
      if (colorMode === "community" && communityColor.size) {
        const counts = new Map();
        for (const node of nodes) {
          const color = communityColor.get(graph.analytics?.nodes?.[node.id]?.community) || OTHER_COMMUNITY;
          counts.set(color, (counts.get(color) || 0) + 1);
        }
        const entries = COMMUNITY_COLORS.filter((color) => counts.has(color)).map((color, index) => [color, `Comunidade ${index + 1}`]);
        if (counts.has(OTHER_COMMUNITY)) entries.push([OTHER_COMMUNITY, "Outras / isoladas"]);
        return el(
          "div",
          { class: "legend-items" },
          ...entries.map(([color, text]) => {
            const dot = el("span", { class: "legend-dot" });
            dot.style.background = color;
            return el("span", { class: "legend-item" }, dot, `${text} (${counts.get(color)})`);
          }),
        );
      }
      return el(
        "div",
        { class: "legend-items" },
        ...["domain", "ipv4", "person", "organization", "file", "hash"].map((type) =>
          el(
            "span",
            { class: "legend-item" },
            el("span", { class: `legend-dot ${typeLayerClass(type)}` }),
            entityTypeLabel(type),
          ),
        ),
      );
    }

    /* Interaction -------------------------------------------------- */

    canvas.addEventListener("pointerdown", (event) => {
      if (event.button !== 0) return;
      if (event.target.closest(".graph-node")) return;
      event.preventDefault();
      canvas.setPointerCapture(event.pointerId);
      panning = {
        pointerId: event.pointerId,
        startX: event.clientX,
        startY: event.clientY,
        originX: viewport.x,
        originY: viewport.y,
      };
      canvas.classList.add("is-panning");
      if (selectedId) {
        selectedId = null;
        render();
      }
    });

    canvas.addEventListener("pointermove", (event) => {
      if (dragging && event.pointerId === dragging.pointerId) {
        const dx = (event.clientX - dragging.startX) / viewport.zoom;
        const dy = (event.clientY - dragging.startY) / viewport.zoom;
        if (Math.abs(dx) > 1 || Math.abs(dy) > 1) dragging.moved = true;
        dragging.node.x = dragging.originX + dx;
        dragging.node.y = dragging.originY + dy;
        updateGeometry();
        return;
      }
      if (panning && event.pointerId === panning.pointerId) {
        viewport.x = panning.originX + event.clientX - panning.startX;
        viewport.y = panning.originY + event.clientY - panning.startY;
        applyTransform();
      }
    });

    function endPointer(event) {
      if (dragging && event.pointerId === dragging.pointerId) {
        dragging.group.classList.remove("is-dragging");
        if (!dragging.moved) {
          selectedId = dragging.node.id;
          render();
        }
        dragging = null;
      }
      if (panning && event.pointerId === panning.pointerId) {
        panning = null;
        canvas.classList.remove("is-panning");
      }
    }
    canvas.addEventListener("pointerup", endPointer);
    canvas.addEventListener("pointercancel", endPointer);

    canvas.addEventListener(
      "wheel",
      (event) => {
        event.preventDefault();
        const rect = canvas.getBoundingClientRect();
        const pointerX = event.clientX - rect.left;
        const pointerY = event.clientY - rect.top;
        const worldX = (pointerX - viewport.x) / viewport.zoom;
        const worldY = (pointerY - viewport.y) / viewport.zoom;
        viewport.zoom = Math.min(
          4,
          Math.max(0.15, viewport.zoom * Math.exp(-event.deltaY * 0.0012)),
        );
        viewport.x = pointerX - worldX * viewport.zoom;
        viewport.y = pointerY - worldY * viewport.zoom;
        applyTransform();
      },
      { passive: false },
    );

    caseSelect.addEventListener("change", () => {
      investigationId = caseSelect.value;
      loadGraph();
    });
    typeSelect.addEventListener("change", () => {
      entityType = typeSelect.value;
      loadGraph();
    });
    layoutSelect.addEventListener("change", () => {
      layout = layoutSelect.value;
      layoutNodes();
      fit();
      render();
    });
    search.addEventListener("input", () => {
      window.clearTimeout(searchTimer);
      searchTimer = window.setTimeout(() => {
        query = search.value;
        loadGraph();
      }, 260);
    });

    root.replaceChildren(
      pageHeader({
        eyebrow: "ANÁLISE DE RELACIONAMENTOS",
        title: "Grafo de relacionamentos",
        description:
          "Nós de entidades e relacionamentos registrados pelo analista no registro compartilhado. Arestas são associações, não provas.",
        actions: [
          button("Quadro", () => go("board", investigationId || undefined)),
          button("Entidades", () => go("entities")),
        ],
      }),
      el(
        "div",
        { class: "graph-toolbar" },
        caseSelect,
        typeSelect,
        layoutSelect,
        colorSelect,
        sizeSelect,
        depthSelect,
        el("label", { class: "toolbar-check", for: "graph-edge-labels" }, edgeLabelToggle, "Rótulos nas arestas"),
        el("div", { class: "search-field" }, el("span", { class: "search-field-icon" }, G.icon("search", { size: 14 })), search),
      ),
      viewTabs,
      shell,
      altHost,
    );

    renderViewTabs();
    await loadGraph();
  }

  G.views.graph = renderGraph;
})();
