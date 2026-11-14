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
  /* Monochrome: entity families are lightness steps; the community view
     is the one place hue carries meaning. */
  const TYPE_COLORS = {
    person: "#F0F1F2",
    username: "#E1E4E7",
    profile: "#E1E4E7",
    email: "#D2D6DA",
    organization: "#C3C8CD",
    domain: "#B4BAC0",
    url: "#A5ACB3",
    ipv4: "#969DA4",
    ipv6: "#969DA4",
    file: "#7A8188",
    image: "#7A8188",
    hash: "#6C737A",
    ioc: "#D2D6DA",
    other: "#5F666D",
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
    let selection = new Set();
    let pinned = new Map();
    let hidden = new Set();
    let marquee = null;
    const tools = G.graphTools;
    const history = new tools.ViewHistory();
    const enrichment = new Map();

    const canvas = el("div", { class: "graph-canvas", tabindex: "0" });
    const svg = svgEl("svg", {
      class: "graph-svg",
      width: "100%",
      height: "100%",
      role: "group",
      "aria-label": "Grafo de relacionamentos entre entidades",
    });
    const legendHost = el("div", { class: "graph-legend" });
    const truncatedNotice = el("p", { class: "graph-truncated", role: "status", hidden: true });
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
    const marqueeRect = svgEl("rect", { class: "graph-marquee", visibility: "hidden" });
    view.append(edgeLayer, nodeLayer, labelLayer, marqueeRect);
    svg.append(view);
    canvas.append(svg);
    const inspector = el("aside", { class: "graph-inspector" });
    const undoButton = button("Desfazer", () => undo(), { title: "Desfazer a última mudança de visualização (Ctrl+Z)", disabled: true });
    const redoButton = button("Refazer", () => redo(), { title: "Refazer (Ctrl+Shift+Z)", disabled: true });
    const hiddenButton = button("", () => showHidden(), { title: "Mostrar de novo as entidades ocultas" });
    hiddenButton.hidden = true;
    const exportMenu = el(
      "details",
      { class: "graph-menu" },
      el("summary", { class: "button button-secondary button-small" }, "Exportar"),
      el(
        "div",
        { class: "graph-menu-list" },
        menuItem("Imagem PNG", () => exportPng()),
        menuItem("Imagem SVG", () => exportSvg()),
        menuItem("GraphML (Gephi, yEd)", () => exportData("graphml")),
        menuItem("JSON com layout", () => exportData("json")),
      ),
    );
    const map = tools.minimap({
      onNavigate: (x, y) => {
        const rect = canvas.getBoundingClientRect();
        viewport.x = rect.width / 2 - x * viewport.zoom;
        viewport.y = rect.height / 2 - y * viewport.zoom;
        applyTransform();
      },
    });

    function menuItem(label, action) {
      return el(
        "button",
        {
          class: "graph-menu-item",
          type: "button",
          onClick: () => {
            exportMenu.open = false;
            action();
          },
        },
        label,
      );
    }

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
          undoButton,
          redoButton,
          exportMenu,
          button("Importar", () => importDialog(), { title: "Importar GraphML ou JSON, ou restaurar um layout exportado" }),
          hiddenButton,
          button("Redefinir", () => {
            record();
            focusedId = null;
            selectedId = null;
            selection = new Set();
            pinned = new Map();
            hidden = new Set();
            persistView();
            layoutNodes();
            fit();
            render();
          }, { title: "Soltar fixações, mostrar ocultos e refazer o layout" }),
        ),
        legendHost,
        truncatedNotice,
        map.element,
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

    async function loadGraph(options = {}) {
      const previous = options.keepPositions ? new Map(nodes.map((node) => [node.id, { x: node.x, y: node.y }])) : null;
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
        const cut = data.truncated;
        truncatedNotice.hidden = !cut;
        truncatedNotice.textContent = cut
          ? `Mostrando as ${cut.nodes_shown} entidades mais conectadas de ${cut.nodes_total} e ${cut.edges_shown} de ${cut.edges_total} relacionamentos. Filtre por tipo ou pesquise para ver o restante.`
          : "";
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
        if (!previous) restoreSavedView();
        layoutNodes();
        if (previous) {
          placeAround(previous);
          enrichment.clear();
        } else {
          history.clear();
          fit();
        }
        selection = new Set([...selection].filter((id) => byId.has(id)));
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
      for (const node of nodes) {
        const pin = pinned.get(node.id);
        if (pin) {
          node.x = pin.x;
          node.y = pin.y;
        }
      }
    }

    /* After a reload that added entities (transform, pivot), existing nodes
       keep their place and new ones are set around the node they attach to. */
    function placeAround(previous) {
      const byId = new Map(nodes.map((node) => [node.id, node]));
      for (const node of nodes) {
        const old = previous.get(node.id);
        if (old) {
          node.x = old.x;
          node.y = old.y;
        }
      }
      const placed = new Map();
      for (const node of nodes) {
        if (previous.has(node.id) || pinned.has(node.id)) continue;
        const edge = edges.find(
          (item) =>
            (item.source_entity_id === node.id && previous.has(item.target_entity_id)) ||
            (item.target_entity_id === node.id && previous.has(item.source_entity_id)),
        );
        if (!edge) continue;
        const anchorId = edge.source_entity_id === node.id ? edge.target_entity_id : edge.source_entity_id;
        const anchor = byId.get(anchorId);
        const index = placed.get(anchorId) || 0;
        placed.set(anchorId, index + 1);
        const angle = index * 2.399963;
        const distance = 120 + 22 * Math.floor(index / 7);
        node.x = anchor.x + Math.cos(angle) * distance;
        node.y = anchor.y + Math.sin(angle) * distance;
      }
    }

    /* View state: undo/redo and the per-scope saved view. ------------ */

    function snapshot() {
      return {
        positions: nodes.map((node) => [node.id, node.x, node.y]),
        pinned: [...pinned.entries()].map(([id, point]) => [id, { ...point }]),
        hidden: [...hidden],
        layout,
      };
    }

    function restore(state) {
      const positions = new Map(state.positions.map(([id, x, y]) => [id, [x, y]]));
      for (const node of nodes) {
        const point = positions.get(node.id);
        if (point) [node.x, node.y] = point;
      }
      pinned = new Map(state.pinned);
      hidden = new Set(state.hidden);
      layout = state.layout;
      layoutSelect.value = layout;
      selection = new Set([...selection].filter((id) => !hidden.has(id)));
      persistView();
      render();
    }

    function record() {
      history.push(snapshot());
      syncHistoryButtons();
    }

    function undo() {
      const state = history.undo(snapshot());
      if (state) restore(state);
      syncHistoryButtons();
    }

    function redo() {
      const state = history.redo(snapshot());
      if (state) restore(state);
      syncHistoryButtons();
    }

    function syncHistoryButtons() {
      undoButton.disabled = !history.canUndo;
      redoButton.disabled = !history.canRedo;
    }

    function persistView() {
      tools.saveView(investigationId, { pinned: [...pinned.entries()], hidden: [...hidden], layout });
    }

    function restoreSavedView() {
      const saved = tools.loadView(investigationId);
      pinned = new Map(Array.isArray(saved?.pinned) ? saved.pinned : []);
      hidden = new Set(Array.isArray(saved?.hidden) ? saved.hidden : []);
      if (saved?.layout && G.graphLayouts[saved.layout]) {
        layout = saved.layout;
        layoutSelect.value = layout;
      }
    }

    function targets() {
      if (selection.size) return [...selection];
      return selectedId ? [selectedId] : [];
    }

    function selectNode(id, additive = false) {
      if (additive) {
        if (selection.has(id)) selection.delete(id);
        else selection.add(id);
        selectedId = selection.has(id) ? id : [...selection].pop() || null;
      } else {
        selection = new Set([id]);
        selectedId = id;
      }
      render();
    }

    function pinNodes(ids, on) {
      record();
      const byId = new Map(nodes.map((node) => [node.id, node]));
      for (const id of ids) {
        const node = byId.get(id);
        if (on && node) pinned.set(id, { x: node.x, y: node.y });
        else pinned.delete(id);
      }
      persistView();
      render();
    }

    function hideNodes(ids) {
      record();
      ids.forEach((id) => hidden.add(id));
      selection = new Set([...selection].filter((id) => !hidden.has(id)));
      if (hidden.has(selectedId)) selectedId = null;
      persistView();
      render();
    }

    function showHidden() {
      if (!hidden.size) return;
      record();
      hidden = new Set();
      persistView();
      render();
    }

    function isolateSelection() {
      record();
      for (const node of nodes) if (!selection.has(node.id)) hidden.add(node.id);
      persistView();
      render();
    }

    function selectNeighbours() {
      const visible = visibleNodeSet();
      for (const edge of edges) {
        if (selection.has(edge.source_entity_id) && visible.has(edge.target_entity_id)) selection.add(edge.target_entity_id);
        if (selection.has(edge.target_entity_id) && visible.has(edge.source_entity_id)) selection.add(edge.source_entity_id);
      }
      render();
    }

    async function copyIdentifiers() {
      const byId = new Map(nodes.map((node) => [node.id, node]));
      const text = targets().map((id) => byId.get(id)).filter(Boolean).map((node) => node.identifier || node.name).join("\n");
      try {
        await navigator.clipboard.writeText(text);
        toast(`${targets().length} identificador(es) copiados.`);
      } catch (error) {
        toast("O navegador não permitiu copiar para a área de transferência.", "warning");
      }
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
        graph.nodes.filter((node) => types.has(node.entity_type) && !hidden.has(node.id)).map((node) => node.id),
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
      map.setViewport(viewport, canvas.getBoundingClientRect());
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
          await loadGraph({ keepPositions: true });
        } catch (error) {
          submit.disabled = false;
          toast(error.message, "error");
        }
      });
    }

    /* Import ------------------------------------------------------- */

    const IMPORT_REASONS = {
      "missing or repeated node id": "id de nó ausente ou repetido",
      "an endpoint is missing or invalid": "uma das pontas está ausente ou é inválida",
      "both ends are the same entity": "as duas pontas são a mesma entidade",
    };

    function importDialog() {
      let file = null;
      let content = "";
      let format = "";
      let layoutPayload = null;
      const fileInput = el("input", { class: "input", type: "file", accept: ".graphml,.xml,.json,application/json" });
      const scope = el(
        "select",
        { class: "input", "aria-label": "Vincular a uma investigação" },
        el("option", { value: "" }, "Sem vincular a um caso"),
        ...G.state.investigations.map((item) => el("option", { value: item.id }, item.name)),
      );
      scope.value = investigationId;
      const body = el("div", { class: "import-result", "aria-live": "polite" });
      const previewButton = el("button", { class: "button button-secondary", type: "button", disabled: true }, "Pré-visualizar");
      const commitButton = el("button", { class: "button button-primary", type: "button", disabled: true }, "Importar");
      const layoutButton = el("button", { class: "button button-secondary", type: "button", hidden: true }, "Aplicar só o layout");
      const dialog = el(
        "dialog",
        { class: "app-dialog pivot-dialog", "aria-label": "Importar grafo" },
        el(
          "div",
          { class: "dialog-form" },
          el(
            "div",
            { class: "dialog-heading" },
            el(
              "div",
              {},
              el("p", { class: "eyebrow" }, "IMPORTAR"),
              el("h2", {}, "Importar grafo"),
              el(
                "p",
                { class: "dialog-description" },
                "GraphML (Gephi, yEd e outros) ou JSON (este app, Cytoscape, D3). Cada nó vira uma entidade, ou reaproveita a que já existe com o mesmo tipo e identificador; cada aresta vira um relacionamento não verificado que cita o arquivo. Nada é gravado antes da sua confirmação.",
              ),
            ),
          ),
          el(
            "div",
            { class: "pivot-body" },
            el("label", { class: "field" }, el("span", {}, "Arquivo (até 8 MiB)"), fileInput),
            el("label", { class: "field" }, el("span", {}, "Investigação"), scope),
            body,
          ),
          el(
            "div",
            { class: "dialog-actions" },
            el("button", { class: "button button-secondary", type: "button", onClick: () => dialog.close() }, "Fechar"),
            layoutButton,
            previewButton,
            commitButton,
          ),
        ),
      );
      document.body.append(dialog);
      dialog.addEventListener("close", () => dialog.remove());
      dialog.showModal();

      fileInput.addEventListener("change", async () => {
        file = fileInput.files[0] || null;
        commitButton.disabled = true;
        layoutButton.hidden = true;
        layoutPayload = null;
        body.replaceChildren();
        if (!file) return;
        if (file.size > 8 * 1024 * 1024) {
          body.replaceChildren(G.inlineError("O arquivo passa de 8 MiB."));
          previewButton.disabled = true;
          return;
        }
        format = /\.json$/i.test(file.name) ? "json" : "graphml";
        content = await file.text();
        previewButton.disabled = false;
        if (format === "json") {
          try {
            const parsed = JSON.parse(content);
            if (parsed?.format === "garbage-graph" && Array.isArray(parsed.nodes)) {
              const present = new Set(nodes.map((node) => node.id));
              const matches = parsed.nodes.filter((node) => present.has(node.id)).length;
              if (matches) {
                layoutPayload = parsed;
                layoutButton.hidden = false;
                layoutButton.textContent = `Aplicar só o layout (${matches} nó(s) deste grafo)`;
              }
            }
          } catch (error) {
            /* the server preview reports the parse error */
          }
        }
      });

      async function send(commit) {
        previewButton.disabled = true;
        commitButton.disabled = true;
        body.replaceChildren(loadingBlock(commit ? "Importando…" : "Lendo o arquivo…"));
        try {
          const result = await api("/api/graph/import", {
            method: "POST",
            body: JSON.stringify({ content, format, file_name: file.name, investigation_id: scope.value || null, commit }),
          });
          const c = result.counts;
          const typeRows = Object.entries(result.new_by_type).map(([type, count]) => `${entityTypeLabel(type)}: ${count}`).join(", ");
          body.replaceChildren(
            G.kvList([
              ["Arquivo", `${result.nodes} nó(s), ${result.edges} aresta(s)`],
              ["Entidades novas", `${c.new_entities}${typeRows ? ` (${typeRows})` : ""}`],
              ["Já existentes", String(c.existing_entities)],
              ["Nós inválidos", String(c.invalid_nodes)],
              ["Relacionamentos novos", String(c.new_relationships)],
              ["Relacionamentos já registrados", String(c.existing_relationships)],
              ["Arestas ignoradas", String(c.skipped_edges)],
            ]),
            result.problems.length
              ? el(
                  "ul",
                  { class: "import-problems" },
                  ...result.problems.map((item) =>
                    el("li", {}, el("code", {}, item.key || "—"), ` ${IMPORT_REASONS[item.reason] || G.translateError(item.reason)}`),
                  ),
                )
              : null,
          );
          if (commit) {
            toast(`Importado: ${c.new_entities} entidade(s) e ${c.new_relationships} relacionamento(s) novos.`);
            dialog.close();
            if (scope.value && scope.value !== investigationId) {
              investigationId = scope.value;
              caseSelect.value = investigationId;
              await loadGraph();
            } else {
              await loadGraph({ keepPositions: true });
            }
          } else {
            commitButton.disabled = c.new_entities + c.new_relationships + c.existing_entities === 0;
            commitButton.textContent = `Importar ${c.new_entities} entidade(s) e ${c.new_relationships} relacionamento(s)`;
          }
        } catch (error) {
          body.replaceChildren(G.inlineError(error.message));
        } finally {
          previewButton.disabled = !file;
        }
      }
      previewButton.addEventListener("click", () => send(false));
      commitButton.addEventListener("click", () => send(true));
      layoutButton.addEventListener("click", () => {
        record();
        const saved = new Map(layoutPayload.nodes.map((node) => [node.id, node]));
        for (const node of nodes) {
          const item = saved.get(node.id);
          if (!item) continue;
          if (Number.isFinite(item.x) && Number.isFinite(item.y)) {
            node.x = item.x;
            node.y = item.y;
          }
          if (item.pinned) pinned.set(node.id, { x: node.x, y: node.y });
          else pinned.delete(node.id);
          if (item.hidden) hidden.add(node.id);
          else hidden.delete(node.id);
        }
        persistView();
        fit();
        render();
        toast("Layout aplicado. Use Desfazer para voltar.");
        dialog.close();
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
    function buildExportSvg() {
      const { shown } = visibleSubgraph();
      if (!shown.length) {
        toast("Não há nada visível para exportar.", "warning");
        return null;
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
        const properties = ["fill", "stroke", "stroke-width", "stroke-dasharray", "stroke-linecap", "stroke-linejoin", "opacity", "font-size", "font-family", "font-weight", "visibility", "paint-order"];
        // Presentation attributes, not a style attribute: the CSP blocks
        // inline styles even on a detached clone.
        properties.forEach((name) => {
          const value = style.getPropertyValue(name);
          if (value) target.setAttribute(name, value);
        });
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
      // The canvas itself is transparent; paint the stage colour so light
      // labels stay readable in viewers with a white background.
      const stageColor = getComputedStyle(canvas.parentElement).backgroundColor;
      background.setAttribute("fill", stageColor && !stageColor.endsWith(", 0)") ? stageColor : "#101214");
      copy.insertBefore(background, copy.firstChild.nextSibling);
      copy.querySelector(".graph-marquee")?.remove();
      copy.querySelectorAll(".graph-node").forEach((node) => node.removeAttribute("tabindex"));
      return { text: new XMLSerializer().serializeToString(copy), width, height };
    }

    function exportName(extension) {
      const slug = (graph.investigation?.name || "")
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-|-$/g, "")
        .slice(0, 40);
      const scope = slug ? `-${slug}` : "";
      return `grafo${scope}-${new Date().toISOString().slice(0, 10)}.${extension}`;
    }

    function exportSvg() {
      const built = buildExportSvg();
      if (!built) return;
      tools.download(new Blob([built.text], { type: "image/svg+xml" }), exportName("svg"));
      toast("SVG do grafo exportado.");
    }

    async function exportPng() {
      const built = buildExportSvg();
      if (!built) return;
      try {
        const blob = await tools.rasterize(built.text, built.width, built.height, 2);
        tools.download(blob, exportName("png"));
        toast("PNG do grafo exportado em resolução dupla.");
      } catch (error) {
        toast(error.message, "error");
      }
    }

    function exportData(kind) {
      const { shown, links } = visibleSubgraph();
      if (!shown.length) {
        toast("Não há nada visível para exportar.", "warning");
        return;
      }
      const rows = shown.map((node) => ({ ...node, pinned: pinned.has(node.id) }));
      const meta = { scope: graph.investigation?.name || "Todos os casos" };
      if (kind === "graphml") {
        tools.download(new Blob([tools.toGraphML(rows, links, meta)], { type: "application/graphml+xml" }), exportName("graphml"));
        toast(`GraphML exportado: ${shown.length} entidade(s), ${links.length} relacionamento(s).`);
      } else {
        tools.download(new Blob([tools.toJSON(rows, links, meta)], { type: "application/json" }), exportName("json"));
        toast(`JSON exportado: ${shown.length} entidade(s), ${links.length} relacionamento(s), com posições.`);
      }
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
          class: `graph-node type-${node.entity_type}${node.id === selectedId || selection.has(node.id) ? " is-selected" : ""}${pinned.has(node.id) ? " is-pinned" : ""}${pathIds.has(node.id) ? " is-path" : ""}${neighbourIds.has(node.id) ? " is-near" : ""}`,
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
        circle.append(svgEl("title", {}, `${node.name} · ${entityTypeLabel(node.entity_type)}${pinned.has(node.id) ? " · fixada" : ""}`));
        group.append(circle, tools.glyph(node.entity_type, radius));
        if (pinned.has(node.id)) {
          group.append(svgEl("circle", { cx: radius * 0.74, cy: -radius * 0.74, r: 3.4, class: "graph-pin" }));
        }
        group.addEventListener("click", (event) => event.stopPropagation());
        group.addEventListener("keydown", (event) => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            selectNode(node.id, event.shiftKey);
          }
        });
        group.addEventListener("pointerenter", () => {
          if (dragging || panning || marquee || hoverId === node.id) return;
          hoverId = node.id;
          applyHover();
        });
        group.addEventListener("pointerleave", () => {
          if (hoverId !== node.id) return;
          hoverId = null;
          applyHover();
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
            origins: null,
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
      hiddenButton.hidden = hidden.size === 0;
      hiddenButton.textContent = `Ocultas (${hidden.size}) · mostrar`;
      syncHistoryButtons();
      map.update(visibleNodes, selection);
      map.setViewport(viewport, canvas.getBoundingClientRect());
      renderInspector();
    }

    /* Hover only changes classes: rebuilding every element on each
       pointerenter cost about half a second on a 1,500-node case. */
    function applyHover() {
      const near = new Set(hoverId ? [hoverId] : []);
      const touching = new Set();
      if (hoverId) {
        for (const edge of edges) {
          if (edge.source_entity_id === hoverId) near.add(edge.target_entity_id);
          else if (edge.target_entity_id === hoverId) near.add(edge.source_entity_id);
          else continue;
          touching.add(edge.id);
        }
      }
      svg.classList.toggle("has-hover", Boolean(hoverId));
      for (const group of nodeLayer.querySelectorAll(".graph-node")) group.classList.toggle("is-near", near.has(group.dataset.id));
      for (const label of labelLayer.querySelectorAll(".graph-node-label")) label.classList.toggle("is-near", near.has(label.dataset.id));
      for (const path of edgeLayer.querySelectorAll(".graph-edge")) path.classList.toggle("is-near", touching.has(path.dataset.id));
      for (const text of labelLayer.querySelectorAll(".graph-edge-label")) text.classList.toggle("is-near", touching.has(text.dataset.edge));
    }

    function updateGeometry() {
      const byId = new Map(nodes.map((node) => [node.id, node]));
      const edgeById = new Map(edges.map((edge) => [edge.id, edge]));
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
        const edge = edgeById.get(path.dataset.id);
        if (!edge) continue;
        const source = byId.get(edge.source_entity_id);
        const target = byId.get(edge.target_entity_id);
        if (source && target) path.setAttribute("d", updatePath(source, target, radiusOf));
      }
      for (const text of labelLayer.querySelectorAll(".graph-edge-label")) {
        const edge = edgeById.get(text.dataset.edge);
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

    function bulkInspector() {
      const byId = new Map(nodes.map((node) => [node.id, node]));
      const chosen = [...selection].map((id) => byId.get(id)).filter(Boolean);
      const counts = new Map();
      chosen.forEach((node) => counts.set(node.entity_type, (counts.get(node.entity_type) || 0) + 1));
      const allPinned = chosen.every((node) => pinned.has(node.id));
      inspector.replaceChildren(
        panel(
          { eyebrow: "SELEÇÃO", title: `${chosen.length} entidades selecionadas` },
          G.kvList([...counts.entries()].sort((a, b) => b[1] - a[1]).map(([type, count]) => [entityTypeLabel(type), String(count)])),
          el(
            "div",
            { class: "inspector-actions" },
            button(allPinned ? "Soltar posições" : "Fixar posições", () => pinNodes([...selection], !allPinned), { title: "Atalho: P" }),
            button("Ocultar", () => hideNodes([...selection]), { title: "Atalho: H ou Delete" }),
            button("Mostrar só a seleção", () => isolateSelection()),
            button("Selecionar vizinhos", () => selectNeighbours()),
            button("Copiar identificadores", () => copyIdentifiers()),
            button("Limpar seleção", () => {
              selection = new Set();
              selectedId = null;
              render();
            }, { title: "Atalho: Esc" }),
          ),
          el(
            "div",
            { class: "graph-relation-list" },
            ...chosen.slice(0, 60).map((node) =>
              el(
                "div",
                { class: "graph-relation" },
                el("button", { class: "link-button", type: "button", onClick: () => selectNode(node.id) }, node.name),
                el("span", { class: "record-meta" }, `${entityTypeLabel(node.entity_type)}${pinned.has(node.id) ? " · fixada" : ""}`),
              ),
            ),
            chosen.length > 60 ? el("p", { class: "panel-note" }, `E mais ${chosen.length - 60}.`) : null,
          ),
          el("p", { class: "panel-note" }, "Shift+clique adiciona ou remove; Shift+arrastar no fundo seleciona uma área; Ctrl+A seleciona tudo o que está visível."),
        ),
      );
    }

    function enrichmentSection(node) {
      if (!G.moduleEnabled("transforms") || ["person", "username", "profile"].includes(node.entity_type)) return null;
      const box = el("div", { class: "graph-enrichment" }, el("h3", { class: "subheading" }, "Enriquecimento"));
      const fill = (history) => {
        if (!history.items.length) {
          box.append(el("p", { class: "panel-empty" }, "Nenhuma transformação executada nesta entidade."));
          return;
        }
        box.append(
          el(
            "div",
            { class: "graph-relation-list" },
            ...history.items.slice(0, 5).map((item) =>
              el(
                "div",
                { class: "graph-relation" },
                el("strong", {}, G.connectorLabel ? G.connectorLabel(item.transform_id) : item.transform_id),
                el(
                  "span",
                  { class: "record-meta" },
                  `${G.formatDate(item.started_at, { time: true })} · ${item.result_count} resultado(s) · ${item.created_count} nova(s)`,
                ),
              ),
            ),
          ),
          history.total > 5 ? el("a", { class: "table-link", href: `#/entities/${node.id}` }, `Ver as ${history.total} execuções`) : null,
        );
      };
      let pending = enrichment.get(node.id);
      if (!pending) {
        pending = api(`/api/entities/${node.id}/transforms?limit=5`).catch(() => ({ items: [], total: 0 }));
        enrichment.set(node.id, pending);
      }
      pending.then(fill);
      return box;
    }

    function renderInspector() {
      if (selection.size > 1) {
        bulkInspector();
        return;
      }
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
            enrichmentSection(node),
            el(
              "div",
              { class: "inspector-actions" },
              button("Abrir registro da entidade", () => go("entities", node.id), {
                variant: "button-primary",
              }),
              G.moduleEnabled("transforms") && G.moduleEnabled("intel-orchestrator") && !["person", "username", "profile"].includes(node.entity_type)
                ? button("Transformações", () => G.transformDialog(node, { investigationId: investigationId || null, onDone: () => loadGraph({ keepPositions: true }) }))
                : null,
              button(pinned.has(node.id) ? "Soltar posição" : "Fixar posição", () => pinNodes([node.id], !pinned.has(node.id)), { title: "Atalho: P" }),
              button("Ocultar", () => hideNodes([node.id]), { title: "Atalho: H ou Delete" }),
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
                record();
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

    function worldPoint(event) {
      const rect = canvas.getBoundingClientRect();
      return {
        x: (event.clientX - rect.left - viewport.x) / viewport.zoom,
        y: (event.clientY - rect.top - viewport.y) / viewport.zoom,
      };
    }

    function drawMarquee() {
      const x = Math.min(marquee.x0, marquee.x1);
      const y = Math.min(marquee.y0, marquee.y1);
      marqueeRect.setAttribute("x", x);
      marqueeRect.setAttribute("y", y);
      marqueeRect.setAttribute("width", Math.abs(marquee.x1 - marquee.x0));
      marqueeRect.setAttribute("height", Math.abs(marquee.y1 - marquee.y0));
      marqueeRect.setAttribute("stroke-width", String(1.2 / viewport.zoom));
      marqueeRect.setAttribute("visibility", "visible");
    }

    canvas.addEventListener("pointerdown", (event) => {
      if (event.button !== 0) return;
      if (event.target.closest(".graph-node") || event.target.closest(".graph-minimap")) return;
      event.preventDefault();
      canvas.setPointerCapture(event.pointerId);
      canvas.focus({ preventScroll: true });
      if (event.shiftKey) {
        const point = worldPoint(event);
        marquee = { pointerId: event.pointerId, x0: point.x, y0: point.y, x1: point.x, y1: point.y };
        drawMarquee();
        return;
      }
      panning = {
        pointerId: event.pointerId,
        startX: event.clientX,
        startY: event.clientY,
        originX: viewport.x,
        originY: viewport.y,
        moved: false,
      };
      canvas.classList.add("is-panning");
    });

    canvas.addEventListener("pointermove", (event) => {
      if (dragging && event.pointerId === dragging.pointerId) {
        const dx = (event.clientX - dragging.startX) / viewport.zoom;
        const dy = (event.clientY - dragging.startY) / viewport.zoom;
        if (!dragging.moved && (Math.abs(dx) > 1 || Math.abs(dy) > 1)) {
          dragging.moved = true;
          record();
          const moving = selection.has(dragging.node.id) && selection.size > 1
            ? nodes.filter((node) => selection.has(node.id))
            : [dragging.node];
          dragging.origins = moving.map((node) => [node, node.x, node.y]);
        }
        if (!dragging.moved) return;
        for (const [node, originX, originY] of dragging.origins) {
          node.x = originX + dx;
          node.y = originY + dy;
          if (pinned.has(node.id)) pinned.set(node.id, { x: node.x, y: node.y });
        }
        updateGeometry();
        return;
      }
      if (marquee && event.pointerId === marquee.pointerId) {
        const point = worldPoint(event);
        marquee.x1 = point.x;
        marquee.y1 = point.y;
        drawMarquee();
        return;
      }
      if (panning && event.pointerId === panning.pointerId) {
        if (Math.abs(event.clientX - panning.startX) + Math.abs(event.clientY - panning.startY) > 3) panning.moved = true;
        viewport.x = panning.originX + event.clientX - panning.startX;
        viewport.y = panning.originY + event.clientY - panning.startY;
        applyTransform();
      }
    });

    function endPointer(event) {
      if (dragging && event.pointerId === dragging.pointerId) {
        dragging.group.classList.remove("is-dragging");
        const { node, moved } = dragging;
        dragging = null;
        if (!moved) selectNode(node.id, event.shiftKey || event.ctrlKey || event.metaKey);
        else {
          if (pinned.size) persistView();
          render();
        }
      }
      if (marquee && event.pointerId === marquee.pointerId) {
        const left = Math.min(marquee.x0, marquee.x1);
        const right = Math.max(marquee.x0, marquee.x1);
        const top = Math.min(marquee.y0, marquee.y1);
        const bottom = Math.max(marquee.y0, marquee.y1);
        const visible = visibleNodeSet();
        const inside = nodes.filter((node) => visible.has(node.id) && node.x >= left && node.x <= right && node.y >= top && node.y <= bottom);
        inside.forEach((node) => selection.add(node.id));
        if (inside.length) selectedId = inside[inside.length - 1].id;
        marquee = null;
        marqueeRect.setAttribute("visibility", "hidden");
        render();
      }
      if (panning && event.pointerId === panning.pointerId) {
        const clicked = !panning.moved;
        panning = null;
        canvas.classList.remove("is-panning");
        if (clicked && (selection.size || selectedId)) {
          selection = new Set();
          selectedId = null;
          render();
        }
      }
    }
    canvas.addEventListener("pointerup", endPointer);
    canvas.addEventListener("pointercancel", endPointer);

    canvas.addEventListener("keydown", (event) => {
      const key = event.key.toLowerCase();
      const modifier = event.ctrlKey || event.metaKey;
      if (modifier && key === "z") {
        event.preventDefault();
        if (event.shiftKey) redo();
        else undo();
      } else if (modifier && key === "y") {
        event.preventDefault();
        redo();
      } else if (modifier && key === "a") {
        event.preventDefault();
        selection = new Set(visibleNodeSet());
        selectedId = [...selection][0] || null;
        render();
      } else if (event.key === "Escape" && (selection.size || selectedId)) {
        selection = new Set();
        selectedId = null;
        render();
      } else if (!modifier && (event.key === "Delete" || key === "h") && targets().length) {
        event.preventDefault();
        hideNodes(targets());
      } else if (!modifier && key === "p" && targets().length) {
        event.preventDefault();
        const ids = targets();
        pinNodes(ids, !ids.every((id) => pinned.has(id)));
      }
    });

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
      record();
      layout = layoutSelect.value;
      persistView();
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
