"use strict";

/* Relationship graph over the shared entity and relationship records. */

(function () {
  const G = window.GARBAGE;
  const {
    el, svgEl, api, toast, pageHeader, panel, badge, emptyState, loadingBlock,
    formatDate, titleCase, entityTypeLabel, relationshipLabel, statusBadge, go,
  } = G;

  const MAX_FORCE_NODES = 220;
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
    person: "#e5b567",
    username: "#e5b567",
    profile: "#d9a441",
    email: "#d9a441",
    organization: "#c78be0",
    domain: "#5aa9e6",
    url: "#5aa9e6",
    ipv4: "#6fcf97",
    ipv6: "#6fcf97",
    file: "#e07a7a",
    image: "#e07a7a",
    hash: "#e07a7a",
    ioc: "#f2c94c",
    other: "#8fa0b5",
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

  function updatePath(source, target, zoom) {
    const dx = target.x - source.x;
    const dy = target.y - source.y;
    const distance = Math.max(1, Math.hypot(dx, dy));
    const radius = 10 + Math.min(12, (source.degree || 0) * 1.6);
    const targetRadius = 10 + Math.min(12, (target.degree || 0) * 1.6);
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

    const canvas = el("div", { class: "graph-canvas", tabindex: "0" });
    const svg = svgEl("svg", {
      class: "graph-svg",
      width: "100%",
      height: "100%",
      role: "img",
      "aria-label": "Entity relationship graph",
    });
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
          button("−", () => zoomBy(0.85), { title: "Zoom out" }),
          button("＋", () => zoomBy(1.18), { title: "Zoom in" }),
          button("Fit", () => fit(), { title: "Fit graph" }),
          button("Reset", () => {
            focusedId = null;
            selectedId = null;
            viewport = { x: 0, y: 0, zoom: 1 };
            applyTransform();
            render();
          }),
        ),
        el("div", { class: "graph-legend" }, legend()),
      ),
      inspector,
    );

    const caseSelect = el(
      "select",
      { class: "input compact-select", "aria-label": "Filter graph by investigation" },
      el("option", { value: "" }, "All investigations"),
      ...(await G.loadInvestigations()).map((item) =>
        el("option", { value: item.id }, item.name),
      ),
    );
    caseSelect.value = investigationId;

    const typeSelect = el(
      "select",
      { class: "input compact-select", "aria-label": "Filter graph by entity type" },
      el("option", { value: "" }, "All entity types"),
      ...G.ENTITY_TYPES.map(([value, label]) => el("option", { value }, label)),
    );
    const search = el("input", {
      class: "input",
      type: "search",
      placeholder: "Filter entities by name or identifier",
      "aria-label": "Search graph entities",
    });
    const layoutSelect = el(
      "select",
      { class: "input compact-select", "aria-label": "Graph layout" },
      el("option", { value: "force" }, "Force layout"),
      el("option", { value: "circle" }, "Circular layout"),
      el("option", { value: "grid" }, "Grid layout"),
    );

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
        if (focusedId && !byId.has(focusedId)) focusedId = null;
        if (query.trim() || investigationId || entityType) {
          rememberQuery();
        }
        layoutNodes();
        fit();
        render();
      } catch (error) {
        if (token !== requestToken) return;
        inspector.replaceChildren(
          panel({ eyebrow: "GRAPH", title: "Unable to build graph" }, G.inlineError(error.message)),
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
      const mode =
        layout === "force" && nodes.length > MAX_FORCE_NODES ? "circle" : layout;
      if (mode === "circle") {
        const radius = Math.min(width, height) * 0.36;
        nodes.forEach((node, index) => {
          const angle = (index / nodes.length) * Math.PI * 2 - Math.PI / 2;
          node.x = width / 2 + Math.cos(angle) * radius;
          node.y = height / 2 + Math.sin(angle) * radius;
        });
        return;
      }
      if (mode === "grid") {
        const columns = Math.max(1, Math.ceil(Math.sqrt(nodes.length)));
        nodes.forEach((node, index) => {
          node.x = 100 + (index % columns) * 190;
          node.y = 90 + Math.floor(index / columns) * 150;
        });
        return;
      }
      const k = Math.sqrt((width * height) / nodes.length) * 0.62;
      nodes.forEach((node, index) => {
        const angle = (index / nodes.length) * Math.PI * 2;
        node.x = width / 2 + Math.cos(angle) * Math.min(width, height) * 0.28;
        node.y = height / 2 + Math.sin(angle) * Math.min(width, height) * 0.28;
        node.vx = 0;
        node.vy = 0;
      });
      const byId = new Map(nodes.map((node) => [node.id, node]));
      const iterations = 240;
      let temperature = width / 6;
      const cooling = temperature / (iterations + 1);
      for (let iteration = 0; iteration < iterations; iteration += 1) {
        for (let i = 0; i < nodes.length; i += 1) {
          const a = nodes[i];
          for (let j = i + 1; j < nodes.length; j += 1) {
            const b = nodes[j];
            let dx = a.x - b.x;
            let dy = a.y - b.y;
            if (dx === 0 && dy === 0) {
              dx = (i % 2 ? 1 : -1) * 0.5;
              dy = (j % 2 ? 1 : -1) * 0.5;
            }
            const distance = Math.max(0.5, Math.hypot(dx, dy));
            const force = (k * k) / distance;
            const fx = (dx / distance) * force;
            const fy = (dy / distance) * force;
            a.vx += fx;
            a.vy += fy;
            b.vx -= fx;
            b.vy -= fy;
          }
        }
        for (const edge of edges) {
          const a = byId.get(edge.source_entity_id);
          const b = byId.get(edge.target_entity_id);
          if (!a || !b) continue;
          const dx = a.x - b.x;
          const dy = a.y - b.y;
          const distance = Math.max(1, Math.hypot(dx, dy));
          const force = (distance * distance) / k;
          const fx = (dx / distance) * force;
          const fy = (dy / distance) * force;
          a.vx -= fx * 0.02;
          a.vy -= fy * 0.02;
          b.vx += fx * 0.02;
          b.vy += fy * 0.02;
        }
        for (const node of nodes) {
          node.vx += (width / 2 - node.x) * 0.012;
          node.vy += (height / 2 - node.y) * 0.012;
          const speed = Math.max(0.01, Math.hypot(node.vx, node.vy));
          node.x += (node.vx / speed) * Math.min(speed, temperature);
          node.y += (node.vy / speed) * Math.min(speed, temperature);
          node.vx = 0;
          node.vy = 0;
          node.x = Math.max(40, Math.min(width - 40, node.x));
          node.y = Math.max(40, Math.min(height - 40, node.y));
        }
        temperature = Math.max(0.5, temperature - cooling);
      }
    }

    function visibleNodeSet() {
      const types = visibleTypes || new Set(graph.nodes.map((node) => node.entity_type));
      const set = new Set(
        graph.nodes.filter((node) => types.has(node.entity_type)).map((node) => node.id),
      );
      if (focusedId && set.has(focusedId)) {
        const neighbors = new Set([focusedId]);
        for (const edge of graph.edges) {
          if (edge.source_entity_id === focusedId) neighbors.add(edge.target_entity_id);
          if (edge.target_entity_id === focusedId) neighbors.add(edge.source_entity_id);
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
        const path = svgEl("path", {
          d: updatePath(source, target, viewport.zoom),
          class: `graph-edge verification-${edge.verification_status || "not-verified"}`,
          "data-id": edge.id,
        });
        path.append(
          svgEl("title", {}, `${source.name} — ${relationshipLabel(edge.relationship_type)} → ${target.name}`),
        );
        edgeLayer.append(path);
      }

      for (const node of visibleNodes) {
        const radius = 10 + Math.min(12, node.degree * 1.6);
        const group = svgEl("g", {
          class: `graph-node type-${node.entity_type}${node.id === selectedId ? " is-selected" : ""}`,
          transform: `translate(${node.x} ${node.y})`,
          tabindex: "0",
          role: "button",
          "aria-label": `${entityTypeLabel(node.entity_type)}: ${node.name}`,
          "data-id": node.id,
        });
        const circle = svgEl("circle", {
          r: radius,
          fill: TYPE_COLORS[node.entity_type] || TYPE_COLORS.other,
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
            class: "graph-node-label",
            "data-id": node.id,
          },
          node.name.length > 26 ? `${node.name.slice(0, 24)}…` : node.name,
        );
        labelLayer.append(label);
      }
      canvas.classList.toggle("is-empty", nodes.length === 0);
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
        const radius = 10 + Math.min(12, node.degree * 1.6);
        label.setAttribute("x", node.x);
        label.setAttribute("y", node.y + radius + 14);
      }
      for (const path of edgeLayer.querySelectorAll(".graph-edge")) {
        const edge = edges.find((item) => item.id === path.dataset.id);
        if (!edge) continue;
        const source = byId.get(edge.source_entity_id);
        const target = byId.get(edge.target_entity_id);
        if (source && target) path.setAttribute("d", updatePath(source, target, viewport.zoom));
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
              eyebrow: "NODE INSPECTOR",
              title: node.name,
              actions: [statusBadge(node.verification_status)],
            },
            G.kvList([
              ["Category", badge(entityTypeLabel(node.entity_type), "info")],
              ["Identifier", node.identifier || "—"],
              ["Confidence", titleCase(node.confidence)],
              ["Relationships", String(node.degree)],
            ]),
            node.description ? el("p", { class: "prose" }, node.description) : null,
            el(
              "div",
              { class: "inspector-actions" },
              button("Open entity record", () => go("entities", node.id), {
                variant: "button-primary",
              }),
              button(
                focusedId === node.id ? "Clear focus" : "Focus neighborhood",
                () => {
                  focusedId = focusedId === node.id ? null : node.id;
                  render();
                },
              ),
            ),
            el("h3", { class: "subheading" }, `Relationships (${related.length})`),
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
                              "Case",
                            )
                          : null,
                      ),
                      edge.description ? el("p", { class: "panel-note" }, edge.description) : null,
                    ),
                  ),
                )
              : el("p", { class: "panel-empty" }, "No relationships recorded for this entity."),
          ),
          panel(
            { eyebrow: "FILTERS", title: "Entity layers" },
            el(
              "div",
              { class: "graph-type-list" },
              ...typeLegendNodes(),
            ),
            button("Show all layers", () => {
              visibleTypes = null;
              render();
            }),
          ),
        );
        return;
      }
      const components = countComponents();
      inspector.replaceChildren(
        panel(
          { eyebrow: "RELATIONSHIP GRAPH", title: "Graph overview" },
          G.kvList([
            ["Investigation", graph.investigation ? graph.investigation.name : "All cases"],
            ["Entities shown", String(nodes.length)],
            ["Relationships shown", String(edges.length)],
            ["Connected components", String(components)],
            [
              "Layout",
              nodes.length > MAX_FORCE_NODES && layout === "force"
                ? "Circular (node limit)"
                : titleCase(layout),
            ],
          ]),
          nodes.length
            ? el(
                "p",
                { class: "panel-note" },
                "Relationships remain analyst-entered records. A line means a recorded association, not proof of coordination.",
              )
            : null,
        ),
        panel(
          { eyebrow: "LAYERS", title: "Entity types" },
          el("div", { class: "graph-type-list" }, ...typeLegendNodes()),
          button("Show all layers", () => {
            visibleTypes = null;
            render();
          }),
        ),
        historyPanel(),
      );
    }

    function typeLegendNodes() {
      const types = [...new Set(nodes.map((node) => node.entity_type))].sort();
      if (!types.length) {
        return [el("p", { class: "panel-empty" }, "No entities in the current graph.")];
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
        { eyebrow: "HISTORY", title: "Recent graph queries" },
        history.length
          ? el(
              "div",
              { class: "query-history" },
              ...history.map((entry) =>
                button(
                  `${entry.investigation || "All cases"} · ${entry.query || entry.entityType || "full graph"}`,
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
          : el("p", { class: "panel-empty" }, "Filtered graph queries appear here."),
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
        eyebrow: "RELATIONSHIP ANALYSIS",
        title: "Relationship graph",
        description:
          "Entity nodes and analyst-recorded relationships from the shared registry. Edges are associations, not proof.",
        actions: [
          button("Board", () => go("board", investigationId || undefined)),
          button("Entities", () => go("entities")),
        ],
      }),
      el(
        "div",
        { class: "graph-toolbar" },
        caseSelect,
        typeSelect,
        layoutSelect,
        el("div", { class: "search-field" }, el("span", { "aria-hidden": "true" }, "⌕"), search),
      ),
      el(
        "div",
        { class: "metric-grid compact-metrics" },
        G.metric({
          label: "ENTITIES",
          value: "—",
          foot: "Current graph",
          icon: "⬡",
          tone: "violet",
        }),
        G.metric({
          label: "RELATIONSHIPS",
          value: "—",
          foot: "Recorded links",
          icon: "⟷",
          tone: "blue",
        }),
        G.metric({
          label: "COMPONENTS",
          value: "—",
          foot: "Disconnected groups",
          icon: "◫",
          tone: "green",
        }),
        G.metric({
          label: "LAYOUT",
          value: "Force",
          foot: "Client-side simulation",
          icon: "◈",
          tone: "amber",
        }),
      ),
      shell,
    );

    // Replace the static metric values once data is loaded.
    const metrics = root.querySelectorAll(".metric-card .metric-value");
    const originalRender = render;
    render = function renderWithMetrics() {
      originalRender();
      if (metrics[0]) metrics[0].textContent = String(nodes.length);
      if (metrics[1]) metrics[1].textContent = String(edges.length);
      if (metrics[2]) metrics[2].textContent = String(countComponents());
      if (metrics[3]) metrics[3].textContent = titleCase(layout);
    };

    await loadGraph();
  }

  G.views.graph = renderGraph;
})();
