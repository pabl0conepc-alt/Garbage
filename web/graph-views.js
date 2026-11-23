"use strict";

/* Alternative views of the relationship graph: adjacency matrix and a
   timeline of when entities and relationships were recorded. */

(function () {
  const G = window.GARBAGE;
  const { el, entityTypeLabel, relationshipLabel } = G;
  const C = G.charts;
  const SVG = "http://www.w3.org/2000/svg";
  const MAX_MATRIX = 150;

  const VERIFICATION = [
    ["verified", "Verificado", "var(--viz-good)"],
    ["not-verified", "Não verificado", "var(--viz-seq-4)"],
    ["disputed", "Contestado", "var(--viz-warning)"],
    ["false-positive", "Falso positivo", "var(--viz-critical)"],
  ];
  const VERIFICATION_COLOR = Object.fromEntries(VERIFICATION.map(([key, , color]) => [key, color]));
  const VERIFICATION_LABEL = Object.fromEntries(VERIFICATION.map(([key, label]) => [key, label]));

  function svg(tag, attributes = {}, text = null) {
    const node = document.createElementNS(SVG, tag);
    for (const [key, value] of Object.entries(attributes)) node.setAttribute(key, String(value));
    if (text !== null) node.textContent = text;
    return node;
  }

  const shorten = (text, length) => (text.length > length ? `${text.slice(0, length - 1)}…` : text);

  /* Rows and columns ordered by community, then degree, so clusters show as
     blocks along the diagonal. */
  function matrix({ nodes, edges, analytics, onSelect }) {
    const community = (node) => analytics?.nodes?.[node.id]?.community ?? 0;
    const ordered = [...nodes]
      .sort((a, b) => community(a) - community(b) || b.degree - a.degree || a.name.localeCompare(b.name))
      .slice(0, MAX_MATRIX);
    const index = new Map(ordered.map((node, position) => [node.id, position]));
    const count = ordered.length;
    const cell = Math.max(6, Math.min(18, Math.floor(720 / Math.max(1, count))));
    const showLabels = cell >= 10;
    const gutter = showLabels ? 150 : 8;
    const size = gutter + count * cell + 8;
    const root = svg("svg", { width: size, height: size, class: "matrix-svg", role: "group", "aria-label": "Matriz de adjacência" });

    let start = 0;
    for (let position = 1; position <= count; position += 1) {
      if (position === count || community(ordered[position]) !== community(ordered[start])) {
        if (position - start > 1) {
          root.append(svg("rect", { x: gutter + start * cell, y: gutter + start * cell, width: (position - start) * cell, height: (position - start) * cell, class: "matrix-block" }));
        }
        start = position;
      }
    }
    for (let position = 0; position <= count; position += 1) {
      root.append(svg("line", { x1: gutter, x2: gutter + count * cell, y1: gutter + position * cell, y2: gutter + position * cell, class: "matrix-grid" }));
      root.append(svg("line", { y1: gutter, y2: gutter + count * cell, x1: gutter + position * cell, x2: gutter + position * cell, class: "matrix-grid" }));
    }
    if (showLabels) {
      ordered.forEach((node, position) => {
        root.append(svg("text", { x: gutter - 6, y: gutter + position * cell + cell * 0.72, "text-anchor": "end", class: "matrix-label" }, shorten(node.name, 22)));
        root.append(
          svg(
            "text",
            { x: 0, y: 0, transform: `translate(${gutter + position * cell + cell * 0.72} ${gutter - 6}) rotate(-60)`, class: "matrix-label" },
            shorten(node.name, 22),
          ),
        );
      });
    }
    const byId = new Map(nodes.map((node) => [node.id, node]));
    const highlightRow = svg("rect", { x: gutter, height: cell, width: count * cell, class: "matrix-highlight", visibility: "hidden" });
    const highlightColumn = svg("rect", { y: gutter, width: cell, height: count * cell, class: "matrix-highlight", visibility: "hidden" });
    root.append(highlightRow, highlightColumn);
    for (const edge of edges) {
      const row = index.get(edge.source_entity_id);
      const column = index.get(edge.target_entity_id);
      if (row === undefined || column === undefined) continue;
      for (const [r, c] of [[row, column], [column, row]]) {
        const mark = svg("rect", {
          x: gutter + c * cell + 1,
          y: gutter + r * cell + 1,
          width: cell - 2,
          height: cell - 2,
          rx: 2,
          class: "matrix-cell",
          tabindex: r === row ? "0" : "-1",
        });
        mark.style.fill = VERIFICATION_COLOR[edge.verification_status] || VERIFICATION_COLOR["not-verified"];
        const source = byId.get(edge.source_entity_id);
        const target = byId.get(edge.target_entity_id);
        const readout = (event) => {
          highlightRow.setAttribute("y", gutter + r * cell);
          highlightColumn.setAttribute("x", gutter + c * cell);
          highlightRow.setAttribute("visibility", "visible");
          highlightColumn.setAttribute("visibility", "visible");
          C.showTooltip(event, `${source.name} → ${target.name}`, [
            { value: relationshipLabel(edge.relationship_type), label: "" },
            { value: VERIFICATION_LABEL[edge.verification_status] || edge.verification_status, label: "verificação" },
          ]);
        };
        const leave = () => {
          highlightRow.setAttribute("visibility", "hidden");
          highlightColumn.setAttribute("visibility", "hidden");
          C.hideTooltip();
        };
        mark.addEventListener("pointermove", readout);
        mark.addEventListener("focus", readout);
        mark.addEventListener("pointerleave", leave);
        mark.addEventListener("blur", leave);
        mark.setAttribute("role", "button");
        mark.setAttribute("aria-label", `${source.name} → ${target.name}: ${relationshipLabel(edge.relationship_type)}, ${VERIFICATION_LABEL[edge.verification_status] || edge.verification_status}`);
        mark.addEventListener("click", () => onSelect?.(source.id));
        mark.addEventListener("keydown", (event) => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            onSelect?.(source.id);
          }
        });
        root.append(mark);
      }
    }
    return {
      element: el("div", { class: "matrix-scroll" }, root),
      truncated: nodes.length > MAX_MATRIX,
      legend: C.legend(VERIFICATION.map(([, label, color]) => ({ label, color }))),
    };
  }

  /* Swimlanes by entity type; each dot is an entity on the day it was
     recorded, the bottom lane holds relationships. */
  function timeline({ nodes, edges, onSelect }) {
    const wrap = el("div", { class: "graph-timeline" });
    const items = nodes.filter((node) => node.created_at);
    const links = edges.filter((edge) => edge.created_at);
    if (!items.length) {
      wrap.append(el("p", { class: "panel-empty" }, "As entidades deste grafo não têm data de registro."));
      return wrap;
    }
    const draw = () => {
      const width = Math.max(420, wrap.clientWidth || 900);
      const types = [...new Set(items.map((node) => node.entity_type))].sort();
      const lanes = [...types.map((type) => ({ key: type, label: entityTypeLabel(type) })), { key: "__links", label: "Relacionamentos" }];
      const laneHeight = 36;
      const pad = { left: 150, right: 18, top: 10, bottom: 28 };
      const height = pad.top + lanes.length * laneHeight + pad.bottom;
      const times = [...items.map((node) => Date.parse(node.created_at)), ...links.map((edge) => Date.parse(edge.created_at))].filter(Number.isFinite);
      let min = Math.min(...times);
      let max = Math.max(...times);
      if (max - min < 3600_000) {
        min -= 1800_000;
        max += 1800_000;
      }
      const plotW = width - pad.left - pad.right;
      const x = (time) => pad.left + ((time - min) / (max - min)) * plotW;
      const root = svg("svg", { width, height, class: "timeline-svg", role: "group", "aria-label": "Linha do tempo do grafo" });
      lanes.forEach((lane, position) => {
        const y = pad.top + position * laneHeight + laneHeight / 2;
        root.append(svg("line", { x1: pad.left, x2: width - pad.right, y1: y, y2: y, class: "chart-grid" }));
        root.append(svg("text", { x: pad.left - 10, y: y + 4, "text-anchor": "end", class: "timeline-lane" }, lane.label));
      });
      root.append(svg("line", { x1: pad.left, x2: width - pad.right, y1: height - pad.bottom, y2: height - pad.bottom, class: "chart-baseline" }));
      const span = max - min;
      const ticks = 5;
      for (let tick = 0; tick <= ticks; tick += 1) {
        const time = min + (span * tick) / ticks;
        const date = new Date(time);
        const text = span > 3 * 86400_000
          ? date.toLocaleDateString("pt-BR", { day: "2-digit", month: "short" })
          : date.toLocaleString("pt-BR", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });
        root.append(svg("text", { x: x(time), y: height - 8, "text-anchor": tick === 0 ? "start" : tick === ticks ? "end" : "middle", class: "chart-axis-text" }, text));
      }
      const laneIndex = new Map(lanes.map((lane, position) => [lane.key, position]));
      const stacks = new Map();
      /* Same-moment records stack in a small column (5 high), then spill
         sideways so none hides under another. */
      const place = (laneKey, time) => {
        const column = Math.round(x(time) / 6);
        const key = `${laneKey}:${column}`;
        const offset = stacks.get(key) || 0;
        stacks.set(key, offset + 1);
        const slot = offset % 5;
        const jitter = slot === 0 ? 0 : (slot % 2 ? -1 : 1) * Math.ceil(slot / 2) * 6;
        return {
          cx: x(time) + Math.floor(offset / 5) * 7,
          cy: pad.top + laneIndex.get(laneKey) * laneHeight + laneHeight / 2 + jitter,
        };
      };
      const dot = (cx, cy, fill, title, rows, select) => {
        const group = svg("g", { class: "timeline-dot", tabindex: "0", role: select ? "button" : "img", "aria-label": [title, ...rows.map((row) => [row.label, row.value].filter(Boolean).join(": "))].join(", ") });
        group.append(svg("circle", { cx, cy, r: 12, class: "timeline-hit" }));
        const mark = svg("circle", { cx, cy, r: 4.5, class: "timeline-mark" });
        mark.style.fill = fill;
        group.append(mark);
        const readout = (event) => C.showTooltip(event, title, rows);
        group.addEventListener("pointermove", readout);
        group.addEventListener("focus", readout);
        group.addEventListener("pointerleave", C.hideTooltip);
        group.addEventListener("blur", C.hideTooltip);
        if (select) {
          group.addEventListener("click", select);
          group.addEventListener("keydown", (event) => {
            if (event.key === "Enter") select();
          });
        }
        root.append(group);
      };
      const when = (iso) => new Date(iso).toLocaleString("pt-BR", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
      for (const node of [...items].sort((a, b) => a.created_at.localeCompare(b.created_at))) {
        const time = Date.parse(node.created_at);
        const spot = place(node.entity_type, time);
        dot(spot.cx, spot.cy, "var(--viz-1)", node.name, [
          { value: entityTypeLabel(node.entity_type), label: "" },
          { value: when(node.created_at), label: "registrado" },
        ], () => onSelect?.(node.id));
      }
      const names = new Map(nodes.map((node) => [node.id, node.name]));
      for (const edge of [...links].sort((a, b) => a.created_at.localeCompare(b.created_at))) {
        const time = Date.parse(edge.created_at);
        const spot = place("__links", time);
        dot(spot.cx, spot.cy, "var(--viz-2)", `${names.get(edge.source_entity_id) || "?"} → ${names.get(edge.target_entity_id) || "?"}`, [
          { value: relationshipLabel(edge.relationship_type), label: "" },
          { value: when(edge.created_at), label: "registrado" },
        ]);
      }
      wrap.replaceChildren(root);
    };
    requestAnimationFrame(draw);
    return wrap;
  }

  G.graphViews = { matrix, timeline, VERIFICATION };
})();
