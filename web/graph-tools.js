"use strict";

/* Graph tooling shared by the graph view: entity glyphs, view history
 * (undo/redo), the minimap, and exports (PNG, GraphML, JSON layout).
 */

(function () {
  const G = window.GARBAGE;
  const { svgEl } = G;

  /* 24x24 stroke glyphs drawn inside the node circle. */
  const TYPE_GLYPHS = {
    person: "M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4.5 21a7.5 7.5 0 0 1 15 0",
    username: "M16 12a4 4 0 1 1-8 0 4 4 0 0 1 8 0zM16 12v1.5a2.5 2.5 0 0 0 5 0V12a9 9 0 1 0-3.5 7.1",
    profile: "M3.5 5h17v14h-17zM9 12a2 2 0 1 0 0-4 2 2 0 0 0 0 4zM5.5 16.5a3.5 3.5 0 0 1 7 0M14.5 9.5h3.5M14.5 13h3.5",
    email: "M3.5 5.5h17v13h-17zM3.5 6l8.5 7 8.5-7",
    organization: "M4 21V5l8-2v18M12 8h8v13M7 8h2M7 12h2M7 16h2M15 12h2M15 16h2M2.5 21h19",
    domain: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM3 12h18M12 3c2.5 2.7 3.8 5.7 3.8 9s-1.3 6.3-3.8 9c-2.5-2.7-3.8-5.7-3.8-9S9.5 5.7 12 3z",
    url: "M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1",
    ipv4: "M4 4.5h16v6H4zM4 13.5h16v6H4zM7.5 7.5h.01M7.5 16.5h.01M11 7.5h6M11 16.5h6",
    ipv6: "M4 4.5h16v6H4zM4 13.5h16v6H4zM7.5 7.5h.01M7.5 16.5h.01M11 7.5h6M11 16.5h6",
    file: "M14 3H6.5A1.5 1.5 0 0 0 5 4.5v15A1.5 1.5 0 0 0 6.5 21h11a1.5 1.5 0 0 0 1.5-1.5V8zM14 3v5h5M8.5 13h7M8.5 16.5h5",
    image: "M3.5 5h17v14h-17zM3.5 16l5-5 4 4 2.5-2.5 6 6M15.5 9.5h.01",
    hash: "M9 4 7 20M17 4l-2 16M4.5 9h16M3.5 15h16",
    ioc: "M12 3l9.5 17h-19zM12 10v4.5M12 17.5v.3",
    other: "M12 12.5a.5.5 0 1 0 0-1 .5.5 0 0 0 0 1zM6.5 12.5a.5.5 0 1 0 0-1 .5.5 0 0 0 0 1zM17.5 12.5a.5.5 0 1 0 0-1 .5.5 0 0 0 0 1z",
  };

  function glyph(type, radius) {
    const scale = (radius * 1.15) / 24;
    return svgEl("path", {
      d: TYPE_GLYPHS[type] || TYPE_GLYPHS.other,
      class: "graph-node-glyph",
      transform: `translate(${-12 * scale} ${-12 * scale}) scale(${scale})`,
      "stroke-width": String(1.5 / scale),
    });
  }

  /* Undo/redo over snapshots of the view (positions, pins, hidden). */
  class ViewHistory {
    constructor(limit = 60) {
      this.limit = limit;
      this.past = [];
      this.future = [];
    }

    push(snapshot) {
      this.past.push(snapshot);
      if (this.past.length > this.limit) this.past.shift();
      this.future = [];
    }

    undo(current) {
      if (!this.past.length) return null;
      this.future.push(current);
      return this.past.pop();
    }

    redo(current) {
      if (!this.future.length) return null;
      this.past.push(current);
      return this.future.pop();
    }

    clear() {
      this.past = [];
      this.future = [];
    }

    get canUndo() {
      return this.past.length > 0;
    }

    get canRedo() {
      return this.future.length > 0;
    }
  }

  /* Minimap: every visible node as a dot and the viewport as a frame.
     Clicking or dragging recentres the main view. */
  function minimap({ width = 180, height = 120, onNavigate }) {
    const svg = svgEl("svg", {
      class: "graph-minimap",
      width: String(width),
      height: String(height),
      viewBox: `0 0 ${width} ${height}`,
      role: "img",
      "aria-label": "Minimapa do grafo",
    });
    const dots = svgEl("g", { class: "minimap-dots" });
    const frame = svgEl("rect", { class: "minimap-frame" });
    svg.append(dots, frame);
    let transform = null;

    function update(nodes, selection) {
      dots.replaceChildren();
      if (!nodes.length) {
        frame.setAttribute("width", "0");
        transform = null;
        return;
      }
      const pad = 40;
      const minX = Math.min(...nodes.map((node) => node.x)) - pad;
      const minY = Math.min(...nodes.map((node) => node.y)) - pad;
      const maxX = Math.max(...nodes.map((node) => node.x)) + pad;
      const maxY = Math.max(...nodes.map((node) => node.y)) + pad;
      const scale = Math.min(width / (maxX - minX), height / (maxY - minY));
      const offsetX = (width - (maxX - minX) * scale) / 2;
      const offsetY = (height - (maxY - minY) * scale) / 2;
      transform = { minX, minY, scale, offsetX, offsetY };
      for (const node of nodes) {
        dots.append(
          svgEl("circle", {
            cx: offsetX + (node.x - minX) * scale,
            cy: offsetY + (node.y - minY) * scale,
            r: selection.has(node.id) ? 2.6 : 1.6,
            class: selection.has(node.id) ? "is-selected" : "",
          }),
        );
      }
    }

    function setViewport(viewport, canvasRect) {
      if (!transform) return;
      const { minX, minY, scale, offsetX, offsetY } = transform;
      const left = offsetX + (-viewport.x / viewport.zoom - minX) * scale;
      const top = offsetY + (-viewport.y / viewport.zoom - minY) * scale;
      const right = left + (canvasRect.width / viewport.zoom) * scale;
      const bottom = top + (canvasRect.height / viewport.zoom) * scale;
      // Clip to the minimap so a zoomed-out view still draws a sane frame.
      const x = Math.max(0, left);
      const y = Math.max(0, top);
      frame.setAttribute("x", x);
      frame.setAttribute("y", y);
      frame.setAttribute("width", Math.max(4, Math.min(width, right) - x));
      frame.setAttribute("height", Math.max(4, Math.min(height, bottom) - y));
    }

    function navigate(event) {
      if (!transform) return;
      const rect = svg.getBoundingClientRect();
      const x = ((event.clientX - rect.left) * width) / rect.width;
      const y = ((event.clientY - rect.top) * height) / rect.height;
      onNavigate(
        transform.minX + (x - transform.offsetX) / transform.scale,
        transform.minY + (y - transform.offsetY) / transform.scale,
      );
    }
    let dragging = false;
    svg.addEventListener("pointerdown", (event) => {
      event.stopPropagation();
      event.preventDefault();
      dragging = true;
      svg.setPointerCapture(event.pointerId);
      navigate(event);
    });
    svg.addEventListener("pointermove", (event) => dragging && navigate(event));
    svg.addEventListener("pointerup", () => { dragging = false; });
    svg.addEventListener("pointercancel", () => { dragging = false; });
    return { element: svg, update, setViewport };
  }

  /* ---------------------------------------------------------------- */
  /* Exports                                                           */
  /* ---------------------------------------------------------------- */

  function xml(value) {
    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, "");
  }

  const NODE_KEYS = ["entity_type", "name", "identifier", "verification_status", "confidence", "x", "y", "pinned"];
  const EDGE_KEYS = ["relationship_type", "verification_status", "confidence", "description", "investigation_id"];

  function toGraphML(nodes, edges, meta = {}) {
    const lines = [
      '<?xml version="1.0" encoding="UTF-8"?>',
      '<graphml xmlns="http://graphml.graphdrawing.org/xmlns" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://graphml.graphdrawing.org/xmlns http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd">',
      `  <!-- GARBAGE graph export ${xml(meta.exportedAt || new Date().toISOString())}${meta.scope ? ` · ${xml(meta.scope)}` : ""} -->`,
    ];
    NODE_KEYS.forEach((key) => {
      const type = key === "x" || key === "y" ? "double" : key === "pinned" ? "boolean" : "string";
      lines.push(`  <key id="n_${key}" for="node" attr.name="${key}" attr.type="${type}"/>`);
    });
    EDGE_KEYS.forEach((key) => lines.push(`  <key id="e_${key}" for="edge" attr.name="${key}" attr.type="string"/>`));
    lines.push('  <graph id="garbage" edgedefault="directed">');
    for (const node of nodes) {
      lines.push(`    <node id="${xml(node.id)}">`);
      for (const key of NODE_KEYS) {
        let value = node[key];
        if (key === "x" || key === "y") value = Math.round(Number(value || 0) * 10) / 10;
        if (value === undefined || value === null || value === "") continue;
        lines.push(`      <data key="n_${key}">${xml(value)}</data>`);
      }
      lines.push("    </node>");
    }
    for (const edge of edges) {
      lines.push(`    <edge id="${xml(edge.id)}" source="${xml(edge.source_entity_id)}" target="${xml(edge.target_entity_id)}">`);
      for (const key of EDGE_KEYS) {
        if (edge[key] === undefined || edge[key] === null || edge[key] === "") continue;
        lines.push(`      <data key="e_${key}">${xml(edge[key])}</data>`);
      }
      lines.push("    </edge>");
    }
    lines.push("  </graph>", "</graphml>");
    return lines.join("\n");
  }

  function toJSON(nodes, edges, meta = {}) {
    return JSON.stringify(
      {
        format: "garbage-graph",
        version: 1,
        exported_at: meta.exportedAt || new Date().toISOString(),
        scope: meta.scope || "",
        nodes: nodes.map((node) => ({
          id: node.id,
          entity_type: node.entity_type,
          name: node.name,
          identifier: node.identifier || "",
          verification_status: node.verification_status,
          x: Math.round(node.x * 10) / 10,
          y: Math.round(node.y * 10) / 10,
          pinned: Boolean(node.pinned),
          hidden: Boolean(node.hidden),
        })),
        edges: edges.map((edge) => ({
          id: edge.id,
          source: edge.source_entity_id,
          target: edge.target_entity_id,
          relationship_type: edge.relationship_type,
          verification_status: edge.verification_status,
          description: edge.description || "",
        })),
      },
      null,
      2,
    );
  }

  function download(blob, filename) {
    const url = URL.createObjectURL(blob);
    const link = G.el("a", { href: url, download: filename });
    document.body.append(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1500);
  }

  /* Rasterise a standalone SVG string to a PNG blob at `scale`x. */
  function rasterize(svgText, width, height, scale = 2) {
    return new Promise((resolve, reject) => {
      const url = URL.createObjectURL(new Blob([svgText], { type: "image/svg+xml" }));
      const image = new Image();
      image.onload = () => {
        const maxSide = 8192;
        const factor = Math.min(scale, maxSide / width, maxSide / height);
        const canvas = document.createElement("canvas");
        canvas.width = Math.max(1, Math.round(width * factor));
        canvas.height = Math.max(1, Math.round(height * factor));
        const context = canvas.getContext("2d");
        context.drawImage(image, 0, 0, canvas.width, canvas.height);
        URL.revokeObjectURL(url);
        canvas.toBlob((blob) => (blob ? resolve(blob) : reject(new Error("PNG não gerado"))), "image/png");
      };
      image.onerror = () => {
        URL.revokeObjectURL(url);
        reject(new Error("Não foi possível desenhar o grafo como imagem"));
      };
      image.src = url;
    });
  }

  /* Saved view (pins, hidden nodes, layout) per graph scope, per browser. */
  function storageKey(scope) {
    return `garbage.graph.view.${scope || "all"}`;
  }

  function loadView(scope) {
    try {
      const raw = window.localStorage.getItem(storageKey(scope));
      return raw ? JSON.parse(raw) : null;
    } catch (error) {
      return null;
    }
  }

  function saveView(scope, view) {
    try {
      window.localStorage.setItem(storageKey(scope), JSON.stringify(view));
      return true;
    } catch (error) {
      return false;
    }
  }

  G.graphTools = {
    TYPE_GLYPHS,
    glyph,
    ViewHistory,
    minimap,
    toGraphML,
    toJSON,
    download,
    rasterize,
    loadView,
    saveView,
  };
})();
