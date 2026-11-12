"use strict";

/* Investigation board: persisted layout over shared entities and relationships. */

(function () {
  const G = window.GARBAGE;
  const {
    el, api, toast, confirm, formDialog, pageHeader, panel, badge, emptyState,
    table, loadingBlock, inlineError, formatDate, shortId, titleCase, entityTypeLabel,
    relationshipLabel, go, state,
  } = G;

  const ENTITY_LAYER = {
    person: "people",
    username: "accounts",
    profile: "accounts",
    email: "accounts",
    organization: "accounts",
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
  const KIND_LAYER = { note: "notes", text: "notes", group: "groups" };
  const LAYER_LABELS = {
    people: "People",
    accounts: "Accounts",
    domains: "Domains",
    ips: "IP addresses",
    files: "Files",
    notes: "Notes",
    groups: "Groups",
    other: "Other",
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

  function uid(prefix) {
    return `${prefix}-${crypto.randomUUID()}`;
  }

  function svgNode(name, attributes = {}) {
    const node = document.createElementNS("http://www.w3.org/2000/svg", name);
    for (const [key, value] of Object.entries(attributes)) {
      node.setAttribute(key, String(value));
    }
    return node;
  }

  function escapeXml(value) {
    return String(value)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;");
  }

  /* ================================================================ */
  /* Case selector                                                     */
  /* ================================================================ */

  async function renderBoard(root, params) {
    if (!params[0]) {
      const investigations = await G.loadInvestigations(true);
      root.append(
        pageHeader({
          eyebrow: "VISUAL ANALYSIS",
          title: "Investigation board",
          description:
            "Persisted layouts over shared entities. Open a case to arrange its board.",
        }),
        panel(
          { eyebrow: "BOARDS", title: "Select an investigation" },
          investigations.length
            ? table({
                columns: [
                  {
                    label: "INVESTIGATION",
                    render: (row) =>
                      el(
                        "div",
                        { class: "cell-stack" },
                        el("strong", {}, row.name),
                        el("span", {}, row.description || "No description"),
                      ),
                  },
                  { label: "STATUS", render: (row) => G.statusBadge(row.status) },
                  { label: "ENTITIES", className: "numeric-col", render: (row) => String(row.entity_count) },
                  { label: "UPDATED", render: (row) => formatDate(row.updated_at) },
                  { label: "", render: (row) => button("Open board", () => go("board", row.id)) },
                ],
                rows: investigations,
                emptyMessage: "No investigations exist.",
                onRowClick: (row) => go("board", row.id),
              })
            : emptyState({
                icon: "▦",
                title: "No case boards",
                description: "Create an investigation and link entities to start a board.",
                action: button("Create investigation", () => G.newInvestigation(), {
                  variant: "button-primary",
                }),
              }),
        ),
      );
      return;
    }
    await renderBoardCanvas(root, params[0]);
  }

  /* ================================================================ */
  /* Board canvas                                                      */
  /* ================================================================ */

  async function renderBoardCanvas(root, investigationId) {
    let board = null;
    let elements = [];
    let connections = [];
    let relationships = [];
    let selection = null;
    let dirty = false;
    let saving = false;
    let conflict = false;
    let autosaveTimer = null;
    let dragging = null;
    let panning = null;

    const canvas = el("div", {
      class: "board-canvas",
      tabindex: "0",
      "aria-label": "Investigation board canvas",
    });
    const world = el("div", { class: "board-world" });
    const edgeLayer = svgNode("svg", {
      class: "board-edges",
      width: "1",
      height: "1",
      "aria-hidden": "true",
    });
    world.append(edgeLayer);
    canvas.append(world);
    const statusLabel = el("span", { class: "board-status" }, "Loading…");
    const toolbar = el("div", { class: "board-toolbar" });
    const inspector = el("aside", { class: "board-inspector" });
    const shell = el(
      "div",
      { class: "board-shell" },
      toolbar,
      el(
        "div",
        { class: "board-stage" },
        canvas,
        el(
          "div",
          { class: "board-zoom" },
          button("−", () => zoomBy(0.85), { title: "Zoom out" }),
          button("＋", () => zoomBy(1.18), { title: "Zoom in" }),
          button("Fit", () => fit(), { title: "Fit board" }),
        ),
      ),
      inspector,
    );
    let header;

    const nodeEls = new Map();
    const edgeEls = new Map();

    async function load() {
      const [data, relationshipData, investigations] = await Promise.all([
        api(`/api/investigations/${investigationId}/board`),
        api(`/api/relationships?investigation_id=${encodeURIComponent(investigationId)}&limit=500`).catch(() => ({
          items: [],
        })),
        G.loadInvestigations(),
      ]);
      board = data.board;
      elements = data.elements;
      connections = data.connections;
      relationships = relationshipData.items || [];
      selection = null;
      dirty = false;
      conflict = false;
      const investigation = investigations.find((item) => item.id === investigationId);
      header = pageHeader({
        eyebrow: "INVESTIGATION BOARD",
        title: board.name,
        description: investigation?.description || "Persisted visual workspace.",
        actions: [
          button("‹ All boards", () => go("board")),
          button("Open case", () => go("investigations", investigationId)),
          button("Graph", () => go("graph", investigationId)),
          button("Save now", () => saveNow(), { variant: "button-primary" }),
        ],
      });
      root.replaceChildren(header, shell);
      renderAll();
    }

    function setStatus(text, tone = "") {
      statusLabel.textContent = text;
      statusLabel.className = `board-status ${tone}`;
    }

    function markDirty() {
      dirty = true;
      conflict = false;
      setStatus("Unsaved changes", "is-dirty");
      window.clearTimeout(autosaveTimer);
      const delay = Math.max(
        300,
        Number(G.state.settings?.["board.autosave_delay_ms"] || 1200),
      );
      autosaveTimer = window.setTimeout(() => saveNow(), delay);
    }

    function payload() {
      return {
        revision: board.revision,
        name: board.name,
        viewport: { ...board.viewport },
        layers: { ...board.layers },
        elements: elements.map((record) => ({
          id: record.id,
          element_kind: record.element_kind,
          entity_id: record.entity_id,
          label: record.label,
          content: record.content,
          x: record.x,
          y: record.y,
          width: record.width,
          height: record.height,
          layer: record.layer,
          z_index: record.z_index,
        })),
        connections: connections.map((record) => ({
          id: record.id,
          source_element_id: record.source_element_id,
          target_element_id: record.target_element_id,
          relationship_id: record.relationship_id,
          label: record.label,
          connection_type: record.connection_type,
        })),
      };
    }

    async function saveNow() {
      if (!board || saving || !dirty) {
        if (board && !dirty) setStatus("Saved", "is-saved");
        return;
      }
      window.clearTimeout(autosaveTimer);
      saving = true;
      setStatus("Saving…", "is-saving");
      try {
        const result = await api(`/api/investigations/${investigationId}/board`, {
          method: "PUT",
          body: JSON.stringify(payload()),
        });
        board.revision = result.board.revision;
        board.updated_at = result.board.updated_at;
        dirty = false;
        conflict = false;
        setStatus(`Saved · revision ${board.revision}`, "is-saved");
        renderInspector();
      } catch (error) {
        if (error.status === 409) {
          conflict = true;
          renderToolbar();
          setStatus("Revision conflict", "is-error");
          toast("The board changed elsewhere. Reload to continue safely.", "error");
          renderInspector();
        } else {
          setStatus("Save failed", "is-error");
          toast(error.message, "error");
        }
      } finally {
        saving = false;
      }
    }

    function renderAll() {
      renderToolbar();
      renderWorld();
      renderInspector();
      setStatus(
        dirty ? "Unsaved changes" : `Saved · revision ${board.revision}`,
        dirty ? "is-dirty" : "is-saved",
      );
    }

    function renderToolbar() {
      const investigationSelector = el(
        "select",
        {
          class: "input board-case-select",
          "aria-label": "Switch investigation board",
          onChange: (event) => go("board", event.target.value),
        },
        ...G.state.investigations.map((item) =>
          el("option", { value: item.id, selected: item.id === investigationId }, item.name),
        ),
      );
      toolbar.replaceChildren(
        investigationSelector,
        el("span", { class: "toolbar-divider" }),
        button("＋ Entity", () => addEntity()),
        button("＋ Note", () => addFreeElement("note")),
        button("＋ Text", () => addFreeElement("text")),
        button("＋ Group", () => addFreeElement("group")),
        button("⟷ Connect", () => addConnection(), {
          disabled: elements.length < 2,
          title: elements.length < 2 ? "Add at least two elements" : "",
        }),
        el("span", { class: "toolbar-divider" }),
        button("Arrange", () => arrange()),
        button("Export SVG", () => exportSvg()),
        el("span", { class: "toolbar-spacer" }),
        statusLabel,
      );
      if (conflict) {
        toolbar.append(
          button("Reload", () => load(), { variant: "button-danger" }),
        );
      }
    }

    function nodeById(id) {
      return elements.find((record) => record.id === id);
    }

    function isVisible(record) {
      if (!record) return false;
      return board.layers[record.layer] !== false;
    }

    function connectionPath(connection) {
      const source = nodeById(connection.source_element_id);
      const target = nodeById(connection.target_element_id);
      if (!source || !target) return "";
      const x1 = source.x + source.width / 2;
      const y1 = source.y + source.height / 2;
      const x2 = target.x + target.width / 2;
      const y2 = target.y + target.height / 2;
      const dx = Math.max(50, Math.abs(x2 - x1) * 0.45);
      const direction = x2 >= x1 ? 1 : -1;
      return `M ${x1} ${y1} C ${x1 + dx * direction} ${y1}, ${x2 - dx * direction} ${y2}, ${x2} ${y2}`;
    }

    function renderWorld() {
      world.style.transform = `translate(${board.viewport.x}px, ${board.viewport.y}px) scale(${board.viewport.zoom})`;
      nodeEls.clear();
      edgeEls.clear();
      for (const child of [...world.children]) {
        if (child !== edgeLayer) child.remove();
      }
      edgeLayer.replaceChildren();

      for (const record of elements) {
        const node = buildNode(record);
        world.append(node);
        nodeEls.set(record.id, node);
      }
      for (const connection of connections) {
        const group = svgNode("g", {
          class: "board-edge",
          "data-id": connection.id,
          tabindex: "0",
          role: "button",
        });
        const hit = svgNode("path", { class: "board-edge-hit" });
        const line = svgNode("path", { class: "board-edge-line" });
        group.append(hit, line);
        const activate = (event) => {
          event.stopPropagation();
          selection = { type: "connection", id: connection.id };
          updateSelection();
        };
        group.addEventListener("click", activate);
        group.addEventListener("keydown", (event) => {
          if (event.key === "Enter" || event.key === " ") activate(event);
        });
        edgeLayer.append(group);
        edgeEls.set(connection.id, group);
        updateEdgeGeometry(connection, group);
      }
      updateVisibility();
      canvas.classList.toggle("is-empty", elements.length === 0);
      updateSelection();
    }

    function buildNode(record) {
      const isEntity = record.element_kind === "entity";
      const label = record.label || (isEntity ? record.entity_name : record.element_kind);
      const node = el(
        "div",
        {
          class: `board-node kind-${record.element_kind} layer-${record.layer}`,
          tabindex: "0",
          role: "button",
          "aria-label": `${titleCase(record.element_kind)}: ${label}`,
          dataset: { id: record.id },
        },
        el(
          "div",
          { class: "board-node-head" },
          el(
            "span",
            { class: "board-node-type" },
            isEntity ? entityTypeLabel(record.entity_type) : titleCase(record.element_kind),
          ),
          isEntity
            ? el(
                "span",
                { class: `board-node-dot verification-${record.entity_verification || "not-verified"}` },
              )
            : null,
        ),
        el("strong", { class: "board-node-label" }, label),
        isEntity && record.entity_identifier
          ? el("code", { class: "board-node-id" }, record.entity_identifier)
          : null,
        record.content
          ? el("p", { class: "board-node-content" }, record.content)
          : null,
        el(
          "div",
          { class: "board-node-foot" },
          isEntity ? el("span", {}, record.entity_name) : el("span", {}, LAYER_LABELS[record.layer] || record.layer),
          el("span", { class: "mono" }, shortId(record.id)),
        ),
      );
      node.style.left = `${record.x}px`;
      node.style.top = `${record.y}px`;
      node.style.width = `${record.width}px`;
      node.style.height = `${record.height}px`;
      node.style.zIndex = String(
        record.z_index || (record.element_kind === "group" ? 0 : 1),
      );
      node.addEventListener("pointerdown", (event) => startDrag(event, record));
      node.addEventListener("click", (event) => {
        event.stopPropagation();
        selection = { type: "element", id: record.id };
        updateSelection();
      });
      node.addEventListener("dblclick", (event) => {
        event.stopPropagation();
        if (isEntity && record.entity_id) go("entities", record.entity_id);
      });
      return node;
    }

    function updateEdgeGeometry(connection, group = edgeEls.get(connection.id)) {
      if (!group) return;
      const path = connectionPath(connection);
      group.querySelector(".board-edge-hit").setAttribute("d", path);
      group.querySelector(".board-edge-line").setAttribute("d", path);
    }

    function updateGeometry() {
      for (const record of elements) {
        const node = nodeEls.get(record.id);
        if (!node) continue;
        node.style.left = `${record.x}px`;
        node.style.top = `${record.y}px`;
        node.style.width = `${record.width}px`;
        node.style.height = `${record.height}px`;
      }
      for (const connection of connections) {
        updateEdgeGeometry(connection);
      }
    }

    function updateVisibility() {
      for (const record of elements) {
        const node = nodeEls.get(record.id);
        if (node) node.classList.toggle("is-hidden", !isVisible(record));
      }
      for (const connection of connections) {
        const group = edgeEls.get(connection.id);
        const source = nodeById(connection.source_element_id);
        const target = nodeById(connection.target_element_id);
        if (group) {
          group.classList.toggle(
            "is-hidden",
            !isVisible(source) || !isVisible(target),
          );
        }
      }
    }

    function updateSelection() {
      document.querySelectorAll(".board-node.is-selected").forEach((node) =>
        node.classList.remove("is-selected"),
      );
      document.querySelectorAll(".board-edge.is-selected").forEach((edge) =>
        edge.classList.remove("is-selected"),
      );
      if (selection?.type === "element") {
        nodeEls.get(selection.id)?.classList.add("is-selected");
      } else if (selection?.type === "connection") {
        edgeEls.get(selection.id)?.classList.add("is-selected");
      }
      renderInspector();
    }

    /* ------------------------------------------------------------ */
    /* Interaction                                                  */
    /* ------------------------------------------------------------ */

    function startDrag(event, record) {
      if (event.button !== 0) return;
      if (event.target.closest(".board-node-actions")) return;
      event.stopPropagation();
      event.preventDefault();
      canvas.focus({ preventScroll: true });
      const node = nodeEls.get(record.id);
      node.setPointerCapture(event.pointerId);
      selection = { type: "element", id: record.id };
      updateSelection();
      dragging = {
        record,
        node,
        pointerId: event.pointerId,
        startX: event.clientX,
        startY: event.clientY,
        originX: record.x,
        originY: record.y,
        moved: false,
      };
      node.classList.add("is-dragging");
    }

    canvas.addEventListener("pointerdown", (event) => {
      if (event.button !== 0 && event.button !== 1) return;
      if (event.target.closest(".board-node") || event.target.closest(".board-edge")) return;
      event.preventDefault();
      canvas.setPointerCapture(event.pointerId);
      panning = {
        pointerId: event.pointerId,
        startX: event.clientX,
        startY: event.clientY,
        originX: board.viewport.x,
        originY: board.viewport.y,
      };
      canvas.classList.add("is-panning");
      selection = null;
      updateSelection();
    });

    canvas.addEventListener("pointermove", (event) => {
      if (dragging && event.pointerId === dragging.pointerId) {
        const dx = (event.clientX - dragging.startX) / board.viewport.zoom;
        const dy = (event.clientY - dragging.startY) / board.viewport.zoom;
        if (Math.abs(dx) > 1 || Math.abs(dy) > 1) dragging.moved = true;
        dragging.record.x = Math.round(dragging.originX + dx);
        dragging.record.y = Math.round(dragging.originY + dy);
        updateGeometry();
        return;
      }
      if (panning && event.pointerId === panning.pointerId) {
        board.viewport.x = Math.round(panning.originX + event.clientX - panning.startX);
        board.viewport.y = Math.round(panning.originY + event.clientY - panning.startY);
        world.style.transform = `translate(${board.viewport.x}px, ${board.viewport.y}px) scale(${board.viewport.zoom})`;
      }
    });

    function endPointer(event) {
      if (dragging && event.pointerId === dragging.pointerId) {
        dragging.node.classList.remove("is-dragging");
        if (dragging.moved) markDirty();
        dragging = null;
      }
      if (panning && event.pointerId === panning.pointerId) {
        canvas.classList.remove("is-panning");
        markDirty();
        panning = null;
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
        const worldX = (pointerX - board.viewport.x) / board.viewport.zoom;
        const worldY = (pointerY - board.viewport.y) / board.viewport.zoom;
        const next = Math.min(
          3,
          Math.max(0.2, board.viewport.zoom * Math.exp(-event.deltaY * 0.0012)),
        );
        board.viewport.zoom = Number(next.toFixed(3));
        board.viewport.x = pointerX - worldX * board.viewport.zoom;
        board.viewport.y = pointerY - worldY * board.viewport.zoom;
        world.style.transform = `translate(${board.viewport.x}px, ${board.viewport.y}px) scale(${board.viewport.zoom})`;
        markDirty();
      },
      { passive: false },
    );

    canvas.addEventListener("keydown", (event) => {
      if (!selection) return;
      if (event.key === "Delete" || event.key === "Backspace") {
        event.preventDefault();
        removeSelection();
      } else if (event.key === "Escape") {
        selection = null;
        updateSelection();
      }
    });

    document.addEventListener("keydown", onGlobalKey);
    window.addEventListener("beforeunload", beforeUnload);
    G.cleanupFns.push(() => {
      window.clearTimeout(autosaveTimer);
      document.removeEventListener("keydown", onGlobalKey);
      window.removeEventListener("beforeunload", beforeUnload);
    });

    function onGlobalKey(event) {
      if (
        (event.key === "Delete" || event.key === "Backspace") &&
        selection &&
        !event.target.closest("input, textarea, select") &&
        !event.target.closest("[contenteditable='true']")
      ) {
        event.preventDefault();
        removeSelection();
      }
    }

    function beforeUnload(event) {
      if (dirty) {
        event.preventDefault();
        event.returnValue = "";
      }
    }

    function zoomBy(factor) {
      const rect = canvas.getBoundingClientRect();
      const pointerX = rect.width / 2;
      const pointerY = rect.height / 2;
      const worldX = (pointerX - board.viewport.x) / board.viewport.zoom;
      const worldY = (pointerY - board.viewport.y) / board.viewport.zoom;
      board.viewport.zoom = Number(
        Math.min(3, Math.max(0.2, board.viewport.zoom * factor)).toFixed(3),
      );
      board.viewport.x = pointerX - worldX * board.viewport.zoom;
      board.viewport.y = pointerY - worldY * board.viewport.zoom;
      world.style.transform = `translate(${board.viewport.x}px, ${board.viewport.y}px) scale(${board.viewport.zoom})`;
      markDirty();
    }

    function fit(mark = true) {
      if (!elements.length) {
        board.viewport = { x: 0, y: 0, zoom: 1 };
      } else {
        const minX = Math.min(...elements.map((record) => record.x));
        const minY = Math.min(...elements.map((record) => record.y));
        const maxX = Math.max(...elements.map((record) => record.x + record.width));
        const maxY = Math.max(...elements.map((record) => record.y + record.height));
        const rect = canvas.getBoundingClientRect();
        const width = Math.max(1, maxX - minX);
        const height = Math.max(1, maxY - minY);
        const zoom = Math.min(
          1.1,
          Math.max(0.2, Math.min((rect.width - 140) / width, (rect.height - 140) / height)),
        );
        board.viewport.zoom = Number(zoom.toFixed(3));
        board.viewport.x = Math.round((rect.width - width * zoom) / 2 - minX * zoom);
        board.viewport.y = Math.round((rect.height - height * zoom) / 2 - minY * zoom);
      }
      world.style.transform = `translate(${board.viewport.x}px, ${board.viewport.y}px) scale(${board.viewport.zoom})`;
      if (mark) markDirty();
    }

    function arrange() {
      const placed = elements.filter((record) => record.element_kind !== "group");
      const groups = elements.filter((record) => record.element_kind === "group");
      const columns = Math.max(1, Math.ceil(Math.sqrt(placed.length)));
      placed.forEach((record, index) => {
        record.x = 80 + (index % columns) * 300;
        record.y = 80 + Math.floor(index / columns) * 200;
      });
      groups.forEach((record, index) => {
        record.x = 40 + index * 20;
        record.y = 40 + index * 20;
      });
      updateGeometry();
      markDirty();
      renderInspector();
    }

    function viewportCenter() {
      return {
        x: Math.round((canvas.clientWidth / 2 - board.viewport.x) / board.viewport.zoom - 120),
        y: Math.round((canvas.clientHeight / 2 - board.viewport.y) / board.viewport.zoom - 70),
      };
    }

    async function addEntity() {
      let data;
      try {
        data = await api(
          `/api/entities?limit=500&investigation_id=${encodeURIComponent(investigationId)}`,
        );
      } catch (error) {
        toast(error.message, "error");
        return;
      }
      const placed = new Set(
        elements.filter((record) => record.entity_id).map((record) => record.entity_id),
      );
      const available = data.items.filter((entity) => !placed.has(entity.id));
      if (!available.length) {
        toast(
          data.items.length
            ? "All entities linked to this case are already on the board."
            : "Link entities to this investigation first.",
          "error",
        );
        return;
      }
      await formDialog({
        eyebrow: "ADD ENTITY",
        title: "Place a shared entity",
        description: "The board stores layout only; the entity record remains canonical.",
        fields: [
          {
            name: "entity_id",
            label: "Entity",
            type: "select",
            options: available.map((entity) => [
              entity.id,
              `${entity.name} · ${entityTypeLabel(entity.entity_type)}`,
            ]),
          },
        ],
        submitLabel: "Add to board",
        onSubmit: async (values) => {
          const entity = available.find((item) => item.id === values.entity_id);
          if (!entity) throw new Error("Select an entity.");
          const center = viewportCenter();
          elements.push({
            id: uid("el"),
            board_id: board.id,
            element_kind: "entity",
            entity_id: entity.id,
            entity_name: entity.name,
            entity_type: entity.entity_type,
            entity_identifier: entity.identifier,
            entity_verification: entity.verification_status,
            label: entity.name,
            content: "",
            x: center.x,
            y: center.y,
            width: 240,
            height: 140,
            layer: ENTITY_LAYER[entity.entity_type] || "other",
            z_index: Math.max(1, ...elements.map((record) => record.z_index || 0)),
          });
          selection = { type: "element", id: elements[elements.length - 1].id };
          renderWorld();
          markDirty();
        },
      });
    }

    async function addFreeElement(kind) {
      await formDialog({
        eyebrow: `ADD ${kind.toUpperCase()}`,
        title:
          kind === "note" ? "Add an analyst note" : kind === "text" ? "Add a text block" : "Add a group frame",
        description: "Notes and groups are board-local presentation elements.",
        fields: [
          {
            name: "label",
            label: "Label",
            required: true,
            maxlength: 300,
            placeholder: kind === "group" ? "Cluster name" : "Short title",
          },
          ...(kind === "group"
            ? []
            : [
                {
                  name: "content",
                  label: "Content",
                  type: "textarea",
                  rows: 4,
                  placeholder: "Analyst annotation. Not a sourced observation.",
                },
              ]),
        ],
        submitLabel: "Add",
        onSubmit: async (values) => {
          const center = viewportCenter();
          const record = {
            id: uid("el"),
            board_id: board.id,
            element_kind: kind,
            entity_id: null,
            label: values.label,
            content: values.content || "",
            x: center.x,
            y: center.y,
            width: kind === "group" ? 420 : 240,
            height: kind === "group" ? 280 : 140,
            layer: KIND_LAYER[kind] || "notes",
            z_index: kind === "group" ? 0 : 10,
          };
          elements.unshift(record);
          selection = { type: "element", id: record.id };
          renderWorld();
          markDirty();
        },
      });
    }

    async function addConnection() {
      if (elements.length < 2) {
        toast("Add at least two elements before connecting.", "error");
        return;
      }
      const options = elements.map((record) => [
        record.id,
        `${record.label || record.element_kind} (${record.element_kind})`,
      ]);
      const typeOptions = (G.RELATIONSHIP_TYPES || []).map(([value, label]) => [value, label]);
      await formDialog({
        eyebrow: "BOARD CONNECTION",
        title: "Connect two elements",
        description:
          "If the two entities share a recorded relationship, the board connection references it.",
        fields: [
          { name: "source_element_id", label: "Source", type: "select", options },
          { name: "target_element_id", label: "Target", type: "select", options },
          {
            name: "connection_type",
            label: "Type",
            type: "select",
            options: typeOptions,
            value: "connected-to",
          },
          { name: "label", label: "Label", maxlength: 300 },
        ],
        submitLabel: "Connect",
        onSubmit: async (values) => {
          if (values.source_element_id === values.target_element_id) {
            throw new Error("Choose two different elements.");
          }
          if (
            connections.some(
              (record) =>
                (record.source_element_id === values.source_element_id &&
                  record.target_element_id === values.target_element_id) ||
                (record.source_element_id === values.target_element_id &&
                  record.target_element_id === values.source_element_id),
            )
          ) {
            throw new Error("These elements are already connected.");
          }
          const source = nodeById(values.source_element_id);
          const target = nodeById(values.target_element_id);
          let relationshipId = null;
          if (source?.entity_id && target?.entity_id) {
            const match = relationships.find(
              (relationship) =>
                (relationship.source_entity_id === source.entity_id &&
                  relationship.target_entity_id === target.entity_id) ||
                (relationship.source_entity_id === target.entity_id &&
                  relationship.target_entity_id === source.entity_id),
            );
            relationshipId = match?.id || null;
          }
          connections.push({
            id: uid("cn"),
            board_id: board.id,
            source_element_id: values.source_element_id,
            target_element_id: values.target_element_id,
            relationship_id: relationshipId,
            label: values.label || "",
            connection_type: values.connection_type,
            relationship_verification: relationshipId
              ? relationships.find((item) => item.id === relationshipId)?.verification_status
              : null,
            relationship_type: relationshipId
              ? relationships.find((item) => item.id === relationshipId)?.relationship_type
              : null,
          });
          renderWorld();
          markDirty();
        },
      });
    }

    function removeSelection() {
      if (!selection) return;
      if (selection.type === "element") {
        elements = elements.filter((record) => record.id !== selection.id);
        connections = connections.filter(
          (record) =>
            record.source_element_id !== selection.id &&
            record.target_element_id !== selection.id,
        );
      } else if (selection.type === "connection") {
        connections = connections.filter((record) => record.id !== selection.id);
      }
      selection = null;
      renderWorld();
      markDirty();
    }

    /* ------------------------------------------------------------ */
    /* Inspector                                                    */
    /* ------------------------------------------------------------ */

    function renderInspector() {
      if (selection?.type === "element") {
        const record = nodeById(selection.id);
        if (!record) {
          selection = null;
          return renderInspector();
        }
        const isEntity = record.element_kind === "entity";
        const label = el("input", {
          class: "input",
          value: record.label,
          maxlength: 300,
          "aria-label": "Element label",
        });
        const content = el("textarea", {
          class: "input",
          rows: 4,
          maxlength: 5000,
          placeholder: isEntity ? "Board annotation" : "Element content",
          "aria-label": "Element content",
        });
        content.value = record.content || "";
        const layer = el(
          "select",
          { class: "input", "aria-label": "Element layer" },
          ...Object.entries(LAYER_LABELS).map(([value, text]) =>
            el("option", { value, selected: value === record.layer }, text),
          ),
        );
        const applyButton = button(
          "Apply changes",
          () => {
            if (!label.value.trim()) {
              toast("A label is required.", "error");
              return;
            }
            record.label = label.value.trim();
            record.content = content.value;
            record.layer = layer.value;
            renderWorld();
            markDirty();
          },
          { variant: "button-primary" },
        );
        inspector.replaceChildren(
          panel(
            { eyebrow: isEntity ? "ENTITY ELEMENT" : titleCase(record.element_kind), title: record.label || "Untitled" },
            isEntity
              ? G.kvList([
                  ["Entity", record.entity_name],
                  ["Category", entityTypeLabel(record.entity_type)],
                  ["Identifier", record.entity_identifier || "—"],
                  ["Verification", G.statusBadge(record.entity_verification || "not-verified")],
                ])
              : null,
            el("div", { class: "field" }, el("label", {}, "Label"), label),
            el("div", { class: "field" }, el("label", {}, "Content"), content),
            el("div", { class: "field" }, el("label", {}, "Layer"), layer),
            el("div", { class: "inspector-actions" }, applyButton),
            isEntity
              ? button("Open entity record", () => go("entities", record.entity_id))
              : null,
            button("Remove from board", () => removeSelection(), {
              variant: "button-danger",
            }),
            el(
              "p",
              { class: "panel-note" },
              "Removing a board element never deletes the shared entity or its relationships.",
            ),
          ),
        );
        return;
      }
      if (selection?.type === "connection") {
        const record = connections.find((item) => item.id === selection.id);
        if (!record) {
          selection = null;
          return renderInspector();
        }
        const type = el(
          "select",
          { class: "input", "aria-label": "Connection type" },
          ...(G.RELATIONSHIP_TYPES || []).map(([value, label]) =>
            el("option", { value, selected: value === record.connection_type }, label),
          ),
        );
        const label = el("input", {
          class: "input",
          value: record.label || "",
          maxlength: 300,
          "aria-label": "Connection label",
        });
        const source = nodeById(record.source_element_id);
        const target = nodeById(record.target_element_id);
        inspector.replaceChildren(
          panel(
            { eyebrow: "CONNECTION", title: `${source?.label || "?"} → ${target?.label || "?"}` },
            G.kvList([
              ["Type", relationshipLabel(record.connection_type)],
              [
                "Shared relationship",
                record.relationship_id
                  ? el("code", { class: "hash" }, shortId(record.relationship_id))
                  : "Layout-only connection",
              ],
              [
                "Verification",
                record.relationship_verification
                  ? G.statusBadge(record.relationship_verification)
                  : "Not recorded",
              ],
            ]),
            el("div", { class: "field" }, el("label", {}, "Type"), type),
            el("div", { class: "field" }, el("label", {}, "Label"), label),
            el(
              "div",
              { class: "inspector-actions" },
              button(
                "Apply",
                () => {
                  record.connection_type = type.value;
                  record.label = label.value;
                  renderWorld();
                  markDirty();
                },
                { variant: "button-primary" },
              ),
              button("Delete connection", () => removeSelection(), {
                variant: "button-danger",
              }),
            ),
            record.relationship_id
              ? button("Open relationship context", () => go("investigations", investigationId))
              : el(
                  "p",
                  { class: "panel-note" },
                  "This connection is presentation-only. Record a relationship in the case to make it part of the intelligence graph.",
                ),
          ),
        );
        return;
      }
      const layerToggles = Object.entries(LAYER_LABELS).map(([key, label]) => {
        const input = el("input", {
          type: "checkbox",
          checked: board.layers[key] !== false,
          onChange: (event) => {
            board.layers[key] = event.target.checked;
            updateVisibility();
            markDirty();
          },
        });
        return el(
          "label",
          { class: "layer-toggle" },
          input,
          el("span", { class: `layer-swatch layer-${key}` }),
          label,
        );
      });
      const nameInput = el("input", {
        class: "input",
        value: board.name,
        maxlength: 200,
        "aria-label": "Board name",
      });
      inspector.replaceChildren(
        panel(
          { eyebrow: "BOARD", title: "Layout properties" },
          G.kvList([
            ["Revision", String(board.revision)],
            ["Elements", String(elements.length)],
            ["Connections", String(connections.length)],
            ["Updated", formatDate(board.updated_at, { time: true })],
          ]),
          el("div", { class: "field" }, el("label", {}, "Board name"), nameInput),
          button(
            "Rename board",
            () => {
              if (!nameInput.value.trim()) {
                toast("A board name is required.", "error");
                return;
              }
              board.name = nameInput.value.trim();
              if (header) {
                const heading = header.querySelector("h1");
                if (heading) heading.textContent = board.name;
              }
              markDirty();
            },
          ),
        ),
        panel(
          { eyebrow: "LAYERS", title: "Visibility" },
          el("div", { class: "layer-list" }, ...layerToggles),
          el(
            "p",
            { class: "panel-note" },
            "Hidden layers stay in the saved board and are not deleted.",
          ),
        ),
        panel(
          { eyebrow: "SYNC", title: "Persistence" },
          el(
            "p",
            { class: "panel-note" },
            `Autosave after ${Math.round(
              Number(G.state.settings?.["board.autosave_delay_ms"] || 1200) / 1000,
            )}s of inactivity. Saves use optimistic revisions to prevent overwriting another session.`,
          ),
          button("Save now", () => saveNow(), { variant: "button-primary" }),
          conflict
            ? button("Reload from server", () => load(), { variant: "button-danger" })
            : null,
        ),
      );
    }

    /* ------------------------------------------------------------ */
    /* Export                                                       */
    /* ------------------------------------------------------------ */

    function exportSvg() {
      if (!elements.length) {
        toast("The board is empty.", "error");
        return;
      }
      const padding = 80;
      const minX = Math.min(...elements.map((record) => record.x)) - padding;
      const minY = Math.min(...elements.map((record) => record.y)) - padding;
      const maxX = Math.max(...elements.map((record) => record.x + record.width)) + padding;
      const maxY = Math.max(...elements.map((record) => record.y + record.height)) + padding;
      const width = maxX - minX;
      const height = maxY - minY;
      const parts = [
        `<svg xmlns="http://www.w3.org/2000/svg" width="${Math.round(width)}" height="${Math.round(height)}" viewBox="${minX} ${minY} ${width} ${height}">`,
        `<rect x="${minX}" y="${minY}" width="${width}" height="${height}" fill="#0a0d12"/>`,
      ];
      for (const record of elements) {
        if (!isVisible(record)) continue;
        const fill = record.element_kind === "group" ? "rgba(255,255,255,0.03)" : "#12171f";
        const stroke = record.element_kind === "group" ? "#4b5a70" : "#2c3644";
        parts.push(
          `<rect x="${record.x}" y="${record.y}" width="${record.width}" height="${record.height}" rx="8" fill="${fill}" stroke="${stroke}"/>`,
          `<text x="${record.x + 16}" y="${record.y + 26}" fill="#8fa0b5" font-family="ui-monospace, monospace" font-size="10">${escapeXml(
            record.element_kind === "entity"
              ? entityTypeLabel(record.entity_type)
              : titleCase(record.element_kind),
          )}</text>`,
          `<text x="${record.x + 16}" y="${record.y + 50}" fill="#e7edf5" font-family="system-ui, sans-serif" font-size="15" font-weight="600">${escapeXml(
            (record.label || "").slice(0, 42),
          )}</text>`,
        );
        if (record.entity_identifier) {
          parts.push(
            `<text x="${record.x + 16}" y="${record.y + 72}" fill="#7f8ea3" font-family="ui-monospace, monospace" font-size="11">${escapeXml(
              record.entity_identifier.slice(0, 44),
            )}</text>`,
          );
        }
        if (record.content) {
          const lines = record.content.slice(0, 220).match(/.{1,52}(\s|$)/g) || [];
          lines.slice(0, 5).forEach((line, index) => {
            parts.push(
              `<text x="${record.x + 16}" y="${record.y + 94 + index * 16}" fill="#a8b6c8" font-family="system-ui, sans-serif" font-size="12">${escapeXml(
                line.trim(),
              )}</text>`,
            );
          });
        }
      }
      for (const connection of connections) {
        const source = nodeById(connection.source_element_id);
        const target = nodeById(connection.target_element_id);
        if (!source || !target || !isVisible(source) || !isVisible(target)) continue;
        const x1 = source.x + source.width / 2;
        const y1 = source.y + source.height / 2;
        const x2 = target.x + target.width / 2;
        const y2 = target.y + target.height / 2;
        const dx = Math.max(50, Math.abs(x2 - x1) * 0.45);
        const direction = x2 >= x1 ? 1 : -1;
        parts.push(
          `<path d="M ${x1} ${y1} C ${x1 + dx * direction} ${y1}, ${x2 - dx * direction} ${y2}, ${x2} ${y2}" fill="none" stroke="#5b718c" stroke-width="1.5"/>`,
        );
      }
      parts.push("</svg>");
      const blob = new Blob([parts.join("\n")], { type: "image/svg+xml" });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = `board-${investigationId.slice(0, 8)}.svg`;
      document.body.append(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(link.href), 2000);
      toast("Board exported as SVG.");
    }

    /* ------------------------------------------------------------ */
    /* Boot                                                          */
    /* ------------------------------------------------------------ */

    G.setLoading(true);
    root.replaceChildren(loadingBlock("Opening investigation board…"));
    try {
      await load();
    } catch (error) {
      root.replaceChildren(
        el(
          "div",
          { class: "empty-state" },
          el("span", { class: "empty-icon", "aria-hidden": "true" }, "!"),
          el("h2", {}, "Board unavailable"),
          el("p", {}, error.message),
          button("Retry", () => renderBoardCanvas(root, investigationId), {
            variant: "button-primary",
          }),
        ),
      );
    } finally {
      G.setLoading(false);
    }
  }

  G.views.board = renderBoard;
})();
