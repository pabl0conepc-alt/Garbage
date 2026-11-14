"use strict";

/* GEOINT map: EXIF GPS of analysed images and approximate network
 * locations, drawn over a local Natural Earth outline (no tile server). */

(function () {
  const G = window.GARBAGE;
  const { el, svgEl, api, panel, badge, table, loadingBlock, inlineError, pageHeader, formatDate } = G;

  const KIND = {
    photo: { label: "GPS de imagem", color: "var(--viz-1)", note: "posição gravada pelo dispositivo" },
    network: { label: "Rede (aproximada)", color: "var(--viz-2)", note: "cidade ou região do bloco de IPs, não de uma pessoa" },
  };
  const WIDTH = 360;
  const HEIGHT = 180;

  function project(point) {
    return [point.longitude + 180, 90 - point.latitude];
  }

  async function world() {
    if (!G.state.worldMap) G.state.worldMap = await api("/world.json");
    return G.state.worldMap;
  }

  async function renderGeoint(root, params = []) {
    let investigationId = params[0] || "";
    let view = { x: 0, y: 0, width: WIDTH, height: HEIGHT };
    let selected = null;
    let data = { points: [], counts: { photo: 0, network: 0 } };
    let visibleKinds = new Set(["photo", "network"]);

    const svg = svgEl("svg", { class: "geo-map", role: "group", "aria-label": "Mapa com as posições registradas", preserveAspectRatio: "xMidYMid meet" });
    const base = svgEl("g", { class: "geo-base" });
    const markers = svgEl("g", { class: "geo-markers" });
    svg.append(base, markers);
    const detail = el("div", { class: "geo-detail" });
    const listHost = el("div");
    const legendHost = el("div", { class: "geo-legend" });
    const caseSelect = el(
      "select",
      { class: "input compact-select", "aria-label": "Escopo do mapa" },
      el("option", { value: "" }, "Todas as investigações"),
      ...(await G.loadInvestigations()).map((item) => el("option", { value: item.id }, item.name)),
    );
    caseSelect.value = investigationId;

    function setViewBox() {
      svg.setAttribute("viewBox", `${view.x} ${view.y} ${view.width} ${view.height}`);
      const scale = WIDTH / view.width;
      svg.style.setProperty("--geo-scale", String(scale));
      drawMarkers();
    }

    function zoom(factor, centerX = view.x + view.width / 2, centerY = view.y + view.height / 2) {
      const width = Math.min(WIDTH, Math.max(4, view.width / factor));
      const height = width / 2;
      view = {
        x: Math.min(WIDTH - width, Math.max(0, centerX - (centerX - view.x) * (width / view.width))),
        y: Math.min(HEIGHT - height, Math.max(0, centerY - (centerY - view.y) * (height / view.height))),
        width,
        height,
      };
      setViewBox();
    }

    function centerOn(point, width = 24) {
      const [x, y] = project(point);
      const height = width / 2;
      view = {
        x: Math.min(WIDTH - width, Math.max(0, x - width / 2)),
        y: Math.min(HEIGHT - height, Math.max(0, y - height / 2)),
        width,
        height,
      };
      setViewBox();
    }

    function shown() {
      return data.points.filter((point) => visibleKinds.has(point.kind));
    }

    function drawMarkers() {
      markers.replaceChildren();
      const radius = (view.width / WIDTH) * 4.2;
      for (const point of shown()) {
        const [x, y] = project(point);
        const network = point.kind === "network";
        const marker = svgEl("circle", {
          cx: x,
          cy: y,
          r: network ? radius * 1.8 : radius,
          class: `geo-marker kind-${point.kind}${selected === point.id ? " is-selected" : ""}`,
          "stroke-width": radius * 0.45,
          tabindex: "0",
          role: "button",
          "aria-label": `${KIND[point.kind].label}: ${point.label}`,
        });
        marker.append(svgEl("title", {}, `${point.label} · ${KIND[point.kind].label}`));
        const choose = () => {
          selected = point.id;
          drawMarkers();
          drawDetail();
        };
        marker.addEventListener("click", (event) => {
          event.stopPropagation();
          choose();
        });
        marker.addEventListener("keydown", (event) => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            choose();
          }
        });
        markers.append(marker);
      }
    }

    function drawDetail() {
      const point = data.points.find((item) => item.id === selected);
      if (!point) {
        detail.replaceChildren(el("p", { class: "panel-empty" }, "Clique num ponto para ver a origem e a precisão."));
        return;
      }
      const rows = [
        ["Tipo", badge(KIND[point.kind].label, "neutral")],
        ["Coordenadas", el("code", {}, `${point.latitude}, ${point.longitude}`)],
        ["Precisão", point.kind === "photo"
          ? point.horizontal_error_m != null ? `erro declarado de ${point.horizontal_error_m} m` : "não declarada pelo dispositivo"
          : "aproximada: cidade ou região da rede"],
      ];
      if (point.kind === "photo") {
        rows.push(["Arquivo", point.label], ["Câmera", point.camera || "—"], ["Capturada", point.observed_at || "—"], ["SHA-256", el("code", { class: "hash" }, point.sha256)]);
      } else {
        rows.push(["Artefato", el("code", {}, point.label)], ["Local", point.place || "—"], ["Fuso", point.timezone || "—"], ["Fonte", G.connectorLabel ? G.connectorLabel(point.source) : point.source], ["Consultado em", formatDate(point.observed_at, { time: true })]);
      }
      if (point.investigation_name || point.investigation_id) {
        rows.push(["Caso", el("a", { class: "table-link", href: `#/investigations/${point.investigation_id}` }, point.investigation_name || "abrir")]);
      }
      detail.replaceChildren(
        G.kvList(rows),
        el(
          "div",
          { class: "inspector-actions" },
          point.kind === "network"
            ? el("a", { class: "button button-secondary button-small", href: `#/multisearch/${point.run_id}` }, "Abrir consulta")
            : el("a", { class: "button button-secondary button-small", href: "#/files" }, "Abrir análises de arquivos"),
          el("button", { class: "button button-secondary button-small", type: "button", onClick: () => centerOn(point) }, "Aproximar"),
        ),
        el("p", { class: "tool-limit" }, KIND[point.kind].note.replace(/^./, (c) => c.toUpperCase()) + "."),
      );
    }

    function drawLegend() {
      legendHost.replaceChildren(
        ...Object.entries(KIND).map(([kind, item]) => {
          const box = el("input", {
            type: "checkbox",
            checked: visibleKinds.has(kind),
            onChange: (event) => {
              if (event.target.checked) visibleKinds.add(kind);
              else visibleKinds.delete(kind);
              drawMarkers();
              drawList();
            },
          });
          const swatch = el("span", { class: `geo-swatch kind-${kind}` });
          return el("label", { class: "layer-toggle" }, box, swatch, `${item.label} (${data.counts[kind] || 0})`);
        }),
      );
    }

    function drawList() {
      listHost.replaceChildren(
        table({
          columns: [
            { label: "TIPO", render: (row) => KIND[row.kind].label },
            { label: "REGISTRO", render: (row) => el("div", { class: "cell-stack" }, el("strong", {}, row.label), row.place ? el("span", {}, row.place) : null) },
            { label: "COORDENADAS", render: (row) => el("code", {}, `${row.latitude}, ${row.longitude}`) },
            { label: "QUANDO", render: (row) => (row.observed_at ? formatDate(row.observed_at, { time: true }) : "—") },
          ],
          rows: shown(),
          emptyMessage: "Nenhum ponto neste escopo.",
          onRowClick: (row) => {
            selected = row.id;
            centerOn(row);
            drawDetail();
          },
        }),
      );
    }

    async function load() {
      listHost.replaceChildren(loadingBlock("Carregando pontos…"));
      try {
        const parameters = investigationId ? `?investigation_id=${encodeURIComponent(investigationId)}` : "";
        data = await api(`/api/geoint${parameters}`);
      } catch (error) {
        listHost.replaceChildren(inlineError(error.message));
        return;
      }
      selected = null;
      drawLegend();
      drawMarkers();
      drawDetail();
      drawList();
    }

    caseSelect.addEventListener("change", () => {
      investigationId = caseSelect.value;
      history.replaceState(null, "", `#/geoint${investigationId ? `/${investigationId}` : ""}`);
      load();
    });

    let drag = null;
    svg.addEventListener("pointerdown", (event) => {
      if (event.target.closest(".geo-marker")) return;
      svg.setPointerCapture(event.pointerId);
      drag = { x: event.clientX, y: event.clientY, view: { ...view } };
    });
    svg.addEventListener("pointermove", (event) => {
      if (!drag) return;
      const rect = svg.getBoundingClientRect();
      const perPixel = Math.max(view.width / rect.width, view.height / rect.height);
      view.x = Math.min(WIDTH - view.width, Math.max(0, drag.view.x - (event.clientX - drag.x) * perPixel));
      view.y = Math.min(HEIGHT - view.height, Math.max(0, drag.view.y - (event.clientY - drag.y) * perPixel));
      svg.setAttribute("viewBox", `${view.x} ${view.y} ${view.width} ${view.height}`);
    });
    const endDrag = () => { drag = null; };
    svg.addEventListener("pointerup", endDrag);
    svg.addEventListener("pointercancel", endDrag);
    svg.addEventListener(
      "wheel",
      (event) => {
        event.preventDefault();
        const rect = svg.getBoundingClientRect();
        const perPixel = Math.max(view.width / rect.width, view.height / rect.height);
        const offsetX = (rect.width - view.width / perPixel) / 2;
        const offsetY = (rect.height - view.height / perPixel) / 2;
        const x = view.x + (event.clientX - rect.left - offsetX) * perPixel;
        const y = view.y + (event.clientY - rect.top - offsetY) * perPixel;
        zoom(Math.exp(-event.deltaY * 0.0015), x, y);
      },
      { passive: false },
    );

    root.replaceChildren(
      pageHeader({
        eyebrow: "ANÁLISE",
        title: "Mapa GEOINT",
        description:
          "Posições já presentes no workspace: GPS do EXIF de imagens analisadas e localização aproximada de redes vinda das consultas. Nada é geocodificado nem buscado fora; o mapa-base é local (Natural Earth, domínio público).",
      }),
      el("div", { class: "resolution-toolbar" }, legendHost, el("label", { class: "field inline-field" }, el("span", {}, "Escopo"), caseSelect)),
      el(
        "div",
        { class: "geo-shell" },
        el(
          "div",
          { class: "geo-stage" },
          svg,
          el(
            "div",
            { class: "graph-controls" },
            el("button", { class: "button button-secondary button-small", type: "button", title: "Diminuir zoom", onClick: () => zoom(1 / 1.6) }, "−"),
            el("button", { class: "button button-secondary button-small", type: "button", title: "Aumentar zoom", onClick: () => zoom(1.6) }, "＋"),
            el("button", { class: "button button-secondary button-small", type: "button", onClick: () => { view = { x: 0, y: 0, width: WIDTH, height: HEIGHT }; setViewBox(); } }, "Mundo"),
          ),
        ),
        panel({ eyebrow: "PONTO", title: "Detalhes" }, detail),
      ),
      panel({ eyebrow: "REGISTROS", title: "Pontos no mapa" }, listHost),
    );

    try {
      const map = await world();
      const graticule = [];
      for (let lon = 30; lon < 360; lon += 30) graticule.push(`M${lon} 0V180`);
      for (let lat = 30; lat < 180; lat += 30) graticule.push(`M0 ${lat}H360`);
      base.replaceChildren(
        svgEl("rect", { x: 0, y: 0, width: WIDTH, height: HEIGHT, class: "geo-ocean" }),
        svgEl("path", { d: graticule.join(""), class: "geo-graticule" }),
        svgEl("path", { d: map.land, class: "geo-land" }),
        svgEl("path", { d: map.borders, class: "geo-borders" }),
      );
    } catch (error) {
      base.replaceChildren();
      detail.replaceChildren(inlineError("Não foi possível carregar o mapa-base local."));
    }
    setViewBox();
    await load();
  }

  G.views.geoint = renderGeoint;
})();
