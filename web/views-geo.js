"use strict";

/* Map: every coordinate a case holds, with its origin, plus analyst points. */

(function () {
  const G = window.GARBAGE;
  const { el, api, toast, pageHeader, panel, badge, table, loadingBlock, formatDate } = G;
  const SVG_NS = "http://www.w3.org/2000/svg";
  const ORIGIN_TONE = { photo: "warning", network: "info", manual: "success" };

  function svg(tag, attrs = {}, ...children) {
    const node = document.createElementNS(SVG_NS, tag);
    for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
    node.append(...children);
    return node;
  }

  /* Equirectangular plot fitted to the points, with a labelled graticule.
     No base tiles: the server never fetches a map, and the browser fetches
     one only when the analyst opens a point on OpenStreetMap. */
  function plot(points, onSelect) {
    const width = 900;
    const height = 450;
    let [west, east, south, north] = [-180, 180, -85, 85];
    if (points.length) {
      const lons = points.map((p) => p.longitude);
      const lats = points.map((p) => p.latitude);
      const pad = Math.max(0.05, (Math.max(...lons) - Math.min(...lons)) * 0.15, (Math.max(...lats) - Math.min(...lats)) * 0.15);
      west = Math.max(-180, Math.min(...lons) - pad);
      east = Math.min(180, Math.max(...lons) + pad);
      south = Math.max(-85, Math.min(...lats) - pad);
      north = Math.min(85, Math.max(...lats) + pad);
      // Keep the aspect ratio of the frame so distances are not distorted.
      const span = Math.max((east - west) / 2, north - south);
      const midLon = (east + west) / 2;
      const midLat = (north + south) / 2;
      west = midLon - span;
      east = midLon + span;
      south = midLat - span / 2;
      north = midLat + span / 2;
    }
    const x = (lon) => ((lon - west) / (east - west)) * width;
    const y = (lat) => ((north - lat) / (north - south)) * height;
    const root = svg("svg", { viewBox: `0 0 ${width} ${height}`, class: "geo-plot", role: "img", "aria-label": `Mapa com ${points.length} pontos` });
    root.append(svg("rect", { x: 0, y: 0, width, height, class: "geo-bg" }));
    const step = [90, 45, 30, 10, 5, 2, 1, 0.5, 0.2, 0.1, 0.05, 0.01].find((value) => (east - west) / value >= 4) || 0.01;
    for (let lon = Math.ceil(west / step) * step; lon <= east; lon += step) {
      root.append(svg("line", { x1: x(lon), x2: x(lon), y1: 0, y2: height, class: "geo-grid" }));
      root.append(svg("text", { x: x(lon) + 3, y: height - 4, class: "geo-label" }, `${+lon.toFixed(3)}°`));
    }
    for (let lat = Math.ceil(south / step) * step; lat <= north; lat += step) {
      root.append(svg("line", { x1: 0, x2: width, y1: y(lat), y2: y(lat), class: "geo-grid" }));
      root.append(svg("text", { x: 3, y: y(lat) - 3, class: "geo-label" }, `${+lat.toFixed(3)}°`));
    }
    points.forEach((point) => {
      const dot = svg("circle", { cx: x(point.longitude), cy: y(point.latitude), r: 6, class: `geo-dot origin-${point.origin}`, tabindex: 0 },
        svg("title", {}, `${point.label} · ${point.origin_label}`));
      dot.addEventListener("click", () => onSelect(point));
      dot.addEventListener("keydown", (event) => event.key === "Enter" && onSelect(point));
      root.append(dot);
    });
    return root;
  }

  async function renderGeo(root, params = []) {
    const investigations = await G.loadInvestigations();
    let caseId = params[0] || "";
    const caseSelect = el(
      "select",
      { class: "input compact-select", "aria-label": "Investigação" },
      el("option", { value: "" }, "Todas as investigações"),
      ...investigations.map((item) => el("option", { value: item.id, selected: item.id === caseId }, item.name)),
    );
    const mapHost = el("div", { class: "geo-map-host" });
    const detailHost = el("div");
    const listHost = el("div");

    const form = {
      label: el("input", { class: "input", type: "text", placeholder: "Rótulo", "aria-label": "Rótulo do ponto", maxlength: "200" }),
      lat: el("input", { class: "input", type: "number", step: "any", min: "-90", max: "90", placeholder: "Latitude", "aria-label": "Latitude" }),
      lon: el("input", { class: "input", type: "number", step: "any", min: "-180", max: "180", placeholder: "Longitude", "aria-label": "Longitude" }),
      note: el("input", { class: "input", type: "text", placeholder: "Nota e fonte (opcional)", "aria-label": "Nota", maxlength: "2000" }),
    };

    function select(point) {
      detailHost.replaceChildren(
        G.kvList([
          ["Ponto", point.label],
          ["Origem", badge(point.origin_label, ORIGIN_TONE[point.origin])],
          ["Coordenadas", `${point.latitude}, ${point.longitude}`],
          ["Quando", point.time ? formatDate(point.time) : null],
          ["Nota", point.note || null],
          ["Fonte", point.source || null],
          ["Mapa", el("a", { class: "table-link", href: point.map_url, target: "_blank", rel: "noopener noreferrer" }, "Abrir no OpenStreetMap")],
        ]),
      );
    }

    async function load() {
      mapHost.replaceChildren(loadingBlock("Reunindo coordenadas…"));
      const query = caseId ? `?investigation_id=${caseId}` : "";
      const data = await api(`/api/geo${query}`);
      mapHost.replaceChildren(plot(data.items, select));
      detailHost.replaceChildren(el("p", { class: "panel-empty" }, data.total ? "Clique num ponto para ver os detalhes." : "Nenhuma coordenada neste escopo ainda."));
      listHost.replaceChildren(
        table({
          columns: [
            { label: "PONTO", render: (p) => p.label },
            { label: "ORIGEM", render: (p) => badge(p.origin_label, ORIGIN_TONE[p.origin]) },
            { label: "LAT, LON", render: (p) => `${p.latitude}, ${p.longitude}` },
            { label: "QUANDO", render: (p) => (p.time ? formatDate(p.time) : "—") },
            {
              label: "",
              render: (p) =>
                p.origin === "manual"
                  ? el("button", { class: "button button-secondary button-small", type: "button", onClick: async (event) => {
                      event.stopPropagation();
                      await api(`/api/geo-points/${p.id}`, { method: "DELETE" });
                      load();
                    } }, "Remover")
                  : null,
            },
          ],
          rows: data.items,
          emptyMessage: "Sem pontos. Fotos com GPS, IPs consultados em um caso e pontos manuais aparecem aqui.",
          onRowClick: select,
        }),
      );
      exportLinks.replaceChildren(
        el("a", { class: "button button-secondary button-small", href: `/api/geo/export?format=geojson${caseId ? `&investigation_id=${caseId}` : ""}` }, "Exportar GeoJSON"),
        el("a", { class: "button button-secondary button-small", href: `/api/geo/export?format=kml${caseId ? `&investigation_id=${caseId}` : ""}` }, "Exportar KML"),
      );
    }

    async function addPoint(event) {
      event.preventDefault();
      if (!caseId) return toast("Escolha uma investigação para adicionar pontos.", "error");
      try {
        await api(`/api/investigations/${caseId}/geo-points`, {
          method: "POST",
          body: JSON.stringify({ label: form.label.value, latitude: form.lat.value, longitude: form.lon.value, note: form.note.value }),
        });
        Object.values(form).forEach((input) => (input.value = ""));
        load();
      } catch (error) {
        toast(error.message, "error");
      }
    }

    const exportLinks = el("div", { class: "row-actions" });
    caseSelect.addEventListener("change", () => {
      caseId = caseSelect.value;
      load();
    });

    root.replaceChildren(
      pageHeader({
        eyebrow: "ANÁLISE",
        title: "Mapa",
        description:
          "Coordenadas que os casos já contêm: GPS de fotos (EXIF), localização aproximada da rede de IPs consultados num caso e pontos adicionados por você. Localização de rede indica onde o bloco de IP está registrado, não onde uma pessoa está. O servidor não baixa mapas; o OpenStreetMap só é aberto quando você clica.",
        actions: [caseSelect],
      }),
      el(
        "div",
        { class: "geo-layout" },
        panel({ eyebrow: "PLANO", title: "Pontos", actions: [exportLinks] }, mapHost,
          el("p", { class: "field-hint" }, badge("Foto (EXIF)", "warning"), " ", badge("Rede de IP (aproximada)", "info"), " ", badge("Adicionado pelo analista", "success"))),
        panel({ eyebrow: "DETALHE", title: "Ponto selecionado" }, detailHost),
      ),
      panel(
        { eyebrow: "NOVO", title: "Adicionar ponto ao caso" },
        el("form", { class: "query-panel watch-form", onSubmit: addPoint }, form.label, form.lat, form.lon, form.note,
          el("button", { class: "button button-primary", type: "submit" }, "Adicionar")),
      ),
      panel({ eyebrow: "LISTA", title: "Todos os pontos" }, listHost),
    );
    try {
      await load();
    } catch (error) {
      mapHost.replaceChildren(G.inlineError(error.message));
    }
  }

  G.views.geo = renderGeo;
})();
