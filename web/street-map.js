"use strict";

/* A small street map from OpenStreetMap's standard tiles, with drag, zoom
 * (buttons, wheel, keyboard) and one marker. Tiles come from OpenStreetMap's
 * servers, so the area viewed is visible to them; the search screen only uses
 * this map while network sources are allowed. Usage follows the OSM tile
 * policy: visible attribution, an identifying Referer, light use. */

(function () {
  const G = window.GARBAGE;
  const { el } = G;
  const TILE = 256;
  const MIN_ZOOM = 2;
  const MAX_ZOOM = 18;

  function project(lat, lon, zoom) {
    const scale = TILE * 2 ** zoom;
    const sin = Math.sin((Math.max(-85.0511, Math.min(85.0511, lat)) * Math.PI) / 180);
    return {
      x: ((lon + 180) / 360) * scale,
      y: (0.5 - Math.log((1 + sin) / (1 - sin)) / (4 * Math.PI)) * scale,
    };
  }

  function tileUrl(x, y, zoom) {
    return `https://tile.openstreetmap.org/${zoom}/${x}/${y}.png`;
  }

  function streetMap({ lat, lon, zoom = 15, label = "" }) {
    const state = { zoom: Math.max(MIN_ZOOM, Math.min(MAX_ZOOM, Math.round(zoom))), center: null };
    state.center = project(lat, lon, state.zoom);
    const tiles = el("div", { class: "smap-tiles" });
    const marker = el("div", { class: "smap-marker", "aria-hidden": "true" });
    const viewport = el(
      "div",
      { class: "smap-viewport", tabindex: "0", role: "application", "aria-label": `Mapa de ruas em ${label || `${lat}, ${lon}`}. Arraste para mover; mais e menos para aproximar.` },
      tiles,
      marker,
    );
    const zoomIn = el("button", { class: "smap-zoom", type: "button", "aria-label": "Aproximar" }, "+");
    const zoomOut = el("button", { class: "smap-zoom", type: "button", "aria-label": "Afastar" }, "−");
    const recenter = el("button", { class: "smap-zoom smap-recenter", type: "button", "aria-label": "Voltar ao ponto", title: "Voltar ao ponto" }, "◎");
    const root = el(
      "div",
      { class: "smap" },
      viewport,
      el("div", { class: "smap-controls" }, zoomIn, zoomOut, recenter),
      el(
        "p",
        { class: "smap-credit" },
        "© ",
        el("a", { href: "https://www.openstreetmap.org/copyright", target: "_blank", rel: "noopener noreferrer" }, "colaboradores do OpenStreetMap"),
      ),
    );
    const cache = new Map();

    function draw() {
      const width = viewport.clientWidth || 600;
      const height = viewport.clientHeight || 280;
      const left = state.center.x - width / 2;
      const top = state.center.y - height / 2;
      const count = 2 ** state.zoom;
      const wanted = new Set();
      for (let tx = Math.floor(left / TILE); tx <= Math.floor((left + width) / TILE); tx += 1) {
        for (let ty = Math.floor(top / TILE); ty <= Math.floor((top + height) / TILE); ty += 1) {
          if (ty < 0 || ty >= count) continue;
          const wrapped = ((tx % count) + count) % count;
          const key = `${state.zoom}/${tx}/${ty}`;
          wanted.add(key);
          let image = cache.get(key);
          if (!image) {
            image = el("img", { class: "smap-tile", alt: "", draggable: "false", decoding: "async" });
            // OpenStreetMap-based tile services ask for an identifying Referer.
            image.referrerPolicy = "origin";
            image.src = tileUrl(wrapped, ty, state.zoom);
            cache.set(key, image);
          }
          image.style.transform = `translate(${tx * TILE - left}px, ${ty * TILE - top}px)`;
          if (image.parentNode !== tiles) tiles.append(image);
        }
      }
      for (const [key, image] of cache) {
        if (!wanted.has(key)) {
          image.remove();
          if (!key.startsWith(`${state.zoom}/`)) cache.delete(key);
        }
      }
      const point = project(lat, lon, state.zoom);
      marker.style.transform = `translate(${point.x - left}px, ${point.y - top}px)`;
      zoomIn.disabled = state.zoom >= MAX_ZOOM;
      zoomOut.disabled = state.zoom <= MIN_ZOOM;
    }

    function setZoom(next, anchor) {
      const zoom = Math.max(MIN_ZOOM, Math.min(MAX_ZOOM, next));
      if (zoom === state.zoom) return;
      const width = viewport.clientWidth || 600;
      const height = viewport.clientHeight || 280;
      // Keep the world point under the anchor (pointer or centre) fixed.
      const ax = anchor ? anchor.x : width / 2;
      const ay = anchor ? anchor.y : height / 2;
      const factor = 2 ** (zoom - state.zoom);
      const worldX = state.center.x - width / 2 + ax;
      const worldY = state.center.y - height / 2 + ay;
      state.center = { x: worldX * factor - ax + width / 2, y: worldY * factor - ay + height / 2 };
      state.zoom = zoom;
      draw();
    }

    let drag = null;
    viewport.addEventListener("pointerdown", (event) => {
      if (event.button !== 0) return;
      drag = { id: event.pointerId, x: event.clientX, y: event.clientY, center: { ...state.center } };
      viewport.setPointerCapture(event.pointerId);
      viewport.classList.add("is-dragging");
    });
    viewport.addEventListener("pointermove", (event) => {
      if (!drag || event.pointerId !== drag.id) return;
      state.center = { x: drag.center.x - (event.clientX - drag.x), y: drag.center.y - (event.clientY - drag.y) };
      draw();
    });
    const endDrag = (event) => {
      if (drag && event.pointerId === drag.id) {
        drag = null;
        viewport.classList.remove("is-dragging");
      }
    };
    viewport.addEventListener("pointerup", endDrag);
    viewport.addEventListener("pointercancel", endDrag);
    viewport.addEventListener(
      "wheel",
      (event) => {
        event.preventDefault();
        const box = viewport.getBoundingClientRect();
        setZoom(state.zoom + (event.deltaY < 0 ? 1 : -1), { x: event.clientX - box.left, y: event.clientY - box.top });
      },
      { passive: false },
    );
    viewport.addEventListener("dblclick", (event) => {
      const box = viewport.getBoundingClientRect();
      setZoom(state.zoom + 1, { x: event.clientX - box.left, y: event.clientY - box.top });
    });
    viewport.addEventListener("keydown", (event) => {
      const step = 80;
      const moves = { ArrowLeft: [-step, 0], ArrowRight: [step, 0], ArrowUp: [0, -step], ArrowDown: [0, step] };
      if (moves[event.key]) {
        event.preventDefault();
        state.center = { x: state.center.x + moves[event.key][0], y: state.center.y + moves[event.key][1] };
        draw();
      } else if (event.key === "+" || event.key === "=") {
        event.preventDefault();
        setZoom(state.zoom + 1);
      } else if (event.key === "-") {
        event.preventDefault();
        setZoom(state.zoom - 1);
      }
    });
    zoomIn.addEventListener("click", () => setZoom(state.zoom + 1));
    zoomOut.addEventListener("click", () => setZoom(state.zoom - 1));
    recenter.addEventListener("click", () => {
      state.center = project(lat, lon, state.zoom);
      draw();
    });
    if (typeof ResizeObserver === "function") new ResizeObserver(() => draw()).observe(viewport);
    requestAnimationFrame(draw);
    return root;
  }

  G.streetMap = streetMap;
  G.mapLinks = function mapLinks(lat, lon, zoom = 16) {
    const latitude = Number(lat).toFixed(6);
    const longitude = Number(lon).toFixed(6);
    return {
      osm: `https://www.openstreetmap.org/?mlat=${latitude}&mlon=${longitude}#map=${zoom}/${latitude}/${longitude}`,
      google: `https://www.google.com/maps/search/?api=1&query=${latitude},${longitude}`,
    };
  };
})();
