"use strict";

/* Small chart kit: horizontal bars, stacked bars and time series.
 *
 * Rules (dataviz method): categorical colours come from the validated
 * --viz-N tokens in fixed order and follow the series, never its rank; text
 * always uses text tokens; marks are thin (bars <= 24px with a 4px rounded
 * data end, 2px lines); every chart has a hover/focus readout and a table
 * view, and labels are inserted with textContent only.
 */

(function () {
  const G = window.GARBAGE;
  const { el } = G;
  const SVG = "http://www.w3.org/2000/svg";
  const MAX_SERIES = 8;
  const number = new Intl.NumberFormat("pt-BR");
  const compact = new Intl.NumberFormat("pt-BR", { notation: "compact", maximumFractionDigits: 1 });

  function svg(tag, attributes = {}) {
    const node = document.createElementNS(SVG, tag);
    for (const [key, value] of Object.entries(attributes)) {
      if (value !== null && value !== undefined) node.setAttribute(key, String(value));
    }
    return node;
  }

  const seriesColor = (slot) => `var(--viz-${(slot % MAX_SERIES) + 1})`;

  /* One floating readout shared by every chart on the page. */
  let tooltip = null;
  function showTooltip(event, title, rows) {
    if (!tooltip) {
      tooltip = el("div", { class: "chart-tooltip", role: "status" });
      document.body.append(tooltip);
    }
    tooltip.replaceChildren(
      el("div", { class: "chart-tooltip-title" }, title),
      ...rows.map((row) =>
        el(
          "div",
          { class: "chart-tooltip-row" },
          row.color ? el("span", { class: "chart-key", "data-color": "" }) : null,
          el("strong", {}, row.value),
          el("span", {}, row.label),
        ),
      ),
    );
    tooltip.querySelectorAll(".chart-key").forEach((key, index) => {
      key.style.background = rows.filter((row) => row.color)[index].color;
    });
    tooltip.hidden = false;
    const rect = event.target.getBoundingClientRect?.() || { left: 0, top: 0, width: 0 };
    const x = event.clientX ?? rect.left + rect.width / 2;
    const y = event.clientY ?? rect.top;
    const width = tooltip.offsetWidth;
    tooltip.style.left = `${Math.min(window.innerWidth - width - 12, Math.max(12, x + 14))}px`;
    tooltip.style.top = `${Math.max(12, y - tooltip.offsetHeight - 10)}px`;
  }

  function hideTooltip() {
    if (tooltip) tooltip.hidden = true;
  }

  /* Wraps a chart with a title, an optional legend and a table toggle. */
  function card({ eyebrow, title, caption = "", chart, table, legend = null, empty = "" }) {
    const body = el("div", { class: "chart-body" });
    const toggle = el("button", { class: "button button-secondary button-small chart-toggle", type: "button", "aria-pressed": "false" }, "Tabela");
    let showingTable = false;
    const draw = () => {
      body.replaceChildren(empty ? el("p", { class: "panel-empty" }, empty) : showingTable ? table() : chart());
      toggle.textContent = showingTable ? "Gráfico" : "Tabela";
      toggle.setAttribute("aria-pressed", String(showingTable));
    };
    toggle.addEventListener("click", () => {
      showingTable = !showingTable;
      draw();
    });
    const node = G.panel(
      { eyebrow, title, caption, actions: empty ? [] : [toggle], className: "chart-card" },
      legend,
      body,
    );
    draw();
    return node;
  }

  function dataTable(columns, rows) {
    return el(
      "div",
      { class: "table-scroll" },
      el(
        "table",
        { class: "data-table chart-table" },
        el("thead", {}, el("tr", {}, ...columns.map((column) => el("th", { scope: "col", class: column.numeric ? "numeric-col" : "" }, column.label)))),
        el(
          "tbody",
          {},
          ...rows.map((row) =>
            el("tr", {}, ...columns.map((column) => el("td", { class: column.numeric ? "numeric-col" : "" }, column.value(row)))),
          ),
        ),
      ),
    );
  }

  function legend(items) {
    return el(
      "ul",
      { class: "chart-legend" },
      ...items.map((item) => {
        const swatch = el("span", { class: `chart-swatch ${item.line ? "is-line" : ""}`, "aria-hidden": "true" });
        swatch.style.background = item.color;
        return el("li", {}, swatch, el("span", {}, item.label));
      }),
    );
  }

  /* ---------------------------------------------------------------- */
  /* Horizontal bars: one series, value at the tip.                    */

  function bars({ rows, label = (row) => row.label, value = (row) => row.value, format = (v) => number.format(v), onSelect = null, unit = "" }) {
    const max = Math.max(1, ...rows.map(value));
    const list = el("ol", { class: "cbar-list" });
    for (const row of rows) {
      const amount = value(row);
      const fill = el("span", { class: "cbar-fill" });
      fill.style.width = `${Math.max(amount > 0 ? 1.5 : 0, (amount / max) * 100)}%`;
      const item = el(
        onSelect ? "button" : "li",
        { class: "cbar-row", type: onSelect ? "button" : null, tabindex: onSelect ? null : "0" },
        el("span", { class: "cbar-label" }, label(row)),
        el("span", { class: "cbar-track" }, fill),
        el("span", { class: "cbar-value" }, format(amount)),
      );
      const readout = (event) => showTooltip(event, label(row), [{ value: format(amount), label: unit }]);
      item.addEventListener("pointermove", readout);
      item.addEventListener("focus", readout);
      item.addEventListener("pointerleave", hideTooltip);
      item.addEventListener("blur", hideTooltip);
      if (onSelect) item.addEventListener("click", () => onSelect(row));
      list.append(onSelect ? el("li", {}, item) : item);
    }
    return list;
  }

  /* ---------------------------------------------------------------- */
  /* Stacked horizontal bars: fixed segment order, 2px surface gaps.  */

  function stackedBars({ rows, label, segments }) {
    const max = Math.max(1, ...rows.map((row) => segments.reduce((total, segment) => total + (segment.value(row) || 0), 0)));
    const list = el("ol", { class: "cbar-list is-stacked" });
    for (const row of rows) {
      const total = segments.reduce((sum, segment) => sum + (segment.value(row) || 0), 0);
      const track = el("span", { class: "cbar-track" });
      const stack = el("span", { class: "cbar-stack" });
      stack.style.width = `${(total / max) * 100}%`;
      for (const segment of segments) {
        const amount = segment.value(row) || 0;
        if (!amount) continue;
        const part = el("span", { class: "cbar-segment" });
        part.style.flexGrow = String(amount);
        part.style.background = segment.color;
        stack.append(part);
      }
      track.append(stack);
      const item = el(
        "li",
        { class: "cbar-row", tabindex: "0" },
        el("span", { class: "cbar-label" }, label(row)),
        track,
        el("span", { class: "cbar-value" }, number.format(total)),
      );
      const readout = (event) =>
        showTooltip(
          event,
          label(row),
          segments.map((segment) => ({ value: number.format(segment.value(row) || 0), label: segment.label, color: segment.color })),
        );
      item.addEventListener("pointermove", readout);
      item.addEventListener("focus", readout);
      item.addEventListener("pointerleave", hideTooltip);
      item.addEventListener("blur", hideTooltip);
      list.append(item);
    }
    return list;
  }

  /* ---------------------------------------------------------------- */
  /* Time series: 2px lines, crosshair snaps to the nearest day.       */

  function timeSeries({ days, series, height = 220, format = (v) => number.format(v) }) {
    const wrap = el("div", { class: "line-chart" });
    const draw = () => {
      const width = Math.max(280, wrap.clientWidth || 640);
      const pad = { left: 40, right: 14, top: 12, bottom: 26 };
      const plotW = width - pad.left - pad.right;
      const plotH = height - pad.top - pad.bottom;
      const max = Math.max(1, ...series.flatMap((item) => item.values));
      const niceMax = niceCeil(max);
      const x = (index) => pad.left + (days.length <= 1 ? plotW / 2 : (index / (days.length - 1)) * plotW);
      const y = (value) => pad.top + plotH - (value / niceMax) * plotH;
      const root = svg("svg", { width, height, class: "line-svg", role: "img", "aria-label": "Série temporal" });
      for (const tick of [0, 0.5, 1]) {
        const value = niceMax * tick;
        root.append(svg("line", { x1: pad.left, x2: width - pad.right, y1: y(value), y2: y(value), class: tick === 0 ? "chart-baseline" : "chart-grid" }));
        const text = svg("text", { x: pad.left - 6, y: y(value) + 3, "text-anchor": "end", class: "chart-axis-text" });
        text.textContent = compact.format(value);
        root.append(text);
      }
      const step = Math.max(1, Math.ceil(days.length / Math.max(2, Math.floor(plotW / 70))));
      days.forEach((day, index) => {
        if (index % step && index !== days.length - 1) return;
        const text = svg("text", { x: x(index), y: height - 8, "text-anchor": "middle", class: "chart-axis-text" });
        text.textContent = `${day.slice(8, 10)}/${day.slice(5, 7)}`;
        root.append(text);
      });
      series.forEach((item, slot) => {
        const points = item.values.map((value, index) => `${x(index).toFixed(1)},${y(value).toFixed(1)}`).join(" ");
        root.append(svg("polyline", { points, class: "chart-line", stroke: item.color || seriesColor(slot) }));
        const last = item.values.length - 1;
        root.append(svg("circle", { cx: x(last), cy: y(item.values[last]), r: 4, fill: item.color || seriesColor(slot), class: "chart-end-dot" }));
      });
      const cross = svg("line", { y1: pad.top, y2: pad.top + plotH, class: "chart-crosshair", visibility: "hidden" });
      root.append(cross);
      const hit = svg("rect", { x: pad.left, y: pad.top, width: plotW, height: plotH, class: "chart-hit", tabindex: "0" });
      const readAt = (event, index) => {
        cross.setAttribute("x1", x(index));
        cross.setAttribute("x2", x(index));
        cross.setAttribute("visibility", "visible");
        showTooltip(
          event,
          new Date(`${days[index]}T12:00:00`).toLocaleDateString("pt-BR", { day: "2-digit", month: "short" }),
          series.map((item, slot) => ({ value: format(item.values[index]), label: item.label, color: item.color || seriesColor(slot) })),
        );
      };
      let focusIndex = days.length - 1;
      hit.addEventListener("pointermove", (event) => {
        const box = root.getBoundingClientRect();
        const ratio = (event.clientX - box.left - pad.left) / plotW;
        focusIndex = Math.max(0, Math.min(days.length - 1, Math.round(ratio * (days.length - 1))));
        readAt(event, focusIndex);
      });
      hit.addEventListener("keydown", (event) => {
        if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
        event.preventDefault();
        focusIndex = Math.max(0, Math.min(days.length - 1, focusIndex + (event.key === "ArrowRight" ? 1 : -1)));
        const box = root.getBoundingClientRect();
        readAt({ clientX: box.left + x(focusIndex), clientY: box.top + pad.top, target: hit }, focusIndex);
      });
      const leave = () => {
        cross.setAttribute("visibility", "hidden");
        hideTooltip();
      };
      hit.addEventListener("pointerleave", leave);
      hit.addEventListener("blur", leave);
      root.append(hit);
      wrap.replaceChildren(root);
    };
    requestAnimationFrame(draw);
    if ("ResizeObserver" in window) {
      let width = 0;
      new ResizeObserver(() => {
        if (Math.abs(wrap.clientWidth - width) > 4) {
          width = wrap.clientWidth;
          draw();
        }
      }).observe(wrap);
    }
    return wrap;
  }

  function niceCeil(value) {
    const power = 10 ** Math.floor(Math.log10(value));
    for (const step of [1, 2, 2.5, 5, 10]) if (step * power >= value) return step * power;
    return 10 * power;
  }

  /* Fold series beyond the palette into "Outros" (never generate a 9th hue). */
  function foldSeries(series, limit = MAX_SERIES) {
    const ranked = [...series].sort((a, b) => sum(b.values) - sum(a.values));
    if (ranked.length <= limit) return ranked;
    const kept = ranked.slice(0, limit - 1);
    const rest = ranked.slice(limit - 1);
    kept.push({ key: "__other", label: "Outros", values: rest[0].values.map((_, index) => sum(rest.map((item) => item.values[index]))) });
    return kept;
  }

  const sum = (values) => values.reduce((total, value) => total + value, 0);

  G.charts = { card, bars, stackedBars, timeSeries, legend, dataTable, foldSeries, seriesColor, showTooltip, hideTooltip, number, compact };
})();
