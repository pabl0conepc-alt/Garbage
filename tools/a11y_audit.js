/* Accessibility audit for the GARBAGE interface.
 *
 * Paste into the browser console on a running GARBAGE page (or run it with a
 * browser automation tool). It visits every view in the navigation and
 * reports, per view: controls without an accessible name, form fields
 * without a label, images without alt text, duplicate ids, positive
 * tabindex, skipped heading levels and text below WCAG AA contrast (4.5:1,
 * or 3:1 for large text). It reads the page only; nothing is changed.
 *
 *   const report = await garbageA11yAudit();   // all views
 *   const report = await garbageA11yAudit(["#/monitors"]);
 */

(function () {
  function visible(node) {
    if (!(node instanceof Element)) return false;
    if (node.closest("[hidden], [aria-hidden='true'], dialog:not([open])")) return false;
    const style = getComputedStyle(node);
    if (style.display === "none" || style.visibility === "hidden") return false;
    const box = node.getBoundingClientRect();
    return box.width > 0 && box.height > 0;
  }

  function accessibleName(node) {
    const labelledBy = node.getAttribute("aria-labelledby");
    if (labelledBy) {
      const text = labelledBy.split(/\s+/).map((id) => document.getElementById(id)?.textContent || "").join(" ").trim();
      if (text) return text;
    }
    const aria = node.getAttribute("aria-label");
    if (aria && aria.trim()) return aria.trim();
    if (node.labels && node.labels.length) {
      const text = [...node.labels].map((label) => label.textContent).join(" ").trim();
      if (text) return text;
    }
    if (["INPUT", "SELECT", "TEXTAREA"].includes(node.tagName)) {
      return (node.getAttribute("title") || "").trim();
    }
    const text = (node.textContent || "").trim();
    if (text) return text;
    const image = node.querySelector("img[alt], svg[aria-label]");
    if (image) return (image.getAttribute("alt") || image.getAttribute("aria-label") || "").trim();
    return (node.getAttribute("title") || "").trim();
  }

  function describe(node) {
    const id = node.id ? `#${node.id}` : "";
    const cls = typeof node.className === "string" && node.className ? `.${node.className.trim().split(/\s+/).slice(0, 2).join(".")}` : "";
    return `${node.tagName.toLowerCase()}${id}${cls}`;
  }

  function parseColor(value) {
    const match = value.match(/rgba?\(([^)]+)\)/);
    if (!match) return null;
    const parts = match[1].split(/[\s,/]+/).filter(Boolean).map(Number);
    return { r: parts[0], g: parts[1], b: parts[2], a: parts.length > 3 ? parts[3] : 1 };
  }

  function blend(top, bottom) {
    const alpha = top.a + bottom.a * (1 - top.a);
    if (!alpha) return { r: 0, g: 0, b: 0, a: 0 };
    return {
      r: (top.r * top.a + bottom.r * bottom.a * (1 - top.a)) / alpha,
      g: (top.g * top.a + bottom.g * bottom.a * (1 - top.a)) / alpha,
      b: (top.b * top.a + bottom.b * bottom.a * (1 - top.a)) / alpha,
      a: alpha,
    };
  }

  function background(node) {
    const layers = [];
    for (let current = node; current; current = current.parentElement) {
      const style = getComputedStyle(current);
      // Gradients and images cannot be measured this way: skip the node.
      if (style.backgroundImage && style.backgroundImage !== "none") return null;
      const color = parseColor(style.backgroundColor);
      if (color && color.a > 0) {
        layers.push(color);
        if (color.a >= 1) break;
      }
    }
    let result = parseColor(getComputedStyle(document.body).backgroundColor) || { r: 255, g: 255, b: 255, a: 1 };
    for (const layer of layers.reverse()) result = blend(layer, result);
    return result;
  }

  function luminance({ r, g, b }) {
    const channel = (value) => {
      const scaled = value / 255;
      return scaled <= 0.03928 ? scaled / 12.92 : ((scaled + 0.055) / 1.055) ** 2.4;
    };
    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
  }

  function contrast(a, b) {
    const [light, dark] = [luminance(a), luminance(b)].sort((x, y) => y - x);
    return (light + 0.05) / (dark + 0.05);
  }

  function auditPage() {
    const issues = [];
    const add = (rule, node, detail = "") => issues.push({ rule, element: describe(node), detail: detail.slice(0, 80) });

    for (const node of document.querySelectorAll("button, a[href], [role='button'], [role='tab'], [role='menuitem'], summary")) {
      if (visible(node) && !accessibleName(node)) add("control-name", node);
    }
    for (const node of document.querySelectorAll("input:not([type='hidden']), select, textarea")) {
      if (visible(node) && !accessibleName(node)) add("field-label", node, node.getAttribute("placeholder") || node.name || "");
    }
    for (const node of document.querySelectorAll("img")) {
      if (visible(node) && !node.hasAttribute("alt")) add("image-alt", node, node.src);
    }
    const seen = new Map();
    for (const node of document.querySelectorAll("[id]")) seen.set(node.id, (seen.get(node.id) || 0) + 1);
    for (const [id, count] of seen) if (count > 1) issues.push({ rule: "duplicate-id", element: `#${id}`, detail: `${count}x` });
    for (const node of document.querySelectorAll("[tabindex]")) {
      if (Number(node.getAttribute("tabindex")) > 0) add("positive-tabindex", node);
    }
    let previous = 0;
    for (const node of document.querySelectorAll("main h1, main h2, main h3, main h4, main h5, main h6")) {
      if (!visible(node)) continue;
      const level = Number(node.tagName[1]);
      if (previous && level > previous + 1) add("heading-skip", node, `h${previous} → h${level}: ${node.textContent.trim()}`);
      previous = level;
    }
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    const checked = new Set();
    while (walker.nextNode()) {
      const text = walker.currentNode.textContent.trim();
      const node = walker.currentNode.parentElement;
      if (!text || !node || checked.has(node) || !visible(node) || node.closest("svg, canvas")) continue;
      checked.add(node);
      const style = getComputedStyle(node);
      const color = parseColor(style.color);
      const back = background(node);
      if (!color || !back) continue;
      const opacity = Number(style.opacity) * Number(getComputedStyle(node.parentElement || node).opacity);
      const foreground = blend({ ...color, a: color.a * opacity }, back);
      const ratio = contrast(foreground, back);
      const size = parseFloat(style.fontSize);
      const large = size >= 24 || (size >= 18.66 && Number(style.fontWeight) >= 700);
      const needed = large ? 3 : 4.5;
      if (ratio < needed && !node.closest("button:disabled, [aria-disabled='true'], input:disabled, label:has(input:disabled)")) {
        add("contrast", node, `${ratio.toFixed(2)} < ${needed} "${text}"`);
      }
    }
    return issues;
  }

  window.garbageA11yAudit = async function garbageA11yAudit(routes) {
    const targets = routes || [...new Set([...document.querySelectorAll(".rail a.nav-link[href^='#/']")].map((link) => link.getAttribute("href")))];
    const report = {};
    for (const route of targets) {
      location.hash = route;
      await new Promise((resolve) => setTimeout(resolve, 1200));
      report[route] = auditPage();
    }
    return report;
  };
  window.garbageA11yAuditPage = auditPage;
})();
