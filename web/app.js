"use strict";

/* GARBAGE workstation core: API client, components, router and search. */

const G = (window.GARBAGE = window.GARBAGE || {});
G.views = G.views || {};

/* Deferred scripts run only after the stylesheet settles, so a missing design
   token here means the request failed (seen when the local server restarts
   mid-load). Retry a few times instead of leaving the page unstyled. */
(function ensureStylesheet(attempt) {
  if (getComputedStyle(document.documentElement).getPropertyValue("--surface").trim() || attempt > 3) return;
  const current = document.querySelector('link[rel="stylesheet"]');
  const link = document.createElement("link");
  link.rel = "stylesheet";
  link.href = `/style.css?retry=${attempt}`;
  link.addEventListener("load", () => current?.remove(), { once: true });
  link.addEventListener("error", () => link.remove() || setTimeout(() => ensureStylesheet(attempt + 1), 400 * attempt), { once: true });
  document.head.append(link);
})(1);

const statusNode = document.querySelector("#status");
const loadingNode = document.querySelector("#loading-state");
const viewRoot = document.querySelector("#view-root");
const searchDialog = document.querySelector("#search-dialog");
const searchInput = document.querySelector("#global-search-input");
const searchResults = document.querySelector("#global-search-results");
const searchButton = document.querySelector("#global-search-button");
const newInvestigationButton = document.querySelector("#new-investigation-button");
const mobileNavToggle = document.querySelector("#mobile-nav-toggle");
const sidebarClose = document.querySelector("#sidebar-close");
const navBackdrop = document.querySelector("#nav-backdrop");
const displayToggle = document.querySelector("#display-toggle");
const displayMenu = document.querySelector("#display-menu");
const shortcutsButton = document.querySelector("#shortcuts-button");

/* Navigation is grouped into a few areas. The dock shows one entry per
   area; the routes inside an area appear as tabs at the top of its
   screens. Every route keeps its own hash, renderer and module. */
G.NAV = [
  {
    key: "overview",
    label: "Visão geral",
    icon: "overview",
    items: [
      { view: "overview", label: "Visão geral", tab: "Visão geral", icon: "overview" },
    ],
  },
  {
    key: "search",
    label: "Pesquisa",
    icon: "radar",
    items: [
      { view: "multisearch", label: "Pesquisa multifonte", tab: "Pesquisa", icon: "radar", module: "intel-orchestrator" },
      { view: "graph", label: "Grafo de relacionamentos", tab: "Grafo", icon: "graph", module: "relationship-graph" },
      { view: "monitors", label: "Monitoramento", tab: "Monitoramento", icon: "pulse", module: "monitoring" },
      { view: "indicators", label: "Pesquisa de inteligência", tab: "Indicadores", icon: "indicators", module: "indicator-engine" },
    ],
  },
  {
    key: "records",
    label: "Registros",
    icon: "entities",
    items: [
      { view: "entities", label: "Inteligência de entidades", tab: "Entidades", icon: "entities", module: "entities" },
      { view: "evidence", label: "Gerenciador de evidências", tab: "Evidências", icon: "evidence", module: "evidence" },
      { view: "sources", label: "Gerenciador de fontes", tab: "Fontes", icon: "sources", module: "source-manager" },
      { view: "files", label: "Análise de arquivos", tab: "Arquivos", icon: "files", module: "file-intelligence" },
    ],
  },
  {
    key: "analysis",
    label: "Análise",
    icon: "chart",
    items: [
      { view: "board", label: "Quadro de investigação", tab: "Quadro", icon: "board", module: "investigation-board" },
      { view: "analytics", label: "Painel analítico", tab: "Painel", icon: "chart", module: "analytics" },
      { view: "resolution", label: "Resolução de entidades", tab: "Resolução", icon: "merge", module: "entity-resolution" },
      { view: "geoint", label: "Mapa GEOINT", tab: "GEOINT", icon: "globe", module: "geoint" },
    ],
  },
  {
    key: "threats",
    label: "Ameaças",
    icon: "kev",
    items: [
      { view: "attack", label: "MITRE ATT&CK", tab: "MITRE ATT&CK", icon: "matrix", module: "attack-matrix" },
      { view: "actors", label: "Atores de ameaça", tab: "Atores", icon: "radar", module: "attack-matrix" },
      { view: "feeds", label: "Feeds CTI", tab: "Feeds CTI", icon: "feed", module: "taxii-feeds" },
      { view: "kev", label: "CISA KEV", tab: "CISA KEV", icon: "kev", module: "cisa-kev" },
    ],
  },
  {
    key: "reports",
    label: "Relatórios",
    icon: "reports",
    items: [
      { view: "reports", label: "Central de relatórios", tab: "Relatórios", icon: "reports", module: "report-center" },
    ],
  },
  {
    key: "settings",
    label: "Configurações",
    icon: "settings",
    bottom: true,
    items: [
      { view: "settings", label: "Configurações", tab: "Configurações", icon: "settings", module: "settings" },
    ],
  },
];

/* Views reached from Configurações (and the command palette) rather than
   the dock. `home` is the dock entry highlighted while they are open. */
G.EXTRA_VIEWS = [
  { view: "investigations", label: "Investigações", icon: "investigations", module: "investigations", group: "Configurações", home: "settings" },
  { view: "activity", label: "Linha do tempo", icon: "activity", module: "activity-log", group: "Configurações", home: "settings" },
  { view: "modules", label: "Gerenciador de módulos", icon: "modules", module: "module-manager", group: "Configurações", home: "settings" },
];

G.VIEW_LABELS = Object.fromEntries([
  ...G.NAV.flatMap((group) => group.items.map((item) => [item.view, item.label])),
  ...G.EXTRA_VIEWS.map((item) => [item.view, item.label]),
]);
G.VIEW_GROUPS = Object.fromEntries(
  G.NAV.flatMap((group) => group.items.map((item) => [item.view, group.label])),
);

G.ENTITY_TYPES = [
  ["person", "Pessoa"],
  ["username", "Nome de usuário"],
  ["profile", "Perfil público"],
  ["domain", "Domínio"],
  ["ipv4", "Endereço IPv4"],
  ["ipv6", "Endereço IPv6"],
  ["email", "E-mail"],
  ["organization", "Organização"],
  ["file", "Arquivo"],
  ["image", "Imagem"],
  ["hash", "Hash"],
  ["url", "URL"],
  ["ioc", "Indicador"],
  ["other", "Outro"],
];
G.ENTITY_TYPE_LABELS = Object.fromEntries(G.ENTITY_TYPES);
G.RELATIONSHIP_TYPES = [
  ["associated-with", "Associado a"],
  ["belongs-to", "Pertence a"],
  ["references", "Referencia"],
  ["hosted-on", "Hospedado em"],
  ["derived-from", "Derivado de"],
  ["related-to", "Relacionado a"],
  ["connected-to", "Conectado a"],
  ["communicates-with", "Comunica-se com"],
  ["owns", "Possui"],
  ["uses", "Utiliza"],
];
G.RELATIONSHIP_TYPE_LABELS = Object.fromEntries(G.RELATIONSHIP_TYPES);
G.COLLECTION_BASES = [
  ["public", "Pública"],
  ["authorized", "Autorizada"],
  ["user-provided", "Fornecida pelo usuário"],
];
G.CONFIDENCE_LEVELS = [
  ["unconfirmed", "Não confirmada"],
  ["possible", "Possível"],
  ["probable", "Provável"],
  ["confirmed", "Confirmada"],
];
G.VERIFICATION_STATUSES = [
  ["not-verified", "Não verificado"],
  ["verified", "Verificado"],
  ["disputed", "Contestado"],
  ["false-positive", "Falso positivo"],
];
G.SOURCE_CATEGORIES = [
  ["website", "Site"],
  ["documentation", "Documentação"],
  ["api", "API"],
  ["public-database", "Base de dados pública"],
  ["report", "Relatório"],
  ["file", "Arquivo"],
  ["other", "Outro"],
];
G.EVIDENCE_TYPES = [
  ["file", "Arquivo"],
  ["document", "Documento"],
  ["image", "Imagem"],
  ["hash", "Referência de hash"],
  ["note", "Nota do analista"],
  ["url", "Referência de URL"],
];
G.INDICATOR_TYPE_LABELS = {
  ipv4: "Endereço IPv4",
  ipv6: "Endereço IPv6",
  cidr: "Rede CIDR",
  domain: "Domínio",
  url: "URL",
  email: "E-mail",
  md5: "MD5",
  sha1: "SHA-1",
  sha256: "SHA-256",
  username: "Nome de usuário",
};
G.INDICATOR_TYPES = Object.entries(G.INDICATOR_TYPE_LABELS);

G.state = {
  modules: null,
  settings: null,
  investigations: [],
  currentView: "",
  currentParams: [],
  searchIndex: -1,
  pendingIndicatorSearch: "",
};
G.cleanupFns = [];

/* ------------------------------------------------------------------ */
/* DOM helpers                                                        */
/* ------------------------------------------------------------------ */

function append(parent, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    parent.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
}

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key === "dataset") Object.assign(node.dataset, value);
    else if (key === "value") node.value = value;
    else if (key === "checked") node.checked = Boolean(value);
    else if (key === "hidden") node.hidden = Boolean(value);
    else if (key === "disabled") node.disabled = Boolean(value);
    else if (key.startsWith("on") && typeof value === "function") {
      node.addEventListener(key.slice(2).toLowerCase(), value);
    } else if (value === true) node.setAttribute(key, "");
    else node.setAttribute(key, String(value));
  }
  append(node, children);
  return node;
}

function svgEl(tag, attrs = {}, ...children) {
  const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "text") node.textContent = value;
    else if (key === "class") node.setAttribute("class", value);
    else node.setAttribute(key, String(value));
  }
  append(node, children);
  return node;
}

G.el = el;
G.svgEl = svgEl;

/* ------------------------------------------------------------------ */
/* Icons: one soft stroke language — 24px grid, 1.7 stroke, round     */
/* caps and joins, rounded corners, consistent optical size.         */
/* ------------------------------------------------------------------ */

const ICON_PATHS = {
  overview: "M5.7 3.5h2.6a2.2 2.2 0 0 1 2.2 2.2v3.6a2.2 2.2 0 0 1 -2.2 2.2h-2.6a2.2 2.2 0 0 1 -2.2 -2.2v-3.6a2.2 2.2 0 0 1 2.2 -2.2zM15.7 3.5h2.6a2.2 2.2 0 0 1 2.2 2.2v.6a2.2 2.2 0 0 1 -2.2 2.2h-2.6a2.2 2.2 0 0 1 -2.2 -2.2v-.6a2.2 2.2 0 0 1 2.2 -2.2zM15.7 11.5h2.6a2.2 2.2 0 0 1 2.2 2.2v4.6a2.2 2.2 0 0 1 -2.2 2.2h-2.6a2.2 2.2 0 0 1 -2.2 -2.2v-4.6a2.2 2.2 0 0 1 2.2 -2.2zM5.7 14.5h2.6a2.2 2.2 0 0 1 2.2 2.2v1.6a2.2 2.2 0 0 1 -2.2 2.2h-2.6a2.2 2.2 0 0 1 -2.2 -2.2v-1.6a2.2 2.2 0 0 1 2.2 -2.2z",
  investigations: "M20.5 10.5V9.4a2 2 0 0 0-2-2h-5.2a2 2 0 0 1-1.5-.7l-.9-1.1A2 2 0 0 0 9.4 5H5.5a2 2 0 0 0-2 2v10.5a2 2 0 0 0 2 2H11M13.3 15.8a3 3 0 1 0 6 0a3 3 0 1 0 -6 0zM18.5 18 20.5 20",
  activity: "M3.5 12a8.5 8.5 0 1 0 2.5-6M6 2.9V6h3.1M12 7.8v4.4l3 1.9",
  entities: "M12 3.2l7.3 4.1v8.4L12 20.8l-7.3-4.1V7.3zM4.9 7.5 12 11.6l7.1-4.1M12 11.6v9",
  indicators: "M5.8 12a6.2 6.2 0 1 0 12.4 0a6.2 6.2 0 1 0 -12.4 0zM10.6 12a1.4 1.4 0 1 0 2.8 0a1.4 1.4 0 1 0 -2.8 0zM12 2.8v2.8M12 18.4v2.8M2.8 12h2.8M18.4 12h2.8",
  files: "M13.5 3.5H7a2.5 2.5 0 0 0-2.5 2.5v12A2.5 2.5 0 0 0 7 20.5h10a2.5 2.5 0 0 0 2.5-2.5V9.5zM13.5 3.5V8a1.5 1.5 0 0 0 1.5 1.5h4.5M8.5 13.5h7M8.5 17h4",
  board: "M6.7 4h10.6a3.2 3.2 0 0 1 3.2 3.2v9.6a3.2 3.2 0 0 1 -3.2 3.2h-10.6a3.2 3.2 0 0 1 -3.2 -3.2v-9.6a3.2 3.2 0 0 1 3.2 -3.2zM8.1 7.8h2.3a1.1 1.1 0 0 1 1.1 1.1v1.4a1.1 1.1 0 0 1 -1.1 1.1h-2.3a1.1 1.1 0 0 1 -1.1 -1.1v-1.4a1.1 1.1 0 0 1 1.1 -1.1zM13.6 12.6h2.3a1.1 1.1 0 0 1 1.1 1.1v1.4a1.1 1.1 0 0 1 -1.1 1.1h-2.3a1.1 1.1 0 0 1 -1.1 -1.1v-1.4a1.1 1.1 0 0 1 1.1 -1.1zM11.5 9.6h1.7a1 1 0 0 1 1 1v2",
  chart: "M3.5 20h17M7 16.5v-4M12 16.5V6.5M17 16.5V10",
  merge: "M4.7 5a1.8 1.8 0 1 0 3.6 0a1.8 1.8 0 1 0 -3.6 0zM15.7 5a1.8 1.8 0 1 0 3.6 0a1.8 1.8 0 1 0 -3.6 0zM6.5 6.8V8a4 4 0 0 0 4 4h3a4 4 0 0 0 4-4V6.8M12 12v8.3M9.6 18 12 20.4l2.4-2.4",
  transform: "M4 12h11.5M11.5 7.5 16 12l-4.5 4.5M20 5v14",
  bell: "M12 3.2v1.6M6.2 17v-6a5.8 5.8 0 0 1 11.6 0v6l1.4 1.8H4.8zM10 21a2.2 2.2 0 0 0 4 0",
  feed: "M4.3 18.4a1.3 1.3 0 1 0 2.6 0a1.3 1.3 0 1 0 -2.6 0zM4.5 11.5a8 8 0 0 1 8 8M4.5 4.5a15 15 0 0 1 15 15",
  globe: "M3.5 12a8.5 8.5 0 1 0 17 0a8.5 8.5 0 1 0 -17 0zM3.5 12h17M12 3.5c2.4 2.3 3.6 5.2 3.6 8.5s-1.2 6.2-3.6 8.5c-2.4-2.3-3.6-5.2-3.6-8.5S9.6 5.8 12 3.5z",
  matrix: "M4.9 3.5h1.8a1.4 1.4 0 0 1 1.4 1.4v1.8a1.4 1.4 0 0 1 -1.4 1.4h-1.8a1.4 1.4 0 0 1 -1.4 -1.4v-1.8a1.4 1.4 0 0 1 1.4 -1.4zM11.1 3.5h1.8a1.4 1.4 0 0 1 1.4 1.4v1.8a1.4 1.4 0 0 1 -1.4 1.4h-1.8a1.4 1.4 0 0 1 -1.4 -1.4v-1.8a1.4 1.4 0 0 1 1.4 -1.4zM17.3 3.5h1.8a1.4 1.4 0 0 1 1.4 1.4v1.8a1.4 1.4 0 0 1 -1.4 1.4h-1.8a1.4 1.4 0 0 1 -1.4 -1.4v-1.8a1.4 1.4 0 0 1 1.4 -1.4zM4.9 9.7h1.8a1.4 1.4 0 0 1 1.4 1.4v1.8a1.4 1.4 0 0 1 -1.4 1.4h-1.8a1.4 1.4 0 0 1 -1.4 -1.4v-1.8a1.4 1.4 0 0 1 1.4 -1.4zM11.1 9.7h1.8a1.4 1.4 0 0 1 1.4 1.4v1.8a1.4 1.4 0 0 1 -1.4 1.4h-1.8a1.4 1.4 0 0 1 -1.4 -1.4v-1.8a1.4 1.4 0 0 1 1.4 -1.4zM4.9 15.9h1.8a1.4 1.4 0 0 1 1.4 1.4v1.8a1.4 1.4 0 0 1 -1.4 1.4h-1.8a1.4 1.4 0 0 1 -1.4 -1.4v-1.8a1.4 1.4 0 0 1 1.4 -1.4z",
  graph: "M3.6 6a2.4 2.4 0 1 0 4.8 0a2.4 2.4 0 1 0 -4.8 0zM15.6 9a2.4 2.4 0 1 0 4.8 0a2.4 2.4 0 1 0 -4.8 0zM6.6 18a2.4 2.4 0 1 0 4.8 0a2.4 2.4 0 1 0 -4.8 0zM8.3 6.6l7.4 1.8M16.3 10.8l-5.6 5.4M6.6 8.3l1.8 7.4",
  evidence: "M5.1 4h13.8a1.6 1.6 0 0 1 1.6 1.6v1.3a1.6 1.6 0 0 1 -1.6 1.6h-13.8a1.6 1.6 0 0 1 -1.6 -1.6v-1.3a1.6 1.6 0 0 1 1.6 -1.6zM5 8.5v9A2.5 2.5 0 0 0 7.5 20h9a2.5 2.5 0 0 0 2.5-2.5v-9M10 12.5h4",
  sources: "M10.5 13.5a3.5 3.5 0 0 0 5 0l3-3a3.5 3.5 0 0 0-5-5l-1 1M13.5 10.5a3.5 3.5 0 0 0-5 0l-3 3a3.5 3.5 0 0 0 5 5l1-1",
  kev: "M12 3.2c2.3 1.4 4.6 2.2 7 2.5v5.6c0 4.4-2.9 8-7 9.5-4.1-1.5-7-5.1-7-9.5V5.7c2.4-.3 4.7-1.1 7-2.5zM12 8.5v4M12 15.8v.2",
  reports: "M9 4.6H7.5A2.5 2.5 0 0 0 5 7.1v11A2.5 2.5 0 0 0 7.5 20.6h9a2.5 2.5 0 0 0 2.5-2.5v-11a2.5 2.5 0 0 0-2.5-2.5H15M10.2 3h3.6a1.2 1.2 0 0 1 1.2 1.2v.8a1.2 1.2 0 0 1 -1.2 1.2h-3.6a1.2 1.2 0 0 1 -1.2 -1.2v-.8a1.2 1.2 0 0 1 1.2 -1.2zM9 16.5v-2M12 16.5v-5M15 16.5V13",
  modules: "M5.7 3.5h2.6a2.2 2.2 0 0 1 2.2 2.2v2.6a2.2 2.2 0 0 1 -2.2 2.2h-2.6a2.2 2.2 0 0 1 -2.2 -2.2v-2.6a2.2 2.2 0 0 1 2.2 -2.2zM15.7 3.5h2.6a2.2 2.2 0 0 1 2.2 2.2v2.6a2.2 2.2 0 0 1 -2.2 2.2h-2.6a2.2 2.2 0 0 1 -2.2 -2.2v-2.6a2.2 2.2 0 0 1 2.2 -2.2zM5.7 13.5h2.6a2.2 2.2 0 0 1 2.2 2.2v2.6a2.2 2.2 0 0 1 -2.2 2.2h-2.6a2.2 2.2 0 0 1 -2.2 -2.2v-2.6a2.2 2.2 0 0 1 2.2 -2.2zM17 14v6M14 17h6",
  settings: "M4 7h9M17.4 7H20M4 17h2.6M11 17h9M13 7a2.2 2.2 0 1 0 4.4 0a2.2 2.2 0 1 0 -4.4 0zM6.6 17a2.2 2.2 0 1 0 4.4 0a2.2 2.2 0 1 0 -4.4 0z",
  search: "M4.5 11a6.5 6.5 0 1 0 13 0a6.5 6.5 0 1 0 -13 0zM15.8 15.8 20 20",
  radar: "M3.5 12a8.5 8.5 0 1 0 17 0a8.5 8.5 0 1 0 -17 0zM7.5 12a4.5 4.5 0 1 0 9 0a4.5 4.5 0 1 0 -9 0zM12 12l5.2-5.2M11.1 12a.9 .9 0 1 0 1.8 0a.9 .9 0 1 0 -1.8 0z",
  plus: "M12 5.5v13M5.5 12h13",
  close: "M6.5 6.5l11 11M17.5 6.5l-11 11",
  menu: "M4.5 7h15M4.5 12h15M4.5 17h15",
  keyboard: "M6 6h12a3 3 0 0 1 3 3v6a3 3 0 0 1 -3 3h-12a3 3 0 0 1 -3 -3v-6a3 3 0 0 1 3 -3zM7 10h.01M10.3 10h.01M13.7 10h.01M17 10h.01M8.5 14h7",
  display: "M3.5 12a8.5 8.5 0 1 0 17 0a8.5 8.5 0 1 0 -17 0zM12 3.5v17M12 7a5 5 0 0 1 0 10",
  refresh: "M19.5 11.5A7.5 7.5 0 0 0 6.4 7M4.5 12.5A7.5 7.5 0 0 0 17.6 17M6.4 3.5V7h3.5M17.6 20.5V17h-3.5",
  note: "M5 6.5A2.5 2.5 0 0 1 7.5 4h9A2.5 2.5 0 0 1 19 6.5V14l-5 5H7.5A2.5 2.5 0 0 1 5 16.5zM14 19v-3.5a1.5 1.5 0 0 1 1.5-1.5H19M8.5 8.5h7M8.5 12h4",
  upload: "M12 15.5v-11M7.5 8.5 12 4l4.5 4.5M4.5 14.5v3A2.5 2.5 0 0 0 7 20h10a2.5 2.5 0 0 0 2.5-2.5v-3",
  empty: "M3.5 13.5 6 6.1A2 2 0 0 1 7.9 4.7h8.2A2 2 0 0 1 18 6.1l2.5 7.4v4A2.5 2.5 0 0 1 18 20H6a2.5 2.5 0 0 1-2.5-2.5zM3.5 13.5h4.3l1.2 2.4h6l1.2-2.4h4.3",
  alert: "M10.3 4.6a2 2 0 0 1 3.4 0l7 12.2a2 2 0 0 1-1.7 3H5a2 2 0 0 1-1.7-3zM12 9.5v4M12 16.8v.2",
  hash: "M9.5 4 7.5 20M16.5 4l-2 16M4.5 9H20M4 15h15.5",
  check: "M5 12.5l4.5 4.5 9.5-10",
  circle: "M4 12a8 8 0 1 0 16 0a8 8 0 1 0 -16 0z",
  ban: "M4 12a8 8 0 1 0 16 0a8 8 0 1 0 -16 0zM6.4 6.4l11.2 11.2",
  diamond: "M12 3.8 20.2 12 12 20.2 3.8 12z",
  clock: "M3.5 12a8.5 8.5 0 1 0 17 0a8.5 8.5 0 1 0 -17 0zM12 7.5V12l3 2",
  list: "M9 6.5h11M9 12h11M9 17.5h11M4.5 6.5h.01M4.5 12h.01M4.5 17.5h.01",
  dot: "M10.4 12a1.6 1.6 0 1 0 3.2 0a1.6 1.6 0 1 0 -3.2 0z",
  info: "M3.5 12a8.5 8.5 0 1 0 17 0a8.5 8.5 0 1 0 -17 0zM12 11v5.2M12 7.9v.2",
  arrow: "M9.5 6.5 15 12l-5.5 5.5",
  pulse: "M3.5 12.5h3.6l2.2-5.5 4.2 10.5 2.4-5h4.6",
  robot: "M7.5 8.5h9a3 3 0 0 1 3 3v5a3 3 0 0 1 -3 3h-9a3 3 0 0 1 -3 -3v-5a3 3 0 0 1 3 -3zM12 8.5V5.6M10.8 4.4a1.2 1.2 0 1 0 2.4 0a1.2 1.2 0 1 0 -2.4 0zM9 13.2v.6M15 13.2v.6M10 16.6h4M2.5 13v2M21.5 13v2",
  send: "M4.5 12 19.5 5l-4 14-3.5-5.5zM12 13.5l7.5-8.5",
  stop: "M7.5 6h9a1.5 1.5 0 0 1 1.5 1.5v9a1.5 1.5 0 0 1 -1.5 1.5h-9a1.5 1.5 0 0 1 -1.5 -1.5v-9a1.5 1.5 0 0 1 1.5 -1.5z",
  trash: "M4.5 7h15M10 4.5h4M6.5 7l.9 11.2a2 2 0 0 0 2 1.8h5.2a2 2 0 0 0 2-1.8L17.5 7M10.3 11v5M13.7 11v5",
};

/* Legacy glyphs passed by views are mapped onto the icon set so every
   empty state, command and panel shares one visual language. */
const GLYPH_ICONS = {
  "◫": "overview", "⌕": "search", "◷": "clock", "⬡": "entities", "⌁": "indicators",
  "▧": "files", "▦": "board", "⟷": "graph", "▤": "evidence", "⛁": "sources",
  "☰": "list", "⎙": "reports", "⊞": "modules", "⚙": "settings", "＋": "plus",
  "▣": "evidence", "↻": "refresh", "◐": "display", "◌": "circle", "◨": "display",
  "⌘": "keyboard", "◈": "diamond", "○": "circle", "⊘": "ban", "◇": "diamond",
  "·": "dot", "!": "alert", "◎": "indicators",
};

function icon(name, { size = 18, className = "" } = {}) {
  const key = ICON_PATHS[name] ? name : GLYPH_ICONS[name] || "dot";
  const node = svgEl(
    "svg",
    {
      class: `icon ${className}`.trim(),
      viewBox: "0 0 24 24",
      width: size,
      height: size,
      fill: "none",
      stroke: "currentColor",
      "stroke-width": "1.7",
      "stroke-linecap": "round",
      "stroke-linejoin": "round",
      "aria-hidden": "true",
      focusable: "false",
    },
    svgEl("path", { d: ICON_PATHS[key] }),
  );
  return node;
}

function hydrateIcons(root = document) {
  root.querySelectorAll("[data-icon]").forEach((node) => {
    if (node.querySelector(":scope > svg.icon")) return;
    node.prepend(icon(node.dataset.icon));
  });
}

G.icon = icon;
G.hydrateIcons = hydrateIcons;

/* ------------------------------------------------------------------ */
/* Tooltips: 2000 ms on hover, immediate on keyboard focus,           */
/* dismissible with Esc and hoverable (WCAG 1.4.13).                  */
/* ------------------------------------------------------------------ */

const TOOLTIP_DELAY = 2000;
const tooltipNode = document.querySelector("#tooltip");
let tooltipTimer = null;
let tooltipOwner = null;
let tooltipCount = 0;
let tooltipPending = null;

function placeTooltip(target) {
  const rect = target.getBoundingClientRect();
  const tip = tooltipNode.getBoundingClientRect();
  const inRail = Boolean(target.closest(".rail"));
  let left;
  let top;
  if (inRail) {
    left = rect.right + 10;
    top = rect.top + rect.height / 2 - tip.height / 2;
  } else {
    left = rect.left + rect.width / 2 - tip.width / 2;
    top = rect.bottom + 8;
    if (top + tip.height > window.innerHeight - 8) top = rect.top - tip.height - 8;
  }
  left = Math.max(8, Math.min(left, window.innerWidth - tip.width - 8));
  top = Math.max(8, Math.min(top, window.innerHeight - tip.height - 8));
  tooltipNode.style.left = `${Math.round(left)}px`;
  tooltipNode.style.top = `${Math.round(top)}px`;
  tooltipNode.dataset.side = inRail ? "right" : "bottom";
}

function showTooltip(target) {
  const text = target.dataset.tooltip;
  if (!text || !tooltipNode) return;
  if (document.body.classList.contains("nav-open") && target.closest(".rail")) return;
  tooltipOwner = target;
  if (!target.dataset.tooltipId) target.dataset.tooltipId = `tip-${++tooltipCount}`;
  tooltipNode.id = "tooltip";
  tooltipNode.textContent = text;
  tooltipNode.hidden = false;
  tooltipNode.classList.remove("is-visible");
  placeTooltip(target);
  const described = (target.getAttribute("aria-describedby") || "").split(" ").filter(Boolean);
  if (!described.includes("tooltip") && target.getAttribute("aria-label") !== text) {
    target.setAttribute("aria-describedby", [...described, "tooltip"].join(" "));
  }
  requestAnimationFrame(() => tooltipNode.classList.add("is-visible"));
}

function hideTooltip() {
  clearTimeout(tooltipTimer);
  tooltipTimer = null;
  tooltipPending = null;
  if (!tooltipNode) return;
  if (tooltipOwner) {
    const described = (tooltipOwner.getAttribute("aria-describedby") || "")
      .split(" ")
      .filter((id) => id && id !== "tooltip");
    if (described.length) tooltipOwner.setAttribute("aria-describedby", described.join(" "));
    else tooltipOwner.removeAttribute("aria-describedby");
  }
  tooltipOwner = null;
  tooltipNode.classList.remove("is-visible");
  tooltipNode.hidden = true;
}

function bindTooltips() {
  if (!tooltipNode) return;
  document.addEventListener("pointerover", (event) => {
    if (event.pointerType === "touch") return;
    if (event.target.closest?.("#tooltip")) {
      clearTimeout(tooltipTimer);
      return;
    }
    const target = event.target.closest?.("[data-tooltip]");
    if (target && (target === tooltipOwner || target === tooltipPending)) return;
    hideTooltip();
    if (!target) return;
    tooltipPending = target;
    tooltipTimer = window.setTimeout(() => {
      tooltipPending = null;
      showTooltip(target);
    }, TOOLTIP_DELAY);
  });
  document.addEventListener("pointerleave", hideTooltip);
  document.addEventListener("focusin", (event) => {
    const target = event.target.closest?.("[data-tooltip]");
    hideTooltip();
    if (target && target.matches(":focus-visible")) showTooltip(target);
  });
  document.addEventListener("focusout", (event) => {
    if (event.target === tooltipOwner) hideTooltip();
  });
  document.addEventListener("pointerdown", hideTooltip, true);
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && tooltipOwner) hideTooltip();
  }, true);
  window.addEventListener("scroll", hideTooltip, true);
  window.addEventListener("resize", hideTooltip);
}

G.hideTooltip = hideTooltip;

/* ------------------------------------------------------------------ */
/* Formatting                                                         */
/* ------------------------------------------------------------------ */

const LOCALE = "pt-BR";
G.LOCALE = LOCALE;

function formatDate(value, options = {}) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat(LOCALE, {
    dateStyle: options.dateStyle || "medium",
    ...(options.time ? { timeStyle: "short" } : {}),
    timeZone: "UTC",
  }).format(date);
}

function relativeTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  const seconds = Math.round((Date.now() - date.getTime()) / 1000);
  if (seconds < 60) return "agora";
  if (seconds < 3600) return `há ${Math.floor(seconds / 60)} min`;
  if (seconds < 86400) return `há ${Math.floor(seconds / 3600)} h`;
  if (seconds < 172800) return "ontem";
  if (seconds < 604800) return `há ${Math.floor(seconds / 86400)} dias`;
  return formatDate(value);
}

const numberFormat = new Intl.NumberFormat(LOCALE);
const decimalFormat = (digits) =>
  new Intl.NumberFormat(LOCALE, { minimumFractionDigits: digits, maximumFractionDigits: digits });

function formatNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) ? numberFormat.format(number) : String(value ?? "—");
}

function formatBytes(value) {
  const bytes = Number(value) || 0;
  if (bytes < 1024) return `${formatNumber(bytes)} B`;
  if (bytes < 1024 * 1024) return `${decimalFormat(1).format(bytes / 1024)} KiB`;
  return `${decimalFormat(2).format(bytes / (1024 * 1024))} MiB`;
}

function shortId(value) {
  if (!value) return "—";
  return String(value).slice(0, 8);
}

function titleCase(value) {
  return String(value || "")
    .replace(/[-_]/g, " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function entityTypeLabel(value) {
  return G.ENTITY_TYPE_LABELS[value] || titleCase(value);
}

function relationshipLabel(value) {
  return G.RELATIONSHIP_TYPE_LABELS[value] || titleCase(value);
}

/* Presentation labels for enumerated values stored in English. */
const STATUS_LABELS = {
  open: "Aberta", closed: "Fechada", cancelled: "Cancelada",
  enabled: "Ativado", disabled: "Desativado", available: "Disponível", planned: "Planejado",
  error: "Erro", ok: "OK", info: "Informação", attention: "Atenção", warning: "Alerta",
  high: "Alta", medium: "Média", low: "Baixa", critical: "Crítica",
  verified: "Verificado", "not-verified": "Não verificado", disputed: "Contestado",
  "false-positive": "Falso positivo", unverified: "Não verificado", mismatch: "Divergente",
  missing: "Ausente", "not-applicable": "Não se aplica", "reference-only": "Somente referência",
  unconfirmed: "Não confirmada", possible: "Possível", probable: "Provável", confirmed: "Confirmada",
  public: "Pública", authorized: "Autorizada", "user-provided": "Fornecida pelo usuário",
  unknown: "Desconhecido", known: "Conhecido",
  entity: "Entidade", note: "Nota", text: "Texto", group: "Grupo",
  core: "Essencial", intelligence: "Inteligência", analysis: "Análise", evidence: "Evidências",
  output: "Saída", system: "Sistema", workspace: "Workspace", connector: "Conector",
  connectors: "Conectores", "threat-intelligence": "Inteligência de ameaças",
  created: "Criação", updated: "Atualização", deleted: "Exclusão", linked: "Vínculo",
  unlinked: "Desvínculo", verified_integrity: "Integridade verificada",
  observation: "Observação", investigation: "Investigação", relationship: "Relacionamento",
  source: "Fonte", status: "Status", board: "Quadro", indicator: "Indicador",
  file: "Arquivo", module: "Módulo", setting: "Configuração", settings: "Configurações",
  investigations: "Investigações", observations: "Observações", entities: "Entidades",
  sources: "Fontes", relationships: "Relacionamentos", boards: "Quadros", activity: "Atividades",
  evidence_records: "Evidências", file_analyses: "Análises de arquivos", indicators: "Indicadores",
  modules: "Módulos", status_events: "Eventos de status",
  create: "Criação", update: "Atualização", delete: "Exclusão", link: "Vínculo", unlink: "Desvínculo",
  verify: "Verificação", import: "Importação", "intel-run": "Consulta multifonte", assessment: "Avaliação", analysis: "Análise",
  high: "Alta", medium: "Média", low: "Baixa",
};

function statusLabel(value) {
  if (value === null || value === undefined || value === "") return "—";
  const key = String(value);
  return (
    STATUS_LABELS[key] ||
    STATUS_LABELS[key.toLowerCase()] ||
    VALUE_LABELS[key] ||
    G.ENTITY_TYPE_LABELS[key] ||
    G.SOURCE_CATEGORIES.find(([value]) => value === key)?.[1] ||
    G.EVIDENCE_TYPES.find(([value]) => value === key)?.[1] ||
    titleCase(key)
  );
}

function indicatorTypeLabel(value) {
  return G.INDICATOR_TYPE_LABELS[value] || titleCase(value);
}

G.formatDate = formatDate;
G.relativeTime = relativeTime;
G.formatBytes = formatBytes;
G.shortId = shortId;
G.titleCase = (value) => statusLabel(value);
G.entityTypeLabel = entityTypeLabel;
G.relationshipLabel = relationshipLabel;
G.indicatorTypeLabel = indicatorTypeLabel;

/* ------------------------------------------------------------------ */
/* Localization of backend-provided text                              */
/* The API contract, stored rows and CLI output stay in English; only */
/* the presentation is translated here.                               */
/* ------------------------------------------------------------------ */

const FIELD_LABELS = {
  name: "nome", description: "descrição", status: "status", title: "título",
  content: "conteúdo", identifier: "identificador", reference: "referência",
  source_reference: "referência da fonte", category: "categoria", label: "rótulo",
  entity_type: "tipo de entidade", relationship_type: "tipo de relacionamento",
  confidence: "confiança", verification_status: "status de verificação",
  collection_basis: "base de coleta", evidence_type: "tipo de evidência",
  observed_at: "data da observação", accessed_at: "data de acesso", sha256: "SHA-256",
  original_name: "nome original", investigation_id: "investigação", query: "consulta",
  value: "valor", text: "texto", limit: "limite", offset: "deslocamento", note: "nota",
  "entity type": "tipo de entidade", "relationship type": "tipo de relacionamento",
  "verification status": "status de verificação", "collection basis": "base de coleta",
  "indicator type": "tipo de indicador", "indicator value": "valor do indicador",
  "assessment note": "nota de avaliação", "evidence type": "tipo de evidência",
  "source category": "categoria da fonte", "board name": "nome do quadro",
};

function fieldLabel_(field) {
  const label = FIELD_LABELS[field] || field;
  return label.charAt(0).toUpperCase() + label.slice(1);
}

const ERROR_PATTERNS = [
  [/^add an OpenRouter key before using the assistant$/, () => "Adicione a chave do OpenRouter para usar o assistente"],
  [/^choose a model before using the assistant$/, () => "Escolha um modelo para usar o assistente"],
  [/^model must be an OpenRouter model id/, () => "Use o identificador de um modelo do OpenRouter, como provedor/nome-do-modelo"],
  [/^the assistant is still working on this conversation$/, () => "O assistente ainda está trabalhando nesta conversa"],
  [/^answer the pending confirmation first$/, () => "Responda primeiro ao pedido de confirmação"],
  [/^stop the assistant before deleting this conversation$/, () => "Pare o assistente antes de apagar esta conversa"],
  [/^this action is not waiting for confirmation$/, () => "Esta ação não está esperando confirmação"],
  [/^OpenRouter refused the key/, () => "O OpenRouter recusou a chave"],
  [/^the OpenRouter account has no credits left/, () => "A conta do OpenRouter está sem créditos"],
  [/^OpenRouter rate-limited the request/, () => "O OpenRouter limitou as requisições; tente de novo em instantes"],
  [/^OpenRouter answered HTTP (\d+)(.*)$/, (m) => `O OpenRouter respondeu HTTP ${m[1]}${m[2]}`],
  [/^interrupted by a restart$/, () => "Interrompido porque o GARBAGE reiniciou"],
  [/^the OpenRouter key was removed$/, () => "A chave do OpenRouter foi removida"],
  [/^refused by network policy: (.+)$/, (m) => `Bloqueado pela política de rede: ${translateError(m[1])}`],
  [/^TLS verification failed for (.+)$/, (m) => `Falha na verificação TLS de ${m[1]}`],
  [/^TLS handshake with (.+) failed$/, (m) => `Falha no handshake TLS com ${m[1]}`],
  [/^TLS handshake timed out$/, () => "O handshake TLS excedeu o tempo limite"],
  [/^(.+) did not present a certificate$/, (m) => `${m[1]} não apresentou certificado`],
  [/^connection to (.+) failed$/, (m) => `Falha na conexão com ${m[1]}`],
  [/^could not resolve host: (.+)$/, (m) => `Não foi possível resolver o host ${m[1]}`],
  [/^request timed out$/, () => "A solicitação excedeu o tempo limite"],
  [/^request exceeded its time budget$/, () => "A solicitação excedeu o tempo total permitido"],
  [/^too many redirects$/, () => "Redirecionamentos demais"],
  [/^response exceeds the (\d+)-byte limit$/, (m) => `A resposta excede o limite de ${formatNumber(Number(m[1]))} bytes`],
  [/^destination resolves to a non-public address$/, () => "O destino resolve para um endereço não público"],
  [/^destination address is not publicly routable$/, () => "O endereço de destino não é público"],
  [/^destination host is local$/, () => "O host de destino é local"],
  [/^refused redirect from https to http$/, () => "Redirecionamento de https para http recusado"],
  [/^the source answered HTTP (\d+)$/, (m) => `A fonte respondeu HTTP ${m[1]}`],
  [/^the source rejected the API key or requires one \(HTTP (\d+)\)$/, (m) => `A fonte recusou a chave de API ou exige uma (HTTP ${m[1]})`],
  [/^key must be a single token of 8 to 512 letters, digits or - _ \. :$/, () => "A chave deve ser um único token de 8 a 512 letras, números ou - _ . :"],
  [/^unknown key provider: (.+)$/, (m) => `Provedor de chave desconhecido: ${m[1]}`],
  [/^the source rate-limited this request \(HTTP 429\)$/, () => "A fonte limitou a taxa desta solicitação (HTTP 429)"],
  [/^the source returned invalid JSON$/, () => "A fonte retornou JSON inválido"],
  [/^certificate could not be parsed: (.+)$/, (m) => `Não foi possível interpretar o certificado: ${m[1]}`],
  [/^connector failed unexpectedly$/, () => "O conector falhou de forma inesperada"],
  [/^the run was interrupted( by a restart)?$/, (m) => `A consulta foi interrompida${m[1] ? " por um reinício" : ""}`],
  [/^async must be a boolean$/, () => "async deve ser verdadeiro ou falso"],
  [/^transforms do not run on people, usernames or profiles$/, () => "Transformações não rodam sobre pessoas, nomes de usuário ou perfis"],
  [/^the entity has no identifier a transform can query$/, () => "A entidade não tem um identificador que uma transformação possa consultar"],
  [/^the entity's identifier is not a domain, IP, CIDR, URL, email, hash, ASN or CVE$/, () => "O identificador da entidade não é domínio, IP, CIDR, URL, e-mail, hash, ASN nem CVE"],
  [/^the identifier was read as (\S+), which does not match the entity type (\S+)$/, (m) => `O identificador foi lido como ${m[1]}, o que não combina com o tipo ${entityTypeLabel(m[2]).toLowerCase()}`],
  [/^transforms must be a non-empty list of transform ids$/, () => "Selecione pelo menos uma transformação"],
  [/^at most 30 transforms run at once$/, () => "No máximo 30 transformações por vez"],
  [/^unknown transforms: (.+)$/, (m) => `Transformações desconhecidas: ${m[1]}`],
  [/^transforms that do not accept (\S+): (.+)$/, (m) => `Transformações que não aceitam ${m[1]}: ${m[2]}`],
  [/^max_new_entities must be between (\d+) and (\d+)$/, (m) => `O limite de novas entidades deve ficar entre ${m[1]} e ${m[2]}`],
  [/^an entity cannot be merged into itself$/, () => "Uma entidade não pode ser fundida nela mesma"],
  [/^the discovery URL must be an https URL$/, () => "A URL de descoberta deve ser https"],
  [/^give both username and password, or neither$/, () => "Informe usuário e senha, ou nenhum dos dois"],
  [/^the TAXII server refused the credentials \(HTTP (\d+)\)$/, (m) => `O servidor TAXII recusou as credenciais (HTTP ${m[1]})`],
  [/^the TAXII server answered HTTP 404$/, () => "O servidor TAXII respondeu HTTP 404"],
  [/^the DNS resolver did not answer$/, () => "O resolvedor DNS não respondeu"],
  [/^the plugin did not finish within (\d+) s$/, (m) => `O plugin não terminou em ${m[1]} s`],
  [/^the plugin exited without a result$/, () => "O plugin terminou sem resultado"],
  [/^the plugin broke the protocol$/, () => "O plugin quebrou o protocolo"],
  [/^the plugin failed: (.+)$/, (m) => `O plugin falhou: ${m[1]}`],
  [/^the plugin changed after approval; approve it again$/, () => "O plugin foi alterado depois da aprovação; aprove de novo"],
  [/^the plugin changed since it was listed; review it again$/, () => "O plugin mudou desde a listagem; revise de novo"],
  [/^this plugin declared no network access$/, () => "Este plugin não declarou acesso à rede"],
  [/^request limit of (\d+) reached$/, (m) => `Limite de ${m[1]} requisições atingido`],
  [/^the plugin is invalid: (.+)$/, (m) => `O plugin é inválido: ${m[1]}`],
  [/^choose at least one source$/, () => "Escolha pelo menos uma fonte"],
  [/^sources that do not accept (\S+): (.+)$/, (m) => `Fontes que não aceitam ${m[1]}: ${m[2]}`],
  [/^interval must be between (\d+) and (\d+) minutes$/, (m) => `O intervalo deve ficar entre ${m[1]} e ${m[2]} minutos`],
  [/^monitor not found: .+$/, () => "Monitor não encontrado"],
  [/^monitor is already running$/, () => "Este monitor já está rodando; aguarde terminar"],
  [/^this is not a GARBAGE case package$/, () => "Este arquivo não é um pacote de caso do GARBAGE"],
  [/^the case package was modified after export \(SHA-256 does not match\)$/, () => "O pacote foi alterado depois de exportado (o SHA-256 não confere)"],
  [/^unsupported case package version: (.+)$/, (m) => `Versão de pacote não suportada: ${m[1]}`],
  [/^file content does not match its recorded SHA-256$/, () => "o conteúdo do arquivo não confere com o SHA-256 registrado"],
  [/^not in the local ATT&CK data; load ATT&CK first$/, () => "fora dos dados locais do ATT&CK; carregue o ATT&CK primeiro"],
  [/^endpoint missing or unknown type$/, () => "ponta ausente ou tipo desconhecido"],
  [/^unknown entity type$/, () => "tipo de entidade desconhecido"],
  [/^evidence files exceed 48 MiB; export without files$/, () => "Os arquivos de evidência passam de 48 MiB; exporte sem os arquivos"],
  [/^unknown report sections: (.+)$/, (m) => `Seções de relatório desconhecidas: ${m[1]}`],
  [/^plugin\.json is missing$/, () => "Falta o plugin.json"],
  [/^give a registrable domain such as example\.com$/, () => "Informe um domínio registrável, como example.com"],
  [/^the selected objects have no simple observable patterns$/, () => "Os objetos escolhidos não têm padrões simples de observáveis"],
  [/^the Sigma package could not be downloaded(.*)$/, (m) => `Não foi possível baixar o pacote Sigma${m[1]}`],
  [/^two different entity ids are required$/, () => "São necessárias duas entidades diferentes"],
  [/^a person, username or profile can only be merged with the same kind of entity$/, () => "Pessoa, nome de usuário ou perfil só pode ser fundido com o mesmo tipo de entidade"],
  [/^no CISA KEV cache; run an explicit refresh first$/, () => "Sem cache do CISA KEV; faça uma atualização explícita primeiro"],
  [/^the run has no findings to record$/, () => "A consulta não tem resultados para registrar"],
  [/^value was detected as (\w+), not (\w+)$/, (m) => `O valor foi detectado como ${m[1]}, não ${m[2]}`],
  [/^value is not a supported artifact; .+$/, () => "Valor não reconhecido. Use domínio, IP, URL, e-mail, hash, ASN, CVE, CNPJ, CPF, telefone ou endereço; para um lugar só pelo nome, escreva local: antes (ex.: local: São Paulo)"],
  [/^value does not match the type its prefix names$/, () => "O valor não corresponde ao tipo indicado no prefixo (cpf:, cnpj:, tel:, local:)"],
  [/^network connectors cannot accept CPF or phone numbers$/, () => "Fontes de rede não podem receber CPF nem telefone"],
  [/^intel run not found: .+$/, () => "Consulta não encontrada"],
  [/^unknown connectors: (.+)$/, (m) => `Conectores desconhecidos: ${m[1]}`],
  [/^(.+) must not be empty$/, (m) => `${fieldLabel_(m[1])}: não pode ficar vazio`],
  [/^(.+) exceeds (\d+) characters$/, (m) => `${fieldLabel_(m[1])}: excede ${m[2]} caracteres`],
  [/^(.+) contains unsupported control characters$/, (m) => `${fieldLabel_(m[1])}: contém caracteres de controle não suportados`],
  [/^(.+) must be one of: (.+)$/, (m) => `${fieldLabel_(m[1])}: deve ser um destes valores: ${m[2]}`],
  [/^(.+) must be between (.+) and (.+)$/, (m) => `${fieldLabel_(m[1])}: deve estar entre ${m[2]} e ${m[3]}`],
  [/^(.+) must be an integer$/, (m) => `${fieldLabel_(m[1])}: deve ser um número inteiro`],
  [/^(.+) must be a number$/, (m) => `${fieldLabel_(m[1])}: deve ser um número`],
  [/^(.+) must be a string$/, (m) => `${fieldLabel_(m[1])}: deve ser um texto`],
  [/^(.+) must be finite$/, (m) => `${fieldLabel_(m[1])}: deve ser um número finito`],
  [/^(.+) must be true or false$/, (m) => `${fieldLabel_(m[1])}: deve ser verdadeiro ou falso`],
  [/^(.+) must be a boolean$/, (m) => `${fieldLabel_(m[1])}: deve ser verdadeiro ou falso`],
  [/^identifier must be a valid (.+)$/, (m) => ({ "domain name": "O identificador deve ser um nome de domínio válido", "email address": "O identificador deve ser um endereço de e-mail válido", "IPv4 address": "O identificador deve ser um endereço IPv4 válido", "IPv6 address": "O identificador deve ser um endereço IPv6 válido" })[m[1]] || `Identificador inválido (${m[1]})`],
  [/^identifier must be an http or https URL$/, () => "O identificador deve ser uma URL http ou https"],
  [/^another entity already uses this identifier$/, () => "Outra entidade já usa este identificador"],
  [/^a relationship requires two different entities$/, () => "Um relacionamento exige duas entidades diferentes"],
  [/^a connection requires two different elements$/, () => "Uma conexão exige dois elementos diferentes"],
  [/^(?:(\w+) )?entity not found: .+$/, () => "Entidade não encontrada"],
  [/^investigation not found: .+$/, () => "Investigação não encontrada"],
  [/^source not found: .+$/, () => "Fonte não encontrada"],
  [/^evidence not found: .+$/, () => "Evidência não encontrada"],
  [/^relationship not found: .+$/, () => "Relacionamento não encontrado"],
  [/^file analysis not found: .+$/, () => "Análise de arquivo não encontrada"],
  [/^module not found: .+$/, () => "Módulo não encontrado"],
  [/^investigation board not found$/, () => "Quadro de investigação não encontrado"],
  [/^Not found$/, () => "Não encontrado"],
  [/^module is (\w+): (.+); enable it in the module manager first$/, (m) => `O módulo ${G.moduleLabel(m[2])} está ${statusLabel(m[1]).toLowerCase()}; ative-o no gerenciador de módulos primeiro`],
  [/^(global search|indicator engine) is disabled in the module registry$/, (m) => `${m[1] === "global search" ? "A pesquisa global" : "O motor de indicadores"} está desativado no registro de módulos`],
  [/^board revision conflict: expected (\d+) but received (\d+); reload the board and retry$/, (m) => `Conflito de revisão do quadro: esperada ${m[1]}, recebida ${m[2]}; recarregue o quadro e tente novamente`],
  [/^a board is limited to (\d+) elements$/, (m) => `Um quadro é limitado a ${m[1]} elementos`],
  [/^board name must not be empty$/, () => "O nome do quadro não pode ficar vazio"],
  [/^duplicate board connection.*$/, () => "Conexão duplicada no quadro"],
  [/^duplicate board element id.*$/, () => "Elemento duplicado no quadro"],
  [/^entity is not linked to this investigation$/, () => "A entidade não está vinculada a esta investigação"],
  [/^source is not linked to this (investigation|entity)$/, (m) => `A fonte não está vinculada a ${m[1] === "entity" ? "esta entidade" : "esta investigação"}`],
  [/^evidence file exceeds the 4 MiB limit$/, () => "O arquivo de evidência excede o limite de 4 MiB"],
  [/^evidence file must not be empty$/, () => "O arquivo de evidência não pode estar vazio"],
  [/^file exceeds the 4 MiB analysis limit$/, () => "O arquivo excede o limite de análise de 4 MiB"],
  [/^file must not be empty$/, () => "O arquivo não pode estar vazio"],
  [/^evidence has no stored file( to verify)?$/, () => "A evidência não possui arquivo armazenado"],
  [/^stored evidence file is missing$/, () => "O arquivo de evidência armazenado não foi encontrado"],
  [/^file evidence requires a file-backed database$/, () => "Evidências em arquivo exigem um banco de dados em arquivo"],
  [/^preview is only available for image evidence$/, () => "A prévia só está disponível para evidências de imagem"],
  [/^uploaded file is not a recognised image format$/, () => "O arquivo enviado não é um formato de imagem reconhecido"],
  [/^sha256 must be a 64 character hexadecimal digest$/, () => "O SHA-256 deve ter 64 caracteres hexadecimais"],
  [/^provide sha256 or a source reference$/, () => "Informe o SHA-256 ou uma referência de fonte"],
  [/^provide a name or an identifier$/, () => "Informe um nome ou um identificador"],
  [/^provide at least one setting$/, () => "Informe pelo menos uma configuração"],
  [/^provide a module state$/, () => "Informe o estado do módulo"],
  [/^no (\w+) fields were provided$/, () => "Nenhum campo foi informado"],
  [/^at least one of name, description or status is required$/, () => "Informe nome, descrição ou status"],
  [/^unknown settings: (.+)$/, (m) => `Configurações desconhecidas: ${m[1]}`],
  [/^value is required$/, () => "Um valor é obrigatório"],
  [/^Database operation failed$/, () => "A operação no banco de dados falhou"],
  [/^Only same-origin loopback requests are allowed$/, () => "Somente solicitações de mesma origem em loopback são permitidas"],
  [/^Request body .+$/, () => "O corpo da solicitação é inválido"],
  [/^Content-Type must be application\/json$/, () => "O Content-Type deve ser application/json"],
];

const ACTIVITY_PATTERNS = [
  [/^Investigation imported from archive: (.+)$/, "Investigação importada de arquivo: $1"],
  [/^Investigation created: (.+)$/, "Investigação criada: $1"],
  [/^Investigation created$/, "Investigação criada"],
  [/^Entity linked: (.+)$/, "Entidade vinculada: $1"],
  [/^Source linked: (.+)$/, "Fonte vinculada: $1"],
  [/^Investigation status changed to (\w+)$/, (m) => `Status da investigação alterado para ${statusLabel(m[1]).toLowerCase()}`],
  [/^Investigation details updated: (.+)$/, "Detalhes da investigação atualizados: $1"],
  [/^Investigation deleted: (.+)$/, "Investigação excluída: $1"],
  [/^Investigation board layout saved$/, "Layout do quadro de investigação salvo"],
  [/^Observation recorded: (.+)$/, "Observação registrada: $1"],
  [/^Evidence added: (.+)$/, "Evidência adicionada: $1"],
  [/^Evidence integrity checked: (\w+)$/, (m) => `Integridade da evidência verificada: ${statusLabel(m[1]).toLowerCase()}`],
  [/^Evidence deleted: (.+)$/, "Evidência excluída: $1"],
  [/^Source registered: (.+)$/, "Fonte registrada: $1"],
  [/^Source updated: (.+)$/, "Fonte atualizada: $1"],
  [/^Source deleted: (.+)$/, "Fonte excluída: $1"],
  [/^Source linked to investigation$/, "Fonte vinculada à investigação"],
  [/^Source unlinked from investigation$/, "Fonte desvinculada da investigação"],
  [/^Source linked to entity$/, "Fonte vinculada à entidade"],
  [/^Source unlinked from entity$/, "Fonte desvinculada da entidade"],
  [/^Entity registered: (.+) \((.+)\)$/, "Entidade registrada: $1"],
  [/^Entity updated: (.+)$/, "Entidade atualizada: $1"],
  [/^Entity deleted: (.+)$/, "Entidade excluída: $1"],
  [/^Entity linked to investigation: (.+)$/, "Entidade vinculada à investigação: $1"],
  [/^Entity unlinked from investigation$/, "Entidade desvinculada da investigação"],
  [/^Relationship recorded: (.+)$/, (m) => `Relacionamento registrado: ${relationshipLabel(m[1]).toLowerCase()}`],
  [/^Relationship updated: (.+)$/, (m) => `Relacionamento atualizado: ${relationshipLabel(m[1]).toLowerCase()}`],
  [/^Relationship deleted$/, "Relacionamento excluído"],
  [/^Module (.+) set to (\w+)$/, (m) => `Módulo ${m[1]} ${m[2] === "enabled" ? "ativado" : "desativado"}`],
  [/^Settings updated: (.+)$/, "Configurações atualizadas: $1"],
  [/^Indicator assessment set to (.+)$/, (m) => `Avaliação do indicador definida como ${statusLabel(m[1]).toLowerCase()}`],
  [/^File analysed: (.+) \((.+)\)$/, (m) => `Arquivo analisado: ${m[1]} (${FORMAT_LABEL_PT[m[2]] || m[2]})`],
  [/^File analysed: (.+)$/, "Arquivo analisado: $1"],
  [/^Multi-source query: (\S+) (.+)$/, "Consulta multifonte: $1 $2"],
  [/^ATT&CK technique linked: (\S+) (.+)$/, "Técnica ATT&CK vinculada: $1 $2"],
  [/^ATT&CK technique unlinked: (\S+)$/, "Técnica ATT&CK desvinculada: $1"],
  [/^MITRE ATT&CK refreshed: version (\S+), (\d+) techniques$/, "MITRE ATT&CK atualizado: versão $1, $2 técnicas"],
  [/^YARA rule set created: (.+) \((\d+) rules\)$/, "Conjunto de regras YARA criado: $1 ($2 regras)"],
  [/^YARA rule set updated: (.+)$/, "Conjunto de regras YARA editado: $1"],
  [/^YARA rule set deleted: (.+)$/, "Conjunto de regras YARA excluído: $1"],
  [/^API key saved: (.+)$/, "Chave de API salva: $1"],
  [/^API key removed: (.+)$/, "Chave de API removida: $1"],
  [/^Transforms on (\S+) (.+): (\d+) run, (\d+) new entities$/, (m) => `Transformações em ${m[2]}: ${m[3]} executada(s), ${m[4]} entidade(s) nova(s)`],
  [/^Entity merged: (.+) into (.+)$/, "Entidade fundida: $1 em $2"],
  [/^Entity pair marked as distinct$/, "Par de entidades marcado como distinto"],
  [/^TAXII server added: (.+)$/, "Servidor TAXII adicionado: $1"],
  [/^TAXII server removed: (.+)$/, "Servidor TAXII removido: $1"],
  [/^TAXII pull: (\d+) objects from (.+)$/, "Coleta TAXII: $1 objeto(s) de $2"],
  [/^Sigma rules refreshed: (\S+), (\d+) rules$/, "Regras Sigma atualizadas: $1, $2 regras"],
  [/^Plugin approved: (.+) \((\w+)\)$/, "Plugin aprovado: $1 ($2)"],
  [/^Plugin disabled: (.+)$/, "Plugin desativado: $1"],
  [/^Investigation archived: (.+)$/, "Investigação arquivada: $1"],
  [/^Monitor created: (.+) \((\S+) (.+), every (\d+) min\)$/, "Monitor criado: $1 ($2 $3, a cada $4 min)"],
  [/^Monitor deleted: (.+)$/, "Monitor excluído: $1"],
  [/^Investigation restored: (.+)$/, "Investigação desarquivada: $1"],
  [/^Investigation duplicated from (.+): (.+)$/, "Investigação duplicada de $1: $2"],
  [/^Case package exported: (.+)$/, "Pacote do caso exportado: $1"],
  [/^Case package imported: (.+) \((\w+)\)$/, "Pacote de caso importado: $1 ($2)"],
  [/^Evidence note added: (.+)$/, "Anotação de evidência: $1"],
];

const FORMAT_LABEL_PT = {
  "PDF document": "documento PDF", "ZIP archive": "arquivo ZIP", "Word document (OOXML)": "Word OOXML",
  "Excel workbook (OOXML)": "Excel OOXML", "PowerPoint presentation (OOXML)": "PowerPoint OOXML",
  "Word 97-2003 document": "Word 97-2003", "Excel 97-2003 workbook": "Excel 97-2003",
  "PowerPoint 97-2003 presentation": "PowerPoint 97-2003", "Outlook message": "mensagem do Outlook",
  "Windows Installer package": "pacote MSI", "Windows shortcut (LNK)": "atalho LNK", "ISO 9660 disc image": "imagem ISO",
  "Rich Text Format document": "documento RTF", "PE executable": "executável PE", "ELF executable": "executável ELF",
  "Mach-O executable": "executável Mach-O", "JPEG image": "imagem JPEG", "PNG image": "imagem PNG",
  "Plain text": "texto", "Unrecognised binary": "binário não reconhecido", "OLE compound document": "documento OLE",
};

function translateActivity(summary) {
  const text = String(summary || "");
  for (const [pattern, replacement] of ACTIVITY_PATTERNS) {
    const match = text.match(pattern);
    if (!match) continue;
    return typeof replacement === "function" ? replacement(match) : text.replace(pattern, replacement);
  }
  return text;
}

G.translateActivity = translateActivity;

/* Fixed backend sentences (limitations, findings, schema history). */
const TEXT_PT = {
  "Observations are user-entered and have not been independently verified.": "As observações são registradas pelo usuário e não foram verificadas de forma independente.",
  "This tool records evidence; it does not collect data from external services.": "Esta ferramenta registra evidências; ela não coleta dados de serviços externos.",
  "Indicator matches are pattern-based and have not been reputation-checked.": "As correspondências de indicadores são baseadas em padrões e não tiveram a reputação verificada.",
  "Relationships are analyst-entered and keep the verification status recorded for each link.": "Os relacionamentos são registrados pelo analista e mantêm o status de verificação de cada vínculo.",
  "Evidence digests confirm file identity; they do not establish authenticity, origin or intent.": "Os hashes das evidências confirmam a identidade do arquivo; não estabelecem autenticidade, origem ou intenção.",
  "The indicator engine is disabled in the module registry; indicators and correlations were not computed.": "O motor de indicadores está desativado no registro de módulos; indicadores e correlações não foram calculados.",
  "Hardening markers describe compiler and linker choices; they are not a vulnerability verdict.": "Os marcadores de proteção descrevem escolhas de compilador e linker; não são um veredito de vulnerabilidade.",
  "Absence of a marker is not proof that a mitigation is absent from the running process.": "A ausência de um marcador não prova que a mitigação está ausente do processo em execução.",
  "Static, read-only inspection only; no execution, emulation or sandbox detonation.": "Somente inspeção estática e de leitura; sem execução, emulação ou detonação em sandbox.",
  "Archive members are listed, never extracted to disk.": "Os membros de pacotes são listados, nunca extraídos para o disco.",
  "Parsers cover bounded headers and central directories; malformed files can hide fields.": "Os analisadores cobrem cabeçalhos e diretórios centrais limitados; arquivos malformados podem ocultar campos.",
  "Embedded indicators are syntactic string matches, not reputation or attribution.": "Indicadores embutidos são correspondências sintáticas em strings, não reputação nem atribuição.",
  "Hashes identify these exact bytes and do not establish safety or provenance.": "Os hashes identificam exatamente estes bytes e não estabelecem segurança nem proveniência.",
  "Structural inspection only; no DNS, WHOIS, reputation or attribution lookup.": "Somente inspeção estrutural; sem consulta de DNS, WHOIS, reputação ou atribuição.",
  "Canonical values are for comparison and may normalize presentation.": "Os valores canônicos servem para comparação e podem normalizar a apresentação.",
  "Syntactic extraction only; matches are not reputation or attribution.": "Somente extração sintática; correspondências não são reputação nem atribuição.",
  "Text is analyzed in memory and is not written to the database.": "O texto é analisado em memória e não é gravado no banco de dados.",
  "The document declares JavaScript, an open action or a launch action. It was not executed.": "O documento declara JavaScript, uma ação de abertura ou de execução. Ele não foi executado.",
  "The PDF declares encryption; content and metadata may be incomplete.": "O PDF declara criptografia; conteúdo e metadados podem estar incompletos.",
  "Legacy OLE compound document; structured parsing is limited to format identification.": "Documento composto OLE legado; a análise estruturada se limita à identificação do formato.",
  "High byte entropy is consistent with compressed, packed or encrypted content; it is not proof of maliciousness.": "Entropia alta é compatível com conteúdo comprimido, empacotado ou criptografado; não é prova de malícia.",
  "Executable structure was parsed statically. The file was not executed, emulated or detonated.": "A estrutura do executável foi analisada estaticamente. O arquivo não foi executado, emulado nem detonado.",
  "Baseline evidence ledger schema": "Esquema base do registro de evidências",
  "Investigation workspace tables and columns": "Tabelas e colunas do workspace de investigação",
  "Persistent file intelligence analyses": "Análises persistentes de arquivos",
  "Multi-source intelligence runs and source status": "Consultas multifonte e status das fontes",
  "YARA rule sets and file similarity digests": "Conjuntos de regras YARA e hashes de semelhança de arquivos",
  "Local API keys for keyed intelligence connectors": "Chaves de API locais para conectores com chave",
  "Offline MITRE ATT&CK and case techniques": "MITRE ATT&CK offline e técnicas por caso",
  "Transforms, entity resolution and module registry corrections": "Transformações, resolução de entidades e correções no registro de módulos",
  "TLSH and ssdeep measure byte-level resemblance; a close digest is not shared authorship or intent.": "TLSH e ssdeep medem semelhança de bytes; um hash próximo não indica mesma autoria nem mesma intenção.",
  "Embedded signatures mark where another format appears to start; they are not validated or carved.": "Assinaturas embutidas marcam onde outro formato parece começar; não são validadas nem recortadas.",
  "planned, not implemented": "planejado, não implementado",
  "explicit manual refresh": "atualização manual explícita",
  "explicit multi-source query": "consulta multifonte explícita",
  "repository not found": "repositório não encontrado",
  "missing, private or renamed": "inexistente, privado ou renomeado",
  "account not found": "conta não encontrada",
  "personal account; not collected": "conta pessoal; não coletada",
  "GitHub data about people is not collected": "dados do GitHub sobre pessoas não são coletados",
  "not published": "não publicado",
  "published": "publicado",
  "not in hashlookup": "fora do hashlookup",
  "unknown to the known-software sets; says nothing about maliciousness": "desconhecido nas bases de software conhecido; não diz nada sobre ser malicioso",
  "not in VirusTotal": "fora do VirusTotal",
  "never submitted or scanned; not a clean result": "nunca enviado nem analisado; não é um resultado limpo",
  "not observed": "não observado",
  "not seen mass-scanning and not a known benign service": "não visto varrendo a internet e não é serviço benigno conhecido",
  "no Shodan record": "sem registro no Shodan",
  "not indexed by Shodan's scans": "não indexado pelas varreduras do Shodan",
  "not announced": "não anunciado",
  "the run was interrupted": "a consulta foi interrompida",
  "the run was interrupted by a restart": "a consulta foi interrompida por um reinício",
  "Full-text search index": "Índice de busca em texto completo",
  "registered or delegated; not necessarily malicious": "registrado ou delegado; não necessariamente malicioso",
  omission: "omissão", repetition: "repetição", transposition: "transposição", replacement: "tecla vizinha",
  insertion: "inserção", homoglyph: "caractere parecido", hyphenation: "hífen", "vowel-swap": "troca de vogal",
  bitsquatting: "bit trocado", addition: "acréscimo", subdomain: "subdomínio", "tld-swap": "outro TLD",
  "TAXII feeds and Sigma rules": "Feeds TAXII e regras Sigma",
  "Local plugin approvals": "Aprovações de plugins locais",
  "Case objective and archive, evidence custody and notes": "Objetivo e arquivamento de casos, custódia e anotações de evidências",
  "Monitors and notifications": "Monitores e notificações",
  "Search index covers case objectives": "Pesquisa passa a cobrir o objetivo do caso",
};

function translateText(value) {
  const text = String(value ?? "");
  if (TEXT_PT[text]) return TEXT_PT[text];
  let match = text.match(/^The filename extension does not match the detected (.+) structure\.$/);
  if (match) return `A extensão do nome do arquivo não corresponde à estrutura ${match[1]} detectada.`;
  match = text.match(/^Structural notes: (.+)$/);
  if (match) return `Observações estruturais: ${match[1]}`;
  return text;
}

G.translateText = translateText;

/* Case coverage checks are computed by key; the wording is rebuilt here. */
const COVERAGE_TEXT = {
  "observation-sources": ["Observações com proveniência", (n) => n ? `${n} observação(ões) sem referência de fonte.` : "Todas as observações possuem referência de fonte."],
  "entity-links": ["Entidades vinculadas", (n) => n ? `${n} registro(s) de entidade vinculado(s).` : "Vincule pelo menos uma entidade para que o caso use o registro compartilhado."],
  "evidence-integrity": ["Integridade das evidências", (n, c) => c.status === "ok" ? "Todas as evidências armazenadas têm hash verificado." : n ? `${n} registro(s) de evidência não verificado(s).` : "Nenhuma evidência anexada a este caso."],
  "source-records": ["Fontes vinculadas", (n) => n ? `${n} registro(s) de fonte vinculado(s).` : "Registre ou vincule uma fonte para o material utilizado."],
  relationships: ["Cobertura de relacionamentos", (n) => n ? `${n} relacionamento(s) registrado(s).` : "Nenhum relacionamento entre entidades registrado ainda."],
  indicators: ["Extração de indicadores", (n) => n ? `${n} indicador(es) único(s) extraído(s).` : "Nenhum indicador foi extraído dos registros atuais."],
  assessments: ["Avaliação de indicadores", (n) => n ? `${n} indicador(es) ainda sem avaliação do analista.` : "Todos os indicadores extraídos possuem avaliação."],
  disputed: ["Indicadores contestados", (n) => n ? `${n} indicador(es) contestado(s) ou marcado(s) como falso positivo.` : "Nenhum indicador contestado ou marcado como falso positivo."],
  correlations: ["Corroboração entre fontes", (n) => n ? `${n} valor(es) aparecem em várias observações.` : "Nenhum valor exato aparece em mais de uma observação ainda."],
};

G.coverageText = function coverageText(check) {
  const entry = COVERAGE_TEXT[check.key];
  if (!entry) return [check.label, check.detail];
  return [entry[0], entry[1](Number(check.count) || 0, check)];
};

function translateError(message) {
  const text = String(message || "").trim();
  for (const [pattern, render] of ERROR_PATTERNS) {
    const match = text.match(pattern);
    if (match) return render(match);
  }
  return text;
}

const MODULE_TEXT = {
  investigations: ["Investigações", "Ciclo de vida dos casos, observações e linha do tempo de status."],
  "activity-log": ["Registro de atividades", "Trilha de auditoria somente de acréscimo das alterações do workspace."],
  entities: ["Inteligência de entidades", "Registro canônico de entidades compartilhado entre casos."],
  relationships: ["Relacionamentos", "Vínculos entre entidades com status de verificação."],
  "investigation-board": ["Quadro de investigação", "Quadro visual persistente com cartões, notas, grupos e conexões."],
  "relationship-graph": ["Grafo de relacionamentos", "Grafo de entidades com filtros, foco e métricas."],
  evidence: ["Gerenciador de evidências", "Evidências com hash preservado e reverificação de integridade."],
  "image-intelligence": ["Análise de imagens", "Inspeção de formato, dimensões e hash de imagens enviadas."],
  "file-intelligence": ["Análise de arquivos", "Inspeção estática limitada de documentos, pacotes, imagens e executáveis, com histórico persistente."],
  "source-manager": ["Gerenciador de fontes", "Fontes reutilizáveis vinculadas a investigações e entidades."],
  "indicator-engine": ["Motor de indicadores", "Extração de padrões e correlação por valor exato com proveniência."],
  "cti-exchange": ["Troca com MISP e OpenCTI", "Envia casos ao seu MISP ou OpenCTI e procura valores neles pela pesquisa multifonte."],
  antivirus: ["Antivírus (ClamAV)", "Passa cada arquivo analisado pelo ClamAV, quando ele está instalado; tudo local, nada sai da máquina."],
  "ai-assistant": ["Assistente de IA", "Painel lateral em que um modelo escolhido no OpenRouter usa a estação pelas próprias ações, todas registradas."],
  "intel-orchestrator": ["Inteligência multifonte", "Consulta explícita de um artefato em todos os conectores registrados, com cache, limites de taxa, status das fontes e proveniência."],
  "cisa-kev": ["Conector CISA KEV", "Atualização explícita e somente leitura do catálogo público CISA KEV."],
  "report-center": ["Central de relatórios", "Relatórios estruturados em JSON, HTML, CSV e Markdown a partir de registros reais."],
  "global-search": ["Pesquisa global", "Pesquisa unificada em casos, entidades, evidências e fontes."],
  "module-manager": ["Gerenciador de módulos", "Registro controlado dos módulos disponíveis e planejados."],
  settings: ["Configurações", "Preferências de interface e de relatórios salvas, com efeito real."],
  "nvd-connector": ["Conector NVD CVE", "Registro do NIST NVD para uma CVE (descrição, CVSS, CWE, referências) como conector da pesquisa multifonte."],
  "external-osint-connectors": ["Conectores OSINT externos", "Fontes passivas de terceiros (DNS, RDAP, CT, arquivos da web, roteamento, reputação) usadas pela pesquisa multifonte e pelas transformações."],
  transforms: ["Transformações", "Transformações de entidade para entidade sobre os conectores, com parâmetros, log por execução, duração e histórico de enriquecimento."],
  "entity-resolution": ["Resolução de entidades", "Candidatos a duplicata exatos, prováveis e fracos, com fusão aprovada pelo analista e auditada."],
  "attack-matrix": ["MITRE ATT&CK", "Matriz Enterprise ATT&CK offline, detalhe de técnicas e técnicas vinculadas aos casos."],
  "yara-rules": ["Regras YARA", "Conjuntos locais de regras YARA verificados, testados e aplicados às análises de arquivos."],
  analytics: ["Painel analítico", "Gráficos do workspace e do caso calculados a partir dos registros salvos."],
  "taxii-feeds": ["Feeds TAXII", "Cliente TAXII 2.1: descoberta, coleções e coleta paginada de objetos STIX, com indicadores registrados nos casos."],
  "sigma-rules": ["Regras Sigma", "Regras de detecção do SigmaHQ baixadas sob demanda e indexadas por técnica ATT&CK."],
  monitoring: ["Monitoramento", "Consultas multifonte salvas que rodam de novo num intervalo enquanto o servidor está ligado, com a diferença entre execuções e notificações na interface."],
  plugins: ["Plugins locais", "Transformações escritas pelo analista, com manifesto, permissões declaradas e aprovação pelo hash do código, executadas em processo separado."],
  geoint: ["Mapa GEOINT", "Mapa local das posições GPS do EXIF de imagens analisadas e da localização aproximada de redes vinda das consultas."],
  "cti-export": ["Exportação CTI", "Pacotes STIX 2.1, eventos MISP e CSV de IOCs gerados a partir dos registros do caso."],
  "media-forensics": ["Perícia de mídia", "Análise de mídia mais profunda planejada; hoje existem apenas hash e metadados."],
};

const MODULE_CATEGORIES = {
  Core: "Essencial", Workspace: "Workspace", Intelligence: "Inteligência", Analysis: "Análise",
  Evidence: "Evidências", "Threat Intelligence": "Inteligência de ameaças", Output: "Saída", System: "Sistema",
};

function moduleLabel(moduleId, fallback) {
  return MODULE_TEXT[moduleId]?.[0] || fallback || moduleId;
}

function moduleDescription(moduleId, fallback) {
  return MODULE_TEXT[moduleId]?.[1] || fallback || "";
}

const SETTING_TEXT = {
  "interface.theme": ["Tema da interface", "Tema claro ou variante escura de alto contraste."],
  "interface.density": ["Densidade de informação", "Espaçamento confortável ou layout compacto para telas menores."],
  "interface.reduce_motion": ["Reduzir movimento", "Desativa transições de painéis e telas."],
  "board.autosave_delay_ms": ["Atraso do salvamento automático do quadro", "Milissegundos de inatividade antes de salvar o estado do quadro."],
  "search.result_limit": ["Limite de resultados da pesquisa global", "Número máximo de resultados por grupo na pesquisa global."],
  "report.include_limitations": ["Incluir limitações nos relatórios", "Acrescenta limitações analíticas explícitas aos relatórios gerados."],
  "intel.allow_network": ["Permitir que conectores de inteligência usem a rede", "Quando desativado, conectores que acessam serviços externos são ignorados; os conectores locais continuam funcionando."],
  "intel.allow_target_contact": ["Permitir contato com o alvo", "Quando desativado, conectores que enviam uma requisição ou handshake TLS aos servidores do próprio artefato são ignorados. Também exige rede."],
  "intel.max_workers": ["Conectores em paralelo", "Número máximo de conectores consultados ao mesmo tempo para um artefato."],
  "report.include_raw_observations": ["Incluir observações completas", "Inclui o texto completo das observações nos relatórios HTML gerados."],
};

const VALUE_LABELS = {
  dark: "Claro", contrast: "Alto contraste (escuro)", comfortable: "Confortável", compact: "Compacta",
  true: "Sim", false: "Não", force: "Força", circular: "Circular", grid: "Grade",
  unattributed: "Sem atribuição",
};

G.translateError = translateError;
G.moduleLabel = moduleLabel;
G.moduleDescription = moduleDescription;
G.moduleCategory = (value) => MODULE_CATEGORIES[value] || value;
G.settingText = (key, label, description) => SETTING_TEXT[key] || [label, description];
G.statusLabel = statusLabel;
G.formatNumber = formatNumber;

/* ------------------------------------------------------------------ */
/* API and feedback                                                   */
/* ------------------------------------------------------------------ */

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (options.body) headers["Content-Type"] = "application/json";
  const response = await fetch(path, { ...options, headers });
  const contentType = response.headers.get("Content-Type") || "";
  let payload = null;
  if (contentType.includes("application/json")) {
    payload = await response.json();
  }
  if (!response.ok) {
    const error = new Error(translateError(payload?.error) || `A solicitação falhou (${response.status})`);
    error.status = response.status;
    error.code = payload?.code;
    throw error;
  }
  return payload;
}

let toastTimer = null;
function toast(message, tone = "success") {
  statusNode.textContent = message;
  statusNode.dataset.tone = tone;
  statusNode.classList.remove("is-visible");
  void statusNode.offsetWidth;
  statusNode.classList.add("is-visible");
  clearTimeout(toastTimer);
  toastTimer = window.setTimeout(
    () => statusNode.classList.remove("is-visible"),
    tone === "error" ? 9000 : 4200,
  );
}

function setLoading(loading) {
  loadingNode.classList.toggle("is-loading", loading);
  loadingNode.setAttribute("aria-hidden", String(!loading));
  viewRoot.setAttribute("aria-busy", String(loading));
  document.body.classList.toggle("is-navigating", loading);
}

function moduleEnabled(moduleId) {
  if (!moduleId) return true;
  const item = G.state.modules?.items?.find((entry) => entry.module_id === moduleId);
  if (!item) return true;
  return item.state === "enabled";
}

function applySettings(values = G.state.settings) {
  if (!values) return;
  document.documentElement.dataset.theme = values["interface.theme"] || "dark";
  document.documentElement.dataset.density = values["interface.density"] || "comfortable";
  document.documentElement.dataset.reduceMotion =
    values["interface.reduce_motion"] === "true" ? "true" : "false";
}

G.api = api;
G.toast = toast;
G.setLoading = setLoading;
G.moduleEnabled = moduleEnabled;
G.applySettings = applySettings;

/* ------------------------------------------------------------------ */
/* Shared components                                                  */
/* ------------------------------------------------------------------ */

const STATUS_TONES = {
  open: "success",
  closed: "neutral",
  cancelled: "danger",
  enabled: "success",
  disabled: "neutral",
  available: "info",
  planned: "warning",
  error: "danger",
  verified: "success",
  "not-verified": "neutral",
  disputed: "warning",
  "false-positive": "danger",
  unconfirmed: "neutral",
  possible: "info",
  probable: "warning",
  confirmed: "success",
};

function badge(text, tone = "neutral") {
  return el("span", { class: `badge badge-${tone}` }, text);
}

function statusBadge(value) {
  return badge(statusLabel(value), STATUS_TONES[value] || "neutral");
}

let pageInfoCount = 0;

/* Title first. A short line may sit under it; anything longer waits
   behind a small info toggle. `eyebrow` is still accepted, not drawn. */
function pageHeader({ eyebrow, title, description, actions = [] }) {
  const text = typeof description === "string" ? description.trim() : description;
  const short = typeof text === "string" && text.length <= 72;
  let infoButton = null;
  let descriptionNode = null;
  if (text && short) {
    descriptionNode = el("p", { class: "page-description" }, text);
  } else if (text) {
    const id = `page-info-${++pageInfoCount}`;
    descriptionNode = el("p", { class: "page-description", id, hidden: true }, text);
    infoButton = el(
      "button",
      {
        class: "icon-button page-info",
        type: "button",
        "aria-label": "Sobre esta tela",
        "aria-expanded": "false",
        "aria-controls": id,
        onClick: () => {
          descriptionNode.hidden = !descriptionNode.hidden;
          infoButton.setAttribute("aria-expanded", String(!descriptionNode.hidden));
        },
      },
      icon("info", { size: 16 }),
    );
  }
  return el(
    "div",
    { class: "page-heading" },
    el(
      "div",
      { class: "page-heading-copy" },
      el("div", { class: "page-title-row" }, el("h1", {}, title), infoButton),
      descriptionNode,
    ),
    actions.length ? el("div", { class: "page-actions" }, actions) : null,
  );
}

/* Secondary actions collapse into one "Mais" menu so each area keeps a
   single clear primary action. */
function moreMenu(items, label = "Mais") {
  const list = el("div", { class: "more-menu-list" }, items.filter(Boolean));
  const menu = el(
    "details",
    { class: "more-menu" },
    el("summary", { class: "button button-secondary button-small" }, label),
    list,
  );
  list.addEventListener("click", (event) => {
    if (event.target.closest("button, a")) menu.open = false;
  });
  return menu;
}

document.addEventListener("click", (event) => {
  document.querySelectorAll("details.more-menu[open]").forEach((menu) => {
    if (!menu.contains(event.target)) menu.open = false;
  });
});
document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") return;
  document.querySelectorAll("details.more-menu[open]").forEach((menu) => {
    menu.open = false;
    menu.querySelector("summary")?.focus();
  });
});

G.moreMenu = moreMenu;

function sentenceCase(text) {
  const lower = String(text).toLocaleLowerCase("pt-BR");
  return lower.charAt(0).toLocaleUpperCase("pt-BR") + lower.slice(1);
}

function panel({ eyebrow, title, caption, actions = [], className = "" }, ...children) {
  if (!title && eyebrow) title = sentenceCase(eyebrow);
  eyebrow = null;
  if (typeof caption === "string" && caption.length > 48) caption = null;
  const heading =
    title || actions.length
      ? el(
          "div",
          { class: "panel-heading" },
          el(
            "div",
            {},
            eyebrow ? el("p", { class: "eyebrow" }, eyebrow) : null,
            title ? el("h2", {}, title) : null,
          ),
          el(
            "div",
            { class: "panel-heading-side" },
            caption ? el("span", { class: "panel-caption" }, caption) : null,
            actions.length ? el("div", { class: "panel-actions" }, actions) : null,
          ),
        )
      : null;
  return el(
    "section",
    { class: `panel ${className}`.trim() },
    heading,
    el("div", { class: "panel-body" }, children),
  );
}

function metric({ label, value }) {
  return el(
    "article",
    { class: "metric-card" },
    el("div", { class: "metric-value" }, value),
    el("div", { class: "metric-top" }, el("span", {}, sentenceCase(label))),
  );
}

function emptyState({ icon: glyph = "empty", title, description, action = null }) {
  return el(
    "div",
    { class: "empty-state" },
    el("span", { class: "empty-icon" }, icon(glyph, { size: 20 })),
    el("h2", {}, title),
    description ? el("p", {}, description) : null,
    action || null,
  );
}

function errorState({ title = "Não foi possível carregar esta tela", message, retry = null }) {
  return el(
    "div",
    { class: "error-state", role: "alert" },
    el("span", { class: "error-icon" }, icon("alert", { size: 20 })),
    el("h2", {}, title),
    el("p", {}, message || "A API local retornou um erro."),
    retry
      ? el("button", { class: "button button-secondary", type: "button", onClick: retry }, "Tentar novamente")
      : null,
  );
}

function dataTable({ columns, rows, emptyMessage = "Nenhum registro.", onRowClick = null, rowClass = null }) {
  const table = el("table", { class: "data-table" });
  table.append(
    el(
      "thead",
      {},
      el(
        "tr",
        {},
        ...columns.map((column) =>
          el("th", { scope: "col", class: column.className || "" }, column.label),
        ),
      ),
    ),
  );
  const tbody = el("tbody");
  if (!rows.length) {
    // An empty list is one quiet line, without column headings.
    table.classList.add("is-empty");
    tbody.append(
      el(
        "tr",
        {},
        el("td", { class: "table-empty", colspan: String(columns.length) }, emptyMessage),
      ),
    );
  }
  for (const row of rows) {
    const tr = el("tr", { class: rowClass ? rowClass(row) : "" });
    if (onRowClick) {
      tr.classList.add("is-clickable");
      tr.tabIndex = 0;
      tr.addEventListener("click", (event) => {
        if (event.target.closest("button, a, input, select")) return;
        onRowClick(row);
      });
      tr.addEventListener("keydown", (event) => {
        if (event.key === "Enter" && event.target === tr) onRowClick(row);
      });
    }
    for (const column of columns) {
      const td = el("td", { class: column.cellClass || "" });
      append(td, [column.render(row)]);
      tr.append(td);
    }
    tbody.append(tr);
  }
  table.append(tbody);
  return el("div", { class: "table-scroll" }, table);
}

function tabs({ items, active, onSelect }) {
  return el(
    "div",
    { class: "tabs", role: "tablist" },
    ...items.map((item) =>
      el(
        "button",
        {
          class: `tab${item.key === active ? " is-active" : ""}`,
          type: "button",
          role: "tab",
          "aria-selected": String(item.key === active),
          onClick: () => onSelect(item.key),
        },
        item.label,
        item.count !== undefined && item.count !== null
          ? el("span", { class: "tab-count" }, String(item.count))
          : null,
      ),
    ),
  );
}

function sectionHeading(title, caption = null) {
  return el(
    "div",
    { class: "subsection-heading" },
    el("h3", {}, title),
    caption ? el("span", { class: "panel-caption" }, caption) : null,
  );
}

function kvList(pairs) {
  const dl = el("dl", { class: "kv-list" });
  for (const [key, value] of pairs) {
    if (value === null || value === undefined || value === "") continue;
    dl.append(el("dt", {}, key), el("dd", {}, value));
  }
  return dl;
}

function loadingBlock(message = "Carregando…") {
  return el("div", { class: "loading-block", role: "status" }, el("span", { class: "spinner", "aria-hidden": "true" }), message);
}

function inlineError(message) {
  return el("p", { class: "inline-error", role: "alert" }, message);
}

G.pageHeader = pageHeader;
G.panel = panel;
G.metric = metric;
G.badge = badge;
G.statusBadge = statusBadge;
G.emptyState = emptyState;
G.errorState = errorState;
G.table = dataTable;
G.tabs = tabs;
G.sectionHeading = sectionHeading;
G.kvList = kvList;
G.loadingBlock = loadingBlock;
G.inlineError = inlineError;
G.titleCase = (value) => statusLabel(value);

/* ------------------------------------------------------------------ */
/* Dialogs                                                            */
/* ------------------------------------------------------------------ */

function fieldLabel(field) {
  return el(
    "span",
    { class: "field-label" },
    field.label,
    field.optional ? el("span", { class: "optional-label" }, "OPCIONAL") : null,
  );
}

function fieldControl(field) {
  if (field.type === "textarea") {
    const textarea = el("textarea", {
      name: field.name,
      rows: field.rows || 4,
      placeholder: field.placeholder || "",
      maxlength: field.maxlength || "",
    });
    textarea.value = field.value || "";
    return textarea;
  }
  if (field.type === "select") {
    const select = el("select", { name: field.name });
    for (const option of field.options || []) {
      const value = Array.isArray(option) ? option[0] : option;
      const label = Array.isArray(option) ? option[1] : titleCase(option);
      select.append(el("option", { value }, label));
    }
    select.value = field.value !== undefined ? String(field.value) : "";
    return select;
  }
  if (field.type === "checkbox") {
    return el("input", {
      type: "checkbox",
      name: field.name,
      checked: Boolean(field.value),
    });
  }
  if (field.type === "file") {
    return el("input", {
      type: "file",
      name: field.name,
      accept: field.accept || "",
    });
  }
  const input = el("input", {
    type: field.type || "text",
    name: field.name,
    placeholder: field.placeholder || "",
    maxlength: field.maxlength || "",
    min: field.min !== undefined ? field.min : "",
    max: field.max !== undefined ? field.max : "",
    step: field.step || "",
    autocomplete: "off",
  });
  input.value = field.value !== undefined && field.value !== null ? String(field.value) : "";
  return input;
}

function fieldNode(field) {
  if (field.type === "checkbox") {
    return el(
      "label",
      { class: "check-field" },
      fieldControl(field),
      el("span", {}, field.label),
      field.hint ? el("span", { class: "field-hint" }, field.hint) : null,
    );
  }
  return el(
    "label",
    { class: "field" },
    fieldLabel(field),
    fieldControl(field),
    field.hint ? el("span", { class: "field-hint" }, field.hint) : null,
  );
}

function readForm(form, fields) {
  const values = {};
  for (const field of fields) {
    const control = form.elements.namedItem(field.name);
    if (!control) continue;
    if (field.type === "checkbox") values[field.name] = Boolean(control.checked);
    else if (field.type === "file") values[field.name] = control.files?.[0] || null;
    else values[field.name] = control.value;
  }
  return values;
}

function formDialog({
  eyebrow = "",
  title,
  description = "",
  fields = [],
  submitLabel = "Salvar",
  danger = false,
  onSubmit,
}) {
  return new Promise((resolve) => {
    const errorNode = el("p", { class: "form-error", role: "alert", hidden: true });
    const submitButton = el(
      "button",
      { class: `button ${danger ? "button-danger" : "button-primary"}`, type: "submit" },
      submitLabel,
    );
    const form = el(
      "form",
      { class: "dialog-form", novalidate: true },
      el(
        "div",
        { class: "dialog-heading" },
        el(
          "div",
          {},
          eyebrow ? el("p", { class: "eyebrow" }, eyebrow) : null,
          el("h2", {}, title),
          description ? el("p", { class: "dialog-description" }, description) : null,
        ),
        el(
          "button",
          {
            class: "icon-button",
            type: "button",
            "aria-label": "Fechar diálogo",
            onClick: () => dialog.close("cancel"),
          },
          icon("close"),
        ),
      ),
      ...fields.map(fieldNode),
      errorNode,
      el(
        "div",
        { class: "dialog-actions" },
        el(
          "button",
          {
            class: "button button-secondary",
            type: "button",
            onClick: () => dialog.close("cancel"),
          },
          "Cancelar",
        ),
        submitButton,
      ),
    );
    const dialog = el("dialog", { class: "app-dialog", "aria-label": title }, form);
    document.body.append(dialog);
    dialog.addEventListener("close", () => {
      dialog.remove();
      resolve(dialog.returnValue === "submitted");
    });
    dialog.addEventListener("click", (event) => {
      if (event.target === dialog) dialog.close("cancel");
    });
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      errorNode.hidden = true;
      const values = readForm(form, fields);
      const missing = fields.filter((field) => {
        if (!field.required) return false;
        if (field.type === "checkbox") return !values[field.name];
        if (field.type === "file") return !values[field.name];
        return !String(values[field.name] ?? "").trim();
      });
      if (missing.length) {
        errorNode.textContent = `Obrigatório: ${missing.map((field) => field.label).join(", ")}`;
        errorNode.hidden = false;
        return;
      }
      submitButton.disabled = true;
      try {
        await onSubmit?.(values, form, dialog);
        dialog.close("submitted");
      } catch (error) {
        errorNode.textContent = error.message;
        errorNode.hidden = false;
      } finally {
        submitButton.disabled = false;
      }
    });
    dialog.showModal();
  });
}

function confirmDialog({ title, message, confirmLabel = "Confirmar", danger = false }) {
  return new Promise((resolve) => {
    let confirmed = false;
    const dialog = el(
      "dialog",
      { class: "app-dialog confirm-dialog", "aria-label": title },
      el(
        "div",
        { class: "dialog-form" },
        el(
          "div",
          { class: "dialog-heading" },
          el("div", {}, el("p", { class: "eyebrow" }, "CONFIRMAR AÇÃO"), el("h2", {}, title)),
        ),
        el("p", { class: "confirm-message" }, message),
        el(
          "div",
          { class: "dialog-actions" },
          el(
            "button",
            { class: "button button-secondary", type: "button", onClick: () => dialog.close() },
            "Cancelar",
          ),
          el(
            "button",
            {
              class: `button ${danger ? "button-danger" : "button-primary"}`,
              type: "button",
              onClick: () => {
                confirmed = true;
                dialog.close();
              },
            },
            confirmLabel,
          ),
        ),
      ),
    );
    document.body.append(dialog);
    dialog.addEventListener("close", () => {
      dialog.remove();
      resolve(confirmed);
    });
    dialog.showModal();
  });
}

G.formDialog = formDialog;
G.confirm = confirmDialog;

/* ------------------------------------------------------------------ */
/* Navigation                                                         */
/* ------------------------------------------------------------------ */

function navLink(group, items) {
  return el(
    "a",
    {
      class: "nav-link",
      href: `#/${items[0].view}`,
      "aria-label": group.label,
      dataset: { area: group.key, views: items.map((item) => item.view).join(" "), tooltip: group.label },
    },
    el("span", { class: "nav-icon" }, icon(group.icon, { size: 20 })),
    el("span", { class: "nav-label", "aria-hidden": "true" }, group.label),
  );
}

function renderNav() {
  const container = document.querySelector("#nav-groups");
  container.replaceChildren();
  const section = el("section", { class: "nav-section", "aria-label": "Áreas" });
  const bottom = document.querySelector("#nav-bottom");
  bottom?.replaceChildren();
  for (const group of G.NAV) {
    const items = group.items.filter((item) => moduleEnabled(item.module));
    if (!items.length) continue;
    if (group.bottom && bottom) bottom.append(navLink(group, items));
    else section.append(navLink(group, items));
  }
  container.append(section);
}

/* Underline tabs between the routes of one area, above the screen. */
function areaTabs(view) {
  const group = G.NAV.find((entry) => entry.items.some((item) => item.view === view));
  if (!group) return null;
  const items = group.items.filter((item) => moduleEnabled(item.module));
  if (items.length < 2) return null;
  return el(
    "nav",
    { class: "area-tabs", "aria-label": group.label },
    ...items.map((item) =>
      el(
        "a",
        {
          class: `area-tab${item.view === view ? " is-active" : ""}`,
          href: `#/${item.view}`,
          "aria-current": item.view === view ? "page" : null,
        },
        item.tab || item.label,
      ),
    ),
  );
}

function renderShellState() {
  renderNav();
  if (newInvestigationButton) {
    newInvestigationButton.hidden = !moduleEnabled("investigations");
  }
  if (searchButton) {
    searchButton.hidden = !moduleEnabled("global-search");
  }
}

function markActiveNav(view) {
  const extra = G.EXTRA_VIEWS.find((item) => item.view === view);
  // An open case belongs to the main flow; the case index to Configurações.
  const params = G.state.currentParams || [];
  const home = view === "investigations" && params.length ? "overview" : extra?.home || view;
  document.querySelectorAll(".nav-link").forEach((link) => {
    const active = (link.dataset.views || "").split(" ").includes(home);
    link.classList.toggle("is-active", active);
    if (active) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  });
}

function setBreadcrumb(view) {
  const label = G.VIEW_LABELS[view] || titleCase(view);
  const crumb = document.querySelector("#page-breadcrumb");
  if (crumb) crumb.textContent = label;
  document.title = `${label} · GARBAGE`;
}

function go(...parts) {
  const target = `#/${parts.filter(Boolean).join("/")}`;
  if (location.hash === target) route();
  else location.hash = target;
}

async function route() {
  if (!G.views) return;
  setMobileNav(false);
  closeDisplayMenu();
  viewRoot.classList.remove("is-ready");
  for (const cleanup of G.cleanupFns.splice(0)) {
    try {
      cleanup();
    } catch {
      /* cleanup is best effort */
    }
  }
  // "?key=value" after the path is read by the view itself (hashQuery).
  const raw = location.hash.replace(/^#\/?/, "").split("?")[0];
  const segments = raw.split("/").filter(Boolean);
  const candidate = segments[0] || "overview";
  const view = G.views[candidate] ? candidate : "overview";
  const params = segments.slice(1);
  G.state.currentView = view;
  G.state.currentParams = params;
  markActiveNav(view);
  setBreadcrumb(view);
  hideTooltip();
  viewRoot.dataset.view = view;
  viewRoot.dataset.detail = params.length ? "true" : "false";
  setLoading(true);
  viewRoot.replaceChildren();
  try {
    const tabHost = document.querySelector("#area-tabs-host");
    if (tabHost) {
      tabHost.dataset.view = view;
      tabHost.replaceChildren(...[areaTabs(view)].filter(Boolean));
    }
    await G.views[view](viewRoot, params);
  } catch (error) {
    viewRoot.replaceChildren(
      errorState({
        title: "Não foi possível carregar esta tela",
        message: error.message,
        retry: () => route(),
      }),
    );
  } finally {
    setLoading(false);
    viewRoot.focus({ preventScroll: true });
    window.requestAnimationFrame(() => viewRoot.classList.add("is-ready"));
  }
  window.scrollTo({ top: 0, behavior: "auto" });
  viewRoot.scrollTop = 0;
}

G.go = go;
G.refreshView = route;
G.reloadModules = async function reloadModules() {
  G.state.modules = await api("/api/modules");
  renderShellState();
};
G.loadInvestigations = async function loadInvestigations(force = false) {
  if (G.state.investigations.length && !force) return G.state.investigations;
  G.state.investigations = await api("/api/investigations");
  return G.state.investigations;
};
G.invalidateInvestigations = function invalidateInvestigations() {
  G.state.investigations = [];
};

G.newInvestigation = async function newInvestigation() {
  await formDialog({
    eyebrow: "NOVO CASO",
    title: "Criar investigação",
    description: "Abra um caso. As observações permanecem com fonte registrada e sem verificação.",
    fields: [
      {
        name: "name",
        label: "Nome da investigação",
        required: true,
        maxlength: 200,
        placeholder: "ex.: Revisão de infraestrutura suspeita",
      },
      {
        name: "description",
        label: "Descrição",
        type: "textarea",
        rows: 3,
        placeholder: "Escopo e contexto",
      },
      {
        name: "objective",
        label: "Objetivo",
        type: "textarea",
        rows: 2,
        maxlength: 2000,
        placeholder: "A pergunta que o caso precisa responder",
      },
    ],
    submitLabel: "Criar investigação",
    onSubmit: async (values) => {
      const created = await api("/api/investigations", {
        method: "POST",
        body: JSON.stringify(values),
      });
      G.invalidateInvestigations();
      toast("Investigação criada.");
      go("investigations", created.id);
    },
  });
};

/* ------------------------------------------------------------------ */
/* Global search                                                      */
/* ------------------------------------------------------------------ */

let searchTimer = null;

function renderSearchHint(message = "Digite pelo menos dois caracteres para pesquisar registros locais.") {
  searchResults.replaceChildren(el("p", { class: "search-hint" }, message));
  G.state.searchIndex = -1;
}

function commandActions() {
  return [
    {
      label: "Nova investigação",
      icon: "＋",
      hint: "N",
      keywords: "create case open criar caso abrir nova investigação",
      module: "investigations",
      run: () => G.newInvestigation(),
    },
    {
      label: "Pesquisa multifonte",
      icon: "radar",
      hint: "M",
      keywords: "multi source fan out osint dns rdap whois asn crt certificate wayback epss pesquisa fontes consultar",
      module: "intel-orchestrator",
      run: () => go("multisearch"),
    },
    {
      label: "Registrar entidade",
      icon: "⬡",
      keywords: "new domain ip person organization nova entidade domínio pessoa organização",
      module: "entities",
      run: () => G.entityDialog(),
    },
    {
      label: "Registrar fonte",
      icon: "⛁",
      keywords: "new reference provenance nova fonte referência proveniência",
      module: "source-manager",
      run: () => G.sourceDialog(),
    },
    {
      label: "Adicionar evidência",
      icon: "▣",
      keywords: "upload file hash capture enviar arquivo evidência captura",
      module: "evidence",
      run: () => G.evidenceDialog(),
    },
    {
      label: "Triar texto colado",
      icon: "⌁",
      hint: "T",
      keywords: "extract indicator ioc paste defang text triage extrair indicador colar texto triagem",
      module: "indicator-engine",
      run: () => {
        go("indicators");
        window.setTimeout(() => document.querySelector("#triage-text")?.focus(), 200);
      },
    },
    {
      label: "Abrir análise de arquivos",
      icon: "▧",
      keywords: "analyse analyze upload pdf binary archive analisar arquivo binário",
      module: "file-intelligence",
      run: () => go("files"),
    },
    {
      label: "Atualizar tela atual",
      icon: "↻",
      hint: "R",
      keywords: "reload update",
      run: () => G.refreshView(),
    },
    {
      label: "Alternar densidade compacta",
      icon: "▤",
      keywords: "density spacing compact comfortable layout densidade espaçamento compacta confortável",
      run: () => toggleInterfaceSetting("interface.density", "compact", "comfortable"),
    },
    {
      label: "Alternar alto contraste",
      icon: "◐",
      keywords: "theme contrast dark appearance tema contraste escuro aparência",
      run: () => toggleInterfaceSetting("interface.theme", "contrast", "dark"),
    },
    {
      label: "Alternar movimento reduzido",
      icon: "◌",
      keywords: "motion animation accessibility movimento animação acessibilidade",
      run: () => toggleInterfaceSetting("interface.reduce_motion", "true", "false"),
    },
    {
      label: "Preferências de exibição",
      icon: "◨",
      keywords: "theme density motion appearance tema densidade movimento exibição",
      run: () => openDisplayMenu(),
    },
    {
      label: "Atalhos de teclado",
      icon: "⌘",
      hint: "?",
      keywords: "keys help commands teclas ajuda comandos atalhos",
      run: () => G.openShortcuts(),
    },
  ].filter((action) => moduleEnabled(action.module));
}

function commandNavItems() {
  const groups = [
    ...G.NAV,
    { label: "Configurações", items: G.EXTRA_VIEWS },
  ];
  return groups.flatMap((group) =>
    group.items
      .filter((item) => moduleEnabled(item.module))
      .map((item) => ({
        label: item.label,
        subtitle: group.label.toLowerCase(),
        icon: item.icon,
        keywords: `${item.label} ${group.label}`,
        run: () => go(item.view),
      })),
  );
}

function matchesCommand(item, query) {
  if (!query) return true;
  return `${item.label} ${item.subtitle || ""} ${item.keywords || ""}`
    .toLowerCase()
    .includes(query);
}

function commandButton(item) {
  return el(
    "button",
    {
      class: "search-result command-result",
      type: "button",
      onClick: () => {
        searchDialog.close();
        window.setTimeout(() => item.run(), 0);
      },
    },
    el("span", { class: "command-result-icon" }, icon(item.icon || "dot", { size: 16 })),
    el(
      "span",
      { class: "command-result-copy" },
      el("span", { class: "search-result-title" }, item.label),
      item.subtitle ? el("span", { class: "search-result-subtitle" }, item.subtitle) : null,
    ),
    item.hint ? el("kbd", {}, item.hint) : null,
  );
}

function appendCommandGroup(query, actionLimit = 6, navLimit = 8) {
  const actions = commandActions()
    .filter((item) => matchesCommand(item, query))
    .slice(0, actionLimit);
  const navigation = commandNavItems()
    .filter((item) => matchesCommand(item, query))
    .slice(0, navLimit);
  let added = 0;
  for (const [label, items] of [
    ["AÇÕES RÁPIDAS", actions],
    ["IR PARA", navigation],
  ]) {
    if (!items.length) continue;
    const section = el(
      "section",
      { class: "search-group command-group" },
      el(
        "div",
        { class: "search-group-label" },
        el("span", {}, label),
        el("span", { class: "search-group-total" }, String(items.length)),
      ),
    );
    for (const item of items) section.append(commandButton(item));
    searchResults.append(section);
    added += items.length;
  }
  return added;
}

function renderCommandMenu(query = "") {
  searchResults.replaceChildren();
  G.state.searchIndex = -1;
  const added = appendCommandGroup(query.trim().toLowerCase(), 20, 20);
  if (!added) renderSearchHint("Nenhum comando ou destino corresponde.");
}

function navigateSearchItem(item) {
  if (item.view === "entities" && item.entity_id) go("entities", item.entity_id);
  else if (item.view === "sources" && item.source_id) go("sources", item.source_id);
  else if (item.view === "evidence" && item.investigation_id) go("evidence", item.investigation_id);
  else if (item.view === "investigations" && item.investigation_id)
    go("investigations", item.investigation_id);
  else if (item.view === "files") go("files");
  else go(item.view);
}

const SEARCH_GROUP_PT = {
  best: "Mais relevantes", investigations: "Investigações", entities: "Entidades", sources: "Fontes",
  evidence: "Evidências", observations: "Observações", files: "Análises de arquivos", indicators: "Indicadores",
};

/* FTS5 marks matches with \u0002…\u0003; turn them into <mark> safely. */
function markedText(text) {
  const parts = String(text || "").split(/(\u0002[^\u0003]*\u0003)/);
  return parts.filter(Boolean).map((part) =>
    part.startsWith("\u0002") ? el("mark", {}, part.slice(1, -1)) : document.createTextNode(part),
  );
}

function searchSubtitle(item) {
  switch (item.kind) {
    case "investigations": return `Investigação · ${statusLabel(item.status).toLowerCase()}`;
    case "entities": return `${entityTypeLabel(item.entity_type)}${item.identifier ? ` · ${item.identifier}` : ""}`;
    case "sources": return "Fonte";
    case "evidence": return "Evidência";
    case "observations": return `Observação · ${item.investigation_name}`;
    case "files": return `Análise de arquivo · ${FORMAT_LABEL_PT[item.format] || item.format}`;
    case "indicators": return `Indicador · ${indicatorTypeLabel(item.indicator_type)} · ${item.origin_count} origem(ns)`;
    default: return item.subtitle || "";
  }
}

function renderSearchResults(data, query = "") {
  searchResults.replaceChildren();
  G.state.searchIndex = -1;
  if (data.message) {
    renderSearchHint(data.message);
    return;
  }
  const commandCount = appendCommandGroup(query, 4, 5);
  // The best-ranked hits come first; groups below skip what is already there.
  const shown = new Set((data.best || []).map((item) => `${item.kind}:${item.id}`));
  const groups = [
    ...(data.best?.length ? [{ key: "best", label: "Best", total: data.best.length, items: data.best }] : []),
    ...(data.groups || []).map((group) => ({
      ...group,
      items: group.items.filter((item) => !shown.has(`${item.kind || group.key}:${item.id}`)),
    })),
  ].filter((group) => group.items.length);
  if (!groups.length) {
    if (!commandCount) renderSearchHint("Nenhum registro local ou comando corresponde.");
    return;
  }
  for (const group of groups) {
    const section = el(
      "section",
      { class: "search-group" },
      el(
        "div",
        { class: "search-group-label" },
        el("span", {}, SEARCH_GROUP_PT[group.key] || group.label),
        el("span", { class: "search-group-total" }, String(group.total)),
      ),
    );
    for (const item of group.items) {
      section.append(
        el(
          "button",
          {
            class: "search-result",
            type: "button",
            onClick: () => {
              searchDialog.close();
              navigateSearchItem(item);
            },
          },
          el("span", { class: "search-result-title" }, ...(item.title_marked ? markedText(item.title_marked) : [item.title])),
          el("span", { class: "search-result-subtitle" }, searchSubtitle({ kind: group.key, ...item })),
          item.snippet && item.snippet.includes("\u0002") && !(item.title_marked || "").includes("\u0002")
            ? el("span", { class: "search-result-snippet" }, ...markedText(item.snippet))
            : null,
        ),
      );
    }
    searchResults.append(section);
  }
}

async function runSearch(query) {
  try {
    const data = await api(`/api/search?q=${encodeURIComponent(query)}`);
    if (searchInput.value.trim() !== query) return;
    renderSearchResults(data, query);
  } catch (error) {
    if (searchInput.value.trim() !== query) return;
    searchResults.replaceChildren(inlineError(error.message));
  }
}

function moveSearchSelection(delta) {
  const buttons = [...searchResults.querySelectorAll(".search-result")];
  if (!buttons.length) return;
  const current = G.state.searchIndex;
  G.state.searchIndex = (current + delta + buttons.length) % buttons.length;
  buttons.forEach((button, index) => button.classList.toggle("is-active", index === G.state.searchIndex));
  buttons[G.state.searchIndex].scrollIntoView({ block: "nearest" });
}

function openSearch() {
  if (!moduleEnabled("global-search")) {
    toast("A pesquisa global está desativada no gerenciador de módulos.", "error");
    return;
  }
  closeDisplayMenu();
  searchInput.value = "";
  renderCommandMenu("");
  searchDialog.showModal();
  window.setTimeout(() => searchInput.focus(), 20);
}

G.openSearch = openSearch;

/* ------------------------------------------------------------------ */
/* Mobile navigation                                                  */
/* ------------------------------------------------------------------ */

function setMobileNav(open) {
  document.body.classList.toggle("nav-open", open);
  if (mobileNavToggle) mobileNavToggle.setAttribute("aria-expanded", String(open));
  if (navBackdrop) navBackdrop.setAttribute("aria-hidden", String(!open));
  const main = document.querySelector(".main-shell");
  if (main) main.inert = open;
  if (open) window.setTimeout(() => sidebarClose?.focus(), 60);
}

function closeMobileNav({ restoreFocus = false } = {}) {
  setMobileNav(false);
  if (restoreFocus) mobileNavToggle?.focus();
}

/* ------------------------------------------------------------------ */
/* Display controls                                                   */
/* ------------------------------------------------------------------ */

async function setInterfaceSetting(key, value) {
  try {
    const result = await api("/api/settings", {
      method: "PATCH",
      body: JSON.stringify({ [key]: value }),
    });
    G.state.settings = result.values;
    applySettings(result.values);
    renderDisplayMenu();
    toast("Preferências de exibição salvas.");
  } catch (error) {
    toast(error.message, "error");
  }
}

function toggleInterfaceSetting(key, first, second) {
  const current = G.state.settings?.[key];
  setInterfaceSetting(key, current === first ? second : first);
}

function displayChoice(label, key, value, active) {
  return el(
    "button",
    {
      class: `display-choice${active ? " is-active" : ""}`,
      type: "button",
      "aria-pressed": String(active),
      onClick: () => setInterfaceSetting(key, value),
    },
    label,
  );
}

function displayGroup(label, children) {
  return el(
    "div",
    { class: "display-group" },
    el("span", { class: "display-label" }, label),
    el("div", { class: "display-options" }, ...children),
  );
}

function renderDisplayMenu() {
  if (!displayMenu) return;
  const settings = G.state.settings || {};
  const theme = settings["interface.theme"] || "dark";
  const density = settings["interface.density"] || "comfortable";
  const motion = settings["interface.reduce_motion"] || "false";
  displayMenu.replaceChildren(
    el(
      "div",
      { class: "display-menu-heading" },
      el("strong", {}, "Exibição"),
      el("span", {}, "Salvo neste workspace"),
    ),
    displayGroup("TEMA", [
      displayChoice("Claro", "interface.theme", "dark", theme === "dark"),
      displayChoice("Alto contraste (escuro)", "interface.theme", "contrast", theme === "contrast"),
    ]),
    displayGroup("DENSIDADE", [
      displayChoice("Confortável", "interface.density", "comfortable", density === "comfortable"),
      displayChoice("Compacta", "interface.density", "compact", density === "compact"),
    ]),
    displayGroup("MOVIMENTO", [
      displayChoice("Completo", "interface.reduce_motion", "false", motion !== "true"),
      displayChoice("Reduzido", "interface.reduce_motion", "true", motion === "true"),
    ]),
    el(
      "div",
      { class: "display-menu-footer" },
      el(
        "button",
        {
          class: "display-link",
          type: "button",
          onClick: () => {
            closeDisplayMenu();
            go("settings");
          },
        },
        "Todas as configurações",
      ),
      el(
        "button",
        {
          class: "display-link",
          type: "button",
          onClick: () => {
            closeDisplayMenu();
            G.openShortcuts();
          },
        },
        "Atalhos",
      ),
    ),
  );
}

function openDisplayMenu() {
  if (!displayMenu || !displayToggle) return;
  renderDisplayMenu();
  displayMenu.hidden = false;
  displayToggle.setAttribute("aria-expanded", "true");
}

function closeDisplayMenu() {
  if (!displayMenu || !displayToggle) return;
  displayMenu.hidden = true;
  displayToggle.setAttribute("aria-expanded", "false");
}

/* ------------------------------------------------------------------ */
/* Keyboard shortcuts                                                */
/* ------------------------------------------------------------------ */

const SHORTCUT_ROWS = [
  ["Ctrl / ⌘ K", "Abrir pesquisa e comandos"],
  ["/", "Focar a pesquisa"],
  ["N", "Nova investigação"],
  ["T", "Triar texto colado"],
  ["M", "Pesquisa multifonte"],
  ["R", "Atualizar tela atual"],
  ["?", "Este guia de atalhos"],
  ["Esc", "Fechar diálogo, menu ou painel"],
  ["Grafo · Shift + clique", "Adicionar ou tirar um nó da seleção"],
  ["Grafo · Shift + arrastar", "Selecionar uma área"],
  ["Grafo · Ctrl / ⌘ A", "Selecionar todos os nós visíveis"],
  ["Grafo · P", "Fixar ou soltar a seleção"],
  ["Grafo · H ou Delete", "Ocultar a seleção"],
  ["Grafo · Ctrl / ⌘ Z", "Desfazer (Shift para refazer)"],
];

G.shortcutList = function shortcutList() {
  return el(
    "div",
    { class: "shortcut-list" },
    ...SHORTCUT_ROWS.map(([keys, label]) =>
      el("div", { class: "shortcut-row" }, el("span", {}, label), el("kbd", {}, keys)),
    ),
  );
};

G.openShortcuts = function openShortcuts() {
  if (document.querySelector(".shortcuts-dialog")) return;
  const dialog = el(
    "dialog",
    { class: "app-dialog shortcuts-dialog", "aria-label": "Atalhos de teclado" },
    el(
      "div",
      { class: "dialog-form" },
      el(
        "div",
        { class: "dialog-heading" },
        el(
          "div",
          {},
          el("h2", {}, "Atalhos de teclado"),
        ),
        el(
          "button",
          { class: "icon-button", type: "button", "aria-label": "Fechar", onClick: () => dialog.close() },
          icon("close"),
        ),
      ),
      G.shortcutList(),
      el(
        "div",
        { class: "dialog-actions" },
        el("button", { class: "button button-primary", type: "button", onClick: () => dialog.close() }, "Concluir"),
      ),
    ),
  );
  document.body.append(dialog);
  dialog.addEventListener("close", () => dialog.remove());
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) dialog.close();
  });
  dialog.showModal();
};

/* ------------------------------------------------------------------ */
/* Boot                                                               */
/* ------------------------------------------------------------------ */

function isTypingTarget(target) {
  return Boolean(
    target?.closest?.("input, textarea, select, [contenteditable='true']"),
  );
}

function bindShell() {
  if (bindShell.bound) return;
  bindShell.bound = true;
  hydrateIcons();
  bindTooltips();
  document.querySelector("#nav-groups").addEventListener("click", (event) => {
    if (event.target.closest("a.nav-link")) setMobileNav(false);
  });
  newInvestigationButton?.addEventListener("click", () => {
    G.newInvestigation().catch((error) => toast(error.message, "error"));
  });
  searchButton?.addEventListener("click", () => {
    setMobileNav(false);
    openSearch();
  });
  mobileNavToggle?.addEventListener("click", () => {
    setMobileNav(!document.body.classList.contains("nav-open"));
  });
  sidebarClose?.addEventListener("click", () => closeMobileNav({ restoreFocus: true }));
  navBackdrop?.addEventListener("click", () => closeMobileNav({ restoreFocus: true }));
  displayToggle?.addEventListener("click", () => {
    if (displayMenu?.hidden) openDisplayMenu();
    else closeDisplayMenu();
  });
  shortcutsButton?.addEventListener("click", () => {
    setMobileNav(false);
    G.openShortcuts();
  });
  document.addEventListener("click", (event) => {
    if (displayMenu && !displayMenu.hidden && !event.target.closest(".display-wrap")) {
      closeDisplayMenu();
    }
  });
  window.addEventListener("resize", () => {
    if (window.innerWidth > 760 && document.body.classList.contains("nav-open")) {
      setMobileNav(false);
    }
  });
  searchDialog.addEventListener("click", (event) => {
    if (event.target === searchDialog) searchDialog.close();
  });
  searchInput.addEventListener("input", () => {
    clearTimeout(searchTimer);
    const query = searchInput.value.trim();
    if (query.length < 2) {
      renderCommandMenu(query);
      return;
    }
    searchResults.replaceChildren(loadingBlock("Pesquisando registros locais…"));
    searchTimer = window.setTimeout(() => runSearch(query), 220);
  });
  searchInput.addEventListener("keydown", (event) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      moveSearchSelection(1);
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      moveSearchSelection(-1);
    } else if (event.key === "Enter") {
      event.preventDefault();
      const buttons = [...searchResults.querySelectorAll(".search-result")];
      if (!buttons.length) return;
      buttons[Math.max(0, G.state.searchIndex)].click();
    }
  });
  document.addEventListener("keydown", (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
      event.preventDefault();
      openSearch();
      return;
    }
    if (event.key === "Escape") {
      closeDisplayMenu();
      if (document.body.classList.contains("nav-open")) {
        closeMobileNav({ restoreFocus: true });
      }
      return;
    }
    if (isTypingTarget(event.target) || document.querySelector("dialog[open]")) return;
    if (event.key === "?") {
      event.preventDefault();
      G.openShortcuts();
    } else if (event.key === "/") {
      event.preventDefault();
      openSearch();
    } else if (event.key.toLowerCase() === "n" && !event.ctrlKey && !event.metaKey && !event.altKey) {
      event.preventDefault();
      G.newInvestigation().catch((error) => toast(error.message, "error"));
    } else if (event.key.toLowerCase() === "t" && !event.ctrlKey && !event.metaKey && !event.altKey) {
      event.preventDefault();
      go("indicators");
      window.setTimeout(() => document.querySelector("#triage-text")?.focus(), 200);
    } else if (
      event.key.toLowerCase() === "m" && !event.ctrlKey && !event.metaKey && !event.altKey &&
      moduleEnabled("intel-orchestrator")
    ) {
      event.preventDefault();
      go("multisearch");
    } else if (event.key.toLowerCase() === "r" && !event.ctrlKey && !event.metaKey && !event.altKey) {
      event.preventDefault();
      G.refreshView();
    }
  });
}

async function boot() {
  bindShell();
  if (!boot.retryBound) {
    boot.retryBound = true;
    window.addEventListener("hashchange", () => {
      route();
    });
  }
  try {
    const [modules, settings] = await Promise.all([api("/api/modules"), api("/api/settings")]);
    G.state.modules = modules;
    G.state.settings = settings.values;
    applySettings();
    renderShellState();
    if (!location.hash) {
      history.replaceState(null, "", "#/overview");
    }
    await route();
  } catch (error) {
    document.querySelector("#nav-groups").replaceChildren();
    viewRoot.replaceChildren(
      errorState({
        title: "O workspace local está indisponível",
        message: `${error.message}. Inicie o servidor com "python3 -m garbage_intel serve" e tente novamente.`,
        retry: () => boot(),
      }),
    );
  }
}

document.addEventListener("DOMContentLoaded", () => {
  boot();
});
