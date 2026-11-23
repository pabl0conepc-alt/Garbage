"use strict";

/* Assistant side panel: the robot button opens a conversation with the model
 * chosen on OpenRouter. The model works through the server's tools
 * (garbage_intel/assistant.py); this file shows the conversation, asks the
 * analyst before destructive actions and performs the interface actions the
 * model requested (open a screen, change the graph). */

(function () {
  const G = window.GARBAGE;
  const { el, api } = G;
  const STORAGE_KEY = "garbage.assistant.conversation";
  const POLL_MS = 800;

  const state = {
    open: false,
    mode: "chat",
    status: null,
    conversation: null,
    handled: new Set(),
    pollTimer: null,
    models: null,
    sending: false,
  };

  function remembered() {
    try {
      return localStorage.getItem(STORAGE_KEY) || "";
    } catch {
      return "";
    }
  }

  function remember(id) {
    try {
      if (id) localStorage.setItem(STORAGE_KEY, id);
      else localStorage.removeItem(STORAGE_KEY);
    } catch {
      /* the panel works without storage */
    }
  }

  function iconButton(icon, label, onClick, extra = {}) {
    const node = el("button", { class: "assistant-icon-button", type: "button", "aria-label": label, title: label, ...extra }, G.icon(icon, { size: 17 }));
    node.addEventListener("click", onClick);
    return node;
  }

  /* ---- Shell ------------------------------------------------------------ */

  const fab = el(
    "button",
    { class: "assistant-fab", type: "button", "aria-label": "Abrir o assistente de IA", "aria-expanded": "false", "aria-controls": "assistant-panel", title: "Assistente de IA" },
    G.icon("robot", { size: 24 }),
  );
  const title = el("strong", { class: "assistant-title" }, "Assistente");
  const modelLabel = el("span", { class: "assistant-model" });
  const body = el("div", { class: "assistant-body" });
  const composerInput = el("textarea", {
    class: "assistant-input",
    rows: "1",
    "aria-label": "Mensagem para o assistente",
  });
  const sendButton = el("button", { class: "assistant-send", type: "submit", "aria-label": "Enviar", title: "Enviar" }, G.icon("send", { size: 17 }));
  const composer = el("form", { class: "assistant-composer" }, composerInput, sendButton);
  const panel = el(
    "aside",
    { class: "assistant-panel", id: "assistant-panel", "aria-label": "Assistente de IA", hidden: true },
    el(
      "header",
      { class: "assistant-head" },
      el("span", { class: "assistant-head-icon" }, G.icon("robot", { size: 20 })),
      el("div", { class: "assistant-head-text" }, title, modelLabel),
      iconButton("plus", "Nova conversa", () => newConversation()),
      iconButton("list", "Conversas anteriores", () => setMode(state.mode === "history" ? "chat" : "history")),
      iconButton("files", "Arquivos do assistente", () => setMode(state.mode === "files" ? "chat" : "files")),
      iconButton("settings", "Chave e modelo", () => setMode(state.mode === "setup" ? "chat" : "setup")),
      iconButton("close", "Fechar o assistente", () => toggle(false)),
    ),
    body,
    composer,
  );

  function toggle(open = !state.open) {
    state.open = open;
    panel.hidden = !open;
    fab.setAttribute("aria-expanded", String(open));
    document.body.classList.toggle("assistant-open", open);
    if (open) {
      loadStatus().then(() => {
        if (state.mode === "chat") composerInput.focus();
      });
    } else {
      stopPolling();
      fab.focus();
    }
  }

  function setMode(mode) {
    state.mode = mode;
    render();
  }

  /* ---- Data ------------------------------------------------------------- */

  async function loadStatus() {
    try {
      state.status = await api("/api/assistant");
    } catch (error) {
      body.replaceChildren(G.inlineError(error.message));
      return;
    }
    const ready = state.status.configured && state.status.model;
    if (!ready) state.mode = "setup";
    else if (!state.conversation) {
      const id = remembered();
      if (id && state.status.conversations.some((item) => item.id === id)) await openConversation(id);
    }
    render();
  }

  async function openConversation(id) {
    try {
      const conversation = await api(`/api/assistant/conversations/${id}`);
      // Actions already on record were performed when they happened.
      state.handled = new Set(conversation.messages.filter((message) => message.role === "tool").map((message) => message.id));
      state.conversation = conversation;
      remember(id);
      state.mode = "chat";
      render();
      follow();
    } catch {
      remember("");
      state.conversation = null;
    }
  }

  function newConversation() {
    stopPolling();
    state.conversation = null;
    state.handled = new Set();
    remember("");
    state.mode = state.status?.configured && state.status?.model ? "chat" : "setup";
    render();
    composerInput.focus();
  }

  function context() {
    return { view: G.state.currentView || "", params: G.state.currentParams || [] };
  }

  async function send(text) {
    if (state.sending) return;
    state.sending = true;
    try {
      const payload = { content: text, context: context() };
      const conversation = state.conversation
        ? await api(`/api/assistant/conversations/${state.conversation.id}/messages`, { method: "POST", body: JSON.stringify(payload) })
        : await api("/api/assistant/conversations", { method: "POST", body: JSON.stringify(payload) });
      composerInput.value = "";
      resizeInput();
      receive(conversation);
      remember(conversation.id);
      follow();
    } catch (error) {
      G.toast(error.message, "error");
    } finally {
      state.sending = false;
      render();
    }
  }

  async function answer(message, approve) {
    try {
      const conversation = await api(`/api/assistant/conversations/${state.conversation.id}/confirm`, {
        method: "POST",
        body: JSON.stringify({ message_id: message.id, approve }),
      });
      receive(conversation);
      follow();
    } catch (error) {
      G.toast(error.message, "error");
    }
  }

  async function stopRun() {
    if (!state.conversation) return;
    try {
      receive(await api(`/api/assistant/conversations/${state.conversation.id}/stop`, { method: "POST", body: "{}" }));
    } catch (error) {
      G.toast(error.message, "error");
    }
  }

  function stopPolling() {
    window.clearTimeout(state.pollTimer);
    state.pollTimer = null;
  }

  function follow() {
    stopPolling();
    const conversation = state.conversation;
    if (!conversation || !(conversation.running || conversation.status === "running")) return;
    state.pollTimer = window.setTimeout(async () => {
      if (state.conversation?.id !== conversation.id) return;
      try {
        receive(await api(`/api/assistant/conversations/${conversation.id}`));
      } catch {
        /* next poll retries */
      }
      follow();
    }, POLL_MS);
  }

  function receive(conversation) {
    const fresh = conversation.messages.filter((message) => message.role === "tool" && !state.handled.has(message.id) && message.action?.status !== "pending");
    state.conversation = conversation;
    for (const message of fresh) state.handled.add(message.id);
    perform(fresh);
    if (state.open) render();
  }

  /* ---- Interface actions the model asked for ---------------------------- */

  function whenView(view, timeout = 4000) {
    const started = Date.now();
    return new Promise((resolve) => {
      (function check() {
        const ready = G.state.currentView === view && document.querySelector("#view-root")?.classList.contains("is-ready");
        if (ready || Date.now() - started > timeout) resolve();
        else window.setTimeout(check, 80);
      })();
    });
  }

  async function perform(messages) {
    const refresh = new Set();
    for (const message of messages) {
      const action = message.action || {};
      for (const view of action.refresh || []) refresh.add(view);
      const ui = action.ui;
      if (!ui || action.status !== "done") continue;
      if (ui.type === "open") {
        G.go(ui.view, ...(ui.params || []));
        refresh.clear();
      } else if (ui.type === "graph") {
        if (G.state.currentView !== "graph") {
          G.go("graph");
          await whenView("graph");
        }
        window.dispatchEvent(new CustomEvent("garbage:graph", { detail: ui }));
      }
    }
    const current = G.state.currentView;
    if (refresh.has(current) || (refresh.has("entities") && current === "entities") || (refresh.has("investigations") && current === "investigations")) {
      G.refreshView();
    }
  }

  /* ---- Rendering -------------------------------------------------------- */

  function render() {
    if (!state.open) return;
    const status = state.status;
    modelLabel.textContent = status?.model || "sem modelo";
    composer.hidden = state.mode !== "chat";
    const busy = Boolean(state.conversation && (state.conversation.running || state.conversation.status === "running"));
    const waiting = state.conversation?.status === "waiting";
    composerInput.disabled = busy || waiting || state.sending;
    sendButton.disabled = composerInput.disabled;
    if (state.mode === "setup") body.replaceChildren(setupView());
    else if (state.mode === "history") body.replaceChildren(historyView());
    else if (state.mode === "files") body.replaceChildren(filesView());
    else body.replaceChildren(chatView(busy));
    if (state.mode === "chat") {
      const log = body.querySelector(".assistant-log");
      if (log) log.scrollTop = log.scrollHeight;
    }
  }

  function chatView(busy) {
    const conversation = state.conversation;
    if (!conversation || !conversation.messages.length) {
      return el(
        "div",
        { class: "assistant-empty" },
        el("p", {}, "Peça em linguagem normal. Exemplos:"),
        ...[
          "Pesquisa example.org e me diz o que chama atenção",
          "Cria um caso “Phishing banco” e anota o que achar sobre bb-login.com",
          "Abre o grafo do caso e organiza em anéis",
          "Salva um resumo do CVE-2024-3400 nos seus arquivos",
        ].map((text) => {
          const node = el("button", { class: "assistant-suggestion", type: "button" }, text);
          node.addEventListener("click", () => send(text));
          return node;
        }),
        el("p", { class: "assistant-fineprint" }, "As mensagens e os resultados das ações vão para o OpenRouter e o modelo escolhido. Excluir sempre pede sua confirmação."),
      );
    }
    const log = el("div", { class: "assistant-log", role: "log", "aria-live": "polite" });
    for (const message of conversation.messages) {
      if (message.role === "user") log.append(el("div", { class: "assistant-msg is-user" }, message.content));
      else if (message.role === "assistant") {
        if (message.content) log.append(richText(message.content));
      } else log.append(actionLine(message));
    }
    if (busy) {
      log.append(
        el(
          "div",
          { class: "assistant-working" },
          el("span", { class: "assistant-dots", "aria-hidden": "true" }, el("i"), el("i"), el("i")),
          "Trabalhando…",
          (() => {
            const node = el("button", { class: "assistant-link", type: "button" }, "Parar");
            node.addEventListener("click", stopRun);
            return node;
          })(),
        ),
      );
    }
    if (conversation.status === "error" && conversation.error) {
      log.append(el("div", { class: "assistant-error", role: "alert" }, G.translateError(conversation.error)));
    }
    return log;
  }

  /* Models answer in light Markdown: paragraphs, lists, **bold** and
     `code` are kept; everything else stays plain text. */
  function inline(text) {
    const parts = [];
    let last = 0;
    for (const match of text.matchAll(/\*\*[^*]+\*\*|`[^`]+`/g)) {
      if (match.index > last) parts.push(text.slice(last, match.index));
      const token = match[0];
      parts.push(token.startsWith("**") ? el("strong", {}, token.slice(2, -2)) : el("code", {}, token.slice(1, -1)));
      last = match.index + token.length;
    }
    parts.push(text.slice(last));
    return parts;
  }

  function richText(text) {
    const node = el("div", { class: "assistant-msg is-model" });
    let list = null;
    for (const raw of text.split("\n")) {
      const line = raw.trimEnd();
      const item = line.match(/^\s*(?:[-*•]|(\d+)[.)])\s+(.*)$/);
      if (item) {
        if (!list) node.append((list = el(item[1] ? "ol" : "ul")));
        list.append(el("li", {}, ...inline(item[2])));
        continue;
      }
      list = null;
      if (!line.trim()) continue;
      const heading = line.match(/^#{1,4}\s+(.*)$/);
      node.append(el("p", {}, heading ? el("strong", {}, ...inline(heading[1])) : inline(line)));
    }
    return node;
  }

  function uiSummary(ui) {
    if (ui.type === "open") return `Abriu ${G.VIEW_LABELS[ui.view] || ui.view}`;
    if (ui.action === "layout") return `Organizou o grafo: ${G.graphLayouts?.[ui.layout]?.label || ui.layout}`;
    if (ui.action === "focus") return "Focou uma entidade no grafo";
    return "Enquadrou o grafo";
  }

  function actionLine(message) {
    const action = message.action || {};
    const status = action.status || "done";
    if (status === "pending") {
      const allow = el("button", { class: "button button-primary button-small", type: "button" }, "Permitir");
      const decline = el("button", { class: "button button-secondary button-small", type: "button" }, "Recusar");
      allow.addEventListener("click", () => answer(message, true));
      decline.addEventListener("click", () => answer(message, false));
      return el("div", { class: "assistant-confirm", role: "group", "aria-label": "Confirmação" }, el("p", {}, action.summary || "Permitir esta ação?"), el("div", { class: "assistant-confirm-buttons" }, decline, allow));
    }
    const icon = { done: "check", error: "alert", declined: "ban" }[status] || "dot";
    const line = el("div", { class: `assistant-action is-${status}` }, G.icon(icon, { size: 14 }), el("span", {}, action.ui ? uiSummary(action.ui) : action.summary || message.tool));
    if (action.link) {
      const open = el("a", { class: "assistant-link", href: action.link }, "Abrir");
      line.append(open);
    }
    if (action.file) {
      line.append(el("a", { class: "assistant-link", href: `/api/assistant/files/${encodeURIComponent(action.file)}`, download: action.file }, "Baixar"));
    }
    if (action.error) line.title = action.error;
    return line;
  }

  function historyView() {
    const items = state.status?.conversations || [];
    if (!items.length) return el("p", { class: "assistant-empty" }, "Nenhuma conversa ainda.");
    return el(
      "ul",
      { class: "assistant-list" },
      ...items.map((item) => {
        const openButton = el("button", { class: "assistant-list-main", type: "button" }, el("span", {}, item.title), el("small", {}, G.relativeTime ? G.relativeTime(item.updated_at) : item.updated_at));
        openButton.addEventListener("click", () => openConversation(item.id));
        const remove = iconButton("trash", "Apagar conversa", async () => {
          const ok = await G.confirm({ title: "Apagar esta conversa?", message: "O registro das ações dela também some. Os casos, entidades e arquivos que ela criou continuam.", confirmLabel: "Apagar", danger: true });
          if (!ok) return;
          try {
            await api(`/api/assistant/conversations/${item.id}`, { method: "DELETE" });
            if (state.conversation?.id === item.id) newConversation();
            await loadStatus();
            state.mode = "history";
            render();
          } catch (error) {
            G.toast(error.message, "error");
          }
        });
        return el("li", {}, openButton, remove);
      }),
    );
  }

  function filesView() {
    const files = state.status?.files || { items: [] };
    const wrap = el("div", { class: "assistant-files" }, el("p", { class: "assistant-fineprint" }, "Pasta do assistente: ", el("code", {}, files.folder || "")));
    if (!files.items.length) {
      wrap.append(el("p", { class: "assistant-empty" }, "Ainda sem arquivos. Peça para ele salvar uma nota, um resumo ou uma lista."));
      return wrap;
    }
    wrap.append(
      el(
        "ul",
        { class: "assistant-list" },
        ...files.items.map((file) => {
          const link = el("a", { class: "assistant-list-main", href: `/api/assistant/files/${encodeURIComponent(file.name)}`, download: file.name }, el("span", {}, file.name), el("small", {}, G.formatBytes(file.size)));
          const remove = iconButton("trash", `Apagar ${file.name}`, async () => {
            const ok = await G.confirm({ title: `Apagar ${file.name}?`, message: "O arquivo sai da pasta do assistente e não volta.", confirmLabel: "Apagar", danger: true });
            if (!ok) return;
            try {
              await api(`/api/assistant/files/${encodeURIComponent(file.name)}`, { method: "DELETE" });
              await loadStatus();
              state.mode = "files";
              render();
            } catch (error) {
              G.toast(error.message, "error");
            }
          });
          return el("li", {}, link, remove);
        }),
      ),
    );
    return wrap;
  }

  function setupView() {
    const status = state.status || {};
    const keyInput = el("input", { class: "input", type: "password", autocomplete: "off", spellcheck: "false", id: "assistant-key", placeholder: status.configured ? `Chave salva ${status.key_hint}` : "sk-or-…" });
    const modelInput = el("input", { class: "input", type: "text", autocomplete: "off", spellcheck: "false", id: "assistant-model", list: "assistant-models", value: status.model || "", placeholder: "ex.: anthropic/claude-sonnet-5.5" });
    const options = el("datalist", { id: "assistant-models" });
    const modelHint = el("p", { class: "assistant-fineprint" }, "Digite para filtrar. Só aparecem modelos que aceitam ferramentas.");
    const save = el("button", { class: "button button-primary", type: "submit" }, "Salvar");
    const form = el(
      "form",
      { class: "assistant-setup" },
      el("p", {}, "O assistente usa o modelo de IA das ", el("a", { href: "#/settings" }, "Configurações"), ": um modelo local (Ollama, LM Studio, llama.cpp, vLLM), uma API compatível com OpenAI (OpenRouter, OpenAI…) ou a Anthropic. O mesmo modelo serve ao Investigador IA. Aqui dá para configurar rápido com o ", el("a", { href: "https://openrouter.ai/settings/keys", target: "_blank", rel: "noopener noreferrer" }, "OpenRouter"), ". A chave fica só neste computador e nunca volta para a tela."),
      status.provider && status.provider !== "disabled"
        ? el("p", { class: "assistant-fineprint" }, `Em uso: ${status.provider} · ${status.base_url || "endereço padrão"}${status.local ? " (nesta máquina ou rede local)" : ""}`)
        : null,
      el("label", { for: "assistant-key" }, "Chave da API (vazio para modelos locais)"),
      keyInput,
      el("label", { for: "assistant-model" }, "Modelo"),
      modelInput,
      options,
      modelHint,
      el("p", { class: "assistant-fineprint" }, status.local
        ? "O modelo roda nesta máquina ou na rede local; nada sai dela."
        : "Com um provedor externo, as mensagens e os resultados das ações vão para ele e para o modelo escolhido; cada modelo cobra o próprio preço."),
      save,
    );
    const fill = (items) => {
      options.replaceChildren(...items.map((item) => el("option", { value: item.id }, `${item.name}${item.prompt_price ? ` · $${(Number(item.prompt_price) * 1e6).toFixed(2)}/M entrada` : ""}`)));
      modelHint.textContent = `${items.length} modelos com ferramentas. Digite para filtrar.`;
    };
    if (state.models) fill(state.models);
    else {
      api("/api/assistant/models")
        .then((data) => {
          state.models = data.items;
          fill(data.items);
        })
        .catch(() => {
          modelHint.textContent = "Não deu para baixar a lista do OpenRouter. Digite o identificador do modelo, como provedor/nome-do-modelo.";
        });
    }
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      save.disabled = true;
      try {
        const key = keyInput.value.trim();
        if (key) await api("/api/intel/keys/ai", { method: "PUT", body: JSON.stringify({ key }) });
        const model = modelInput.value.trim();
        if (model && model !== status.model) await api("/api/assistant/config", { method: "PUT", body: JSON.stringify({ model }) });
        keyInput.value = "";
        await loadStatus();
        if (state.status.configured && state.status.model) {
          G.toast("Assistente pronto");
          setMode("chat");
          composerInput.focus();
        } else {
          G.toast(state.status.model ? "Falta a chave da API do modelo" : "Falta escolher o modelo", "error");
        }
      } catch (error) {
        G.toast(error.message, "error");
      } finally {
        save.disabled = false;
      }
    });
    return form;
  }

  /* ---- Composer --------------------------------------------------------- */

  function resizeInput() {
    composerInput.style.height = "auto";
    composerInput.style.height = `${Math.min(160, composerInput.scrollHeight)}px`;
  }

  composerInput.addEventListener("input", resizeInput);
  composerInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey && !event.isComposing) {
      event.preventDefault();
      composer.requestSubmit();
    }
  });
  composer.addEventListener("submit", (event) => {
    event.preventDefault();
    const text = composerInput.value.trim();
    if (text) send(text);
  });
  panel.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !event.defaultPrevented) toggle(false);
  });
  fab.addEventListener("click", () => toggle());

  function mount() {
    if (!G.moduleEnabled("ai-assistant")) return;
    if (!fab.isConnected) document.body.append(fab, panel);
  }

  G.toggleAssistant = toggle;
  // Modules load after the first route; mount once they are known.
  (function waitForModules(attempt) {
    if (G.state.modules || attempt > 50) mount();
    else window.setTimeout(() => waitForModules(attempt + 1), 100);
  })(0);
})();
