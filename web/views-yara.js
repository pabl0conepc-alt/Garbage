"use strict";

/* YARA rule sets: list, edit, validate and test against a local file. */

(function () {
  const G = window.GARBAGE;
  const { el, api, toast, panel, badge, table, formatDate, formatBytes, emptyState } = G;

  const MAX_BYTES = 4 * 1024 * 1024;
  const TEMPLATE = `rule download_powershell : script
{
    meta:
        description = "PowerShell que baixa conteúdo"
    strings:
        $a = "DownloadString" nocase
        $b = "Net.WebClient" nocase
        $c = "Invoke-WebRequest" nocase
    condition:
        any of them
}
`;

  const ERROR_PT = [
    [/^unknown identifier '(.+)' \(modules are not supported\)$/, "Identificador desconhecido “$1” (módulos não são suportados)."],
    [/^expected '(.+)' near '(.*)'$/, "Esperado “$1” perto de “$2”."],
    [/^expected an identifier$/, "Esperado um identificador."],
    [/^expected a quoted string$/, "Esperado um texto entre aspas."],
    [/^expected a text, hex or regular expression string$/, "Esperado um texto, uma string hex ou uma expressão regular."],
    [/^undefined string (.+)$/, "A string $1 não foi definida."],
    [/^duplicate rule '(.+)'$/, "Regra “$1” duplicada."],
    [/^duplicate string (.+)$/, "String $1 duplicada."],
    [/^'(.+)' is a reserved word$/, "“$1” é uma palavra reservada."],
    [/^unexpected keyword '(.+)'$/, "Palavra reservada inesperada: “$1”."],
    [/^modules and includes are not supported$/, "Módulos e include não são suportados."],
    [/^unbounded jump (.+): give an upper bound up to (\d+)$/, "Salto sem limite $1: informe um limite superior de até $2."],
    [/^invalid jump (.+)$/, "Salto inválido: $1."],
    [/^invalid hex token '(.+)'$/, "Token hex inválido: “$1”."],
    [/^hex strings cannot start or end with a jump$/, "Strings hex não podem começar nem terminar com um salto."],
    [/^unbalanced '(.)' in hex string$/, "“$1” sem par na string hex."],
    [/^nested unbounded repetition .+$/, "Repetição ilimitada dentro de outra pode levar tempo exponencial; reescreva a expressão."],
    [/^invalid regular expression: (.+)$/, "Expressão regular inválida: $1"],
    [/^invalid pattern for (.+?): (.+)$/, "Padrão inválido em $1: $2"],
    [/^the (\w+) modifier is not supported$/, "O modificador $1 não é suportado."],
    [/^modifier not supported on (\w+) strings in this engine$/, "Modificador não suportado em strings $1 neste motor."],
    [/^xor and nocase cannot be combined$/, "xor e nocase não podem ser combinados."],
    [/^xor range must be within 0-255$/, "O intervalo do xor deve ficar entre 0 e 255."],
    [/^anonymous '(.)' is only valid inside 'for \.\.\. of'$/, "“$1” anônimo só vale dentro de “for ... of”."],
    [/^'them' used in a rule without strings$/, "“them” usado em uma regra sem strings."],
    [/^no strings match (.+)$/, "Nenhuma string corresponde a $1."],
    [/^no earlier rules match (.+)$/, "Nenhuma regra anterior corresponde a $1."],
    [/^unterminated string$/, "Texto sem aspas de fechamento."],
    [/^unterminated comment$/, "Comentário sem fechamento."],
    [/^unterminated regular expression$/, "Expressão regular sem barra de fechamento."],
    [/^unterminated hex string$/, "String hex sem chave de fechamento."],
    [/^newline in (string|regular expression)$/, "Quebra de linha dentro de $1."],
    [/^unknown escape '(.+)'$/, "Escape desconhecido: “$1”."],
    [/^empty string$/, "Texto vazio."],
    [/^rule source is empty$/, "O código das regras está vazio."],
    [/^no rules defined$/, "Nenhuma regra definida."],
    [/^'matches' needs module strings, which are not supported$/, "“matches” precisa de strings de módulos, que não são suportados."],
  ];

  /* "line 6: unknown identifier ..." -> { line: 6, text: "Identificador ..." } */
  function translateYaraError(message) {
    const text = String(message || "").replace(/^YARA rule error: /, "");
    const found = text.match(/^line (\d+): (.*)$/);
    const body = found ? found[2] : text;
    for (const [pattern, replacement] of ERROR_PT) {
      if (pattern.test(body)) return { line: found ? Number(found[1]) : 0, text: body.replace(pattern, replacement) };
    }
    return { line: found ? Number(found[1]) : 0, text: body };
  }

  function button(label, onClick, options = {}) {
    return el(
      "button",
      {
        class: `button ${options.variant || "button-secondary"} button-small`,
        type: "button",
        disabled: Boolean(options.disabled),
        onClick,
      },
      label,
    );
  }

  function readBase64(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onerror = () => reject(new Error("Não foi possível ler o arquivo selecionado."));
      reader.onload = () => {
        const text = String(reader.result || "");
        resolve(text.slice(text.indexOf(",") + 1));
      };
      reader.readAsDataURL(file);
    });
  }

  /* One rule match: name, tags, meta and the strings that hit. Shared with
     the file analysis result. */
  function matchCard(match, rulesetName = "") {
    const meta = Object.entries(match.meta || {});
    return el(
      "article",
      { class: "yara-match" },
      el(
        "header",
        { class: "yara-match-head" },
        el("strong", {}, match.rule),
        rulesetName ? el("span", { class: "yara-set" }, rulesetName) : null,
        ...(match.tags || []).map((tag) => badge(tag, "neutral")),
      ),
      meta.length
        ? G.kvList(meta.map(([key, value]) => [key, String(value)]))
        : null,
      match.strings?.length
        ? table({
            columns: [
              { label: "STRING", render: (row) => el("code", {}, row.identifier) },
              { label: "OCORRÊNCIAS", className: "numeric-col", render: (row) => String(row.count) },
              {
                label: "PRIMEIRA POSIÇÃO",
                render: (row) => el("code", {}, `0x${row.matches[0].offset.toString(16)}`),
              },
              {
                label: "TRECHO",
                render: (row) => el("code", { class: "yara-snippet" }, row.matches[0].text),
              },
            ],
            rows: match.strings,
          })
        : el("p", { class: "panel-note" }, "Condição satisfeita sem strings (por exemplo, por estrutura ou tamanho)."),
    );
  }

  G.yaraMatchCard = matchCard;

  async function renderYaraTab(host) {
    let rulesets = [];
    let editing = null; // null = new rule set
    let testFile = null;

    const listHost = el("div");
    const name = el("input", { class: "input", type: "text", maxlength: "120", "aria-label": "Nome do conjunto" });
    const description = el("input", {
      class: "input",
      type: "text",
      maxlength: "1000",
      "aria-label": "Descrição do conjunto",
      placeholder: "Opcional",
    });
    const source = el("textarea", {
      class: "input yara-source",
      rows: "20",
      spellcheck: "false",
      autocomplete: "off",
      "aria-label": "Código das regras",
    });
    const enabled = el("input", { type: "checkbox", checked: true, id: "yara-enabled" });
    const status = el("div", { class: "yara-status", "aria-live": "polite" });
    const testResult = el("div", { class: "yara-test-result", "aria-live": "polite" });
    const fileInput = el("input", {
      type: "file",
      class: "visually-hidden",
      id: "yara-test-file",
      onChange: (event) => {
        testFile = event.target.files?.[0] || null;
        runTest();
      },
    });
    let heading = null;
    const deleteButton = button("Excluir", () => remove(), { variant: "button-danger" });

    function fill(item) {
      editing = item;
      name.value = item?.name || "";
      description.value = item?.description || "";
      source.value = item?.source || TEMPLATE;
      enabled.checked = item ? item.enabled : true;
      heading.textContent = item ? `Editar: ${item.name}` : "Novo conjunto de regras";
      deleteButton.hidden = !item;
      status.replaceChildren();
      testResult.replaceChildren();
      drawList();
    }

    function showCheck(result) {
      if (result.valid) {
        status.replaceChildren(
          el(
            "p",
            { class: "yara-ok" },
            `${result.rules.length} regra(s) válida(s): `,
            ...result.rules.map((rule, index) =>
              el("span", {}, index ? ", " : "", el("code", {}, rule.name), rule.private ? " (privada)" : ""),
            ),
          ),
        );
      } else {
        const error = translateYaraError(result.error);
        status.replaceChildren(
          el("p", { class: "inline-error", role: "alert" }, error.line ? `Linha ${error.line}: ` : "", error.text),
        );
        if (error.line) focusLine(error.line);
      }
    }

    function focusLine(line) {
      const lines = source.value.split("\n");
      const start = lines.slice(0, line - 1).reduce((total, text) => total + text.length + 1, 0);
      source.focus();
      source.setSelectionRange(start, start + (lines[line - 1] || "").length);
    }

    async function validate() {
      try {
        showCheck(await api("/api/intelligence/yara/test", { method: "POST", body: JSON.stringify({ source: source.value }) }));
      } catch (error) {
        toast(error.message, "error");
      }
    }

    async function runTest() {
      if (!testFile) return;
      if (testFile.size > MAX_BYTES) {
        toast("O arquivo excede o limite de 4 MiB.", "error");
        return;
      }
      testResult.replaceChildren(G.loadingBlock(`Testando contra ${testFile.name}…`));
      try {
        const result = await api("/api/intelligence/yara/test", {
          method: "POST",
          body: JSON.stringify({ source: source.value, content_base64: await readBase64(testFile) }),
        });
        showCheck(result);
        if (!result.valid) {
          testResult.replaceChildren();
          return;
        }
        const outcome = result.result;
        testResult.replaceChildren(
          el(
            "p",
            { class: "panel-note" },
            `${testFile.name} · ${formatBytes(testFile.size)} · `,
            outcome.error
              ? el("span", { class: "inline-error" }, outcome.timed_out ? "A varredura passou de 20 s e foi interrompida." : outcome.error)
              : `${outcome.matches.length} regra(s) correspondente(s)`,
          ),
          ...outcome.matches.map((match) => matchCard(match)),
        );
      } catch (error) {
        testResult.replaceChildren();
        toast(error.message, "error");
      } finally {
        fileInput.value = "";
      }
    }

    async function save() {
      const body = {
        name: name.value.trim(),
        description: description.value.trim(),
        source: source.value,
        enabled: enabled.checked,
      };
      try {
        const saved = editing
          ? await api(`/api/intelligence/yara/${editing.id}`, { method: "PATCH", body: JSON.stringify(body) })
          : await api("/api/intelligence/yara", { method: "POST", body: JSON.stringify(body) });
        toast(`Conjunto salvo: ${saved.name} (${saved.rule_count} regra(s)).`);
        await load();
        fill(saved);
      } catch (error) {
        const translated = String(error.message).includes("YARA rule error") ? translateYaraError(error.message) : { line: 0, text: G.translateError ? G.translateError(error.message) : error.message };
        status.replaceChildren(
          el("p", { class: "inline-error", role: "alert" }, translated.line ? `Linha ${translated.line}: ` : "", translated.text),
        );
        if (translated.line) focusLine(translated.line);
      }
    }

    async function remove() {
      if (!editing) return;
      const confirmed = await G.confirm({
        title: "Excluir conjunto de regras",
        message: `“${editing.name}” deixará de rodar nas próximas análises. Análises já feitas não mudam.`,
        confirmLabel: "Excluir",
        danger: true,
      });
      if (!confirmed) return;
      try {
        await api(`/api/intelligence/yara/${editing.id}`, { method: "DELETE" });
        toast("Conjunto excluído.");
        await load();
        fill(null);
      } catch (error) {
        toast(error.message, "error");
      }
    }

    async function toggle(item, value) {
      try {
        await api(`/api/intelligence/yara/${item.id}`, { method: "PATCH", body: JSON.stringify({ enabled: value }) });
        item.enabled = value;
        toast(value ? `“${item.name}” vai rodar nas próximas análises.` : `“${item.name}” foi pausado.`);
      } catch (error) {
        toast(error.message, "error");
        drawList();
      }
    }

    async function openRuleset(item) {
      try {
        fill(await api(`/api/intelligence/yara/${item.id}`));
      } catch (error) {
        toast(error.message, "error");
      }
    }

    function drawList() {
      listHost.replaceChildren(
        rulesets.length
          ? table({
              columns: [
                {
                  label: "CONJUNTO",
                  render: (row) =>
                    el(
                      "div",
                      { class: "cell-stack" },
                      el("strong", {}, row.name),
                      el("span", {}, row.description || row.rule_names.slice(0, 4).join(", ")),
                      el("span", {}, `Atualizado ${formatDate(row.updated_at)}`),
                    ),
                },
                { label: "REGRAS", className: "numeric-col", render: (row) => String(row.rule_count) },
                {
                  label: "ATIVO",
                  render: (row) =>
                    el("input", {
                      type: "checkbox",
                      checked: row.enabled,
                      "aria-label": `Rodar ${row.name} nas análises`,
                      onClick: (event) => event.stopPropagation(),
                      onChange: (event) => toggle(row, event.target.checked),
                    }),
                },
              ],
              rows: rulesets,
              onRowClick: (row) => openRuleset(row),
              rowClass: (row) => (editing && row.id === editing.id ? "is-selected" : ""),
            })
          : emptyState({
              icon: "▤",
              title: "Nenhum conjunto de regras",
              description: "Crie um conjunto ao lado. Os conjuntos ativos rodam em cada arquivo analisado.",
            }),
      );
    }

    async function load() {
      try {
        rulesets = (await api("/api/intelligence/yara")).items;
      } catch (error) {
        rulesets = [];
        toast(error.message, "error");
      }
      drawList();
    }

    source.addEventListener("keydown", (event) => {
      if (event.key === "Tab" && !event.shiftKey) {
        event.preventDefault();
        source.setRangeText("    ", source.selectionStart, source.selectionEnd, "end");
      }
      if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
        event.preventDefault();
        save();
      }
    });

    host.replaceChildren(
      el(
        "div",
        { class: "yara-layout" },
        panel(
          {
            eyebrow: "CONJUNTOS",
            title: "Regras do workspace",
            caption: "Clique para editar",
            actions: [button("Novo conjunto", () => fill(null))],
          },
          listHost,
        ),
        panel(
          { eyebrow: "EDITOR", title: "Novo conjunto de regras", className: "yara-editor" },
          el(
            "div",
            { class: "form-grid" },
            el("div", { class: "field" }, el("label", {}, "Nome"), name),
            el("div", { class: "field" }, el("label", {}, "Descrição"), description),
          ),
          el("div", { class: "field" }, el("label", {}, "Regras"), source),
          el(
            "label",
            { class: "switch-row", for: "yara-enabled" },
            enabled,
            el(
              "span",
              {},
              el("strong", {}, "Rodar nas próximas análises de arquivo"),
              el("small", {}, "Análises antigas não são reprocessadas: o arquivo original não fica guardado."),
            ),
          ),
          status,
          el(
            "div",
            { class: "toolbar-end yara-actions" },
            deleteButton,
            button("Validar", () => validate()),
            el("label", { class: "button button-secondary button-small", for: "yara-test-file" }, "Testar com arquivo…"),
            fileInput,
            button("Salvar", () => save(), { variant: "button-primary" }),
          ),
          testResult,
          el(
            "p",
            { class: "tool-limit" },
            "Subconjunto compatível com YARA, conferido com o YARA 4.5.5. Fora do escopo: módulos (pe, elf, math…), " +
              "base64 e saltos sem limite superior. Cada varredura roda em processo separado e para em 20 s. " +
              "Uma regra que bate descreve o padrão do autor; não é um veredito.",
          ),
        ),
      ),
    );
    heading = host.querySelector(".yara-editor .panel-heading h2");
    fill(null);
    await load();
  }

  G.renderYaraTab = renderYaraTab;
})();
