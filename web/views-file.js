"use strict";

/* File intelligence: bounded static analysis of analyst-supplied files. */

(function () {
  const G = window.GARBAGE;
  const {
    el, api, toast, pageHeader, panel, metric, badge, emptyState, table,
    loadingBlock, inlineError, formatDate, formatBytes, shortId, titleCase, go,
  } = G;

  const MAX_BYTES = 4 * 1024 * 1024;

  const FORMAT_PT = {
    pdf: "Documento PDF", zip: "Arquivo ZIP", docx: "Documento Word (OOXML)", xlsx: "Planilha Excel (OOXML)",
    pptx: "Apresentação PowerPoint (OOXML)", epub: "Publicação EPUB", jar: "Pacote Java", apk: "Pacote Android",
    gzip: "Fluxo GZIP", tar: "Arquivo TAR", "7z": "Arquivo 7-Zip", rar: "Arquivo RAR", json: "Documento JSON",
    xml: "Documento XML", html: "Documento HTML", text: "Texto simples", png: "Imagem PNG", jpeg: "Imagem JPEG",
    gif: "Imagem GIF", webp: "Imagem WebP", bmp: "Imagem BMP", elf: "Executável ELF", pe: "Executável PE",
    macho: "Executável Mach-O", ole: "Documento composto OLE", sqlite: "Banco SQLite", woff: "Fonte WOFF",
    woff2: "Fonte WOFF2", ttf: "Fonte TrueType", otf: "Fonte OpenType", unknown: "Binário não reconhecido",
    doc: "Documento Word 97-2003", xls: "Planilha Excel 97-2003", ppt: "Apresentação PowerPoint 97-2003",
    msg: "Mensagem do Outlook", msi: "Pacote do Windows Installer", lnk: "Atalho do Windows (LNK)",
    iso: "Imagem de disco ISO 9660", rtf: "Documento RTF",
  };
  const formatLabel = (analysis) => FORMAT_PT[analysis.format] || analysis.format_label;

  const SIGNATURE_PT = {
    zip: "Cabeçalho local ZIP", gzip: "Fluxo GZIP", bzip2: "Fluxo BZIP2", xz: "Fluxo XZ", "7z": "Arquivo 7-Zip",
    rar: "Arquivo RAR", zstd: "Quadro Zstandard", cab: "Gabinete Microsoft (CAB)", pe: "Executável PE",
    elf: "Executável ELF", macho: "Executável Mach-O", pdf: "Documento PDF", png: "Imagem PNG", jpeg: "Imagem JPEG",
    gif: "Imagem GIF", ole: "Arquivo composto OLE", sqlite: "Banco SQLite", squashfs: "Sistema de arquivos SquashFS",
    cpio: "Arquivo CPIO (newc)", tar: "Arquivo TAR", iso: "Imagem ISO 9660", uimage: "Imagem U-Boot",
    dex: "Bytecode Android (DEX)", "java-class": "Classe Java", "macho-fat": "Binário universal Mach-O",
    rtf: "Documento RTF", lnk: "Atalho do Windows", pem: "Bloco PEM", wasm: "Módulo WebAssembly",
  };
  const EXECUTABLE_SIGNATURES = new Set(["pe", "elf", "macho", "macho-fat", "dex", "java-class", "wasm"]);
  const PEM_PT = { certificate: "certificado", "private key": "chave privada", "public key": "chave pública", other: "outro" };

  function signatureDetail(item) {
    const detail = String(item.detail || "");
    if (item.kind === "pem") return PEM_PT[detail] || detail;
    return detail
      .replace(/^width: (\d+)$/, "largura $1 px")
      .replace(/^data bytes: (\d+)$/, "$1 bytes de dados")
      .replace(/^class file version (\d+)$/, "versão $1")
      .replace(/^(\d+) architecture\(s\)$/, "$1 arquitetura(s)")
      .replace(/^block size (\d+)k$/, "blocos de $1 KB")
      .replace(/^(\d+) local headers from here on$/, "$1 cabeçalhos locais a partir daqui");
  }

  const KEYWORD_PT = {
    process: "execução de processos", objects: "objetos COM", network: "rede", files: "arquivos",
    native: "chamadas nativas", obfuscation: "ofuscação", scripting: "interpretadores", environment: "ambiente",
  };
  const SIGNATURE_LABEL_PT = {
    "PE executable": "executável PE", "ELF executable": "executável ELF", "Mach-O executable": "executável Mach-O",
    "Mach-O universal binary": "binário universal Mach-O", "Android DEX bytecode": "bytecode DEX",
    "Java class file": "classe Java", "WebAssembly module": "módulo WebAssembly",
  };

  /* New findings carry details inside the sentence; rebuild them by code. */
  const FINDING_PT = {
    "vba-macros": (m) => `Projeto de macros VBA com ${m.match(/with (\d+)/)?.[1] ?? "?"} módulo(s); o código foi descomprimido só para leitura e não foi executado.`,
    "vba-autoexec": (m) => `As macros rodam sozinhas ao abrir ou fechar o documento: ${m.match(/through: (.+)\.$/)?.[1] ?? ""}.`,
    "vba-suspicious-keywords": (m) => {
      const list = (m.match(/associated with: (.+?)\. Keywords/)?.[1] || "").split(", ").map((key) => KEYWORD_PT[key] || key);
      return `O código das macros usa palavras-chave ligadas a: ${list.join(", ")}. Palavras-chave indicam capacidade, não comportamento.`;
    },
    "msi-custom-actions": () => "O instalador declara a tabela CustomAction; ações personalizadas podem rodar comandos ou binários embutidos durante a instalação.",
    "ole-embedded-objects": (m) => `Há ${m.match(/\((\d+)\)/)?.[1] ?? "?"} objeto(s) OLE embutido(s). Foram listados, não abertos.`,
    "lnk-command": (m) => `O destino ou os argumentos do atalho citam interpretador de scripts, baixador ou caminho remoto: ${m.match(/path: (.+)\.$/)?.[1] ?? ""}.`,
    "lnk-padded-arguments": () => "Os argumentos têm uma longa sequência de espaços, que esconde o comando real na janela de propriedades do Windows.",
    "lnk-tracker": () => "O atalho guarda o nome NetBIOS da máquina onde foi criado. Use como pista de investigação, não como atribuição.",
    "iso-executable-content": (m) => `A imagem contém executáveis ou scripts: ${m.match(/files: (.+?)\. Disc/)?.[1] ?? ""}. Imagens de disco são um meio comum de entregá-los sem a marca de download do Windows.`,
    "rtf-objects": (m) => {
      const found = m.match(/objects: (\d+) \(classes: (.+)\)\./);
      return found ? `Objetos OLE embutidos: ${found[1]} (classes: ${found[2] === "unnamed" ? "sem nome" : found[2]}). Foram decodificados para inspeção, não abertos.` : m;
    },
    "rtf-equation-editor": () => "Há um objeto do Editor de Equações, vetor de exploração frequente em RTF. A presença sozinha não prova um exploit.",
    "rtf-remote-template": () => "O documento aponta para um modelo remoto, que o Word pode baixar ao abrir.",
    "rtf-auto-update": () => "Há objetos configurados para atualizar sozinhos ou vinculados a uma fonte externa.",
    "rtf-dde": () => "Há um campo DDE; o DDE pode pedir ao Word que inicie outro programa.",
    "rtf-package": (m) => `Há arquivos empacotados no documento: ${m.match(/embedded: (.+)\.$/)?.[1] ?? ""}.`,
    "embedded-executable": (m) => {
      const found = m.match(/\((\d+); first: (.+) at offset (0x[0-9a-f]+)\)/);
      return found
        ? `Há cabeçalhos de executável dentro do arquivo (${found[1]}; o primeiro é ${SIGNATURE_LABEL_PT[found[2]] || found[2]} na posição ${found[3]}). Foram localizados, não extraídos.`
        : m;
    },
    "embedded-private-key": (m) => `Há bloco(s) PEM de chave privada (${m.match(/\((\d+)\)/)?.[1] ?? "?"}). Trate o arquivo como material sensível.`,
    "yara-match": (m) => {
      const found = m.match(/matched \((\d+)\): (.+?)\. A match/);
      return found ? `Regras YARA correspondentes (${found[1]}): ${found[2]}. Uma correspondência indica que os bytes seguem o padrão do autor da regra; não é um veredito.` : m;
    },
    "yara-error": (m) => `Alguns conjuntos de regras não terminaram: ${m.match(/finish: (.+)\.$/)?.[1] ?? ""}.`,
  };
  function translateFinding(finding, analysis) {
    if (finding.code === "extension-mismatch") {
      return `A extensão do nome do arquivo não corresponde à estrutura detectada (${formatLabel(analysis)}).`;
    }
    return FINDING_PT[finding.code] ? FINDING_PT[finding.code](String(finding.message)) : G.translateText(finding.message);
  }

  const ENGINE_PT = {
    "c-native": "motor C nativo",
    "rust-native": "motor Rust nativo",
    "python-fallback": "referência em Python",
    unavailable: "indisponível",
    "garbage-yara-subset": "motor YARA do GARBAGE",
  };
  const engineLabel = (engine) => ENGINE_PT[engine] || engine;
  const hex = (value) => `0x${Number(value).toString(16)}`;
  const yesNo = (value) => (value ? "Sim" : "Não");

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

  function fileToBase64(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onerror = () => reject(new Error("Não foi possível ler o arquivo selecionado."));
      reader.onload = () => {
        const result = String(reader.result || "");
        const comma = result.indexOf(",");
        resolve(comma >= 0 ? result.slice(comma + 1) : result);
      };
      reader.readAsDataURL(file);
    });
  }

  function flattenMetadata(value, prefix = "", pairs = []) {
    if (value === null || value === undefined || value === "") return pairs;
    if (Array.isArray(value)) {
      for (const item of value) {
        if (item && typeof item === "object" && "key" in item && "value" in item) {
          pairs.push([titleCase(item.key), String(item.value)]);
        } else if (typeof item !== "object") {
          pairs.push([prefix || "Valor", String(item)]);
        }
      }
      return pairs;
    }
    if (typeof value === "object") {
      for (const [key, item] of Object.entries(value)) {
        flattenMetadata(item, prefix ? `${prefix} · ${titleCase(key)}` : titleCase(key), pairs);
      }
      return pairs;
    }
    pairs.push([prefix || "Valor", String(value)]);
    return pairs;
  }

  const OLE_KIND_PT = {
    doc: "Documento Word 97-2003", xls: "Planilha Excel 97-2003", ppt: "Apresentação PowerPoint 97-2003",
    msg: "Mensagem do Outlook", msi: "Pacote do Windows Installer", ole: "Contêiner OLE genérico",
  };
  const PROPERTY_PT = {
    title: "Título", subject: "Assunto", author: "Autor", keywords: "Palavras-chave", comments: "Comentários",
    template: "Modelo", last_saved_by: "Salvo por último por", revision: "Revisão", last_printed: "Impresso em",
    created: "Criado em", last_saved: "Salvo em", pages: "Páginas", words: "Palavras", characters: "Caracteres",
    application: "Aplicativo", security: "Segurança", category: "Categoria", manager: "Gerente", company: "Empresa",
    product: "Produto", manufacturer: "Fabricante", platform_languages: "Plataforma e idiomas",
    package_code: "Código do pacote", installer_version: "Versão mínima do instalador", source_flags: "Opções de origem",
  };
  const LNK_BLOCK_PT = {
    tracker: "rastreio de origem", "environment-variables": "variáveis de ambiente", "known-folder": "pasta conhecida",
    "special-folder": "pasta especial", "property-store": "propriedades", "vista-id-list": "lista de IDs",
    "icon-environment": "ícone com variáveis", console: "console", "console-codepage": "página de código do console",
    darwin: "Darwin (MSI)", shim: "camada de compatibilidade",
  };
  const SHOW_PT = { normal: "normal", minimized: "minimizada", maximized: "maximizada" };
  const DRIVE_PT = { fixed: "disco fixo", removable: "removível", remote: "rede", cdrom: "CD/DVD", ramdisk: "RAM", unknown: "desconhecido", "no-root": "sem raiz" };

  function macroPanel(projects) {
    const modules = projects.flatMap((project) => project.modules.map((module) => ({ ...module, storage: project.storage })));
    return panel(
      {
        eyebrow: "MACROS VBA",
        title: `${modules.length} módulo(s) em ${projects.length} projeto(s)`,
        caption: "Código descomprimido só para leitura",
      },
      ...modules.map((module) =>
        el(
          "article",
          { class: "macro-module" },
          el(
            "header",
            { class: "macro-module-head" },
            el("code", {}, module.name || module.stream),
            el("span", { class: "muted-text" }, `${module.storage} · ${module.lines || 0} linha(s) · ${formatBytes(module.source_bytes || 0)}`),
            ...(module.autoexec || []).map((word) => badge(`Auto: ${word}`, "warning")),
            ...Object.keys(module.suspicious || {}).map((category) => badge(KEYWORD_PT[category] || category, "neutral")),
          ),
          module.error
            ? el("p", { class: "inline-error" }, `Não foi possível descomprimir: ${module.error}`)
            : el(
                "details",
                { class: "macro-source" },
                el("summary", {}, module.truncated ? "Ver código (primeiros 64 KB)" : "Ver código"),
                el("pre", { class: "code-block" }, module.source || "(vazio)"),
              ),
        ),
      ),
    );
  }

  function engineSections(analysis) {
    const sections = [];
    const structure = analysis.structure || {};

    const compound = structure.compound;
    if (compound) {
      const streams = compound.streams.filter((item) => !item.storage);
      sections.push(
        panel(
          {
            eyebrow: "CONTÊINER OLE",
            title: OLE_KIND_PT[compound.kind] || compound.kind,
            caption: `${compound.stream_count} fluxo(s)`,
          },
          G.kvList([
            ["CLSID raiz", compound.root_clsid ? el("code", {}, compound.root_clsid) : null],
            ["Versão do formato", String(compound.major_version)],
            ["Objetos OLE embutidos", compound.ole_objects.length ? String(compound.ole_objects.length) : null],
            ...(compound.kind === "msi"
              ? [
                  ["Tabelas", String(compound.msi_tables.length)],
                  ["Ações personalizadas", yesNo(compound.msi_custom_actions)],
                  ["Binários embutidos", String(compound.msi_binary_streams)],
                ]
              : []),
          ]),
          compound.kind === "msi" && compound.msi_tables.length
            ? el("div", { class: "chip-list" }, ...compound.msi_tables.map((name) => el("code", {}, name)))
            : null,
          el(
            "details",
            { class: "raw-details" },
            el("summary", {}, `Fluxos (${streams.length})`),
            table({
              columns: [
                { label: "CAMINHO", render: (row) => el("code", { class: "reference-code" }, row.path.replace(/[\x00-\x1f]/g, "·")) },
                { label: "TAMANHO", render: (row) => formatBytes(row.size_bytes || 0) },
                { label: "MODIFICADO", render: (row) => (row.modified ? formatDate(row.modified, { time: true }) : "—") },
              ],
              rows: streams.slice(0, 200),
            }),
          ),
        ),
      );
      const properties = { ...(compound.summary || {}), ...(compound.document_summary || {}) };
      if (Object.keys(properties).length) {
        sections.push(
          panel(
            { eyebrow: "PROPRIEDADES DO DOCUMENTO", title: "Informações de resumo" },
            G.kvList(
              Object.entries(properties).map(([key, value]) => [
                PROPERTY_PT[key] || key,
                ["created", "last_saved", "last_printed"].includes(key) ? formatDate(value, { time: true }) : String(value),
              ]),
            ),
          ),
        );
      }
    }
    const projects = compound?.vba || structure.vba || [];
    if (projects.length) sections.push(macroPanel(projects));

    const shortcut = structure.lnk;
    if (shortcut) {
      sections.push(
        panel(
          { eyebrow: "ATALHO DO WINDOWS", title: shortcut.local_base_path || shortcut.relative_path || "Destino não informado" },
          G.kvList([
            ["Argumentos", shortcut.arguments ? el("code", { class: "reference-code" }, shortcut.arguments.trim()) : null],
            ["Tamanho dos argumentos", shortcut.arguments ? `${shortcut.arguments_length} caracteres` : null],
            ["Diretório de trabalho", shortcut.working_dir],
            ["Caminho relativo", shortcut.relative_path],
            ["Compartilhamento de rede", shortcut.network_share],
            ["Ícone", shortcut.icon_location ? `${shortcut.icon_location} (#${shortcut.icon_index})` : null],
            ["Janela", SHOW_PT[shortcut.show_command] || shortcut.show_command],
            ["Destino criado", shortcut.target_created ? formatDate(shortcut.target_created, { time: true }) : null],
            ["Destino modificado", shortcut.target_modified ? formatDate(shortcut.target_modified, { time: true }) : null],
            ["Volume", shortcut.volume ? `${shortcut.volume.label || "sem rótulo"} · série ${shortcut.volume.serial} · ${DRIVE_PT[shortcut.volume.drive_type] || shortcut.volume.drive_type}` : null],
            ["Máquina de origem (NetBIOS)", shortcut.machine_id],
            ["MAC no identificador de rastreio", shortcut.droid_mac],
            ["Blocos extras", shortcut.extra_blocks.length ? shortcut.extra_blocks.map((block) => LNK_BLOCK_PT[block] || block).join(", ") : null],
          ]),
          shortcut.risky_command.length
            ? el("div", { class: "chip-list" }, ...shortcut.risky_command.map((word) => el("code", {}, word)))
            : null,
        ),
      );
    }

    const image = structure.iso;
    if (image) {
      sections.push(
        panel(
          { eyebrow: "IMAGEM ISO 9660", title: image.volume_id || "Volume sem nome", caption: image.joliet ? "Nomes Joliet" : "Nomes ISO 9660" },
          G.kvList([
            ["Publicador", image.publisher],
            ["Preparador", image.preparer],
            ["Aplicativo", image.application],
            ["Sistema", image.system_id],
            ["Criado em", image.created ? formatDate(image.created, { time: true }) : null],
            ["Tamanho declarado", formatBytes(image.declared_size_bytes)],
            ["Inicializável (El Torito)", yesNo(image.el_torito_boot)],
          ]),
          image.risky_entries.length
            ? el("div", {}, el("p", { class: "panel-note" }, "Executáveis e scripts na imagem:"), el("div", { class: "chip-list" }, ...image.risky_entries.map((path) => el("code", {}, path))))
            : null,
        ),
      );
    }

    const rtf = structure.rtf;
    if (rtf) {
      sections.push(
        panel(
          { eyebrow: "DOCUMENTO RTF", title: `${rtf.object_count} objeto(s) embutido(s)` },
          G.kvList([
            ["Cabeçalho padrão", yesNo(rtf.standard_header)],
            ["Atualização automática", yesNo(rtf.auto_update_objects)],
            ["Objetos vinculados", yesNo(rtf.linked_objects)],
            ["Blocos binários (\\bin)", String(rtf.binary_runs)],
            ["Classes", rtf.object_classes.length ? rtf.object_classes.join(", ") : null],
            ["Modelo remoto", rtf.remote_templates.length ? rtf.remote_templates.join(", ") : null],
          ]),
          rtf.objects.length
            ? table({
                columns: [
                  { label: "POSIÇÃO", render: (row) => el("code", {}, hex(row.offset)) },
                  { label: "CLASSE", render: (row) => row.class_name || "—" },
                  { label: "DADOS", render: (row) => formatBytes(row.data_bytes) },
                  {
                    label: "CONTEÚDO",
                    render: (row) =>
                      row.package_label
                        ? `Pacote: ${row.package_label}${row.package_source_path ? ` (${row.package_source_path})` : ""}`
                        : row.embedded_ole
                          ? `OLE interno: ${row.embedded_ole.streams.slice(0, 4).join(", ") || row.embedded_ole.kind}`
                          : row.truncated
                            ? "Cabeçalho truncado"
                            : "—",
                  },
                ],
                rows: rtf.objects,
              })
            : null,
          rtf.fields.length
            ? table({
                columns: [
                  { label: "CAMPO", render: (row) => badge(row.type, row.type.startsWith("DDE") ? "warning" : "neutral") },
                  { label: "ALVO", render: (row) => el("code", { class: "reference-code" }, row.target) },
                ],
                rows: rtf.fields,
              })
            : null,
        ),
      );
    }

    const embedded = analysis.embedded;
    if (embedded?.items?.length && (embedded.items.length > 1 || embedded.items[0].offset > 0)) {
      sections.push(
        panel(
          {
            eyebrow: "ASSINATURAS EMBUTIDAS",
            title: `${embedded.total} início(s) de formato`,
            caption: `${engineLabel(embedded.engine)}${embedded.truncated ? " · lista truncada" : ""}`,
          },
          table({
            columns: [
              { label: "POSIÇÃO", render: (row) => el("code", {}, hex(row.offset)) },
              {
                label: "FORMATO",
                render: (row) =>
                  el(
                    "span",
                    { class: "row-inline" },
                    SIGNATURE_PT[row.kind] || row.label,
                    EXECUTABLE_SIGNATURES.has(row.kind) && row.offset > 0 ? badge("Executável", "warning") : null,
                  ),
              },
              { label: "DETALHE", render: (row) => signatureDetail(row) || "—" },
            ],
            rows: embedded.items,
          }),
          el("p", { class: "tool-limit" }, "Cada linha marca onde outro formato parece começar. Nada foi recortado ou extraído."),
        ),
      );
    }

    const yara = analysis.yara;
    if (yara) {
      const hits = yara.rulesets.flatMap((set) => set.matches.map((match) => ({ match, set: set.ruleset })));
      const failed = yara.rulesets.filter((set) => set.error);
      sections.push(
        panel(
          {
            eyebrow: "REGRAS YARA",
            title: hits.length ? `${hits.length} regra(s) correspondente(s)` : "Nenhuma regra correspondeu",
            caption: `${yara.rulesets.length} conjunto(s) ativo(s)`,
            actions: [el("a", { class: "button button-secondary button-small", href: "#/files/yara" }, "Gerenciar regras")],
          },
          ...hits.map(({ match, set }) => G.yaraMatchCard(match, set)),
          ...failed.map((set) => el("p", { class: "inline-error" }, `${set.ruleset}: ${set.error}`)),
        ),
      );
    }
    return sections;
  }

  async function renderFiles(root, params = []) {
    let activeTab = params[0] === "yara" ? "yara" : "analysis";
    let investigations = [];
    let selectedFile = null;
    let analysis = null;
    let analyses = { items: [], total: 0 };
    let busy = false;

    try {
      investigations = await G.loadInvestigations();
    } catch (error) {
      // History and analysis still work without a case list.
    }

    const fileInput = el("input", {
      type: "file",
      "aria-label": "Arquivo para análise",
      onChange: (event) => {
        selectedFile = event.target.files?.[0] || null;
        updateSelection();
      },
    });
    const dropZone = el(
      "div",
      { class: "drop-zone", tabindex: "0" },
      el("span", { class: "drop-icon", "aria-hidden": "true" }, "▧"),
      el("strong", {}, "Escolha um arquivo ou solte-o aqui"),
      el("span", {}, "Máximo de 4 MiB. Somente inspeção estática: nada é executado ou extraído."),
      fileInput,
    );
    dropZone.addEventListener("dragover", (event) => {
      event.preventDefault();
      dropZone.classList.add("is-dragging");
    });
    dropZone.addEventListener("dragleave", () => dropZone.classList.remove("is-dragging"));
    dropZone.addEventListener("drop", (event) => {
      event.preventDefault();
      dropZone.classList.remove("is-dragging");
      const file = event.dataTransfer?.files?.[0];
      if (file) {
        selectedFile = file;
        updateSelection();
      }
    });

    const caseSelect = el(
      "select",
      { class: "input", "aria-label": "Associar a análise a uma investigação" },
      el("option", { value: "" }, "Somente histórico do workspace"),
      ...investigations.map((investigation) =>
        el("option", { value: investigation.id }, investigation.name),
      ),
    );
    const selectedLabel = el("p", { class: "file-selection" }, "Nenhum arquivo selecionado.");
    const analyzeButton = button("Analisar arquivo", () => analyse(), {
      variant: "button-primary",
      disabled: true,
    });

    function updateSelection() {
      if (!selectedFile) {
        selectedLabel.textContent = "Nenhum arquivo selecionado.";
        analyzeButton.disabled = true;
        return;
      }
      selectedLabel.replaceChildren(
        el("strong", {}, selectedFile.name),
        el("span", {}, `${formatBytes(selectedFile.size)} · ${selectedFile.type || "tipo desconhecido"}`),
      );
      analyzeButton.disabled = busy || selectedFile.size > MAX_BYTES;
      if (selectedFile.size > MAX_BYTES) {
        toast("O arquivo excede o limite de análise de 4 MiB.", "error");
      }
    }

    async function analyse() {
      if (!selectedFile || busy) return;
      if (selectedFile.size > MAX_BYTES) {
        toast("O arquivo excede o limite de análise de 4 MiB.", "error");
        return;
      }
      busy = true;
      analyzeButton.disabled = true;
      analyzeButton.textContent = "Analisando…";
      try {
        const content_base64 = await fileToBase64(selectedFile);
        analysis = await api("/api/intelligence/files", {
          method: "POST",
          body: JSON.stringify({
            filename: selectedFile.name,
            content_base64,
            ...(caseSelect.value ? { investigation_id: caseSelect.value } : {}),
          }),
        });
        toast(`Analisado: ${analysis.file_name} · ${formatLabel(analysis)}.`);
        await loadHistory();
        drawResult();
      } catch (error) {
        toast(error.message, "error");
      } finally {
        busy = false;
        analyzeButton.disabled = !selectedFile;
        analyzeButton.textContent = "Analisar arquivo";
      }
    }

    async function loadHistory() {
      try {
        analyses = await api("/api/intelligence/files?limit=50");
      } catch (error) {
        analyses = { items: [], total: 0 };
      }
      drawHistory();
    }

    async function openAnalysis(id) {
      try {
        analysis = await api(`/api/intelligence/files/${id}`);
        drawResult();
      } catch (error) {
        toast(error.message, "error");
      }
    }

    async function attachEvidence() {
      if (!analysis?.investigation_id) return;
      if (!selectedFile || selectedFile.size > MAX_BYTES) {
        toast("Selecione novamente o arquivo original para anexá-lo como evidência.", "error");
        return;
      }
      try {
        await api(`/api/investigations/${analysis.investigation_id}/evidence`, {
          method: "POST",
          body: JSON.stringify({
            title: analysis.file_name,
            evidence_type: "file",
            description:
              "Anexado pela Análise de arquivos após análise estática. O arquivo não foi executado.",
            source_reference: "note://file-intelligence",
            original_name: selectedFile.name,
            content_base64: await fileToBase64(selectedFile),
          }),
        });
        toast("Evidência adicionada com seu próprio registro de integridade SHA-256.");
      } catch (error) {
        toast(error.message, "error");
      }
    }

    const resultHost = el("div", { class: "file-result" });
    const similarHost = el("div");

    async function loadSimilar(current) {
      similarHost.replaceChildren();
      if (!current?.analysis_id || !(current.hashes.tlsh || current.hashes.ssdeep)) return;
      try {
        const result = await api(`/api/intelligence/files/${current.analysis_id}/similar`);
        if (analysis !== current) return;
        similarHost.replaceChildren(
          panel(
            {
              eyebrow: "SEMELHANÇA",
              title: result.items.length ? `Arquivos parecidos (${result.items.length})` : "Arquivos parecidos",
              caption: `${result.compared} análise(s) comparada(s) · TLSH ≤ ${result.thresholds.tlsh_max_distance} ou ssdeep > 0`,
            },
            result.items.length
              ? table({
                  columns: [
                    {
                      label: "ARQUIVO",
                      render: (row) =>
                        el("div", { class: "cell-stack" }, el("strong", {}, row.file_name), el("span", {}, FORMAT_PT[row.format] || row.format)),
                    },
                    {
                      label: "TLSH",
                      className: "numeric-col",
                      render: (row) => (row.exact ? badge("Cópia idêntica", "success") : row.tlsh_distance === null ? "—" : `distância ${row.tlsh_distance}`),
                    },
                    {
                      label: "SSDEEP",
                      className: "numeric-col",
                      render: (row) => (row.ssdeep_score === null ? "—" : `${row.ssdeep_score}/100`),
                    },
                    {
                      label: "CASO",
                      render: (row) =>
                        row.investigation_id
                          ? el("a", { class: "table-link", href: `#/investigations/${row.investigation_id}` }, row.investigation_name || shortId(row.investigation_id))
                          : "Workspace",
                    },
                    { label: "", render: (row) => button("Abrir", () => openAnalysis(row.id)) },
                  ],
                  rows: result.items,
                  onRowClick: (row) => openAnalysis(row.id),
                })
              : el("p", { class: "panel-empty" }, "Nenhuma análise anterior tem bytes parecidos com este arquivo."),
            el(
              "p",
              { class: "tool-limit" },
              "TLSH: quanto menor a distância, mais parecido (abaixo de 50 costuma indicar variante próxima). ssdeep: 0 a 100. Semelhança de bytes não indica mesma autoria nem mesmo propósito.",
            ),
          ),
        );
      } catch (error) {
        similarHost.replaceChildren();
      }
    }
    const historyHost = el("div");

    function drawResult() {
      if (!analysis) {
        resultHost.replaceChildren(
          emptyState({
            icon: "▧",
            title: "Nenhuma análise selecionada",
            description:
              "Escolha um arquivo autorizado dentro do limite. O GARBAGE identifica estrutura e metadados sem executá-lo ou descompactá-lo.",
          }),
        );
        return;
      }
      const findings = (analysis.findings || []).map((finding) =>
        el(
          "div",
          { class: `file-finding level-${finding.level}` },
          badge(titleCase(finding.level), finding.level === "warning" ? "warning" : finding.level === "note" ? "neutral" : "info"),
          el("span", {}, translateFinding(finding, analysis)),
        ),
      );
      const indicators = analysis.indicators || [];
      const structure = analysis.structure || {};
      const metadataPairs = flattenMetadata(analysis.metadata || {});
      const hashRows = G.kvList([
        ["SHA-256", el("code", { class: "hash" }, analysis.hashes.sha256)],
        ["SHA-1", el("code", { class: "hash" }, analysis.hashes.sha1)],
        ["MD5", el("code", { class: "hash" }, analysis.hashes.md5)],
        [
          "TLSH",
          analysis.hashes.tlsh
            ? el("code", { class: "hash" }, analysis.hashes.tlsh)
            : analysis.similarity_engine
              ? el("span", { class: "muted-text" }, analysis.similarity_engine === "unavailable" ? "Indisponível: arquivo grande sem o motor nativo" : "Sem digest: arquivo curto ou uniforme demais")
              : null,
        ],
        [
          "ssdeep",
          analysis.hashes.ssdeep
            ? el("code", { class: "hash" }, analysis.hashes.ssdeep)
            : analysis.similarity_engine === "unavailable"
              ? el("span", { class: "muted-text" }, "Indisponível: arquivo grande sem o motor nativo")
              : null,
        ],
        ["Assinatura (magic bytes)", el("code", {}, analysis.magic_hex)],
        ["Entropia", `${analysis.entropy} / 8`],
      ]);

      const sections = [];
      if (structure.entries?.length) {
        sections.push(
          panel(
            {
              eyebrow: "ESTRUTURA DO PACOTE",
              title: `Membros (${structure.entry_count})`,
              caption: "Somente listados; nunca extraídos",
            },
            table({
              columns: [
                { label: "NOME", render: (row) => el("code", { class: "reference-code" }, row.name) },
                { label: "TAMANHO", render: (row) => formatBytes(row.size_bytes) },
                {
                  label: "TAXA",
                  className: "numeric-col",
                  render: (row) => (row.ratio === null ? "—" : `${row.ratio}×`),
                },
                {
                  label: "SINALIZADORES",
                  render: (row) =>
                    el(
                      "div",
                      { class: "row-actions" },
                      row.path_traversal ? badge("Travessia de caminho", "warning") : null,
                      row.encrypted ? badge("Criptografado", "neutral") : null,
                    ),
                },
              ],
              rows: structure.entries,
              emptyMessage: "Nenhum membro.",
            }),
          ),
        );
      }
      if (structure.header) {
        const header = structure.header;
        sections.push(
          panel(
            { eyebrow: "CABEÇALHO BINÁRIO", title: formatLabel(analysis) },
            G.kvList(
              Object.entries(header)
                .filter(([, value]) => value !== "" && value !== null && !Array.isArray(value))
                .map(([key, value]) => [titleCase(key), String(value)]),
            ),
            header.segments?.length
              ? table({
                  columns: [
                    { label: "SEGMENTO", render: (row) => el("code", {}, row.name || "—") },
                    { label: "TAMANHO VM", render: (row) => formatBytes(row.vm_size || 0) },
                    { label: "TAMANHO NO ARQUIVO", render: (row) => formatBytes(row.file_size || 0) },
                  ],
                  rows: header.segments,
                })
              : null,
            header.architectures?.length
              ? table({
                  columns: [
                    { label: "ARQUITETURA", render: (row) => row.cpu },
                    { label: "DESLOCAMENTO", render: (row) => `0x${Number(row.offset).toString(16)}` },
                    { label: "TAMANHO", render: (row) => formatBytes(row.size) },
                  ],
                  rows: header.architectures,
                })
              : null,
          ),
        );
      }
      if (analysis.hardening?.checks?.length) {
        const hardening = analysis.hardening;
        const tone = (status) =>
          status === "enabled"
            ? "success"
            : status === "missing"
              ? "warning"
              : "neutral";
        sections.push(
          panel(
            {
              eyebrow: "PROTEÇÕES DO BINÁRIO",
              title: `${hardening.enabled_count} ativas · ${hardening.missing_count} não encontradas`,
              caption: `${hardening.detail} · ${hardening.engine}`,
            },
            el(
              "div",
              { class: "file-findings" },
              ...hardening.checks.map((check) =>
                el(
                  "div",
                  { class: "file-finding" },
                  badge(titleCase(check.status), tone(check.status)),
                  el(
                    "div",
                    {},
                    el("strong", {}, check.label),
                    el("p", { class: "panel-note" }, check.detail),
                  ),
                ),
              ),
            ),
            ...(hardening.limitations || []).map((limit) =>
              el("p", { class: "tool-limit" }, G.translateText(limit)),
            ),
          ),
        );
      }
      if (structure.sections?.length) {
        sections.push(
          panel(
            { eyebrow: "SEÇÕES", title: `${structure.sections.length} analisadas` },
            table({
              columns: [
                { label: "SEÇÃO", render: (row) => el("code", {}, row.name || "—") },
                { label: "TIPO", render: (row) => String(row.type) },
                { label: "DESLOCAMENTO", render: (row) => `0x${Number(row.offset).toString(16)}` },
                { label: "TAMANHO", render: (row) => formatBytes(row.size_bytes) },
              ],
              rows: structure.sections,
            }),
          ),
        );
      }
      if (structure.gzip) {
        sections.push(
          panel(
            { eyebrow: "FLUXO GZIP", title: "Prévia de descompressão limitada" },
            G.kvList(
              Object.entries(structure.gzip).map(([key, value]) => [
                titleCase(key),
                typeof value === "boolean" ? (value ? "Sim" : "Não") : String(value),
              ]),
            ),
            el(
              "p",
              { class: "panel-note" },
              "A prévia é limitada a 1 MiB e nunca é gravada em disco.",
            ),
          ),
        );
      }
      if (structure.image) {
        sections.push(
          panel(
            { eyebrow: "ESTRUTURA DA IMAGEM", title: "Dimensões" },
            G.kvList(Object.entries(structure.image).map(([key, value]) => [titleCase(key), String(value)])),
          ),
        );
      }
      if (structure.version || structure.approximate_page_count !== undefined) {
        sections.push(
          panel(
            { eyebrow: "ESTRUTURA DO PDF", title: "Dados do documento" },
            G.kvList(
              Object.entries(structure).map(([key, value]) => [titleCase(key), String(value)]),
            ),
          ),
        );
      }
      sections.push(...engineSections(analysis));
      if (analysis.imports?.length) {
        sections.push(
          panel(
            { eyebrow: "IMPORTAÇÕES ESTÁTICAS", title: `${analysis.imports.length} referenciadas` },
            el("div", { class: "chip-list" }, ...analysis.imports.map((item) => el("code", {}, item))),
          ),
        );
      }

      loadSimilar(analysis);
      resultHost.replaceChildren(
        el(
          "div",
          { class: "result-heading" },
          el(
            "div",
            {},
            el("p", { class: "eyebrow" }, "ANÁLISE ESTÁTICA"),
            el("h2", {}, analysis.file_name),
            el(
              "div",
              { class: "case-meta" },
              badge(formatLabel(analysis), "info"),
              badge(analysis.media_type, "neutral"),
              el("span", {}, formatBytes(analysis.size_bytes)),
              analysis.investigation_id
                ? el("a", { class: "table-link", href: `#/investigations/${analysis.investigation_id}` }, "Abrir caso")
                : el("span", {}, "Histórico do workspace"),
              el("span", {}, formatDate(analysis.created_at, { time: true })),
            ),
          ),
          el(
            "div",
            { class: "row-actions" },
            analysis.investigation_id
              ? button("Anexar como evidência", attachEvidence, { variant: "button-primary" })
              : null,
            button("Limpar", () => {
              analysis = null;
              drawResult();
            }),
          ),
        ),
        el(
          "div",
          { class: "metric-grid compact-metrics" },
          metric({
            label: "FORMATO",
            value: formatLabel(analysis),
            foot: analysis.media_type,
            icon: "▧",
            tone: "blue",
          }),
          metric({
            label: "TAMANHO",
            value: formatBytes(analysis.size_bytes),
            foot: `${analysis.strings.count} strings amostradas`,
            icon: "◫",
            tone: "violet",
          }),
          metric({
            label: "ENTROPIA",
            value: String(analysis.entropy),
            foot: "Bits por byte",
            icon: "◈",
            tone: analysis.entropy >= 7.2 ? "amber" : "green",
          }),
          metric({
            label: "INDICADORES",
            value: String(indicators.length),
            foot: "Correspondências sintáticas em strings",
            icon: "⌁",
            tone: "amber",
          }),
        ),
        panel({ eyebrow: "ACHADOS", title: "Observações estáticas" }, ...findings),
        el(
          "div",
          { class: "detail-grid" },
          panel(
            {
              eyebrow: "INTEGRIDADE",
              title: "Hashes",
              caption: analysis.similarity_engine ? `Hashes difusos: ${engineLabel(analysis.similarity_engine)}` : "",
            },
            hashRows,
          ),
          panel(
            { eyebrow: "METADADOS", title: "Propriedades extraídas" },
            metadataPairs.length
              ? G.kvList(metadataPairs.slice(0, 80))
              : el("p", { class: "panel-empty" }, "Nenhum metadado extraído."),
          ),
        ),
        ...sections,
        similarHost,
        panel(
          {
            eyebrow: "INDICADORES EMBUTIDOS",
            title: `Correspondências sintáticas (${indicators.length})`,
            caption: "Sem verificação de reputação",
          },
          indicators.length
            ? table({
                columns: [
                  { label: "TIPO", render: (row) => badge(G.indicatorTypeLabel(row.type), "info") },
                  { label: "VALOR", render: (row) => el("code", { class: "reference-code" }, row.value) },
                  {
                    label: "NOTA",
                    render: () => "Correspondência sintática nas strings ou no conteúdo decodificado; não é resultado de reputação.",
                  },
                ],
                rows: indicators,
              })
            : el("p", { class: "panel-empty" }, "Nenhum indicador corresponde às strings extraídas."),
        ),
        panel(
          {
            eyebrow: "STRINGS",
            title: `Amostra (${analysis.strings.count})`,
            caption: analysis.strings.truncated ? "truncado no limite" : "complete sample",
          },
          el(
            "pre",
            { class: "code-block strings-block" },
            analysis.strings.items
              .map((item) => `0x${item.offset.toString(16).padStart(6, "0")}  ${item.value}`)
              .join("\n") || "Nenhuma string imprimível.",
          ),
        ),
        panel(
          { eyebrow: "LIMITAÇÕES", title: "Limites analíticos" },
          el(
            "ul",
            { class: "plain-list" },
            ...analysis.limitations.map((limitation) => el("li", {}, G.translateText(limitation))),
          ),
        ),
        el(
          "details",
          { class: "raw-details" },
          el("summary", {}, "Estrutura bruta (JSON)"),
          el("pre", { class: "code-block" }, JSON.stringify(analysis.structure, null, 2)),
        ),
      );
    }

    function drawHistory() {
      historyHost.replaceChildren(
        panel(
          {
            eyebrow: "HISTÓRICO",
            title: "Registros de análise",
            caption: `${analyses.items.length} de ${analyses.total}`,
          },
          analyses.items.length
            ? table({
                columns: [
                  {
                    label: "ARQUIVO",
                    render: (row) =>
                      el(
                        "div",
                        { class: "cell-stack" },
                        el("strong", {}, row.file_name),
                        el("span", {}, row.format),
                      ),
                  },
                  { label: "TAMANHO", render: (row) => formatBytes(row.size_bytes) },
                  {
                    label: "SHA-256",
                    render: (row) => el("code", { class: "hash" }, row.sha256.slice(0, 16)),
                  },
                  {
                    label: "CASO",
                    render: (row) =>
                      row.investigation_id
                        ? el("a", { class: "table-link", href: `#/investigations/${row.investigation_id}` }, row.investigation_name || shortId(row.investigation_id))
                        : "Workspace",
                  },
                  { label: "ANÁLISE", render: (row) => formatDate(row.created_at) },
                  { label: "", render: (row) => button("Abrir", () => openAnalysis(row.id)) },
                ],
                rows: analyses.items,
                emptyMessage: "Nenhum arquivo foi analisado ainda.",
                onRowClick: (row) => openAnalysis(row.id),
              })
            : el("p", { class: "panel-empty" }, "Nenhum histórico ainda."),
        ),
      );
    }

    const tabStrip = el("div");
    const analysisHost = el("div");
    const yaraHost = el("div");

    function renderTabs() {
      tabStrip.replaceChildren(
        G.tabs({
          items: [
            { key: "analysis", label: "Análise" },
            { key: "yara", label: "Regras YARA" },
          ],
          active: activeTab,
          onSelect: (key) => {
            activeTab = key;
            history.replaceState(null, "", key === "yara" ? "#/files/yara" : "#/files");
            renderTabs();
          },
        }),
      );
      analysisHost.hidden = activeTab !== "analysis";
      yaraHost.hidden = activeTab !== "yara";
      if (activeTab === "yara" && !yaraHost.childElementCount) G.renderYaraTab(yaraHost);
    }

    analysisHost.append(
      el(
        "div",
        { class: "file-layout" },
        panel(
          { eyebrow: "ENTRADA", title: "Analisar um arquivo" },
          dropZone,
          selectedLabel,
          el(
            "div",
            { class: "field" },
            el("label", {}, "Associar a uma investigação (opcional)"),
            caseSelect,
          ),
          el("div", { class: "toolbar-end" }, analyzeButton),
        ),
        panel(
          { eyebrow: "ESCOPO", title: "O que é inspecionado" },
          el(
            "ul",
            { class: "plain-list" },
            el("li", {}, "PDF, ZIP/OOXML/EPUB/JAR/APK, TAR, GZIP e imagens: estrutura, metadados e sinais de conteúdo ativo."),
            el("li", {}, "ELF, PE e Mach-O: cabeçalhos, seções, importações e proteções do binário."),
            el("li", {}, "Office 97-2003, MSI e Outlook (OLE): fluxos, propriedades e macros VBA descomprimidas para leitura."),
            el("li", {}, "Atalhos LNK, imagens ISO 9660 e documentos RTF com objetos embutidos."),
            el("li", {}, "Hashes TLSH e ssdeep, assinaturas embutidas e regras YARA ativas do workspace."),
          ),
          el(
            "p",
            { class: "panel-note" },
            "Formatos fora da lista são identificados pela assinatura, sem presumir o conteúdo.",
          ),
        ),
      ),
      resultHost,
      historyHost,
    );

    root.append(
      pageHeader({
        eyebrow: "ANÁLISE DE ARQUIVOS",
        title: "Análise estática de arquivos",
        description:
          "Identifique formato, hashes, metadados, estrutura de pacotes, cabeçalhos binários e indicadores embutidos sem execução.",
        actions: [button("Atualizar histórico", () => loadHistory())],
      }),
      el(
        "div",
        { class: "notice" },
        "Nada é executado, emulado ou extraído automaticamente. A análise é limitada e somente leitura; " +
          "indicadores embutidos são correspondências sintáticas, não resultados de reputação.",
      ),
      tabStrip,
      analysisHost,
      yaraHost,
    );

    renderTabs();
    drawResult();
    await loadHistory();
  }

  G.views.files = renderFiles;
})();
