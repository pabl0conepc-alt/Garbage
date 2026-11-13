"use strict";

/* Shared dialogs, overview, investigation management and activity log. */

(function () {
  const G = window.GARBAGE;
  const {
    el, api, toast, confirm, formDialog, pageHeader, panel, metric, badge,
    statusBadge, emptyState, table, tabs, sectionHeading, kvList, loadingBlock,
    inlineError, formatDate, relativeTime, formatBytes, shortId, titleCase,
    entityTypeLabel, relationshipLabel, indicatorTypeLabel, go, state, moduleEnabled,
  } = G;

  /* ---------------------------------------------------------------- */
  /* Helpers                                                          */
  /* ---------------------------------------------------------------- */

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

  function selectOptions(pairs, selected) {
    return pairs.map((pair) =>
      el(
        "option",
        { value: pair[0], selected: String(pair[0]) === String(selected ?? "") },
        pair[1],
      ),
    );
  }

  function referenceNode(reference) {
    if (!reference) return el("span", { class: "muted" }, "—");
    if (/^https?:\/\//i.test(reference)) {
      return el(
        "a",
        {
          class: "reference-link",
          href: reference,
          target: "_blank",
          rel: "noopener noreferrer",
        },
        reference,
      );
    }
    return el("code", { class: "reference-code" }, reference);
  }

  function caseLink(investigationId, name) {
    return el(
      "a",
      { class: "table-link", href: `#/investigations/${investigationId}` },
      name || shortId(investigationId),
    );
  }

  function statCell(label, value, tone = "") {
    return el(
      "div",
      { class: "stat-cell" },
      el("span", {}, label),
      el("strong", { class: tone }, String(value)),
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

  /* ---------------------------------------------------------------- */
  /* Shared dialogs                                                   */
  /* ---------------------------------------------------------------- */

  G.entityDialog = async function entityDialog(initial = {}, options = {}) {
    const isEdit = Boolean(initial.id);
    await formDialog({
      eyebrow: isEdit ? "EDITAR ENTIDADE" : "NOVA ENTIDADE",
      title: isEdit ? "Atualizar registro da entidade" : "Registrar entidade",
      description:
        "Entidades são compartilhadas entre casos, o quadro de investigação e o grafo de relacionamentos.",
      fields: [
        {
          name: "entity_type",
          label: "Categoria",
          type: "select",
          options: G.ENTITY_TYPES,
          value: initial.entity_type || "domain",
        },
        {
          name: "name",
          label: "Nome de exibição",
          value: initial.name || "",
          placeholder: "Usa o identificador por padrão",
          maxlength: 300,
        },
        {
          name: "identifier",
          label: "Identificador",
          value: initial.identifier || "",
          placeholder: "Domínio, endereço, URL, nome de usuário, hash…",
          maxlength: 2000,
          hint: "Validado por categoria. Identificadores duplicados são rejeitados.",
        },
        {
          name: "description",
          label: "Descrição",
          type: "textarea",
          rows: 3,
          value: initial.description || "",
        },
        {
          name: "source_reference",
          label: "Referência da fonte",
          value: initial.source_reference || "",
          placeholder: "https://… or note://analyst",
        },
        {
          name: "collection_basis",
          label: "Base de coleta",
          type: "select",
          options: G.COLLECTION_BASES,
          value: initial.collection_basis || "user-provided",
        },
        {
          name: "confidence",
          label: "Confiança",
          type: "select",
          options: G.CONFIDENCE_LEVELS,
          value: initial.confidence || "unconfirmed",
        },
        {
          name: "verification_status",
          label: "Verificação",
          type: "select",
          options: G.VERIFICATION_STATUSES,
          value: initial.verification_status || "not-verified",
        },
      ],
      submitLabel: isEdit ? "Salvar alterações" : "Registrar entidade",
      onSubmit: async (values) => {
        const saved = isEdit
          ? await api(`/api/entities/${initial.id}`, {
              method: "PATCH",
              body: JSON.stringify(values),
            })
          : await api("/api/entities", {
              method: "POST",
              body: JSON.stringify(values),
            });
        toast(isEdit ? "Entidade atualizada." : "Entidade registrada.");
        if (options.onSaved) await options.onSaved(saved);
        else G.refreshView();
      },
    });
  };

  G.sourceDialog = async function sourceDialog(initial = {}, options = {}) {
    const isEdit = Boolean(initial.id);
    await formDialog({
      eyebrow: isEdit ? "EDITAR FONTE" : "NOVA FONTE",
      title: isEdit ? "Atualizar fonte" : "Registrar fonte",
      description: "Fontes preservam de onde veio a informação e quando ela foi consultada.",
      fields: [
        {
          name: "title",
          label: "Título",
          required: true,
          maxlength: 300,
          value: initial.title || "",
        },
        {
          name: "reference",
          label: "Referência",
          required: true,
          value: initial.reference || "",
          placeholder: "https://… or note://analyst",
          hint: "Somente referências http, https, file e note são aceitas.",
        },
        {
          name: "category",
          label: "Categoria",
          type: "select",
          options: G.SOURCE_CATEGORIES,
          value: initial.category || "website",
        },
        {
          name: "description",
          label: "Descrição",
          type: "textarea",
          rows: 3,
          value: initial.description || "",
        },
        {
          name: "accessed_at",
          label: "Acessada em",
          value: initial.accessed_at || "",
          placeholder: "ISO 8601; padrão: agora",
        },
        {
          name: "verification_status",
          label: "Verificação",
          type: "select",
          options: G.VERIFICATION_STATUSES,
          value: initial.verification_status || "not-verified",
        },
      ],
      submitLabel: isEdit ? "Salvar alterações" : "Registrar fonte",
      onSubmit: async (values) => {
        if (!values.accessed_at) delete values.accessed_at;
        const saved = isEdit
          ? await api(`/api/sources/${initial.id}`, {
              method: "PATCH",
              body: JSON.stringify(values),
            })
          : await api("/api/sources", {
              method: "POST",
              body: JSON.stringify(values),
            });
        toast(isEdit ? "Fonte atualizada." : "Fonte registrada.");
        if (options.onSaved) await options.onSaved(saved);
        else G.refreshView();
      },
    });
  };

  G.observationDialog = async function observationDialog(investigation, options = {}) {
    if (investigation.status !== "open") {
      toast("Reabra a investigação antes de registrar observações.", "error");
      return;
    }
    await formDialog({
      eyebrow: "REGISTRO DE EVIDÊNCIA",
      title: "Registrar observação",
      description: investigation.name,
      fields: [
        {
          name: "title",
          label: "Título da observação",
          required: true,
          maxlength: 300,
          placeholder: "Uma descrição concisa e factual",
        },
        {
          name: "content",
          label: "Detalhes",
          type: "textarea",
          rows: 5,
          required: true,
          placeholder: "O que foi observado? Preserve o contexto relevante.",
        },
        {
          name: "source_reference",
          label: "Referência da fonte",
          required: true,
          placeholder: "https://… or note://analyst",
        },
        {
          name: "collection_basis",
          label: "Base de coleta",
          type: "select",
          options: G.COLLECTION_BASES,
          value: "public",
        },
        {
          name: "observed_at",
          label: "Observada em",
          placeholder: "ISO 8601 com fuso horário; padrão: agora",
          hint: "Registre apenas informações que você está autorizado a acessar e usar.",
        },
      ],
      submitLabel: "Salvar observação",
      onSubmit: async (values) => {
        if (!values.observed_at) delete values.observed_at;
        await api(`/api/investigations/${investigation.id}/observations`, {
          method: "POST",
          body: JSON.stringify(values),
        });
        toast("Observação registrada.");
        if (options.onSaved) await options.onSaved();
        else G.refreshView();
      },
    });
  };

  G.evidenceDialog = async function evidenceDialog(investigationId = "", options = {}) {
    let caseId = investigationId;
    const fields = [];
    if (!caseId) {
      const investigations = await G.loadInvestigations();
      const open = investigations.filter((item) => item.status === "open");
      if (!open.length) {
        toast("Crie ou reabra uma investigação antes de adicionar evidências.", "error");
        return;
      }
      fields.push({
        name: "investigation_id",
        label: "Investigação",
        type: "select",
        required: true,
        options: open.map((item) => [item.id, item.name]),
        value: open[0].id,
      });
    }
    fields.push(
      {
        name: "title",
        label: "Título da evidência",
        required: true,
        maxlength: 300,
        placeholder: "ex.: Cabeçalho de página capturado",
      },
      {
        name: "evidence_type",
        label: "Tipo de evidência",
        type: "select",
        options: G.EVIDENCE_TYPES,
        value: "file",
      },
      {
        name: "description",
        label: "Descrição",
        type: "textarea",
        rows: 3,
        placeholder: "Contexto de aquisição e observações",
      },
      {
        name: "source_reference",
        label: "Referência da fonte",
        placeholder: "https://… or note://analyst",
      },
      {
        name: "original_name",
        label: "Nome original do arquivo",
        placeholder: "Opcional para registros apenas de referência",
      },
      {
        name: "file",
        label: "Arquivo",
        type: "file",
        accept: "",
        hint: "Máximo de 4 MiB. Os arquivos são armazenados com um nome interno gerado, recebem hash SHA-256 e nunca são executados.",
      },
      {
        name: "sha256",
        label: "SHA-256 conhecido",
        placeholder: "Opcional ao anexar um arquivo",
        maxlength: 64,
      },
    );
    await formDialog({
      eyebrow: "REGISTRO DE EVIDÊNCIA",
      title: "Adicionar evidência",
      description:
        "O original permanece intacto; o GARBAGE armazena uma cópia com hash e registra o contexto de aquisição.",
      fields,
      submitLabel: "Adicionar evidência",
      onSubmit: async (values) => {
        caseId = values.investigation_id || investigationId;
        const payload = {
          title: values.title,
          evidence_type: values.evidence_type,
          description: values.description,
          source_reference: values.source_reference,
          original_name: values.original_name,
          sha256: values.sha256,
        };
        delete payload.investigation_id;
        const file = values.file;
        if (file) {
          if (file.size > 4 * 1024 * 1024) {
            throw new Error("O arquivo de evidência excede o limite de 4 MiB.");
          }
          payload.content_base64 = await fileToBase64(file);
          payload.original_name = file.name;
          delete payload.sha256;
        }
        const record = await api(`/api/investigations/${caseId}/evidence`, {
          method: "POST",
          body: JSON.stringify(payload),
        });
        toast("Evidência adicionada e com hash calculado.");
        if (options.onSaved) await options.onSaved(record);
        else G.refreshView();
      },
    });
  };

  G.relationshipDialog = async function relationshipDialog({
    investigationId = "",
    entities = null,
    relationship = null,
    onSaved = null,
  } = {}) {
    const isEdit = Boolean(relationship?.id);
    let entityOptions = entities;
    if (!isEdit && !entityOptions) {
      const data = await api("/api/entities?limit=500");
      entityOptions = data.items;
    }
    if (!isEdit && (!entityOptions || entityOptions.length < 2)) {
      toast("Registre pelo menos duas entidades antes de registrar um relacionamento.", "error");
      return;
    }
    const fields = [];
    if (!isEdit) {
      fields.push(
        {
          name: "source_entity_id",
          label: "Entidade de origem",
          type: "select",
          options: entityOptions.map((entity) => [entity.id, entity.name]),
        },
        {
          name: "target_entity_id",
          label: "Entidade de destino",
          type: "select",
          options: entityOptions.map((entity) => [entity.id, entity.name]),
        },
      );
    }
    if (!isEdit && !investigationId) {
      const investigations = await G.loadInvestigations();
      fields.push({
        name: "investigation_id",
        label: "Contexto da investigação",
        type: "select",
        options: [["", "Nenhuma investigação"]].concat(
          investigations.map((item) => [item.id, item.name]),
        ),
      });
    }
    fields.push(
      {
        name: "relationship_type",
        label: "Tipo de relacionamento",
        type: "select",
        options: G.RELATIONSHIP_TYPES,
        value: relationship?.relationship_type || "associated-with",
      },
      {
        name: "description",
        label: "Descrição",
        type: "textarea",
        rows: 2,
        value: relationship?.description || "",
      },
      {
        name: "source_reference",
        label: "Referência da fonte",
        value: relationship?.source_reference || "",
      },
      {
        name: "confidence",
        label: "Confiança",
        type: "select",
        options: G.CONFIDENCE_LEVELS,
        value: relationship?.confidence || "unconfirmed",
      },
      {
        name: "verification_status",
        label: "Verificação",
        type: "select",
        options: G.VERIFICATION_STATUSES,
        value: relationship?.verification_status || "not-verified",
      },
    );
    await formDialog({
      eyebrow: isEdit ? "EDITAR RELACIONAMENTO" : "RELACIONAMENTOS",
      title: isEdit ? "Atualizar relacionamento" : "Registrar relacionamento",
      description:
        "Relacionamentos são registros compartilhados. Vínculos observados permanecem distintos de fatos verificados.",
      fields,
      submitLabel: isEdit ? "Salvar alterações" : "Registrar relacionamento",
      onSubmit: async (values) => {
        if (
          !isEdit &&
          values.source_entity_id === values.target_entity_id
        ) {
          throw new Error("Um relacionamento exige duas entidades diferentes.");
        }
        if (!isEdit && !investigationId && !values.investigation_id) {
          delete values.investigation_id;
        }
        const saved = isEdit
          ? await api(`/api/relationships/${relationship.id}`, {
              method: "PATCH",
              body: JSON.stringify(values),
            })
          : await api("/api/relationships", {
              method: "POST",
              body: JSON.stringify({
                ...values,
                ...(investigationId ? { investigation_id: investigationId } : {}),
              }),
            });
        toast(isEdit ? "Relacionamento atualizado." : "Relacionamento registrado.");
        if (onSaved) await onSaved(saved);
        else G.refreshView();
      },
    });
  };

  G.linkEntityDialog = async function linkEntityDialog(
    investigation,
    linkedIds = [],
    onSaved = null,
  ) {
    const data = await api("/api/entities?limit=500");
    const available = data.items.filter((entity) => !linkedIds.includes(entity.id));
    if (!available.length) {
      toast("Não há entidades desvinculadas disponíveis. Registre uma nova entidade primeiro.", "error");
      return;
    }
    await formDialog({
      eyebrow: "VINCULAR REGISTRO",
      title: "Vincular entidade à investigação",
      description: investigation.name,
      fields: [
        {
          name: "entity_id",
          label: "Entidade",
          type: "select",
          options: available.map((entity) => [
            entity.id,
            `${entity.name} · ${entityTypeLabel(entity.entity_type)}`,
          ]),
        },
      ],
      submitLabel: "Vincular entidade",
      onSubmit: async (values) => {
        await api(`/api/investigations/${investigation.id}/entities`, {
          method: "POST",
          body: JSON.stringify({ entity_id: values.entity_id }),
        });
        toast("Entidade vinculada.");
        if (onSaved) await onSaved();
        else G.refreshView();
      },
    });
  };

  G.linkSourceDialog = async function linkSourceDialog(
    investigation,
    linkedIds = [],
    onSaved = null,
  ) {
    const data = await api("/api/sources?limit=500");
    const available = data.items.filter((source) => !linkedIds.includes(source.id));
    if (!available.length) {
      toast("Não há fontes desvinculadas disponíveis. Registre uma fonte primeiro.", "error");
      return;
    }
    await formDialog({
      eyebrow: "VINCULAR FONTE",
      title: "Vincular fonte à investigação",
      description: investigation.name,
      fields: [
        {
          name: "source_id",
          label: "Fonte",
          type: "select",
          options: available.map((source) => [source.id, source.title]),
        },
      ],
      submitLabel: "Vincular fonte",
      onSubmit: async (values) => {
        await api(`/api/investigations/${investigation.id}/sources`, {
          method: "POST",
          body: JSON.stringify({ source_id: values.source_id }),
        });
        toast("Fonte vinculada.");
        if (onSaved) await onSaved();
        else G.refreshView();
      },
    });
  };

  G.investigationEditDialog = async function investigationEditDialog(investigation) {
    await formDialog({
      eyebrow: "EDITAR CASO",
      title: "Atualizar investigação",
      fields: [
        {
          name: "name",
          label: "Nome da investigação",
          required: true,
          maxlength: 200,
          value: investigation.name,
        },
        {
          name: "description",
          label: "Descrição",
          type: "textarea",
          rows: 4,
          value: investigation.description || "",
        },
        {
          name: "status",
          label: "Status",
          type: "select",
          options: [
            ["open", "Aberta"],
            ["closed", "Fechada"],
            ["cancelled", "Cancelada"],
          ],
          value: investigation.status,
        },
      ],
      submitLabel: "Salvar caso",
      onSubmit: async (values) => {
        await api(`/api/investigations/${investigation.id}`, {
          method: "PATCH",
          body: JSON.stringify(values),
        });
        G.invalidateInvestigations();
        toast("Investigação atualizada.");
        G.refreshView();
      },
    });
  };

  G.deleteInvestigation = async function deleteInvestigation(investigation) {
    const approved = await confirm({
      title: "Excluir investigação",
      message:
        `Excluir "${investigation.name}"? Entidades e fontes compartilhadas são preservadas. ` +
        "Registros próprios do caso só podem ser removidos com uma segunda confirmação.",
      confirmLabel: "Excluir caso",
      danger: true,
    });
    if (!approved) return false;
    try {
      await api(`/api/investigations/${investigation.id}`, { method: "DELETE" });
    } catch (error) {
      if (error.status !== 409) throw error;
      const forced = await confirm({
        title: "Excluir o caso e seus registros próprios",
        message:
          `${error.message}\n\nIsto exclui permanentemente as observações do caso, ` +
          "os arquivos de evidência armazenados, o quadro e os relacionamentos do caso. Entidades " +
          "e fontes compartilhadas nunca são excluídas.",
        confirmLabel: "Excluir registros próprios",
        danger: true,
      });
      if (!forced) return false;
      await api(`/api/investigations/${investigation.id}?force=true`, {
        method: "DELETE",
      });
    }
    G.invalidateInvestigations();
    toast("Investigação excluída.");
    go("investigations");
    return true;
  };

  G.deleteEntity = async function deleteEntity(entity, onDeleted = null) {
    const approved = await confirm({
      title: "Excluir entidade",
      message: `Excluir "${entity.name}" do registro compartilhado?`,
      confirmLabel: "Excluir entidade",
      danger: true,
    });
    if (!approved) return false;
    try {
      await api(`/api/entities/${entity.id}`, { method: "DELETE" });
    } catch (error) {
      if (error.status !== 409) throw error;
      const forced = await confirm({
        title: "Excluir entidade e relacionamentos",
        message: `${error.message}\n\nIsto também remove a entidade do grafo e do quadro.`,
        confirmLabel: "Excluir com relacionamentos",
        danger: true,
      });
      if (!forced) return false;
      await api(`/api/entities/${entity.id}?force=true`, { method: "DELETE" });
    }
    toast("Entidade excluída.");
    if (onDeleted) await onDeleted();
    else go("entities");
    return true;
  };

  G.referenceNode = referenceNode;
  G.renderActivityFeed = renderActivityFeed;

  /* ---------------------------------------------------------------- */
  /* Activity feed                                                    */
  /* ---------------------------------------------------------------- */

  const ACTION_ICONS = {
    create: "plus",
    update: "note",
    status: "clock",
    observation: "evidence",
    evidence: "evidence",
    link: "sources",
    unlink: "ban",
    delete: "close",
    board: "board",
    assessment: "indicators",
    verify: "check",
    settings: "settings",
    module: "modules",
    import: "upload",
  };

  function renderActivityFeed(items, options = {}) {
    const feed = el("div", { class: "activity-feed" });
    if (!items.length) {
      feed.append(
        el(
          "p",
          { class: "panel-empty" },
          options.emptyMessage || "Nenhuma atividade foi registrada ainda.",
        ),
      );
      return feed;
    }
    for (const item of items) {
      const body = el(
        "div",
        { class: "activity-body" },
        el(
          "div",
          { class: "activity-line" },
          el("strong", {}, G.translateActivity(item.summary)),
          item.investigation_id
            ? caseLink(item.investigation_id, item.investigation_name || "Caso")
            : null,
        ),
        el(
          "div",
          { class: "activity-meta" },
          badge(titleCase(item.action), "neutral"),
          el("span", {}, item.actor && item.actor !== "analyst" ? item.actor : "analista"),
          el("span", {}, relativeTime(item.created_at)),
          el("time", { datetime: item.created_at, title: formatDate(item.created_at, { time: true }) }, ""),
        ),
      );
      feed.append(
        el(
          "article",
          { class: "activity-item" },
          el(
            "span",
            { class: `activity-marker action-${item.action}`, "aria-hidden": "true" },
            G.icon(ACTION_ICONS[item.action] || "dot", { size: 14 }),
          ),
          body,
        ),
      );
    }
    return feed;
  }

  /* ---------------------------------------------------------------- */
  /* Overview                                                         */
  /* ---------------------------------------------------------------- */

  async function renderOverview(root) {
    const data = await api("/api/overview");
    const totals = data.totals;
    const actions = [
      button("Atualizar", () => G.refreshView()),
    ];
    root.append(
      pageHeader({
        eyebrow: "VISÃO GERAL",
        title: "Situação do workspace",
        description:
          "Casos, entidades compartilhadas, evidências com hash e indicadores extraídos neste workspace local.",
        actions,
      }),
      el(
        "div",
        { class: "quick-actions" },
        button("Registrar entidade", () => G.entityDialog()),
        button("Registrar fonte", () => G.sourceDialog()),
        button("Abrir quadro", () => go("board")),
        button("Analisar indicadores", () => go("indicators")),
        button("Ver evidências", () => go("evidence")),
      ),
      el(
        "div",
        { class: "metric-grid" },
        metric({
          label: "INVESTIGAÇÕES ABERTAS",
          value: totals.open.toLocaleString("pt-BR"),
          foot: `${totals.investigations} no total · ${totals.closed} fechadas`,
          icon: "⌕",
          tone: "blue",
        }),
        metric({
          label: "ENTIDADES COMPARTILHADAS",
          value: totals.entities.toLocaleString("pt-BR"),
          foot: `${totals.relationships.toLocaleString("pt-BR")} relacionamentos`,
          icon: "⬡",
          tone: "violet",
        }),
        metric({
          label: "REGISTROS DE EVIDÊNCIA",
          value: totals.evidence.toLocaleString("pt-BR"),
          foot: "SHA-256 preservado",
          icon: "▣",
          tone: "green",
        }),
        metric({
          label: "INDICADORES ÚNICOS",
          value: totals.unique_indicators.toLocaleString("pt-BR"),
          foot: `${totals.indicator_origins.toLocaleString("pt-BR")} ocorrências em observações`,
          icon: "⌁",
          tone: "amber",
        }),
        metric({
          label: "OBSERVAÇÕES",
          value: totals.observations.toLocaleString("pt-BR"),
          foot: "Proveniência mantida",
          icon: "▤",
          tone: "blue",
        }),
        metric({
          label: "CORRELAÇÕES EXATAS",
          value: totals.correlations.toLocaleString("pt-BR"),
          foot: "Valores compartilhados entre observações",
          icon: "⟷",
          tone: "violet",
        }),
      ),
    );

    if (totals.investigations === 0) {
      root.append(
        panel(
          { eyebrow: "COMECE AQUI", title: "Monte o primeiro caso" },
          el(
            "div",
            { class: "onboarding" },
            el("p", {}, "Uma investigação integrada avança por registros compartilhados:"),
            el(
              "ol",
              { class: "step-list" },
              el("li", {}, "Crie uma investigação e defina seu escopo."),
              el("li", {}, "Registre entidades e vincule-as ao caso."),
              el("li", {}, "Registre observações, fontes e evidências com hash."),
              el("li", {}, "Registre relacionamentos e organize o quadro de investigação."),
              el("li", {}, "Exporte um relatório a partir dos registros reais."),
            ),
            button("Criar a primeira investigação", () => G.newInvestigation(), {
              variant: "button-primary",
            }),
          ),
        ),
      );
    }

    const recentRows = data.recent_investigations || [];
    root.append(
      el(
        "div",
        { class: "dashboard-grid" },
        panel(
          {
            eyebrow: "ATIVIDADE DOS CASOS",
            title: "Atividade recente",
            caption: "Mais recentes primeiro",
            actions: [button("Abrir linha do tempo", () => go("activity"))],
          },
          renderActivityFeed(data.recent_activity || [], {
            emptyMessage:
              "A atividade aparece aqui depois que casos, entidades e evidências são registrados.",
          }),
        ),
        panel(
          {
            eyebrow: "CASOS",
            title: "Investigações recentes",
            actions: [button("Todos os casos", () => go("investigations"))],
          },
          table({
            columns: [
              {
                label: "CASO",
                render: (row) =>
                  el(
                    "div",
                    { class: "cell-stack" },
                    el("strong", {}, row.name),
                    el("span", { class: "mono" }, shortId(row.id)),
                  ),
              },
              { label: "STATUS", render: (row) => statusBadge(row.status) },
              {
                label: "OBS.",
                className: "numeric-col",
                render: (row) => String(row.observation_count),
              },
              {
                label: "ENT.",
                className: "numeric-col",
                render: (row) => String(row.entity_count),
              },
              {
                label: "EVID.",
                className: "numeric-col",
                render: (row) => String(row.evidence_count),
              },
              {
                label: "",
                render: (row) => button("Abrir", () => go("investigations", row.id)),
              },
            ],
            rows: recentRows,
            emptyMessage: "Nenhuma investigação ainda.",
            onRowClick: (row) => go("investigations", row.id),
          }),
        ),
      ),
      el(
        "div",
        { class: "dashboard-grid" },
        panel(
          {
            eyebrow: "ARTEFATOS OBSERVADOS",
            title: "Distribuição de indicadores",
            caption: `${totals.unique_indicators} únicos`,
          },
          indicatorMix(data.indicator_mix || {}, totals.unique_indicators),
        ),
        panel(
          {
            eyebrow: "PROVENIÊNCIA DAS EVIDÊNCIAS",
            title: "Base de coleta",
            caption: `${totals.observations} observações`,
          },
          collectionBasis(data.collection_basis || {}, totals.observations),
        ),
        panel(
          {
            eyebrow: "SISTEMA",
            title: "Status dos módulos",
            actions: [button("Gerenciar módulos", () => go("modules"))],
          },
          moduleSummary(data.modules || {}),
        ),
      ),
    );
  }

  function barProgress(percent, toneClass, label) {
    const value = Math.max(0, Math.min(100, Math.round(percent)));
    return el("progress", {
      class: `bar-progress ${toneClass}`,
      max: "100",
      value: String(value),
      "aria-label": `${label}: ${value}%`,
    });
  }

  function indicatorMix(counts, total) {
    const keys = Object.keys(counts);
    if (!keys.length) {
      return el(
        "p",
        { class: "panel-empty" },
        total === 0
          ? "Indicadores aparecem quando padrões são encontrados em observações ou entidades registradas."
          : "Nenhuma distribuição de indicadores disponível.",
      );
    }
    const container = el("div", { class: "bar-list" });
    const max = Math.max(...Object.values(counts), 1);
    for (const key of keys.sort((a, b) => counts[b] - counts[a])) {
      container.append(
        el(
          "div",
          { class: "bar-row" },
          el(
            "div",
            { class: "bar-row-heading" },
            el("span", {}, G.indicatorTypeLabel(key)),
            el("strong", {}, counts[key].toLocaleString("pt-BR")),
          ),
          el(
            "div",
            { class: "bar-track" },
            barProgress(
              counts[key] ? Math.max(4, (counts[key] / max) * 100) : 0,
              `tone-${key}`,
              G.indicatorTypeLabel(key),
            ),
          ),
        ),
      );
    }
    return container;
  }

  function collectionBasis(counts, total) {
    const container = el("div", { class: "bar-list" });
    for (const [key, label] of G.COLLECTION_BASES) {
      const count = counts[key] || 0;
      container.append(
        el(
          "div",
          { class: "bar-row" },
          el(
            "div",
            { class: "bar-row-heading" },
            el("span", {}, label),
            el("strong", {}, String(count)),
          ),
          el(
            "div",
            { class: "bar-track" },
            barProgress(total && count ? Math.max(3, (count / total) * 100) : 0, `basis-${key}`, label),
          ),
        ),
      );
    }
    container.append(
      el(
        "div",
        { class: "bar-total" },
        el("span", {}, "Total de observações com fonte"),
        el("strong", {}, String(total)),
      ),
    );
    return container;
  }

  function moduleSummary(counts) {
    const enabled = counts.enabled || 0;
    const planned = counts.planned || 0;
    const disabled = counts.disabled || 0;
    return el(
      "div",
      { class: "module-summary" },
      el("div", { class: "module-summary-row" }, badge("Ativados", "success"), String(enabled)),
      el("div", { class: "module-summary-row" }, badge("Disponíveis", "neutral"), String(disabled)),
      el("div", { class: "module-summary-row" }, badge("Planejados", "warning"), String(planned)),
      el(
        "p",
        { class: "panel-note" },
        "Módulos planejados aparecem como não implementados e não podem ser ativados.",
      ),
    );
  }

  /* ---------------------------------------------------------------- */
  /* Investigations                                                   */
  /* ---------------------------------------------------------------- */

  async function renderInvestigations(root, params) {
    if (params[0]) return renderCaseFile(root, params[0]);
    const investigations = await G.loadInvestigations(true);
    const search = el("input", {
      class: "input",
      type: "search",
      placeholder: "Pesquisar casos, descrições ou status",
      "aria-label": "Pesquisar investigações",
    });
    const statusFilter = el(
      "select",
      { class: "input compact-select", "aria-label": "Filtrar por status" },
      el("option", { value: "" }, "Todos os status"),
      el("option", { value: "open" }, "Abertas"),
      el("option", { value: "closed" }, "Fechadas"),
      el("option", { value: "cancelled" }, "Canceladas"),
    );
    const sortSelect = el(
      "select",
      { class: "input compact-select", "aria-label": "Ordenar investigações" },
      el("option", { value: "updated" }, "Atualizadas recentemente"),
      el("option", { value: "created" }, "Criadas recentemente"),
      el("option", { value: "name" }, "Nome"),
    );
    const countLabel = el("span", { class: "panel-caption" });
    const host = el("div");

    function drawTable() {
      const query = search.value.trim().toLowerCase();
      const status = statusFilter.value;
      let rows = investigations.filter((item) => {
        if (status && item.status !== status) return false;
        return `${item.name} ${item.description} ${item.status}`
          .toLowerCase()
          .includes(query);
      });
      if (sortSelect.value === "created") {
        rows = rows.sort((a, b) => b.created_at.localeCompare(a.created_at));
      } else if (sortSelect.value === "name") {
        rows = rows.sort((a, b) => a.name.localeCompare(b.name));
      } else {
        rows = rows.sort((a, b) => b.updated_at.localeCompare(a.updated_at));
      }
      countLabel.textContent = `${rows.length} de ${investigations.length} investigações`;
      host.replaceChildren(
        table({
          columns: [
            {
              label: "INVESTIGAÇÃO",
              render: (row) =>
                el(
                  "div",
                  { class: "cell-stack" },
                  el("strong", {}, row.name),
                  el("span", {}, row.description || "Nenhuma descrição registrada"),
                  el("span", { class: "mono" }, shortId(row.id)),
                ),
            },
            { label: "STATUS", render: (row) => statusBadge(row.status) },
            {
              label: "ATUALIZAÇÃO",
              render: (row) =>
                el("span", { title: formatDate(row.updated_at, { time: true }) }, relativeTime(row.updated_at)),
            },
            {
              label: "OBS.",
              className: "numeric-col",
              render: (row) => String(row.observation_count),
            },
            {
              label: "ENT.",
              className: "numeric-col",
              render: (row) => String(row.entity_count),
            },
            {
              label: "EVID.",
              className: "numeric-col",
              render: (row) => String(row.evidence_count),
            },
            {
              label: "",
              render: (row) => button("Abrir caso", () => go("investigations", row.id)),
            },
          ],
          rows,
          emptyMessage: investigations.length
            ? "Nenhuma investigação corresponde a estes filtros."
            : "Nenhuma investigação foi criada.",
          onRowClick: (row) => go("investigations", row.id),
        }),
      );
    }

    root.append(
      pageHeader({
        eyebrow: "GESTÃO DE CASOS",
        title: "Investigações",
        description:
          "Todos os casos compartilham o mesmo registro de entidades, armazenamento de evidências e relacionamentos.",
      }),
      panel(
        {
          eyebrow: "CASOS",
          title: "Índice de casos",
          actions: [countLabel],
          className: "table-panel",
        },
        el(
          "div",
          { class: "toolbar" },
          el("div", { class: "search-field" }, el("span", { class: "search-field-icon" }, G.icon("search", { size: 14 })), search),
          statusFilter,
          sortSelect,
        ),
        investigations.length === 0
          ? emptyState({
              icon: "⌕",
              title: "Nenhuma investigação ainda",
              description: "Crie um caso para começar a montar um registro de evidências com fontes.",
              action: button("Criar investigação", () => G.newInvestigation(), {
                variant: "button-primary",
              }),
            })
          : host,
      ),
    );
    if (investigations.length) {
      drawTable();
      search.addEventListener("input", drawTable);
      statusFilter.addEventListener("change", drawTable);
      sortSelect.addEventListener("change", drawTable);
    }
  }

  /* ---------------------------------------------------------------- */
  /* Case file                                                        */
  /* ---------------------------------------------------------------- */

  async function renderCaseFile(root, investigationId) {
    if (G.state.caseId !== investigationId) {
      G.state.caseId = investigationId;
      G.state.caseTab = "overview";
    }
    let activeTab = G.state.caseTab || "overview";
    let report = null;
    let coverage = null;

    async function load() {
      [report, coverage] = await Promise.all([
        api(`/api/investigations/${investigationId}/report`),
        api(`/api/investigations/${investigationId}/coverage`),
      ]);
    }

    async function draw() {
      G.setLoading(true);
      root.replaceChildren(loadingBlock("Carregando caso…"));
      try {
        await load();
      } catch (error) {
        root.replaceChildren(
          errorState({
            title: "Caso indisponível",
            message: error.message,
            retry: () => draw(),
          }),
        );
        G.setLoading(false);
        return;
      }
      G.setLoading(false);
      const investigation = report.investigation;
      const header = pageHeader({
        eyebrow: "CASO",
        title: investigation.name,
        description: investigation.description || "Nenhuma descrição registrada.",
        actions: [
          button("‹ Todos os casos", () => go("investigations")),
          button("Editar caso", () => G.investigationEditDialog(investigation)),
          button(
            investigation.status === "open" ? "Fechar caso" : "Reabrir caso",
            async () => {
              try {
                await api(`/api/investigations/${investigation.id}`, {
                  method: "PATCH",
                  body: JSON.stringify({
                    status: investigation.status === "open" ? "closed" : "open",
                  }),
                });
                toast(
                  investigation.status === "open"
                    ? "Caso fechado; as evidências ficam bloqueadas até a reabertura."
                    : "Caso reaberto.",
                );
                await draw();
              } catch (error) {
                toast(error.message, "error");
              }
            },
          ),
          button("Quadro", () => go("board", investigation.id)),
          button("Grafo", () => go("graph", investigation.id)),
          el(
            "a",
            {
              class: "button button-secondary button-small",
              href: `/reports/${investigation.id}`,
              target: "_blank",
              rel: "noopener",
            },
            "Imprimir relatório",
          ),
          button("Excluir", () => G.deleteInvestigation(investigation), {
            variant: "button-danger",
          }),
        ],
      });
      const meta = el(
        "div",
        { class: "case-meta" },
        statusBadge(investigation.status),
        el("code", {}, investigation.id),
        el("span", {}, `Criada em ${formatDate(investigation.created_at)}`),
        el("span", {}, `Atualizada ${relativeTime(investigation.updated_at)}`),
      );
      const tabBar = tabs({
        items: [
          { key: "overview", label: "Visão geral" },
          { key: "entities", label: "Entidades", count: report.entities.length },
          { key: "evidence", label: "Evidências", count: report.evidence.length },
          { key: "sources", label: "Fontes", count: report.sources.length },
          {
            key: "relationships",
            label: "Relacionamentos",
            count: report.relationships.length,
          },
          { key: "indicators", label: "Indicadores" },
          { key: "timeline", label: "Linha do tempo" },
          { key: "report", label: "Relatório" },
        ],
        active: activeTab,
        onSelect: (tab) => {
          activeTab = tab;
          G.state.caseTab = tab;
          draw();
        },
      });
      const body = el("div", { class: "case-tab-body" });
      root.replaceChildren(header, meta, tabBar, body);
      await renderCaseTab(body, activeTab, investigation);
    }

    async function renderCaseTab(body, tab, investigation) {
      if (tab === "overview") {
        body.append(
          el(
            "div",
            { class: "stat-strip" },
            statCell("Observações", report.observations.length),
            statCell("Entidades", report.entities.length),
            statCell("Evidências", report.evidence.length),
            statCell("Fontes", report.sources.length),
            statCell("Relacionamentos", report.relationships.length),
            statCell("Indicadores", report.indicators.length),
            statCell("Correlações", report.correlations.length),
          ),
          coveragePanel(coverage, () => {
            activeTab = "overview";
            G.state.caseTab = "overview";
            draw();
          }, (tab) => {
            activeTab = tab;
            G.state.caseTab = tab;
            draw();
          }),
          panel(
            { eyebrow: "NARRATIVA", title: "Escopo do caso" },
            el("p", { class: "prose" }, investigation.description || "Nenhuma descrição registrada."),
            kvList([
              ["Status", statusBadge(investigation.status)],
              ["Criação", formatDate(investigation.created_at, { time: true })],
              ["Última atualização", formatDate(investigation.updated_at, { time: true })],
              ["Identificador", el("code", {}, investigation.id)],
            ]),
          ),
          panel(
            {
              eyebrow: "FLUXO DE EVIDÊNCIAS",
              title: `Observações (${report.observations.length})`,
              actions: [
                button(
                  "Registrar observação",
                  () =>
                    G.observationDialog(investigation, {
                      onSaved: () => draw(),
                    }),
                  { disabled: investigation.status !== "open" },
                ),
              ],
            },
            observationList(report.observations),
          ),
          panel(
            { eyebrow: "LIMITES DO ESCOPO", title: "Limitações analíticas" },
            report.limitations.length
              ? el(
                  "ul",
                  { class: "plain-list" },
                  ...report.limitations.map((limitation) => el("li", {}, G.translateText(limitation))),
                )
              : el("p", { class: "panel-empty" }, "Nenhuma limitação registrada."),
          ),
        );
        return;
      }
      if (tab === "entities") {
        const actions = [
          button("Vincular existente", () =>
            G.linkEntityDialog(
              investigation,
              report.entities.map((entity) => entity.id),
              () => draw(),
            ),
          ),
          button(
            "Registrar e vincular",
            () =>
              G.entityDialog(
                {},
                {
                  onSaved: async (entity) => {
                    await api(`/api/investigations/${investigation.id}/entities`, {
                      method: "POST",
                      body: JSON.stringify({ entity_id: entity.id }),
                    });
                    toast("Entidade registrada e vinculada.");
                    await draw();
                  },
                },
              ),
            { variant: "button-primary" },
          ),
        ];
        body.append(
          panel(
            { eyebrow: "REGISTRO COMPARTILHADO", title: `Entidades (${report.entities.length})`, actions },
            report.entities.length
              ? table({
                  columns: [
                    { label: "CATEGORIA", render: (row) => badge(entityTypeLabel(row.entity_type), "info") },
                    { label: "NOME", render: (row) => el("strong", {}, row.name) },
                    {
                      label: "IDENTIFICADOR",
                      render: (row) => el("code", { class: "reference-code" }, row.identifier || "—"),
                    },
                    { label: "VERIFICAÇÃO", render: (row) => statusBadge(row.verification_status) },
                    { label: "FONTE", render: (row) => referenceNode(row.source_reference) },
                    {
                      label: "",
                      render: (row) =>
                        button("Desvincular", async () => {
                          try {
                            await api(
                              `/api/investigations/${investigation.id}/entities/${row.id}`,
                              { method: "DELETE" },
                            );
                            toast("Entidade desvinculada; o registro compartilhado foi preservado.");
                            await draw();
                          } catch (error) {
                            toast(error.message, "error");
                          }
                        }),
                    },
                  ],
                  rows: report.entities,
                  emptyMessage: "Nenhuma entidade vinculada a este caso.",
                })
              : emptyState({
                  icon: "⬡",
                  title: "Nenhuma entidade vinculada",
                  description: "Vincule uma entidade existente ou registre um novo registro compartilhado.",
                }),
          ),
        );
        return;
      }
      if (tab === "evidence") {
        body.append(
          panel(
            {
              eyebrow: "INTEGRIDADE",
              title: `Evidências (${report.evidence.length})`,
              actions: [
                button(
                  "Adicionar evidência",
                  () => G.evidenceDialog(investigation.id, { onSaved: () => draw() }),
                  { variant: "button-primary", disabled: investigation.status !== "open" },
                ),
              ],
            },
            report.evidence.length
              ? table({
                  columns: [
                    {
                      label: "TÍTULO",
                      render: (row) =>
                        el(
                          "div",
                          { class: "cell-stack" },
                          el("strong", {}, row.title),
                          el("span", {}, row.original_name || row.evidence_type),
                        ),
                    },
                    { label: "TIPO", render: (row) => badge(titleCase(row.evidence_type), "neutral") },
                    {
                      label: "SHA-256",
                      render: (row) =>
                        el("code", { class: "hash", title: row.sha256 }, row.sha256 ? row.sha256.slice(0, 16) : "—"),
                    },
                    { label: "TAMANHO", render: (row) => formatBytes(row.size_bytes) },
                    { label: "INTEGRIDADE", render: (row) => statusBadge(row.integrity_status === "unverified" ? "not-verified" : row.integrity_status) },
                    {
                      label: "AÇÕES",
                      render: (row) =>
                        el(
                          "div",
                          { class: "row-actions" },
                          row.has_file
                            ? el(
                                "a",
                                {
                                  class: "button button-secondary button-small",
                                  href: `/api/evidence/${row.id}/download`,
                                },
                                "Baixar",
                              )
                            : null,
                          row.has_file
                            ? button("Verificar", async () => {
                                try {
                                  const result = await api(`/api/evidence/${row.id}/verify`, {
                                    method: "POST",
                                    body: JSON.stringify({}),
                                  });
                                  toast(
                                    result.matches
                                      ? "Integridade verificada: o hash confere."
                                      : `Integridade: ${G.statusLabel(result.integrity_status)}.`,
                                    result.matches ? "success" : "error",
                                  );
                                  await draw();
                                } catch (error) {
                                  toast(error.message, "error");
                                }
                              })
                            : null,
                          button("Excluir", async () => {
                            if (
                              !(await confirm({
                                title: "Excluir evidência",
                                message: `Excluir "${row.title}" e sua cópia armazenada?`,
                                confirmLabel: "Excluir",
                                danger: true,
                              }))
                            )
                              return;
                            try {
                              await api(`/api/evidence/${row.id}`, { method: "DELETE" });
                              toast("Evidência excluída.");
                              await draw();
                            } catch (error) {
                              toast(error.message, "error");
                            }
                          }, { variant: "button-danger" }),
                        ),
                    },
                  ],
                  rows: report.evidence,
                  emptyMessage: "Nenhuma evidência foi registrada para este caso.",
                })
              : emptyState({
                  icon: "▣",
                  title: "Nenhuma evidência ainda",
                  description:
                    "Adicione um arquivo ou uma referência. Os arquivos recebem hash SHA-256 e nunca são executados.",
                }),
          ),
        );
        return;
      }
      if (tab === "sources") {
        body.append(
          panel(
            {
              eyebrow: "PROVENIÊNCIA",
              title: `Fontes (${report.sources.length})`,
              actions: [
                button("Vincular existente", () =>
                  G.linkSourceDialog(
                    investigation,
                    report.sources.map((source) => source.id),
                    () => draw(),
                  ),
                ),
                button(
                  "Registrar e vincular",
                  () =>
                    G.sourceDialog(
                      {},
                      {
                        onSaved: async (source) => {
                          await api(`/api/investigations/${investigation.id}/sources`, {
                            method: "POST",
                            body: JSON.stringify({ source_id: source.id }),
                          });
                          toast("Fonte registrada e vinculada.");
                          await draw();
                        },
                      },
                    ),
                  { variant: "button-primary" },
                ),
              ],
            },
            report.sources.length
              ? table({
                  columns: [
                    { label: "TÍTULO", render: (row) => el("strong", {}, row.title) },
                    { label: "CATEGORIA", render: (row) => badge(titleCase(row.category), "neutral") },
                    { label: "REFERÊNCIA", render: (row) => referenceNode(row.reference) },
                    { label: "ACESSO", render: (row) => formatDate(row.accessed_at) },
                    { label: "VERIFICAÇÃO", render: (row) => statusBadge(row.verification_status) },
                    {
                      label: "",
                      render: (row) =>
                        button("Desvincular", async () => {
                          try {
                            await api(
                              `/api/investigations/${investigation.id}/sources/${row.id}`,
                              { method: "DELETE" },
                            );
                            toast("Fonte desvinculada; o registro compartilhado foi preservado.");
                            await draw();
                          } catch (error) {
                            toast(error.message, "error");
                          }
                        }),
                    },
                  ],
                  rows: report.sources,
                  emptyMessage: "Nenhuma fonte vinculada a este caso.",
                })
              : emptyState({
                  icon: "⛁",
                  title: "Nenhuma fonte vinculada",
                  description: "Fontes registram onde e quando a informação foi consultada.",
                }),
          ),
        );
        return;
      }
      if (tab === "relationships") {
        body.append(
          panel(
            {
              eyebrow: "RELACIONAMENTOS",
              title: `Relacionamentos (${report.relationships.length})`,
              actions: [
                button(
                  "Registrar relacionamento",
                  () =>
                    G.relationshipDialog({
                      investigationId: investigation.id,
                      entities: report.entities,
                      onSaved: () => draw(),
                    }),
                  {
                    variant: "button-primary",
                    disabled: report.entities.length < 2,
                    title:
                      report.entities.length < 2
                        ? "Vincule pelo menos duas entidades primeiro"
                        : "",
                  },
                ),
              ],
            },
            report.relationships.length
              ? table({
                  columns: [
                    { label: "FONTE", render: (row) => el("strong", {}, row.source_name) },
                    {
                      label: "TIPO",
                      render: (row) => el("span", { class: "relation-type" }, relationshipLabel(row.relationship_type)),
                    },
                    { label: "DESTINO", render: (row) => el("strong", {}, row.target_name) },
                    { label: "VERIFICAÇÃO", render: (row) => statusBadge(row.verification_status) },
                    { label: "CONFIANÇA", render: (row) => badge(titleCase(row.confidence), "neutral") },
                    { label: "FONTE", render: (row) => referenceNode(row.source_reference) },
                    {
                      label: "",
                      render: (row) =>
                        button("Excluir", async () => {
                          if (
                            !(await confirm({
                              title: "Excluir relacionamento",
                              message: "Remover este registro de relacionamento?",
                              confirmLabel: "Excluir",
                              danger: true,
                            }))
                          )
                            return;
                          try {
                            await api(`/api/relationships/${row.id}`, { method: "DELETE" });
                            toast("Relacionamento excluído.");
                            await draw();
                          } catch (error) {
                            toast(error.message, "error");
                          }
                        }, { variant: "button-danger" }),
                    },
                  ],
                  rows: report.relationships,
                  emptyMessage:
                    "Nenhum relacionamento registrado. Vincule pelo menos duas entidades para começar.",
                })
              : emptyState({
                  icon: "⟷",
                  title: "Nenhum relacionamento ainda",
                  description:
                    "Relacionamentos são compartilhados com o quadro e o grafo e possuem um status de verificação.",
                }),
          ),
        );
        return;
      }
      if (tab === "indicators") {
        body.append(loadingBlock("Carregando indicadores do caso…"));
        try {
          const data = await api(
            `/api/indicators?investigation_id=${encodeURIComponent(investigation.id)}&limit=1000`,
          );
          body.replaceChildren(
            panel(
              {
                eyebrow: "ÍNDICE DO CASO",
                title: `Indicadores únicos (${data.total})`,
                caption: `${data.extraction_count} ${data.extraction_count === 1 ? "ocorrência" : "ocorrências"} em texto`,
                actions: [button("Abrir analisador de IOC", () => go("indicators"))],
              },
              el(
                "p",
                { class: "panel-note" },
                "Hosts contidos em uma URL ou e-mail não são duplicados. Selecione um valor para triá-lo no analisador de IOC global.",
              ),
              data.items.length
                ? table({
                    columns: [
                      { label: "TIPO", render: (row) => badge(indicatorTypeLabel(row.type), "info") },
                      {
                        label: "VALOR",
                        render: (row) => el("code", { class: "indicator-value", title: row.value }, row.value),
                      },
                      {
                        label: "ORIGENS",
                        className: "numeric-col",
                        render: (row) => String(row.origin_count),
                      },
                      {
                        label: "AVALIAÇÃO",
                        render: (row) => statusBadge(row.verification_status),
                      },
                      {
                        label: "PRIMEIRA OCORRÊNCIA",
                        render: (row) => (row.first_seen ? formatDate(row.first_seen) : "—"),
                      },
                      {
                        label: "",
                        render: (row) =>
                          button("Triar", () => {
                            G.state.pendingIndicatorSearch = row.value;
                            go("indicators");
                          }),
                      },
                    ],
                    rows: data.items,
                    emptyMessage: "Nenhum indicador foi extraído para este caso.",
                    onRowClick: (row) => {
                      G.state.pendingIndicatorSearch = row.value;
                      go("indicators");
                    },
                  })
                : emptyState({
                    icon: "⌁",
                    title: "Nenhum indicador no caso",
                    description:
                      "Indicadores são extraídos de observações, entidades vinculadas e hashes de evidências.",
                  }),
            ),
          );
        } catch (error) {
          body.replaceChildren(inlineError(error.message));
        }
        return;
      }
      if (tab === "timeline") {
        body.append(loadingBlock("Carregando linha do tempo…"));
        try {
          const timeline = await api(`/api/investigations/${investigation.id}/timeline`);
          body.replaceChildren(
            panel(
              { eyebrow: "CRONOLOGIA", title: "Linha do tempo do caso", caption: `${timeline.events.length} eventos` },
              timeline.events.length
                ? timelineList(timeline.events)
                : emptyState({
                    icon: "◷",
                    title: "Nenhum evento na linha do tempo",
                    description: "Eventos aparecem à medida que registros são adicionados.",
                  }),
            ),
          );
        } catch (error) {
          body.replaceChildren(inlineError(error.message));
        }
        return;
      }
      if (tab === "report") {
        body.append(reportTabContent(investigation, report));
      }
    }

    await draw();
  }

  function coveragePanel(data, onRefresh, onOpen) {
    if (!data) return loadingBlock("Revisando cobertura do caso…");
    const summary = data.summary || {};
    return panel(
      {
        eyebrow: "SITUAÇÃO DO CASO",
        title: "Revisão de cobertura",
        caption: `${summary.attention || 0} pendentes · ${summary.ok || 0} cobertos`,
        actions: [button("Atualizar", onRefresh)],
      },
      el(
        "p",
        { class: "panel-note" },
        "A cobertura verifica fatos presentes no caso. Ela não mede qualidade analítica, risco ou culpa, e a ausência de pendências não prova que o caso está completo.",
      ),
      el(
        "div",
        { class: "coverage-grid" },
        ...data.checks.map((check) =>
          el(
            "article",
            { class: `coverage-item coverage-${check.status}` },
            el(
              "div",
              { class: "coverage-head" },
              badge(
                check.status === "attention" ? "Atenção" : check.status === "info" ? "Revisar" : "Coberto",
                check.status === "attention" ? "danger" : check.status === "info" ? "info" : "success",
              ),
              check.count ? el("strong", { class: "coverage-count" }, String(check.count)) : null,
            ),
            el("h3", {}, G.coverageText(check)[0]),
            el("p", {}, G.coverageText(check)[1]),
            button("Abrir", () => onOpen(check.tab)),
          ),
        ),
      ),
    );
  }

  function observationList(observations) {
    if (!observations.length) {
      return el("p", { class: "panel-empty" }, "Nenhuma observação registrada.");
    }
    const list = el("div", { class: "record-list" });
    for (const observation of [...observations].reverse()) {
      list.append(
        el(
          "article",
          { class: "record-item" },
          el(
            "div",
            { class: "record-heading" },
            el("strong", {}, observation.title),
            badge(titleCase(observation.collection_basis), "neutral"),
          ),
          el("p", { class: "record-content" }, observation.content),
          el(
            "div",
            { class: "record-meta" },
            el("span", {}, `Observada em ${formatDate(observation.observed_at, { time: true })}`),
            el("span", {}, "Fonte: "),
            referenceNode(observation.source_reference),
          ),
        ),
      );
    }
    return list;
  }

  function timelineList(events) {
    const list = el("div", { class: "timeline-list" });
    for (const event of [...events].reverse()) {
      list.append(
        el(
          "article",
          { class: "timeline-event" },
          el(
            "span",
            {
              class: `timeline-marker marker-${event.type}`,
              "aria-hidden": "true",
            },
          ),
          el(
            "div",
            { class: "timeline-body" },
            el(
              "div",
              { class: "timeline-heading" },
              el("strong", {}, G.translateActivity(event.title)),
              el("time", { datetime: event.occurred_at }, formatDate(event.occurred_at, { time: true })),
            ),
            event.collection_basis ? badge(titleCase(event.collection_basis), "neutral") : null,
            event.source_reference
              ? el("p", { class: "record-meta" }, "Fonte: ", referenceNode(event.source_reference))
              : null,
          ),
        ),
      );
    }
    return list;
  }

  function reportTabContent(investigation, report) {
    const formats = [
      ["html", "Relatório HTML"],
      ["json", "Exportação JSON"],
      ["csv", "Exportação CSV"],
      ["markdown", "Markdown"],
    ];
    const tlpSelect = el(
      "select",
      { class: "input compact-select", "aria-label": "Marcação TLP das exportações CTI" },
      ...["white", "green", "amber", "red"].map((value) => el("option", { value, selected: value === "amber" }, `TLP:${value.toUpperCase()}`)),
    );
    const cti = [
      ["stix", "STIX 2.1", "Bundle com indicadores, observáveis, relacionamentos, técnicas ATT&CK e o relatório. Validado pelo validador da OASIS."],
      ["misp", "Evento MISP", "Atributos, hashes de semelhança, etiqueta TLP e galáxia ATT&CK. to_ids só em registros verificados."],
      ["iocs", "IOCs em CSV", "Domínios, IPs, URLs, e-mails e hashes com origem e status de verificação."],
    ];
    const ctiLinks = cti.map(([format, label, text]) => {
      const link = el("a", { class: "export-card", href: `/api/investigations/${investigation.id}/export?format=${format}&tlp=amber`, download: "" }, el("strong", {}, label), el("span", {}, text));
      return [format, link];
    });
    tlpSelect.addEventListener("change", () => {
      for (const [format, link] of ctiLinks) link.href = `/api/investigations/${investigation.id}/export?format=${format}&tlp=${tlpSelect.value}`;
    });
    const ctiPanel = panel(
      { eyebrow: "INTERCÂMBIO CTI", title: "Exportar para outras plataformas", caption: "Pessoas e perfis ficam de fora", actions: [tlpSelect] },
      el("div", { class: "export-grid" }, ...ctiLinks.map(([, link]) => link)),
      el("p", { class: "tool-limit" }, "Indicadores saem com tipo \"unknown\" e com o status de verificação de cada registro: exportar não transforma associação em atribuição."),
    );
    return el(
      "div",
      { class: "report-tab" },
      panel(
        { eyebrow: "SAÍDA", title: "Exportar este caso", caption: "Somente registros reais" },
        el(
          "div",
          { class: "export-grid" },
          ...formats.map(([format, label]) =>
            el(
              "a",
              {
                class: "export-card",
                href: `/api/investigations/${investigation.id}/export?format=${format}`,
                download: "",
              },
              el("strong", {}, label),
              el("span", {}, `Gerado a partir ${format === "csv" ? "dos registros atuais" : "do caso atual"}.`),
            ),
          ),
          el(
            "a",
            {
              class: "export-card",
              href: `/reports/${investigation.id}`,
              target: "_blank",
              rel: "noopener",
            },
            el("strong", {}, "HTML para impressão"),
            el("span", {}, "Abra em uma nova aba e imprima."),
          ),
        ),
      ),
      ctiPanel,
      panel(
        { eyebrow: "INTERPRETAÇÃO", title: "Classes de registro" },
        el(
          "ul",
          { class: "plain-list" },
          ...Object.entries(reportClassEntries(investigation)).map(([key, value]) =>
            el("li", {}, el("strong", {}, titleCase(key)), ": ", value),
          ),
        ),
      ),
      panel(
        { eyebrow: "LIMITES DO ESCOPO", title: "Limitações" },
        report.limitations.length
          ? el(
              "ul",
              { class: "plain-list" },
              ...report.limitations.map((limitation) => el("li", {}, G.translateText(limitation))),
            )
          : el("p", { class: "panel-empty" }, "Nenhuma limitação registrada."),
      ),
    );
  }

  function reportClassEntries() {
    return {
      observations: "Registradas pelo analista, sem verificação independente.",
      evidence: "Arquivo com hash ou referência do analista; o hash confirma apenas a identidade.",
      relationships: "Vínculos informados pelo analista com status de verificação registrado.",
      sources: "Fontes consultadas com data e hora de acesso.",
    };
  }

  /* ---------------------------------------------------------------- */
  /* Activity view                                                    */
  /* ---------------------------------------------------------------- */

  async function renderActivity(root) {
    const investigations = await G.loadInvestigations();
    const filter = el(
      "select",
      { class: "input compact-select", "aria-label": "Filtrar atividade por investigação" },
      el("option", { value: "" }, "Todas as investigações"),
      ...investigations.map((investigation) =>
        el("option", { value: investigation.id }, investigation.name),
      ),
    );
    const host = el("div");
    let offset = 0;
    let total = 0;
    let items = [];

    async function load(reset = true) {
      if (reset) {
        offset = 0;
        items = [];
      }
      const query = new URLSearchParams({ limit: "50", offset: String(offset) });
      if (filter.value) query.set("investigation_id", filter.value);
      const data = await api(`/api/activities?${query}`);
      total = data.total;
      items = items.concat(data.items);
      offset = items.length;
      draw();
    }

    function draw() {
      host.replaceChildren(
        panel(
          {
            eyebrow: "TRILHA DE AUDITORIA",
            title: "Atividade do workspace",
            caption: `${items.length} de ${total}`,
          },
          renderActivityFeed(items),
          offset < total
            ? el(
                "div",
                { class: "toolbar-end" },
                button("Carregar mais", () => load(false)),
              )
            : null,
        ),
      );
    }

    root.append(
      pageHeader({
        eyebrow: "REGISTRO CRONOLÓGICO",
        title: "Linha do tempo",
        description:
          "Registro somente de acréscimo das alterações do workspace. As linhas do tempo das investigações acrescentam a proveniência das observações.",
        actions: [filter],
      }),
      host,
    );
    filter.addEventListener("change", () => load(true));
    await load(true);
  }

  G.views.overview = renderOverview;
  G.views.investigations = renderInvestigations;
  G.views.activity = renderActivity;
})();
