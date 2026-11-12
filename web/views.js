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
      reader.onerror = () => reject(new Error("Unable to read the selected file."));
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
      eyebrow: isEdit ? "EDIT ENTITY" : "NEW ENTITY",
      title: isEdit ? "Update entity record" : "Register entity",
      description:
        "Entities are shared across cases, the investigation board and the relationship graph.",
      fields: [
        {
          name: "entity_type",
          label: "Category",
          type: "select",
          options: G.ENTITY_TYPES,
          value: initial.entity_type || "domain",
        },
        {
          name: "name",
          label: "Display name",
          value: initial.name || "",
          placeholder: "Defaults to the identifier",
          maxlength: 300,
        },
        {
          name: "identifier",
          label: "Identifier",
          value: initial.identifier || "",
          placeholder: "Domain, address, URL, username, hash…",
          maxlength: 2000,
          hint: "Validated per category. Duplicate identifiers are rejected.",
        },
        {
          name: "description",
          label: "Description",
          type: "textarea",
          rows: 3,
          value: initial.description || "",
        },
        {
          name: "source_reference",
          label: "Source reference",
          value: initial.source_reference || "",
          placeholder: "https://… or note://analyst",
        },
        {
          name: "collection_basis",
          label: "Collection basis",
          type: "select",
          options: G.COLLECTION_BASES,
          value: initial.collection_basis || "user-provided",
        },
        {
          name: "confidence",
          label: "Confidence",
          type: "select",
          options: G.CONFIDENCE_LEVELS,
          value: initial.confidence || "unconfirmed",
        },
        {
          name: "verification_status",
          label: "Verification",
          type: "select",
          options: G.VERIFICATION_STATUSES,
          value: initial.verification_status || "not-verified",
        },
      ],
      submitLabel: isEdit ? "Save changes" : "Register entity",
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
        toast(isEdit ? "Entity updated." : "Entity registered.");
        if (options.onSaved) await options.onSaved(saved);
        else G.refreshView();
      },
    });
  };

  G.sourceDialog = async function sourceDialog(initial = {}, options = {}) {
    const isEdit = Boolean(initial.id);
    await formDialog({
      eyebrow: isEdit ? "EDIT SOURCE" : "NEW SOURCE",
      title: isEdit ? "Update source" : "Register source",
      description: "Sources preserve where information came from and when it was consulted.",
      fields: [
        {
          name: "title",
          label: "Title",
          required: true,
          maxlength: 300,
          value: initial.title || "",
        },
        {
          name: "reference",
          label: "Reference",
          required: true,
          value: initial.reference || "",
          placeholder: "https://… or note://analyst",
          hint: "Only http, https, file and note references are accepted.",
        },
        {
          name: "category",
          label: "Category",
          type: "select",
          options: G.SOURCE_CATEGORIES,
          value: initial.category || "website",
        },
        {
          name: "description",
          label: "Description",
          type: "textarea",
          rows: 3,
          value: initial.description || "",
        },
        {
          name: "accessed_at",
          label: "Accessed at",
          value: initial.accessed_at || "",
          placeholder: "ISO 8601, defaults to now",
        },
        {
          name: "verification_status",
          label: "Verification",
          type: "select",
          options: G.VERIFICATION_STATUSES,
          value: initial.verification_status || "not-verified",
        },
      ],
      submitLabel: isEdit ? "Save changes" : "Register source",
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
        toast(isEdit ? "Source updated." : "Source registered.");
        if (options.onSaved) await options.onSaved(saved);
        else G.refreshView();
      },
    });
  };

  G.observationDialog = async function observationDialog(investigation, options = {}) {
    if (investigation.status !== "open") {
      toast("Reopen the investigation before recording observations.", "error");
      return;
    }
    await formDialog({
      eyebrow: "EVIDENCE CAPTURE",
      title: "Record observation",
      description: investigation.name,
      fields: [
        {
          name: "title",
          label: "Observation title",
          required: true,
          maxlength: 300,
          placeholder: "A concise, factual description",
        },
        {
          name: "content",
          label: "Details",
          type: "textarea",
          rows: 5,
          required: true,
          placeholder: "What was observed? Preserve relevant context.",
        },
        {
          name: "source_reference",
          label: "Source reference",
          required: true,
          placeholder: "https://… or note://analyst",
        },
        {
          name: "collection_basis",
          label: "Collection basis",
          type: "select",
          options: G.COLLECTION_BASES,
          value: "public",
        },
        {
          name: "observed_at",
          label: "Observed at",
          placeholder: "ISO 8601 with timezone, defaults to now",
          hint: "Only record information you are authorized to access and use.",
        },
      ],
      submitLabel: "Save observation",
      onSubmit: async (values) => {
        if (!values.observed_at) delete values.observed_at;
        await api(`/api/investigations/${investigation.id}/observations`, {
          method: "POST",
          body: JSON.stringify(values),
        });
        toast("Observation recorded.");
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
        toast("Create or reopen an investigation before adding evidence.", "error");
        return;
      }
      fields.push({
        name: "investigation_id",
        label: "Investigation",
        type: "select",
        required: true,
        options: open.map((item) => [item.id, item.name]),
        value: open[0].id,
      });
    }
    fields.push(
      {
        name: "title",
        label: "Evidence title",
        required: true,
        maxlength: 300,
        placeholder: "e.g. Captured page header",
      },
      {
        name: "evidence_type",
        label: "Evidence type",
        type: "select",
        options: G.EVIDENCE_TYPES,
        value: "file",
      },
      {
        name: "description",
        label: "Description",
        type: "textarea",
        rows: 3,
        placeholder: "Acquisition context and observations",
      },
      {
        name: "source_reference",
        label: "Source reference",
        placeholder: "https://… or note://analyst",
      },
      {
        name: "original_name",
        label: "Original file name",
        placeholder: "Optional for reference-only records",
      },
      {
        name: "file",
        label: "File",
        type: "file",
        accept: "",
        hint: "Maximum 4 MiB. Files are stored under a generated internal name, hashed with SHA-256 and never executed.",
      },
      {
        name: "sha256",
        label: "Known SHA-256",
        placeholder: "Optional when you attach a file",
        maxlength: 64,
      },
    );
    await formDialog({
      eyebrow: "EVIDENCE CAPTURE",
      title: "Add evidence",
      description:
        "The original stays untouched; GARBAGE stores a hashed copy and records its acquisition context.",
      fields,
      submitLabel: "Add evidence",
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
            throw new Error("Evidence file exceeds the 4 MiB limit.");
          }
          payload.content_base64 = await fileToBase64(file);
          payload.original_name = file.name;
          delete payload.sha256;
        }
        const record = await api(`/api/investigations/${caseId}/evidence`, {
          method: "POST",
          body: JSON.stringify(payload),
        });
        toast("Evidence added and hashed.");
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
      toast("Register at least two entities before recording a relationship.", "error");
      return;
    }
    const fields = [];
    if (!isEdit) {
      fields.push(
        {
          name: "source_entity_id",
          label: "Source entity",
          type: "select",
          options: entityOptions.map((entity) => [entity.id, entity.name]),
        },
        {
          name: "target_entity_id",
          label: "Target entity",
          type: "select",
          options: entityOptions.map((entity) => [entity.id, entity.name]),
        },
      );
    }
    if (!isEdit && !investigationId) {
      const investigations = await G.loadInvestigations();
      fields.push({
        name: "investigation_id",
        label: "Investigation context",
        type: "select",
        options: [["", "No investigation"]].concat(
          investigations.map((item) => [item.id, item.name]),
        ),
      });
    }
    fields.push(
      {
        name: "relationship_type",
        label: "Relationship type",
        type: "select",
        options: G.RELATIONSHIP_TYPES,
        value: relationship?.relationship_type || "associated-with",
      },
      {
        name: "description",
        label: "Description",
        type: "textarea",
        rows: 2,
        value: relationship?.description || "",
      },
      {
        name: "source_reference",
        label: "Source reference",
        value: relationship?.source_reference || "",
      },
      {
        name: "confidence",
        label: "Confidence",
        type: "select",
        options: G.CONFIDENCE_LEVELS,
        value: relationship?.confidence || "unconfirmed",
      },
      {
        name: "verification_status",
        label: "Verification",
        type: "select",
        options: G.VERIFICATION_STATUSES,
        value: relationship?.verification_status || "not-verified",
      },
    );
    await formDialog({
      eyebrow: isEdit ? "EDIT RELATIONSHIP" : "RELATIONSHIP ENGINE",
      title: isEdit ? "Update relationship" : "Record relationship",
      description:
        "Relationships are shared records. Observed links stay distinct from verified facts.",
      fields,
      submitLabel: isEdit ? "Save changes" : "Record relationship",
      onSubmit: async (values) => {
        if (
          !isEdit &&
          values.source_entity_id === values.target_entity_id
        ) {
          throw new Error("A relationship requires two different entities.");
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
        toast(isEdit ? "Relationship updated." : "Relationship recorded.");
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
      toast("No unlinked entities are available. Register a new entity first.", "error");
      return;
    }
    await formDialog({
      eyebrow: "LINK RECORD",
      title: "Link entity to investigation",
      description: investigation.name,
      fields: [
        {
          name: "entity_id",
          label: "Entity",
          type: "select",
          options: available.map((entity) => [
            entity.id,
            `${entity.name} · ${entityTypeLabel(entity.entity_type)}`,
          ]),
        },
      ],
      submitLabel: "Link entity",
      onSubmit: async (values) => {
        await api(`/api/investigations/${investigation.id}/entities`, {
          method: "POST",
          body: JSON.stringify({ entity_id: values.entity_id }),
        });
        toast("Entity linked.");
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
      toast("No unlinked sources are available. Register a source first.", "error");
      return;
    }
    await formDialog({
      eyebrow: "LINK SOURCE",
      title: "Link source to investigation",
      description: investigation.name,
      fields: [
        {
          name: "source_id",
          label: "Source",
          type: "select",
          options: available.map((source) => [source.id, source.title]),
        },
      ],
      submitLabel: "Link source",
      onSubmit: async (values) => {
        await api(`/api/investigations/${investigation.id}/sources`, {
          method: "POST",
          body: JSON.stringify({ source_id: values.source_id }),
        });
        toast("Source linked.");
        if (onSaved) await onSaved();
        else G.refreshView();
      },
    });
  };

  G.investigationEditDialog = async function investigationEditDialog(investigation) {
    await formDialog({
      eyebrow: "EDIT CASE",
      title: "Update investigation",
      fields: [
        {
          name: "name",
          label: "Investigation name",
          required: true,
          maxlength: 200,
          value: investigation.name,
        },
        {
          name: "description",
          label: "Description",
          type: "textarea",
          rows: 4,
          value: investigation.description || "",
        },
        {
          name: "status",
          label: "Status",
          type: "select",
          options: [
            ["open", "Open"],
            ["closed", "Closed"],
            ["cancelled", "Cancelled"],
          ],
          value: investigation.status,
        },
      ],
      submitLabel: "Save case",
      onSubmit: async (values) => {
        await api(`/api/investigations/${investigation.id}`, {
          method: "PATCH",
          body: JSON.stringify(values),
        });
        G.invalidateInvestigations();
        toast("Investigation updated.");
        G.refreshView();
      },
    });
  };

  G.deleteInvestigation = async function deleteInvestigation(investigation) {
    const approved = await confirm({
      title: "Delete investigation",
      message:
        `Delete "${investigation.name}"? Shared entities and sources are preserved. ` +
        "Records owned by the case can only be removed with a second confirmation.",
      confirmLabel: "Delete case",
      danger: true,
    });
    if (!approved) return false;
    try {
      await api(`/api/investigations/${investigation.id}`, { method: "DELETE" });
    } catch (error) {
      if (error.status !== 409) throw error;
      const forced = await confirm({
        title: "Delete case and its own records",
        message:
          `${error.message}\n\nThis permanently deletes the case observations, ` +
          "stored evidence files, board and case-scoped relationships. Shared " +
          "entities and sources are never deleted.",
        confirmLabel: "Delete owned records",
        danger: true,
      });
      if (!forced) return false;
      await api(`/api/investigations/${investigation.id}?force=true`, {
        method: "DELETE",
      });
    }
    G.invalidateInvestigations();
    toast("Investigation deleted.");
    go("investigations");
    return true;
  };

  G.deleteEntity = async function deleteEntity(entity, onDeleted = null) {
    const approved = await confirm({
      title: "Delete entity",
      message: `Delete "${entity.name}" from the shared registry?`,
      confirmLabel: "Delete entity",
      danger: true,
    });
    if (!approved) return false;
    try {
      await api(`/api/entities/${entity.id}`, { method: "DELETE" });
    } catch (error) {
      if (error.status !== 409) throw error;
      const forced = await confirm({
        title: "Delete entity and relationships",
        message: `${error.message}\n\nThis also removes the entity from the graph and board.`,
        confirmLabel: "Delete with relationships",
        danger: true,
      });
      if (!forced) return false;
      await api(`/api/entities/${entity.id}?force=true`, { method: "DELETE" });
    }
    toast("Entity deleted.");
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
    create: "＋",
    update: "✎",
    status: "◷",
    observation: "▤",
    evidence: "▣",
    link: "⟷",
    unlink: "⋯",
    delete: "×",
    board: "▦",
    assessment: "⌁",
    verify: "✓",
    settings: "⚙",
    module: "⊞",
    import: "↧",
  };

  function renderActivityFeed(items, options = {}) {
    const feed = el("div", { class: "activity-feed" });
    if (!items.length) {
      feed.append(
        el(
          "p",
          { class: "panel-empty" },
          options.emptyMessage || "No activity has been recorded yet.",
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
          el("strong", {}, item.summary),
          item.investigation_id
            ? caseLink(item.investigation_id, item.investigation_name || "Case")
            : null,
        ),
        el(
          "div",
          { class: "activity-meta" },
          badge(titleCase(item.action), "neutral"),
          el("span", {}, item.actor || "analyst"),
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
            ACTION_ICONS[item.action] || "·",
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
      button("↻ Refresh", () => G.refreshView()),
      button("＋ New investigation", () => G.newInvestigation(), {
        variant: "button-primary",
      }),
    ];
    root.append(
      pageHeader({
        eyebrow: "INTELLIGENCE OVERVIEW",
        title: "Operations at a glance.",
        description:
          "A live view of cases, shared entities, hashed evidence and extracted indicators in this local workspace.",
        actions,
      }),
      el(
        "div",
        { class: "quick-actions" },
        button("Register entity", () => G.entityDialog()),
        button("Register source", () => G.sourceDialog()),
        button("Open board", () => go("board")),
        button("Analyze indicators", () => go("indicators")),
        button("Browse evidence", () => go("evidence")),
      ),
      el(
        "div",
        { class: "metric-grid" },
        metric({
          label: "OPEN INVESTIGATIONS",
          value: totals.open.toLocaleString(),
          foot: `${totals.investigations} total · ${totals.closed} closed`,
          icon: "⌕",
          tone: "blue",
        }),
        metric({
          label: "SHARED ENTITIES",
          value: totals.entities.toLocaleString(),
          foot: `${totals.relationships.toLocaleString()} relationships`,
          icon: "⬡",
          tone: "violet",
        }),
        metric({
          label: "EVIDENCE RECORDS",
          value: totals.evidence.toLocaleString(),
          foot: "SHA-256 preserved",
          icon: "▣",
          tone: "green",
        }),
        metric({
          label: "UNIQUE INDICATORS",
          value: totals.unique_indicators.toLocaleString(),
          foot: `${totals.indicator_origins.toLocaleString()} observation matches`,
          icon: "⌁",
          tone: "amber",
        }),
        metric({
          label: "OBSERVATIONS",
          value: totals.observations.toLocaleString(),
          foot: "Provenance retained",
          icon: "▤",
          tone: "blue",
        }),
        metric({
          label: "EXACT-VALUE CORRELATIONS",
          value: totals.correlations.toLocaleString(),
          foot: "Shared values across observations",
          icon: "⟷",
          tone: "violet",
        }),
      ),
    );

    if (totals.investigations === 0) {
      root.append(
        panel(
          { eyebrow: "START HERE", title: "Build the first case file" },
          el(
            "div",
            { class: "onboarding" },
            el("p", {}, "An integrated investigation moves through shared records:"),
            el(
              "ol",
              { class: "step-list" },
              el("li", {}, "Create an investigation and define its scope."),
              el("li", {}, "Register entities and link them to the case."),
              el("li", {}, "Record observations, sources and hashed evidence."),
              el("li", {}, "Record relationships and arrange the investigation board."),
              el("li", {}, "Export a report from the real records."),
            ),
            button("Create the first investigation", () => G.newInvestigation(), {
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
            eyebrow: "CASE ACTIVITY",
            title: "Recent activity",
            caption: "Newest first",
            actions: [button("Open timeline", () => go("activity"))],
          },
          renderActivityFeed(data.recent_activity || [], {
            emptyMessage:
              "Activity appears here after cases, entities and evidence are recorded.",
          }),
        ),
        panel(
          {
            eyebrow: "CASE WORK",
            title: "Recent investigations",
            actions: [button("All cases", () => go("investigations"))],
          },
          table({
            columns: [
              {
                label: "CASE",
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
                render: (row) => button("Open", () => go("investigations", row.id)),
              },
            ],
            rows: recentRows,
            emptyMessage: "No investigations yet.",
            onRowClick: (row) => go("investigations", row.id),
          }),
        ),
      ),
      el(
        "div",
        { class: "dashboard-grid" },
        panel(
          {
            eyebrow: "OBSERVED ARTIFACTS",
            title: "Indicator mix",
            caption: `${totals.unique_indicators} unique`,
          },
          indicatorMix(data.indicator_mix || {}, totals.unique_indicators),
        ),
        panel(
          {
            eyebrow: "EVIDENCE PROVENANCE",
            title: "Collection basis",
            caption: `${totals.observations} observations`,
          },
          collectionBasis(data.collection_basis || {}, totals.observations),
        ),
        panel(
          {
            eyebrow: "SYSTEM",
            title: "Module status",
            actions: [button("Manage modules", () => go("modules"))],
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
          ? "Indicators appear when patterns are found in observations or registered entities."
          : "No indicator mix is available.",
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
            el("strong", {}, counts[key].toLocaleString()),
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
        el("span", {}, "Total sourced observations"),
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
      el("div", { class: "module-summary-row" }, badge("Enabled", "success"), String(enabled)),
      el("div", { class: "module-summary-row" }, badge("Available", "neutral"), String(disabled)),
      el("div", { class: "module-summary-row" }, badge("Planned", "warning"), String(planned)),
      el(
        "p",
        { class: "panel-note" },
        "Planned modules are listed as not implemented and cannot be enabled.",
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
      placeholder: "Search cases, descriptions or status",
      "aria-label": "Search investigations",
    });
    const statusFilter = el(
      "select",
      { class: "input compact-select", "aria-label": "Filter by status" },
      el("option", { value: "" }, "All statuses"),
      el("option", { value: "open" }, "Open"),
      el("option", { value: "closed" }, "Closed"),
      el("option", { value: "cancelled" }, "Cancelled"),
    );
    const sortSelect = el(
      "select",
      { class: "input compact-select", "aria-label": "Sort investigations" },
      el("option", { value: "updated" }, "Recently updated"),
      el("option", { value: "created" }, "Recently created"),
      el("option", { value: "name" }, "Name"),
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
      countLabel.textContent = `${rows.length} of ${investigations.length} investigations`;
      host.replaceChildren(
        table({
          columns: [
            {
              label: "INVESTIGATION",
              render: (row) =>
                el(
                  "div",
                  { class: "cell-stack" },
                  el("strong", {}, row.name),
                  el("span", {}, row.description || "No description recorded"),
                  el("span", { class: "mono" }, shortId(row.id)),
                ),
            },
            { label: "STATUS", render: (row) => statusBadge(row.status) },
            {
              label: "UPDATED",
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
              render: (row) => button("Open case", () => go("investigations", row.id)),
            },
          ],
          rows,
          emptyMessage: investigations.length
            ? "No investigations match these filters."
            : "No investigations have been created.",
          onRowClick: (row) => go("investigations", row.id),
        }),
      );
    }

    root.append(
      pageHeader({
        eyebrow: "CASE MANAGEMENT",
        title: "Investigations",
        description:
          "Every case shares the same entity registry, evidence store and relationship records.",
        actions: [
          button("＋ New investigation", () => G.newInvestigation(), {
            variant: "button-primary",
          }),
        ],
      }),
      panel(
        {
          eyebrow: "CASEWORK",
          title: "Case index",
          actions: [countLabel],
          className: "table-panel",
        },
        el(
          "div",
          { class: "toolbar" },
          el("div", { class: "search-field" }, el("span", { "aria-hidden": "true" }, "⌕"), search),
          statusFilter,
          sortSelect,
        ),
        investigations.length === 0
          ? emptyState({
              icon: "⌕",
              title: "No investigations yet",
              description: "Create a case to start building a sourced evidence record.",
              action: button("Create investigation", () => G.newInvestigation(), {
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
      root.replaceChildren(loadingBlock("Loading case file…"));
      try {
        await load();
      } catch (error) {
        root.replaceChildren(
          errorState({
            title: "Case file unavailable",
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
        eyebrow: "INVESTIGATION FILE",
        title: investigation.name,
        description: investigation.description || "No description recorded.",
        actions: [
          button("‹ All cases", () => go("investigations")),
          button("Edit case", () => G.investigationEditDialog(investigation)),
          button(
            investigation.status === "open" ? "Close case" : "Reopen case",
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
                    ? "Case closed; evidence is locked until reopened."
                    : "Case reopened.",
                );
                await draw();
              } catch (error) {
                toast(error.message, "error");
              }
            },
          ),
          button("Board", () => go("board", investigation.id)),
          button("Graph", () => go("graph", investigation.id)),
          el(
            "a",
            {
              class: "button button-secondary button-small",
              href: `/reports/${investigation.id}`,
              target: "_blank",
              rel: "noopener",
            },
            "Print report",
          ),
          button("Delete", () => G.deleteInvestigation(investigation), {
            variant: "button-danger",
          }),
        ],
      });
      const meta = el(
        "div",
        { class: "case-meta" },
        statusBadge(investigation.status),
        el("code", {}, investigation.id),
        el("span", {}, `Created ${formatDate(investigation.created_at)}`),
        el("span", {}, `Updated ${relativeTime(investigation.updated_at)}`),
      );
      const tabBar = tabs({
        items: [
          { key: "overview", label: "Overview" },
          { key: "entities", label: "Entities", count: report.entities.length },
          { key: "evidence", label: "Evidence", count: report.evidence.length },
          { key: "sources", label: "Sources", count: report.sources.length },
          {
            key: "relationships",
            label: "Relationships",
            count: report.relationships.length,
          },
          { key: "indicators", label: "Indicators" },
          { key: "timeline", label: "Timeline" },
          { key: "report", label: "Report" },
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
            statCell("Observations", report.observations.length),
            statCell("Entities", report.entities.length),
            statCell("Evidence", report.evidence.length),
            statCell("Sources", report.sources.length),
            statCell("Relationships", report.relationships.length),
            statCell("Indicators", report.indicators.length),
            statCell("Correlations", report.correlations.length),
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
            { eyebrow: "NARRATIVE", title: "Case scope" },
            el("p", { class: "prose" }, investigation.description || "No description recorded."),
            kvList([
              ["Status", statusBadge(investigation.status)],
              ["Created", formatDate(investigation.created_at, { time: true })],
              ["Last updated", formatDate(investigation.updated_at, { time: true })],
              ["Identifier", el("code", {}, investigation.id)],
            ]),
          ),
          panel(
            {
              eyebrow: "EVIDENCE FLOW",
              title: `Observations (${report.observations.length})`,
              actions: [
                button(
                  "＋ Record observation",
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
            { eyebrow: "SCOPE LIMITS", title: "Analytical limitations" },
            report.limitations.length
              ? el(
                  "ul",
                  { class: "plain-list" },
                  ...report.limitations.map((limitation) => el("li", {}, limitation)),
                )
              : el("p", { class: "panel-empty" }, "No limitations recorded."),
          ),
        );
        return;
      }
      if (tab === "entities") {
        const actions = [
          button("Link existing", () =>
            G.linkEntityDialog(
              investigation,
              report.entities.map((entity) => entity.id),
              () => draw(),
            ),
          ),
          button(
            "＋ Register & link",
            () =>
              G.entityDialog(
                {},
                {
                  onSaved: async (entity) => {
                    await api(`/api/investigations/${investigation.id}/entities`, {
                      method: "POST",
                      body: JSON.stringify({ entity_id: entity.id }),
                    });
                    toast("Entity registered and linked.");
                    await draw();
                  },
                },
              ),
            { variant: "button-primary" },
          ),
        ];
        body.append(
          panel(
            { eyebrow: "SHARED REGISTRY", title: `Entities (${report.entities.length})`, actions },
            report.entities.length
              ? table({
                  columns: [
                    { label: "CATEGORY", render: (row) => badge(entityTypeLabel(row.entity_type), "info") },
                    { label: "NAME", render: (row) => el("strong", {}, row.name) },
                    {
                      label: "IDENTIFIER",
                      render: (row) => el("code", { class: "reference-code" }, row.identifier || "—"),
                    },
                    { label: "VERIFICATION", render: (row) => statusBadge(row.verification_status) },
                    { label: "SOURCE", render: (row) => referenceNode(row.source_reference) },
                    {
                      label: "",
                      render: (row) =>
                        button("Unlink", async () => {
                          try {
                            await api(
                              `/api/investigations/${investigation.id}/entities/${row.id}`,
                              { method: "DELETE" },
                            );
                            toast("Entity unlinked; the shared record is preserved.");
                            await draw();
                          } catch (error) {
                            toast(error.message, "error");
                          }
                        }),
                    },
                  ],
                  rows: report.entities,
                  emptyMessage: "No entities are linked to this case.",
                })
              : emptyState({
                  icon: "⬡",
                  title: "No entities linked",
                  description: "Link an existing entity or register a new shared record.",
                }),
          ),
        );
        return;
      }
      if (tab === "evidence") {
        body.append(
          panel(
            {
              eyebrow: "INTEGRITY",
              title: `Evidence (${report.evidence.length})`,
              actions: [
                button(
                  "＋ Add evidence",
                  () => G.evidenceDialog(investigation.id, { onSaved: () => draw() }),
                  { variant: "button-primary", disabled: investigation.status !== "open" },
                ),
              ],
            },
            report.evidence.length
              ? table({
                  columns: [
                    {
                      label: "TITLE",
                      render: (row) =>
                        el(
                          "div",
                          { class: "cell-stack" },
                          el("strong", {}, row.title),
                          el("span", {}, row.original_name || row.evidence_type),
                        ),
                    },
                    { label: "TYPE", render: (row) => badge(titleCase(row.evidence_type), "neutral") },
                    {
                      label: "SHA-256",
                      render: (row) =>
                        el("code", { class: "hash", title: row.sha256 }, row.sha256 ? row.sha256.slice(0, 16) : "—"),
                    },
                    { label: "SIZE", render: (row) => formatBytes(row.size_bytes) },
                    { label: "INTEGRITY", render: (row) => statusBadge(row.integrity_status === "unverified" ? "not-verified" : row.integrity_status) },
                    {
                      label: "ACTIONS",
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
                                "Download",
                              )
                            : null,
                          row.has_file
                            ? button("Verify", async () => {
                                try {
                                  const result = await api(`/api/evidence/${row.id}/verify`, {
                                    method: "POST",
                                    body: JSON.stringify({}),
                                  });
                                  toast(
                                    result.matches
                                      ? "Integrity verified: digest matches."
                                      : `Integrity ${result.integrity_status}.`,
                                    result.matches ? "success" : "error",
                                  );
                                  await draw();
                                } catch (error) {
                                  toast(error.message, "error");
                                }
                              })
                            : null,
                          button("Delete", async () => {
                            if (
                              !(await confirm({
                                title: "Delete evidence",
                                message: `Delete "${row.title}" and its stored copy?`,
                                confirmLabel: "Delete",
                                danger: true,
                              }))
                            )
                              return;
                            try {
                              await api(`/api/evidence/${row.id}`, { method: "DELETE" });
                              toast("Evidence deleted.");
                              await draw();
                            } catch (error) {
                              toast(error.message, "error");
                            }
                          }, { variant: "button-danger" }),
                        ),
                    },
                  ],
                  rows: report.evidence,
                  emptyMessage: "No evidence has been recorded for this case.",
                })
              : emptyState({
                  icon: "▣",
                  title: "No evidence yet",
                  description:
                    "Add a file or a reference. Files are hashed with SHA-256 and never executed.",
                }),
          ),
        );
        return;
      }
      if (tab === "sources") {
        body.append(
          panel(
            {
              eyebrow: "PROVENANCE",
              title: `Sources (${report.sources.length})`,
              actions: [
                button("Link existing", () =>
                  G.linkSourceDialog(
                    investigation,
                    report.sources.map((source) => source.id),
                    () => draw(),
                  ),
                ),
                button(
                  "＋ Register & link",
                  () =>
                    G.sourceDialog(
                      {},
                      {
                        onSaved: async (source) => {
                          await api(`/api/investigations/${investigation.id}/sources`, {
                            method: "POST",
                            body: JSON.stringify({ source_id: source.id }),
                          });
                          toast("Source registered and linked.");
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
                    { label: "TITLE", render: (row) => el("strong", {}, row.title) },
                    { label: "CATEGORY", render: (row) => badge(titleCase(row.category), "neutral") },
                    { label: "REFERENCE", render: (row) => referenceNode(row.reference) },
                    { label: "ACCESSED", render: (row) => formatDate(row.accessed_at) },
                    { label: "VERIFICATION", render: (row) => statusBadge(row.verification_status) },
                    {
                      label: "",
                      render: (row) =>
                        button("Unlink", async () => {
                          try {
                            await api(
                              `/api/investigations/${investigation.id}/sources/${row.id}`,
                              { method: "DELETE" },
                            );
                            toast("Source unlinked; the shared record is preserved.");
                            await draw();
                          } catch (error) {
                            toast(error.message, "error");
                          }
                        }),
                    },
                  ],
                  rows: report.sources,
                  emptyMessage: "No sources are linked to this case.",
                })
              : emptyState({
                  icon: "⛁",
                  title: "No sources linked",
                  description: "Sources record where information was consulted and when.",
                }),
          ),
        );
        return;
      }
      if (tab === "relationships") {
        body.append(
          panel(
            {
              eyebrow: "RELATIONSHIP ENGINE",
              title: `Relationships (${report.relationships.length})`,
              actions: [
                button(
                  "＋ Record relationship",
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
                        ? "Link at least two entities first"
                        : "",
                  },
                ),
              ],
            },
            report.relationships.length
              ? table({
                  columns: [
                    { label: "SOURCE", render: (row) => el("strong", {}, row.source_name) },
                    {
                      label: "TYPE",
                      render: (row) => el("span", { class: "relation-type" }, relationshipLabel(row.relationship_type)),
                    },
                    { label: "TARGET", render: (row) => el("strong", {}, row.target_name) },
                    { label: "VERIFICATION", render: (row) => statusBadge(row.verification_status) },
                    { label: "CONFIDENCE", render: (row) => badge(titleCase(row.confidence), "neutral") },
                    { label: "SOURCE", render: (row) => referenceNode(row.source_reference) },
                    {
                      label: "",
                      render: (row) =>
                        button("Delete", async () => {
                          if (
                            !(await confirm({
                              title: "Delete relationship",
                              message: "Remove this relationship record?",
                              confirmLabel: "Delete",
                              danger: true,
                            }))
                          )
                            return;
                          try {
                            await api(`/api/relationships/${row.id}`, { method: "DELETE" });
                            toast("Relationship deleted.");
                            await draw();
                          } catch (error) {
                            toast(error.message, "error");
                          }
                        }, { variant: "button-danger" }),
                    },
                  ],
                  rows: report.relationships,
                  emptyMessage:
                    "No relationships recorded. Link at least two entities to begin.",
                })
              : emptyState({
                  icon: "⟷",
                  title: "No relationships yet",
                  description:
                    "Relationships are shared with the board and graph and carry a verification status.",
                }),
          ),
        );
        return;
      }
      if (tab === "indicators") {
        body.append(loadingBlock("Loading case indicators…"));
        try {
          const data = await api(
            `/api/indicators?investigation_id=${encodeURIComponent(investigation.id)}&limit=1000`,
          );
          body.replaceChildren(
            panel(
              {
                eyebrow: "CASE-SCOPED INDEX",
                title: `Unique indicators (${data.total})`,
                caption: `${data.extraction_count} text match${data.extraction_count === 1 ? "" : "es"}`,
                actions: [button("Open IOC analyzer", () => go("indicators"))],
              },
              el(
                "p",
                { class: "panel-note" },
                "Hosts embedded in a URL or email are not duplicated. Select a value to triage it in the global IOC analyzer.",
              ),
              data.items.length
                ? table({
                    columns: [
                      { label: "TYPE", render: (row) => badge(indicatorTypeLabel(row.type), "info") },
                      {
                        label: "VALUE",
                        render: (row) => el("code", { class: "indicator-value", title: row.value }, row.value),
                      },
                      {
                        label: "ORIGINS",
                        className: "numeric-col",
                        render: (row) => String(row.origin_count),
                      },
                      {
                        label: "ASSESSMENT",
                        render: (row) => statusBadge(row.verification_status),
                      },
                      {
                        label: "FIRST SEEN",
                        render: (row) => (row.first_seen ? formatDate(row.first_seen) : "—"),
                      },
                      {
                        label: "",
                        render: (row) =>
                          button("Triage", () => {
                            G.state.pendingIndicatorSearch = row.value;
                            go("indicators");
                          }),
                      },
                    ],
                    rows: data.items,
                    emptyMessage: "No indicators were extracted for this case.",
                    onRowClick: (row) => {
                      G.state.pendingIndicatorSearch = row.value;
                      go("indicators");
                    },
                  })
                : emptyState({
                    icon: "⌁",
                    title: "No case indicators",
                    description:
                      "Indicators are extracted from observations, linked entities and evidence digests.",
                  }),
            ),
          );
        } catch (error) {
          body.replaceChildren(inlineError(error.message));
        }
        return;
      }
      if (tab === "timeline") {
        body.append(loadingBlock("Loading timeline…"));
        try {
          const timeline = await api(`/api/investigations/${investigation.id}/timeline`);
          body.replaceChildren(
            panel(
              { eyebrow: "CHRONOLOGY", title: "Case timeline", caption: `${timeline.events.length} events` },
              timeline.events.length
                ? timelineList(timeline.events)
                : emptyState({
                    icon: "◷",
                    title: "No timeline events",
                    description: "Events appear as records are added.",
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
    if (!data) return loadingBlock("Reviewing case coverage…");
    const summary = data.summary || {};
    return panel(
      {
        eyebrow: "CASE HEALTH",
        title: "Coverage review",
        caption: `${summary.attention || 0} attention · ${summary.ok || 0} covered`,
        actions: [button("Refresh", onRefresh)],
      },
      el("p", { class: "panel-note" }, data.disclaimer),
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
                check.status === "attention" ? "Attention" : check.status === "info" ? "Review" : "Covered",
                check.status === "attention" ? "danger" : check.status === "info" ? "info" : "success",
              ),
              check.count ? el("strong", { class: "coverage-count" }, String(check.count)) : null,
            ),
            el("h3", {}, check.label),
            el("p", {}, check.detail),
            button("Open", () => onOpen(check.tab)),
          ),
        ),
      ),
    );
  }

  function observationList(observations) {
    if (!observations.length) {
      return el("p", { class: "panel-empty" }, "No observations recorded.");
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
            el("span", {}, `Observed ${formatDate(observation.observed_at, { time: true })}`),
            el("span", {}, "Source: "),
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
              el("strong", {}, event.title),
              el("time", { datetime: event.occurred_at }, formatDate(event.occurred_at, { time: true })),
            ),
            event.collection_basis ? badge(titleCase(event.collection_basis), "neutral") : null,
            event.source_reference
              ? el("p", { class: "record-meta" }, "Source: ", referenceNode(event.source_reference))
              : null,
          ),
        ),
      );
    }
    return list;
  }

  function reportTabContent(investigation, report) {
    const formats = [
      ["html", "HTML report"],
      ["json", "JSON export"],
      ["csv", "CSV export"],
      ["markdown", "Markdown"],
    ];
    return el(
      "div",
      { class: "report-tab" },
      panel(
        { eyebrow: "OUTPUT", title: "Export this case", caption: "Real records only" },
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
              el("span", {}, `Generated from the live ${format === "csv" ? "records" : "case file"}.`),
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
            el("strong", {}, "Printable HTML"),
            el("span", {}, "Open in a new tab and print."),
          ),
        ),
      ),
      panel(
        { eyebrow: "INTERPRETATION", title: "Record classes" },
        el(
          "ul",
          { class: "plain-list" },
          ...Object.entries(reportClassEntries(investigation)).map(([key, value]) =>
            el("li", {}, el("strong", {}, titleCase(key)), ": ", value),
          ),
        ),
      ),
      panel(
        { eyebrow: "SCOPE LIMITS", title: "Limitations" },
        report.limitations.length
          ? el(
              "ul",
              { class: "plain-list" },
              ...report.limitations.map((limitation) => el("li", {}, limitation)),
            )
          : el("p", { class: "panel-empty" }, "No limitations recorded."),
      ),
    );
  }

  function reportClassEntries() {
    return {
      observations: "Analyst-recorded, not independently verified.",
      evidence: "Hashed file or analyst reference; digest confirms identity only.",
      relationships: "Analyst-entered links with a recorded verification status.",
      sources: "Consulted sources with an access timestamp.",
    };
  }

  /* ---------------------------------------------------------------- */
  /* Activity view                                                    */
  /* ---------------------------------------------------------------- */

  async function renderActivity(root) {
    const investigations = await G.loadInvestigations();
    const filter = el(
      "select",
      { class: "input compact-select", "aria-label": "Filter activity by investigation" },
      el("option", { value: "" }, "All investigations"),
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
            eyebrow: "AUDIT TRAIL",
            title: "Workspace activity",
            caption: `${items.length} of ${total}`,
          },
          renderActivityFeed(items),
          offset < total
            ? el(
                "div",
                { class: "toolbar-end" },
                button("Load more", () => load(false)),
              )
            : null,
        ),
      );
    }

    root.append(
      pageHeader({
        eyebrow: "CHRONOLOGICAL RECORD",
        title: "Activity timeline",
        description:
          "Append-only record of workspace mutations. Investigation timelines add observation provenance.",
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
