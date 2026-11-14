"use strict";

/* Graph layouts. Each takes nodes ({id, degree}), edges
 * ({source_entity_id, target_entity_id}) and options, and writes x/y on the
 * nodes. Disconnected components are laid out separately and packed in rows,
 * so a few isolated entities never squash the main cluster. Deterministic:
 * the same graph always lands in the same place.
 */

(function () {
  const G = window.GARBAGE;
  const SPACING = 120;

  function adjacency(nodes, edges) {
    const map = new Map(nodes.map((node) => [node.id, new Set()]));
    for (const edge of edges) {
      if (edge.source_entity_id === edge.target_entity_id) continue;
      map.get(edge.source_entity_id)?.add(edge.target_entity_id);
      map.get(edge.target_entity_id)?.add(edge.source_entity_id);
    }
    return map;
  }

  function components(nodes, neighbours) {
    const seen = new Set();
    const groups = [];
    for (const node of [...nodes].sort((a, b) => b.degree - a.degree || a.id.localeCompare(b.id))) {
      if (seen.has(node.id)) continue;
      const group = [];
      const queue = [node.id];
      seen.add(node.id);
      while (queue.length) {
        const current = queue.shift();
        group.push(current);
        for (const next of [...(neighbours.get(current) || [])].sort()) {
          if (!seen.has(next)) {
            seen.add(next);
            queue.push(next);
          }
        }
      }
      groups.push(group);
    }
    return groups.sort((a, b) => b.length - a.length);
  }

  /* BFS layers from a root; returns [[ids at depth 0], [depth 1], ...]. */
  function layers(rootId, members, neighbours) {
    const allowed = new Set(members);
    const depth = new Map([[rootId, 0]]);
    const result = [[rootId]];
    const queue = [rootId];
    while (queue.length) {
      const current = queue.shift();
      for (const next of [...(neighbours.get(current) || [])].sort()) {
        if (!allowed.has(next) || depth.has(next)) continue;
        const level = depth.get(current) + 1;
        depth.set(next, level);
        (result[level] ||= []).push(next);
        queue.push(next);
      }
    }
    return { result, depth };
  }

  function pickRoot(members, byId, preferred) {
    if (preferred && members.includes(preferred)) return preferred;
    return [...members].sort((a, b) => byId.get(b).degree - byId.get(a).degree || a.localeCompare(b))[0];
  }

  /* Shelf packing: each block has local coordinates; move them into rows. */
  function pack(blocks, width, height) {
    const area = blocks.reduce((total, block) => total + (block.w + SPACING) * (block.h + SPACING), 0);
    const rowWidth = Math.max(width, Math.sqrt(area) * 1.4);
    let x = 0;
    let y = 0;
    let rowHeight = 0;
    for (const block of blocks) {
      if (x > 0 && x + block.w > rowWidth) {
        x = 0;
        y += rowHeight + SPACING;
        rowHeight = 0;
      }
      for (const node of block.nodes) {
        node.x += x - block.minX;
        node.y += y - block.minY;
      }
      x += block.w + SPACING;
      rowHeight = Math.max(rowHeight, block.h);
    }
    const all = blocks.flatMap((block) => block.nodes);
    const cx = (Math.min(...all.map((n) => n.x)) + Math.max(...all.map((n) => n.x))) / 2;
    const cy = (Math.min(...all.map((n) => n.y)) + Math.max(...all.map((n) => n.y))) / 2;
    for (const node of all) {
      node.x += width / 2 - cx;
      node.y += height / 2 - cy;
    }
  }

  function block(nodes) {
    const minX = Math.min(...nodes.map((node) => node.x));
    const minY = Math.min(...nodes.map((node) => node.y));
    return {
      nodes,
      minX,
      minY,
      w: Math.max(...nodes.map((node) => node.x)) - minX,
      h: Math.max(...nodes.map((node) => node.y)) - minY,
    };
  }

  function perComponent(nodes, edges, options, place) {
    const byId = new Map(nodes.map((node) => [node.id, node]));
    const neighbours = adjacency(nodes, edges);
    const blocks = components(nodes, neighbours).map((members) => {
      const local = members.map((id) => byId.get(id));
      place(members, local, byId, neighbours);
      return block(local);
    });
    pack(blocks, options.width, options.height);
  }

  /* Hierarchical: BFS layers from the selected or best-connected node,
     ordered by barycentre sweeps to cut crossings. */
  function hierarchical(nodes, edges, options) {
    perComponent(nodes, edges, options, (members, local, byId, neighbours) => {
      const { result } = layers(pickRoot(members, byId, options.rootId), members, neighbours);
      const position = new Map();
      result.forEach((level) => level.forEach((id, index) => position.set(id, index)));
      for (let sweep = 0; sweep < 4; sweep += 1) {
        const order = sweep % 2 === 0 ? result.slice(1) : result.slice(0, -1).reverse();
        for (const level of order) {
          const score = new Map(
            level.map((id) => {
              const linked = [...neighbours.get(id)].filter((other) => position.has(other) && !level.includes(other));
              const mean = linked.length ? linked.reduce((sum, other) => sum + position.get(other), 0) / linked.length : position.get(id);
              return [id, mean];
            }),
          );
          level.sort((a, b) => score.get(a) - score.get(b) || a.localeCompare(b));
          level.forEach((id, index) => position.set(id, index));
        }
      }
      const widest = Math.max(...result.map((level) => level.length));
      result.forEach((level, depth) => {
        const offset = ((widest - level.length) * SPACING) / 2;
        level.forEach((id, index) => {
          const node = byId.get(id);
          node.x = offset + index * SPACING;
          node.y = depth * SPACING * 1.1;
        });
      });
    });
  }

  /* Radial: rings by hop distance; each subtree gets a wedge sized by its
     number of leaves so branches do not overlap. */
  function radial(nodes, edges, options) {
    perComponent(nodes, edges, options, (members, local, byId, neighbours) => {
      const root = pickRoot(members, byId, options.rootId);
      const { depth } = layers(root, members, neighbours);
      const children = new Map(members.map((id) => [id, []]));
      for (const id of members) {
        if (id === root) continue;
        const parent = [...neighbours.get(id)].filter((other) => depth.get(other) === depth.get(id) - 1).sort()[0];
        if (parent) children.get(parent).push(id);
      }
      const leaves = new Map();
      const countLeaves = (id) => {
        const kids = children.get(id);
        const total = kids.length ? kids.reduce((sum, kid) => sum + countLeaves(kid), 0) : 1;
        leaves.set(id, total);
        return total;
      };
      countLeaves(root);
      const ring = SPACING * 1.15;
      const place = (id, start, end) => {
        const node = byId.get(id);
        const level = depth.get(id);
        const angle = (start + end) / 2;
        node.x = Math.cos(angle) * ring * level;
        node.y = Math.sin(angle) * ring * level;
        let cursor = start;
        for (const kid of children.get(id).sort((a, b) => leaves.get(b) - leaves.get(a) || a.localeCompare(b))) {
          const span = ((end - start) * leaves.get(kid)) / leaves.get(id);
          place(kid, cursor, cursor + span);
          cursor += span;
        }
      };
      place(root, -Math.PI / 2, (Math.PI * 3) / 2);
    });
  }

  /* Small force pass used inside communities and for the force layout. */
  /* Barnes-Hut: above this many nodes, repulsion from distant groups is
     taken from their centre of mass (quadtree, theta 1.0), so a relaxation
     step costs n log n instead of n². Smaller graphs keep the exact sum. */
  const BARNES_HUT_FROM = 200;
  const THETA = 1.0;

  function cell(x, y, size) {
    return { x, y, size, mass: 0, cx: 0, cy: 0, body: null, kids: null };
  }

  function insert(target, node, depth) {
    target.cx = (target.cx * target.mass + node.x) / (target.mass + 1);
    target.cy = (target.cy * target.mass + node.y) / (target.mass + 1);
    target.mass += 1;
    if (target.mass === 1) {
      target.body = node;
      return;
    }
    if (depth > 24) return; // coincident points stay together in this cell
    if (!target.kids) {
      target.kids = [null, null, null, null];
      const previous = target.body;
      target.body = null;
      if (previous) place(target, previous, depth);
    }
    place(target, node, depth);
  }

  function place(parent, node, depth) {
    const half = parent.size / 2;
    const right = node.x >= parent.x + half ? 1 : 0;
    const below = node.y >= parent.y + half ? 1 : 0;
    const index = below * 2 + right;
    if (!parent.kids[index]) parent.kids[index] = cell(parent.x + right * half, parent.y + below * half, half);
    insert(parent.kids[index], node, depth + 1);
  }

  function quadtree(local) {
    let minX = Infinity;
    let minY = Infinity;
    let maxX = -Infinity;
    let maxY = -Infinity;
    for (const node of local) {
      minX = Math.min(minX, node.x);
      minY = Math.min(minY, node.y);
      maxX = Math.max(maxX, node.x);
      maxY = Math.max(maxY, node.y);
    }
    const root = cell(minX, minY, Math.max(maxX - minX, maxY - minY, 1) + 1);
    for (const node of local) insert(root, node, 0);
    return root;
  }

  function repel(target, node, strength) {
    if (!target || !target.mass || target.body === node) return;
    let dx = node.x - target.cx;
    let dy = node.y - target.cy;
    let distance = Math.hypot(dx, dy);
    if (target.kids && target.size / Math.max(distance, 0.01) > THETA) {
      for (const kid of target.kids) repel(kid, node, strength);
      return;
    }
    if (distance < 0.5) {
      dx = 0.5;
      dy = 0.1;
      distance = Math.hypot(dx, dy);
    }
    const force = (target.mass * strength) / distance;
    node.vx += (dx / distance) * force;
    node.vy += (dy / distance) * force;
  }

  function relax(local, edges, size, iterations) {
    const ids = new Set(local.map((node) => node.id));
    const byId = new Map(local.map((node) => [node.id, node]));
    const inner = edges.filter((edge) => ids.has(edge.source_entity_id) && ids.has(edge.target_entity_id));
    const k = Math.max(60, size / Math.sqrt(Math.max(1, local.length)) * 0.9);
    let temperature = size / 4;
    const cooling = temperature / (iterations + 1);
    for (let step = 0; step < iterations; step += 1) {
      for (const node of local) {
        node.vx = 0;
        node.vy = 0;
      }
      if (local.length > BARNES_HUT_FROM) {
        const tree = quadtree(local);
        for (const node of local) repel(tree, node, k * k);
      } else for (let i = 0; i < local.length; i += 1) {
        for (let j = i + 1; j < local.length; j += 1) {
          const a = local[i];
          const b = local[j];
          let dx = a.x - b.x;
          let dy = a.y - b.y;
          if (!dx && !dy) {
            dx = 0.5;
            dy = (i - j) * 0.1;
          }
          const distance = Math.max(0.5, Math.hypot(dx, dy));
          const force = (k * k) / distance;
          a.vx += (dx / distance) * force;
          a.vy += (dy / distance) * force;
          b.vx -= (dx / distance) * force;
          b.vy -= (dy / distance) * force;
        }
      }
      for (const edge of inner) {
        const a = byId.get(edge.source_entity_id);
        const b = byId.get(edge.target_entity_id);
        const dx = a.x - b.x;
        const dy = a.y - b.y;
        const distance = Math.max(1, Math.hypot(dx, dy));
        const force = (distance * distance) / k;
        a.vx -= (dx / distance) * force;
        a.vy -= (dy / distance) * force;
        b.vx += (dx / distance) * force;
        b.vy += (dy / distance) * force;
      }
      for (const node of local) {
        node.vx -= node.x * 0.01;
        node.vy -= node.y * 0.01;
        const speed = Math.max(0.01, Math.hypot(node.vx, node.vy));
        node.x += (node.vx / speed) * Math.min(speed, temperature);
        node.y += (node.vy / speed) * Math.min(speed, temperature);
      }
      temperature = Math.max(0.5, temperature - cooling);
    }
  }

  function seedCircle(local, radius) {
    local.forEach((node, index) => {
      const angle = (index / Math.max(1, local.length)) * Math.PI * 2;
      node.x = Math.cos(angle) * radius;
      node.y = Math.sin(angle) * radius;
    });
  }

  function force(nodes, edges, options) {
    const iterations = nodes.length > 1000 ? 50 : nodes.length > 300 ? 70 : nodes.length > 120 ? 160 : 240;
    perComponent(nodes, edges, options, (members, local) => {
      if (local.length === 1) {
        local[0].x = 0;
        local[0].y = 0;
        return;
      }
      const size = Math.sqrt(local.length) * SPACING * 1.2;
      seedCircle(local, size / 3);
      relax(local, edges, size, iterations);
    });
  }

  /* Community: Louvain groups laid out apart, each relaxed on its own. */
  function community(nodes, edges, options) {
    const groups = new Map();
    for (const node of nodes) {
      const id = options.analytics?.nodes?.[node.id]?.community ?? -1;
      if (!groups.has(id)) groups.set(id, []);
      groups.get(id).push(node);
    }
    const blocks = [...groups.values()]
      .sort((a, b) => b.length - a.length)
      .map((local) => {
        const size = Math.sqrt(local.length) * SPACING;
        seedCircle(local, local.length > 1 ? size / 3 : 0);
        if (local.length > 2) relax(local, edges, size, 140);
        return block(local);
      });
    pack(blocks, options.width, options.height);
  }

  /* Concentric: most central nodes in the middle ring, by betweenness. */
  function concentric(nodes, edges, options) {
    const metric = (node) => options.analytics?.nodes?.[node.id]?.betweenness ?? node.degree / 100;
    const community = (node) => options.analytics?.nodes?.[node.id]?.community ?? 0;
    const ranked = [...nodes].sort((a, b) => metric(b) - metric(a) || b.degree - a.degree || a.id.localeCompare(b.id));
    const rings = [];
    let capacity = 1;
    let index = 0;
    while (index < ranked.length) {
      rings.push(ranked.slice(index, index + capacity));
      index += capacity;
      capacity = Math.max(6, Math.round(capacity * 1.8 + 4));
    }
    rings.forEach((ring, level) => {
      ring.sort((a, b) => community(a) - community(b) || a.id.localeCompare(b.id));
      const radius = level * SPACING * 1.1;
      ring.forEach((node, position) => {
        const angle = (position / ring.length) * Math.PI * 2 - Math.PI / 2;
        node.x = options.width / 2 + Math.cos(angle) * radius;
        node.y = options.height / 2 + Math.sin(angle) * radius;
      });
    });
  }

  /* Columns by entity type, rows ordered by community then degree. */
  function typeColumns(nodes, edges, options) {
    const types = [...new Set(nodes.map((node) => node.entity_type))].sort();
    const community = (node) => options.analytics?.nodes?.[node.id]?.community ?? 0;
    types.forEach((type, column) => {
      const members = nodes
        .filter((node) => node.entity_type === type)
        .sort((a, b) => community(a) - community(b) || b.degree - a.degree || a.id.localeCompare(b.id));
      members.forEach((node, row) => {
        node.x = column * SPACING * 1.9;
        node.y = row * SPACING * 0.62;
      });
    });
    const height = Math.max(...nodes.map((node) => node.y));
    for (const node of nodes) node.y += options.height / 2 - height / 2;
  }

  function circle(nodes, edges, options) {
    const community = (node) => options.analytics?.nodes?.[node.id]?.community ?? 0;
    const ordered = [...nodes].sort((a, b) => community(a) - community(b) || a.id.localeCompare(b.id));
    const radius = Math.max(Math.min(options.width, options.height) * 0.36, (ordered.length * 34) / (Math.PI * 2));
    ordered.forEach((node, index) => {
      const angle = (index / ordered.length) * Math.PI * 2 - Math.PI / 2;
      node.x = options.width / 2 + Math.cos(angle) * radius;
      node.y = options.height / 2 + Math.sin(angle) * radius;
    });
  }

  function grid(nodes) {
    const columns = Math.max(1, Math.ceil(Math.sqrt(nodes.length)));
    [...nodes].sort((a, b) => a.entity_type.localeCompare(b.entity_type) || a.name.localeCompare(b.name)).forEach((node, index) => {
      node.x = 100 + (index % columns) * 190;
      node.y = 90 + Math.floor(index / columns) * 150;
    });
  }

  G.graphLayouts = {
    force: { label: "Força (agrupa vizinhos)", run: force },
    community: { label: "Por comunidade", run: community },
    hierarchical: { label: "Hierárquico (a partir do nó)", run: hierarchical },
    radial: { label: "Radial (anéis de distância)", run: radial },
    concentric: { label: "Concêntrico (centralidade)", run: concentric },
    columns: { label: "Colunas por tipo", run: typeColumns },
    circle: { label: "Circular", run: circle },
    grid: { label: "Grade", run: grid },
  };
})();
