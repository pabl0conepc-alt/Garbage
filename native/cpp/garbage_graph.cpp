/* Optional C++ graph metrics over analyst-entered relationships. */
#include "garbage_graph.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <unordered_set>
#include <vector>

namespace {

constexpr size_t kMaxNodes = 2'000'000u;

class DisjointSet {
  public:
    explicit DisjointSet(size_t size) : parent_(size), rank_(size, 0) {
        for (size_t index = 0; index < size; ++index) {
            parent_[index] = index;
        }
    }

    size_t find(size_t value) {
        size_t root = value;
        while (parent_[root] != root) {
            root = parent_[root];
        }
        while (parent_[value] != value) {
            const size_t next = parent_[value];
            parent_[value] = root;
            value = next;
        }
        return root;
    }

    void join(size_t left, size_t right) {
        left = find(left);
        right = find(right);
        if (left == right) {
            return;
        }
        if (rank_[left] < rank_[right]) {
            std::swap(left, right);
        }
        parent_[right] = left;
        if (rank_[left] == rank_[right]) {
            ++rank_[left];
        }
    }

  private:
    std::vector<size_t> parent_;
    std::vector<uint32_t> rank_;
};

uint64_t edge_key(uint32_t source, uint32_t target) {
    return (static_cast<uint64_t>(source) << 32u) |
           static_cast<uint64_t>(target);
}

}  // namespace

extern "C" uint32_t gi_graph_abi_version(void) {
    return GI_GRAPH_ABI_VERSION;
}

extern "C" int gi_graph_metrics_calculate(
    size_t node_count, const uint32_t *sources, const uint32_t *targets,
    size_t edge_count, gi_graph_metrics *out) {
    if (out == nullptr) {
        return -1;
    }
    if (node_count > kMaxNodes) {
        return -2;
    }
    if (edge_count != 0u && (sources == nullptr || targets == nullptr)) {
        return -1;
    }

    std::vector<uint64_t> degrees(node_count, 0u);
    std::unordered_set<uint64_t> directed;
    directed.reserve(edge_count * 2u + 1u);
    DisjointSet components(node_count);
    uint64_t self_loops = 0;

    for (size_t index = 0; index < edge_count; ++index) {
        const uint32_t source = sources[index];
        const uint32_t target = targets[index];
        if (source >= node_count || target >= node_count) {
            return -2;
        }
        degrees[source] += 1u;
        degrees[target] += 1u;
        if (source == target) {
            ++self_loops;
        }
        components.join(static_cast<size_t>(source),
                        static_cast<size_t>(target));
        directed.insert(edge_key(source, target));
    }

    uint64_t degree_sum = 0;
    uint64_t max_degree = 0;
    uint32_t max_degree_node = 0;
    uint64_t isolates = 0;
    for (size_t index = 0; index < node_count; ++index) {
        degree_sum += degrees[index];
        if (degrees[index] == 0u) {
            ++isolates;
        }
        if (degrees[index] > max_degree) {
            max_degree = degrees[index];
            max_degree_node = static_cast<uint32_t>(index);
        }
    }

    std::unordered_set<size_t> roots;
    roots.reserve(node_count);
    for (size_t index = 0; index < node_count; ++index) {
        roots.insert(components.find(index));
    }

    uint64_t reciprocal = 0;
    for (size_t index = 0; index < edge_count; ++index) {
        if (directed.count(edge_key(targets[index], sources[index])) != 0u) {
            ++reciprocal;
        }
    }

    const long double possible =
        node_count > 1u
            ? static_cast<long double>(node_count) *
                  static_cast<long double>(node_count - 1u)
            : 1.0L;
    long double density = static_cast<long double>(edge_count) / possible;
    if (density > 1.0L) {
        density = 1.0L;
    }

    out->abi_version = GI_GRAPH_ABI_VERSION;
    out->nodes = node_count;
    out->edges = edge_count;
    out->components = roots.size();
    out->isolates = isolates;
    out->self_loops = self_loops;
    out->reciprocal_edges = reciprocal;
    out->degree_sum = degree_sum;
    out->max_degree = max_degree;
    out->max_degree_node = max_degree_node;
    out->density = static_cast<double>(density);
    return 0;
}

/* ------------------------------------------------------------------------
 * Analytics. These mirror garbage_intel/native.py line by line (same
 * iteration order and arithmetic) so both engines return identical results.
 * ------------------------------------------------------------------------ */

namespace {

bool simple_adjacency(size_t node_count, const uint32_t *sources,
                      const uint32_t *targets, size_t edge_count,
                      std::vector<std::vector<uint32_t>> &out) {
    out.assign(node_count, {});
    for (size_t index = 0; index < edge_count; ++index) {
        const uint32_t source = sources[index];
        const uint32_t target = targets[index];
        if (source >= node_count || target >= node_count) {
            return false;
        }
        if (source == target) {
            continue;
        }
        out[source].push_back(target);
        out[target].push_back(source);
    }
    for (auto &items : out) {
        std::sort(items.begin(), items.end());
        items.erase(std::unique(items.begin(), items.end()), items.end());
    }
    return true;
}

}  // namespace

extern "C" int gi_graph_centrality(size_t node_count, const uint32_t *sources,
                                   const uint32_t *targets, size_t edge_count,
                                   double *degree, double *betweenness,
                                   double *harmonic) {
    if ((edge_count && (!sources || !targets)) ||
        (node_count && (!degree || !betweenness || !harmonic))) {
        return -1;
    }
    if (node_count > kMaxNodes) {
        return -2;
    }
    std::vector<std::vector<uint32_t>> adjacency;
    if (!simple_adjacency(node_count, sources, targets, edge_count, adjacency)) {
        return -2;
    }
    const size_t n = node_count;
    const double scale = n > 1 ? 1.0 / static_cast<double>(n - 1) : 0.0;
    std::vector<double> between(n, 0.0);
    std::vector<double> sigma(n);
    std::vector<double> delta(n);
    std::vector<long long> distance(n);
    std::vector<std::vector<uint32_t>> predecessors(n);
    std::vector<uint32_t> queue;
    std::vector<uint32_t> stack;
    queue.reserve(n);
    stack.reserve(n);
    for (size_t node = 0; node < n; ++node) {
        degree[node] = static_cast<double>(adjacency[node].size()) * scale;
    }
    for (size_t start = 0; start < n; ++start) {
        std::fill(sigma.begin(), sigma.end(), 0.0);
        std::fill(distance.begin(), distance.end(), -1);
        for (auto &items : predecessors) {
            items.clear();
        }
        queue.clear();
        stack.clear();
        sigma[start] = 1.0;
        distance[start] = 0;
        queue.push_back(static_cast<uint32_t>(start));
        for (size_t head = 0; head < queue.size(); ++head) {
            const uint32_t current = queue[head];
            stack.push_back(current);
            for (const uint32_t neighbour : adjacency[current]) {
                if (distance[neighbour] < 0) {
                    distance[neighbour] = distance[current] + 1;
                    queue.push_back(neighbour);
                }
                if (distance[neighbour] == distance[current] + 1) {
                    sigma[neighbour] += sigma[current];
                    predecessors[neighbour].push_back(current);
                }
            }
        }
        double reach = 0.0;
        for (size_t node = 0; node < n; ++node) {
            if (distance[node] > 0) {
                reach += 1.0 / static_cast<double>(distance[node]);
            }
        }
        harmonic[start] = reach * scale;
        std::fill(delta.begin(), delta.end(), 0.0);
        while (!stack.empty()) {
            const uint32_t node = stack.back();
            stack.pop_back();
            for (const uint32_t predecessor : predecessors[node]) {
                delta[predecessor] +=
                    (sigma[predecessor] / sigma[node]) * (1.0 + delta[node]);
            }
            if (node != start) {
                between[node] += delta[node];
            }
        }
    }
    const double norm =
        n > 2 ? 1.0 / (static_cast<double>(n - 1) * static_cast<double>(n - 2)) : 0.0;
    for (size_t node = 0; node < n; ++node) {
        betweenness[node] = between[node] * norm;
    }
    return 0;
}

namespace {

using WeightedGraph = std::vector<std::map<uint32_t, double>>;

double row_sum(const std::map<uint32_t, double> &row) {
    double total = 0.0;
    for (const auto &item : row) {
        total += item.second;
    }
    return total;
}

}  // namespace

extern "C" int gi_graph_communities(size_t node_count, const uint32_t *sources,
                                    const uint32_t *targets, size_t edge_count,
                                    uint32_t *labels, double *modularity) {
    if ((edge_count && (!sources || !targets)) || (node_count && !labels) || !modularity) {
        return -1;
    }
    if (node_count > kMaxNodes) {
        return -2;
    }
    *modularity = 0.0;
    if (node_count == 0) {
        return 0;
    }
    std::vector<std::vector<uint32_t>> adjacency;
    if (!simple_adjacency(node_count, sources, targets, edge_count, adjacency)) {
        return -2;
    }
    WeightedGraph weights(node_count);
    double total = 0.0;
    for (size_t node = 0; node < node_count; ++node) {
        for (const uint32_t neighbour : adjacency[node]) {
            weights[node][neighbour] = 1.0;
        }
        total += row_sum(weights[node]);
    }
    std::vector<uint32_t> membership(node_count);
    for (size_t node = 0; node < node_count; ++node) {
        membership[node] = static_cast<uint32_t>(node);
    }
    if (total == 0.0) {
        for (size_t node = 0; node < node_count; ++node) {
            labels[node] = membership[node];
        }
        return 0;
    }
    WeightedGraph graph = weights;
    for (int level = 0; level < 16; ++level) {
        const size_t size = graph.size();
        std::vector<double> strength(size);
        for (size_t node = 0; node < size; ++node) {
            strength[node] = row_sum(graph[node]);
        }
        std::vector<uint32_t> community(size);
        for (size_t node = 0; node < size; ++node) {
            community[node] = static_cast<uint32_t>(node);
        }
        std::vector<double> totals = strength;
        bool improved = false;
        for (int pass = 0; pass < 100; ++pass) {
            bool moved = false;
            for (size_t node = 0; node < size; ++node) {
                const uint32_t current = community[node];
                std::map<uint32_t, double> links;
                for (const auto &item : graph[node]) {
                    if (item.first == node) {
                        continue;
                    }
                    links[community[item.first]] += item.second;
                }
                totals[current] -= strength[node];
                uint32_t best = current;
                const auto own = links.find(current);
                double best_gain = (own == links.end() ? 0.0 : own->second) -
                                   totals[current] * strength[node] / total;
                for (const auto &candidate : links) {
                    const double gain =
                        candidate.second - totals[candidate.first] * strength[node] / total;
                    if (gain > best_gain + 1e-12) {
                        best = candidate.first;
                        best_gain = gain;
                    }
                }
                totals[best] += strength[node];
                if (best != current) {
                    community[node] = best;
                    moved = true;
                    improved = true;
                }
            }
            if (!moved) {
                break;
            }
        }
        if (!improved) {
            break;
        }
        std::map<uint32_t, uint32_t> renumber;
        std::vector<uint32_t> order;
        for (size_t node = 0; node < size; ++node) {
            if (renumber.emplace(community[node], static_cast<uint32_t>(renumber.size())).second) {
                order.push_back(community[node]);
            }
        }
        for (auto &item : membership) {
            item = renumber[community[item]];
        }
        WeightedGraph aggregated(renumber.size());
        for (size_t node = 0; node < size; ++node) {
            const uint32_t left = renumber[community[node]];
            for (const auto &item : graph[node]) {
                aggregated[left][renumber[community[item.first]]] += item.second;
            }
        }
        if (aggregated.size() == size) {
            break;
        }
        graph = std::move(aggregated);
    }
    // Modularity, summed over labels in order of first appearance.
    std::vector<uint32_t> label_order;
    std::map<uint32_t, double> inside;
    std::map<uint32_t, double> degrees;
    for (size_t node = 0; node < node_count; ++node) {
        const uint32_t label = membership[node];
        if (degrees.find(label) == degrees.end()) {
            label_order.push_back(label);
            degrees[label] = 0.0;
        }
        degrees[label] += row_sum(weights[node]);
        for (const auto &item : weights[node]) {
            if (membership[item.first] == label) {
                inside[label] += item.second;
            }
        }
    }
    double quality = 0.0;
    for (const uint32_t label : label_order) {
        const double ratio = degrees[label] / total;
        quality += inside[label] / total - ratio * ratio;
    }
    *modularity = quality;
    for (size_t node = 0; node < node_count; ++node) {
        labels[node] = membership[node];
    }
    return 0;
}

extern "C" int gi_graph_shortest_path(size_t node_count, const uint32_t *sources,
                                      const uint32_t *targets, size_t edge_count,
                                      uint32_t start, uint32_t goal, uint32_t *path,
                                      size_t path_capacity, size_t *path_length) {
    if ((edge_count && (!sources || !targets)) || !path || !path_length) {
        return -1;
    }
    *path_length = 0;
    if (node_count > kMaxNodes || start >= node_count || goal >= node_count) {
        return -2;
    }
    std::vector<std::vector<uint32_t>> adjacency;
    if (!simple_adjacency(node_count, sources, targets, edge_count, adjacency)) {
        return -2;
    }
    std::vector<long long> parent(node_count, -1);
    std::vector<bool> seen(node_count, false);
    std::vector<uint32_t> queue{start};
    seen[start] = true;
    for (size_t head = 0; head < queue.size(); ++head) {
        const uint32_t current = queue[head];
        if (current == goal) {
            break;
        }
        for (const uint32_t neighbour : adjacency[current]) {
            if (!seen[neighbour]) {
                seen[neighbour] = true;
                parent[neighbour] = current;
                queue.push_back(neighbour);
            }
        }
    }
    if (!seen[goal]) {
        return 1;
    }
    std::vector<uint32_t> reversed{goal};
    while (reversed.back() != start) {
        reversed.push_back(static_cast<uint32_t>(parent[reversed.back()]));
    }
    if (reversed.size() > path_capacity) {
        return -3;
    }
    for (size_t index = 0; index < reversed.size(); ++index) {
        path[index] = reversed[reversed.size() - 1 - index];
    }
    *path_length = reversed.size();
    return 0;
}
