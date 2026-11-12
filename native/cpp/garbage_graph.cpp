/* Optional C++ graph metrics over analyst-entered relationships. */
#include "garbage_graph.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
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
