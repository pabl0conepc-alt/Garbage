/* Optional C++ graph metrics for the investigation relationship graph. */
#ifndef GARBAGE_GRAPH_H
#define GARBAGE_GRAPH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GI_GRAPH_ABI_VERSION 1u

typedef struct {
    uint32_t abi_version;
    uint64_t nodes;
    uint64_t edges;
    uint64_t components;
    uint64_t isolates;
    uint64_t self_loops;
    uint64_t reciprocal_edges;
    uint64_t degree_sum;
    uint64_t max_degree;
    uint32_t max_degree_node;
    double density;
} gi_graph_metrics;

uint32_t gi_graph_abi_version(void);

/* Computes undirected components and degree facts. Edges are directed pairs of
 * node indexes. Returns 0 on success, -1 on invalid pointers, -2 for an
 * out-of-range node index or too many nodes. */
int gi_graph_metrics_calculate(size_t node_count, const uint32_t *sources,
                               const uint32_t *targets, size_t edge_count,
                               gi_graph_metrics *out);

#ifdef __cplusplus
}
#endif

#endif /* GARBAGE_GRAPH_H */
