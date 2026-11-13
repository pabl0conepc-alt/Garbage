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

/* Centrality on the simple undirected graph (self-loops and duplicate pairs
 * ignored): degree, Brandes betweenness normalised by (n-1)(n-2) and harmonic
 * closeness divided by (n-1). Each output array holds node_count doubles.
 * Returns 0, -1 on invalid pointers, -2 for an out-of-range index. */
int gi_graph_centrality(size_t node_count, const uint32_t *sources,
                        const uint32_t *targets, size_t edge_count,
                        double *degree, double *betweenness, double *harmonic);

/* Deterministic Louvain communities on the simple undirected graph. Writes one
 * label per node (labels are 0..k-1 in order of first appearance) and the
 * modularity of the partition. Returns 0, -1 or -2 as above. */
int gi_graph_communities(size_t node_count, const uint32_t *sources,
                         const uint32_t *targets, size_t edge_count,
                         uint32_t *labels, double *modularity);

/* Breadth-first shortest path between two nodes. Returns 0 and writes the node
 * sequence when a path exists, 1 when none exists, -1/-2 on invalid input and
 * -3 when path_capacity is too small. */
int gi_graph_shortest_path(size_t node_count, const uint32_t *sources,
                           const uint32_t *targets, size_t edge_count,
                           uint32_t start, uint32_t goal, uint32_t *path,
                           size_t path_capacity, size_t *path_length);

#ifdef __cplusplus
}
#endif

#endif /* GARBAGE_GRAPH_H */
