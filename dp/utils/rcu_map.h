#ifndef __RCU_MAP_H__
#define __RCU_MAP_H__

#include <stdint.h>

#include "urcu.h"
#include "urcu/rculfhash.h"

typedef uint32_t (*rcu_map_hash_fct)(const void *key);
// return true to exit loop
typedef bool (*rcu_map_for_each_fct)(struct cds_lfht_node *ht_node, void *args);

typedef struct rcu_map_ {
    struct cds_lfht *map;
    cds_lfht_match_fct match;
    rcu_map_hash_fct hash;
    int offset;
} rcu_map_t;


rcu_map_t *rcu_map_init(rcu_map_t *m, uint32_t buckets, int node_offset,
                        cds_lfht_match_fct match_func, rcu_map_hash_fct hash_func);
int rcu_map_destroy(rcu_map_t *m);

void rcu_map_add(rcu_map_t *m, void *data, const void *key);
void *rcu_map_add_replace(rcu_map_t *m, void *data, const void *key);
void *rcu_map_lookup(rcu_map_t *m, const void *key);
void rcu_map_for_each(rcu_map_t *m, rcu_map_for_each_fct each_func, void *args);
int rcu_map_del(rcu_map_t *m, void *data);

#define RCU_MAP_FOR_EACH(m, node) \
    struct cds_lfht_iter iter; \
    cds_lfht_for_each((m)->map, &iter, node)

#define RCU_MAP_ITR_FOR_EACH(m, iter, node) \
    cds_lfht_for_each((m)->map, &iter, node)

#endif
