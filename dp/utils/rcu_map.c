#include "utils/rcu_map.h"

rcu_map_t *rcu_map_init(rcu_map_t *m, uint32_t buckets, int node_offset,
                        cds_lfht_match_fct match_func, rcu_map_hash_fct hash_func)
{
    struct cds_lfht *ht_map;
   
    ht_map = cds_lfht_new(buckets, buckets, 0, CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, NULL);
    if (ht_map == NULL) {
        return NULL;
    }

    m->map = ht_map;
    m->match = match_func;
    m->hash = hash_func;
    m->offset = node_offset;
    return m;
}

int rcu_map_destroy(rcu_map_t *m)
{
    return cds_lfht_destroy(m->map, NULL);
}

void rcu_map_add(rcu_map_t *m, void *data, const void *key)
{
    uint32_t hash = m->hash(key);

    cds_lfht_add(m->map, hash, data);
}

void *rcu_map_add_replace(rcu_map_t *m, void *data, const void *key)
{
    uint32_t hash = m->hash(key);
    struct cds_lfht_node *node;

    node = cds_lfht_add_replace(m->map, hash, m->match, key, data + m->offset);
    if (node == NULL) {
        return NULL;
    } else {
        return (void *)node - m->offset;
    }
}

void *rcu_map_lookup(rcu_map_t *m, const void *key)
{
    struct cds_lfht_iter iter;
    struct cds_lfht_node *node;
    uint32_t hash = m->hash(key);

    cds_lfht_lookup(m->map, hash, m->match, key, &iter);
    node = cds_lfht_iter_get_node(&iter);
    if (node == NULL) {
        return NULL;
    }

    return (void *)node - m->offset;
}

void rcu_map_for_each(rcu_map_t *m, rcu_map_for_each_fct each_func, void *args)
{
    struct cds_lfht_iter iter;
    struct cds_lfht_node *node;

    cds_lfht_for_each(m->map, &iter, node) {
        if (unlikely(each_func(node, args))) {
            break;
        }
    }
}

int rcu_map_del(rcu_map_t *m, void *data)
{
    return cds_lfht_del(m->map, (struct cds_lfht_node *)(data + m->offset));
}


