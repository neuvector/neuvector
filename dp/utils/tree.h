#ifndef __TREE_H__
#define __TREE_H__

#include <stddef.h>

typedef struct tree_node_ {
    struct tree_node_ *links[3];
    uint8_t arm;
} tree_node_t;

typedef int (*tree_cmp_func_t)(void *, tree_node_t *);
typedef void (*tree_each_func_t)(tree_node_t *, void *);
typedef void (*tree_remove_func_t)(tree_node_t *);

typedef struct tree_ {
    tree_node_t *root;
    tree_cmp_func_t cmp;
    uint32_t count;
} tree_t;

tree_t *tree_init(tree_t *root, tree_cmp_func_t cmp);
void tree_destroy(tree_t *root, tree_remove_func_t remove);
void tree_traverse(tree_t *root, tree_each_func_t each, void *data);
tree_node_t *tree_init_node(tree_node_t *node );
uint32_t tree_count_node(tree_t *root);
tree_node_t *tree_insert_node(tree_t *root, tree_node_t *node);
tree_node_t *tree_remove_node(tree_t *root, tree_node_t *node);
tree_node_t *tree_first_node(tree_node_t *node);
tree_node_t *tree_last_node(tree_node_t *node);
tree_node_t *tree_prev_node(tree_node_t *node);
tree_node_t *tree_next_node(tree_node_t *node);
tree_node_t *tree_find_node(tree_t *root, void *target);

#endif
