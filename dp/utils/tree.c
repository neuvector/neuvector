#include "tree.h"

#define ARM_LEFT   0x00
#define ARM_PARENT 0x01
#define ARM_RIGHT  0x02
#define ARM_MIDDLE ARM_PARENT

static inline uint8_t shift(int result)
{
    if (result > 0) {
        return ARM_RIGHT;
    } else if (result < 0) {
        return ARM_LEFT;
    } else {
        return ARM_PARENT;
    }
}

static inline uint8_t opposite(uint8_t arm)
{
    return ARM_MIDDLE - (arm - ARM_MIDDLE);
}

static tree_node_t *find(tree_node_t *node, void *target, tree_node_t **pparent, uint8_t *arm, tree_cmp_func_t cmp)
{
    tree_node_t *cur = node;
    tree_node_t *last = NULL;
    uint8_t cur_arm = ARM_MIDDLE;
    uint8_t next_arm;

    while ((cur != NULL) && ((next_arm = shift(cmp(target, cur)))) != ARM_MIDDLE) {
        last = cur;
        cur_arm = next_arm;
        cur = cur->links[next_arm];
    }
    *pparent = last;
    *arm = cur_arm;
    return cur;
}

uint32_t tree_count_node(tree_t *root) {
    return root->count;
}

static void replace(tree_node_t **pparent, tree_node_t *new_node, tree_node_t *old_node)
{
    *new_node = *old_node;
    *pparent = new_node;
    if (old_node->links[ARM_LEFT]) {
        (old_node->links[ARM_LEFT])->links[ARM_PARENT] = new_node;
    }
    if (old_node->links[ARM_RIGHT]) {
        (old_node->links[ARM_RIGHT])->links[ARM_PARENT] = new_node;
    }
}

static void swap(tree_t *root, tree_node_t *n1, tree_node_t *n2)
{
    tree_node_t **pparent;
    tree_node_t x;
    tree_node_t *px = &x;

    if (n1->links[ARM_PARENT] != NULL) {
        pparent = &(n1->links[ARM_PARENT]->links[n1->arm]);
    } else {
        pparent = &(root->root);
    }
    replace(pparent, px, n1);

    if (n2->links[ARM_PARENT] != NULL) {
        pparent = &(n2->links[ARM_PARENT]->links[n2->arm]);
    } else {
        pparent = &(root->root);
    }
    replace(pparent, n1, n2);

    if (px->links[ARM_PARENT] != NULL) {
        pparent = &(px->links[ARM_PARENT]->links[px->arm]);
    } else {
        pparent = &(root->root);
    }
    replace(pparent, n2, px);
}

static tree_node_t *follow(tree_node_t *node, uint8_t arm)
{
    if (node == NULL) {
        return node;
    }

    while (node->links[arm] != NULL) {
        node = node->links[arm];
    }

    return node;
}

static tree_node_t *sibling(tree_node_t *node, uint8_t arm)
{
    if (node == NULL) {
        return node;
    }

    if (node->links[arm] != NULL) {
        return follow(node->links[arm], opposite(arm));
    } else {
        while (node->links[ARM_PARENT] != NULL) {
            if (arm == node->arm) {
                node = node->links[ARM_PARENT];
            } else {
                return node->links[ARM_PARENT];
            }
        }
    }
  
    return NULL;
}


tree_node_t *tree_init_node(tree_node_t *node)
{
    node->links[ARM_LEFT] = NULL;
    node->links[ARM_PARENT] = NULL;
    node->links[ARM_RIGHT] = NULL;
    node->arm = ARM_MIDDLE;
    return node;
}

tree_t *tree_init(tree_t *root, tree_cmp_func_t cmp)
{
    if (root != NULL) {
        root->root = NULL;
        root->count = 0;
        root->cmp = cmp;
    }
    return root;
}

tree_node_t *tree_insert_node(tree_t *root, tree_node_t *node)
{
    uint8_t arm;
    tree_node_t *old_node, *parent = NULL;

    tree_init_node(node);

    old_node = find(root->root, node, &parent, &arm, root->cmp);

    // No duplication
    if (old_node != NULL) {
        return NULL;
    }

    if (parent == NULL) {
        root->root = node;
    } else {
        parent->links[arm] = node;
        node->links[ARM_PARENT] = parent;
        node->arm = arm;
    }
    root->count ++;
    return node;
}

tree_node_t *tree_remove_node(tree_t *root, tree_node_t *node)
{
    uint8_t arm;
    tree_node_t *p, **pparent;

    if (node->links[ARM_LEFT] != NULL && node->links[ARM_RIGHT] != NULL) {
        swap(root, node, tree_prev_node(node));
    }

    if (node->links[ARM_PARENT] == NULL) {
        pparent = &(root->root);
    } else {
        pparent = &(node->links[ARM_PARENT]->links[node->arm]);
    }

    arm = (node->links[ARM_LEFT]) ? ARM_LEFT : ARM_RIGHT;

    p = node->links[arm];
    if (p != NULL) {
        p->links[ARM_PARENT] = node->links[ARM_PARENT];
        p->arm = node->arm;
    }
    *pparent = p;

    root->count --;
    return node;
}


tree_node_t *tree_find_node(tree_t *root, void *target)
{
    uint8_t arm;
    tree_node_t *p = root->root;
    
    while (p != NULL && (arm = shift(root->cmp(target, p))) != ARM_MIDDLE) {
        p = p->links[arm];
    }

    return p;
}

tree_node_t *tree_first_node(tree_node_t *node)
{
    return follow(node, ARM_LEFT);
}

tree_node_t *tree_last_node(tree_node_t *node)
{
    return follow(node, ARM_RIGHT);
}

tree_node_t *tree_next_node(tree_node_t *node)
{
    return sibling(node, ARM_RIGHT);
}

tree_node_t *tree_prev_node(tree_node_t *node)
{
    return sibling(node, ARM_LEFT);
}

void tree_traverse(tree_t *root, tree_each_func_t each, void *data)
{
    tree_node_t *p = tree_first_node(root->root), *q;

    while (p != NULL) {
        q = tree_next_node(p);
        each(p, data);
        p = q;
    }
}

void tree_destroy(tree_t *root, tree_remove_func_t remove)
{
    tree_node_t *p, *q;

    if (root == NULL || remove == NULL) {
        return;
    }

    p = tree_first_node(root->root);
    while (p != NULL) {
        q = p;
        while (q->links[ARM_RIGHT]) {
            q = follow(q->links[ARM_RIGHT], ARM_LEFT);
        }
        p = q->links[ARM_PARENT];
        if (p != NULL) {
            uint8_t arm = (p->links[ARM_LEFT] == q) ? ARM_LEFT : ARM_RIGHT;
            p->links[arm] = NULL;
        }
        remove(q);
    }

    tree_init(root, root->cmp);
}
