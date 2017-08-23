/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Red-black tree for keeping track parents of protected inodes structure
 *
 * Notes:
 *  - Make sence with own kmem_cache_* allocation
 *
 * Timeline:
 *  - Created: 29.XI.2016
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#ifndef P_LKRG_PROTECTED_P_INODES_RB_TREE_H
#define P_LKRG_PROTECTED_P_INODES_RB_TREE_H

#define p_alloc_p_inodes()      kmem_cache_alloc(p_p_inodes_cache, GFP_ATOMIC)
#define p_free_p_inodes(name)   kmem_cache_free(p_p_inodes_cache, (void *)(name))

#ifdef P_LKRG_DEBUG
#define P_DUMP_P_RB_INODES_TREE                                                                          \
do {                                                                                                     \
   struct rb_node *p_node;                                                                               \
                                                                                                         \
   for (p_node = rb_first(&p_global_p_inodes_root); p_node; p_node = rb_next(p_node))                    \
      p_debug_log(P_LKRG_DBG, "inode => 0x%p\n",                                                         \
                                          rb_entry(p_node, struct p_protected_p_inode, p_rb)->p_inode);  \
} while(0);
#endif

struct p_protected_p_inode {

   struct rb_node p_rb;
   struct inode *p_inode;

   const struct inode_operations *p_inode_orig;
   struct inode_operations p_inode_new;

   const struct file_operations *p_file_orig;
   struct file_operations p_file_new;

   unsigned long p_num;

};

extern struct kmem_cache *p_p_inodes_cache;
extern struct rb_root p_global_p_inodes_root;


static inline void p_rb_init_p_inode_node(struct rb_node *rb) {

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_rb_init_p_inode_node>\n");

   rb->__rb_parent_color = 0;
   rb->rb_right = NULL;
   rb->rb_left = NULL;
   RB_CLEAR_NODE(rb);

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_rb_init_p_inode_node>\n");
}

static inline void p_iget_parent(struct inode *p_inode) {

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_iget_parent>\n");

   /* Increment reference counter */
   atomic_inc(&p_inode->i_count);

   /* Mark inode as dirty */
   mark_inode_dirty(p_inode);
//   __mark_inode_dirty(p_inode, I_DIRTY_SYNC);

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_iget_parent>\n");
}

static inline void p_iput_parent(struct inode *p_inode) {

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_iput_parent>\n");

   /* Decrement reference counter */
   iput(p_inode);

   /* Mark inode as dirty */
   mark_inode_dirty(p_inode);
//   __mark_inode_dirty(p_inode, I_DIRTY_SYNC);

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_iput_parent>\n");
}


struct p_protected_p_inode *p_rb_find_p_inode(struct rb_root *p_root, struct inode *p_arg);
struct p_protected_p_inode *p_rb_add_p_inode(struct rb_root *p_root, struct inode *p_arg, struct p_protected_p_inode *p_source);
void p_rb_del_p_inode(struct rb_root *p_root, struct p_protected_p_inode *p_source);
int p_init_rb_p_inodes(void);
void p_delete_rb_p_inodes(void);

#endif
