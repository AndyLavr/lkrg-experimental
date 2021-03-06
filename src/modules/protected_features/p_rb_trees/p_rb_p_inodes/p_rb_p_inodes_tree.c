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

#include "../../../../p_lkrg_main.h"


struct kmem_cache *p_p_inodes_cache = NULL;
struct rb_root p_global_p_inodes_root = RB_ROOT;


struct p_protected_p_inode *p_rb_find_p_inode(struct rb_root *p_root, struct inode *p_arg) {

   struct rb_node *p_node = p_root->rb_node;
   struct p_protected_p_inode *p_struct = NULL;
   struct p_protected_p_inode *p_ret = NULL;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_rb_find_p_inode>\n");

   while(p_node) {
      p_struct = rb_entry(p_node, struct p_protected_p_inode, p_rb);

      if (p_arg < p_struct->p_inode) {
         p_node = p_node->rb_left;
      } else if (p_arg > p_struct->p_inode) {
         p_node = p_node->rb_right;
      } else {
         p_ret = p_struct;
         goto p_rb_find_p_inode_out;
      }
   }

p_rb_find_p_inode_out:

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_rb_find_p_inode> (p_ret => 0x%p)\n",p_ret);

   return p_ret;
}


struct p_protected_p_inode *p_rb_add_p_inode(struct rb_root *p_root, struct inode *p_arg, struct p_protected_p_inode *p_source) {

   struct rb_node **p_node = &p_root->rb_node;
   struct rb_node *p_parent = NULL;
   struct p_protected_p_inode *p_struct;
   struct p_protected_p_inode *p_ret = NULL;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_rb_add_p_inode>\n");

   while(*p_node) {
      p_parent = *p_node;
      p_struct = rb_entry(p_parent, struct p_protected_p_inode, p_rb);

      if (p_arg < p_struct->p_inode) {
         p_node = &(*p_node)->rb_left;
      } else if (p_arg > p_struct->p_inode) {
         p_node = &(*p_node)->rb_right;
      } else {
         p_ret = p_struct;
         goto p_rb_add_p_inode_out;
      }

   }

   rb_link_node(&p_source->p_rb, p_parent, p_node);   // Insert this new node as a red leaf
   rb_insert_color(&p_source->p_rb, p_root);          // Rebalance the tree, finish inserting

p_rb_add_p_inode_out:

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_rb_add_p_inode> (p_ret => 0x%p)\n",p_ret);

   return p_ret;
}


void p_rb_del_p_inode(struct rb_root *p_root, struct p_protected_p_inode *p_source) {

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_rb_del_p_inode>\n");

   rb_erase(&p_source->p_rb, p_root);       // Erase the node
   p_free_p_inodes(p_source);               // Free the memory

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_rb_del_p_inode>\n");
}

static void p_p_inodes_cache_init(void *p_arg) {

   struct p_protected_p_inode *p_struct = p_arg;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_p_inodes_cache_init>\n");

   memset(p_struct, 0x0, sizeof(struct p_protected_p_inode));

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_p_inodes_cache_init>\n");
}

int p_init_rb_p_inodes(void) {

   int p_ret = P_LKRG_SUCCESS;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_init_rb_p_inodes>\n");

   if ( (p_p_inodes_cache = kmem_cache_create("protected_p_inodes", sizeof(struct p_protected_p_inode),
                                              0x0, SLAB_HWCACHE_ALIGN, p_p_inodes_cache_init)) == NULL) {
      p_print_log(P_LKRG_ERR,
             "kmem_cache_create() for parent inodes error! :(\n");
      p_ret = -ENOMEM;
   }

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_init_rb_p_inodes> (p_ret => %d)\n",p_ret);

   return p_ret;
}

void p_delete_rb_p_inodes(void) {

   struct rb_node *p_node;
   struct p_protected_p_inode *p_tmp;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_delete_rb_p_inodes>\n");

   if (p_p_inodes_cache) {
      for (p_node = rb_first(&p_global_p_inodes_root); p_node; p_node = rb_next(p_node)) {
         p_tmp = rb_entry(p_node, struct p_protected_p_inode, p_rb);
         p_print_log(P_LKRG_INFO, "Deleting parent inode[0x%p] => %ld\n",
                                                   p_tmp->p_inode,p_tmp->p_num);
         if (p_tmp->p_num > 1)
            p_tmp->p_num = 1;
         p_unprotect_p_inode(p_tmp->p_inode);
//         p_free_p_inodes(p_tmp);
      }
      kmem_cache_destroy(p_p_inodes_cache);
      p_p_inodes_cache = NULL;
   }

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_delete_rb_p_inodes>\n");
}
