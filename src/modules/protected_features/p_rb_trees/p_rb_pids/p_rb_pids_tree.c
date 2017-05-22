/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Red-black tree for keeping track protected process pid structure
 *
 * Notes:
 *  - Make sence with own kmem_cache_* allocation
 *
 * Timeline:
 *  - Created: 12.IX.2016
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#include "../../../../p_lkrg_main.h"


struct kmem_cache *p_pids_cache = NULL;
struct rb_root p_global_pids_root = RB_ROOT;


struct p_protected_pid *p_rb_find_pid(struct rb_root *p_root, pid_t p_arg) {

   struct rb_node *p_node = p_root->rb_node;
   struct p_protected_pid *p_struct = NULL;
   struct p_protected_pid *p_ret = NULL;

// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Entering function <p_rb_find_pid>\n");
#endif

   while(p_node) {
      p_struct = rb_entry(p_node, struct p_protected_pid, p_rb);

      if (p_arg < p_struct->p_pid) {
         p_node = p_node->rb_left;
      } else if (p_arg > p_struct->p_pid) {
         p_node = p_node->rb_right;
      } else {
         p_ret = p_struct;
         goto p_rb_find_pid_out;
      }
   }

p_rb_find_pid_out:

// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_rb_find_pid> (p_ret => 0x%p)\n",p_ret);
#endif

   return p_ret;
}


struct p_protected_pid *p_rb_add_pid(struct rb_root *p_root, pid_t p_arg, struct p_protected_pid *p_source) {

   struct rb_node **p_node = &p_root->rb_node;
   struct rb_node *p_parent = NULL;
   struct p_protected_pid *p_struct;
   struct p_protected_pid *p_ret = NULL;

// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Entering function <p_rb_add_pid>\n");
#endif

   while(*p_node) {
      p_parent = *p_node;
      p_struct = rb_entry(p_parent, struct p_protected_pid, p_rb);

      if (p_arg < p_struct->p_pid) {
         p_node = &(*p_node)->rb_left;
      } else if (p_arg > p_struct->p_pid) {
         p_node = &(*p_node)->rb_right;
      } else {
         p_ret = p_struct;
         goto p_rb_add_pid_out;
      }

   }

   rb_link_node(&p_source->p_rb, p_parent, p_node);   // Insert this new node as a red leaf
   rb_insert_color(&p_source->p_rb, p_root);         // Rebalance the tree, finish inserting

p_rb_add_pid_out:

// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_rb_add_pid> (p_ret => 0x%p)\n",p_ret);
#endif

   return p_ret;
}


void p_rb_del_pid(struct rb_root *p_root, struct p_protected_pid *p_source) {

// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Entering function <p_rb_del_pid>\n");
#endif

   rb_erase(&p_source->p_rb, p_root);       // Erase the node
   p_free_pids(p_source);                   // Free the memory

// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_rb_del_pid>\n");
#endif

}

static void p_pids_cache_init(void *p_arg) {

   struct p_protected_pid *p_struct = p_arg;

// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Entering function <p_pids_cache_init>\n");
#endif

   memset(p_struct, 0x0, sizeof(struct p_protected_pid));

// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_pids_cache_init>\n");
#endif

}

int p_init_rb_pids(void) {

   int p_ret = P_LKRG_SUCCESS;

// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Entering function <p_init_rb_pids>\n");
#endif

   if ( (p_pids_cache = kmem_cache_create("protected_pids", sizeof(struct p_protected_pid),
                                           0x0, SLAB_HWCACHE_ALIGN, p_pids_cache_init)) == NULL) {
      p_print_log(P_LKRG_ERR, "kmem_cache_create() for PIDs error! :(\n");
      p_ret = -ENOMEM;
   }

// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_init_rb_pids> (p_ret => %d)\n",p_ret);
#endif

   return p_ret;
}

void p_delete_rb_pids(void) {

   struct rb_node *p_node;
   struct p_protected_pid *p_tmp;

// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Entering function <p_delete_rb_pids>\n");
#endif

   for (p_node = rb_first(&p_global_pids_root); p_node; p_node = rb_next(p_node)) {
      p_tmp = rb_entry(p_node, struct p_protected_pid, p_rb);
      p_print_log(P_LKRG_INFO, "Deleting PID => %d\n",p_tmp->p_pid);
      p_free_pids(p_tmp);
   }
   kmem_cache_destroy(p_pids_cache);

// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_delete_rb_pids>\n");
#endif

}
