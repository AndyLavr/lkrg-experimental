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

#ifndef P_LKRG_PROTECTED_PROCESS_RB_TREE_H
#define P_LKRG_PROTECTED_PROCESS_RB_TREE_H

#define p_alloc_pids()      kmem_cache_alloc(p_pids_cache, GFP_ATOMIC)
#define p_free_pids(name)   kmem_cache_free(p_pids_cache, (void *)(name))

#ifdef P_LKRG_DEBUG
#define P_DUMP_RB_PIDS_TREE                                                                         \
do {                                                                                                \
   struct rb_node *p_node;                                                                          \
                                                                                                    \
   for (p_node = rb_first(&p_global_pids_root); p_node; p_node = rb_next(p_node))                   \
      p_print_log(P_LKRG_DBG, "pid => %d\n",                                                        \
                                      rb_entry(p_node, struct p_protected_pid, p_rb)->p_pid);       \
} while(0);
#endif


struct p_protected_pid {

   struct rb_node p_rb;
   pid_t p_pid;
   /* ... add other driver-specific fields */

};

extern struct kmem_cache *p_pids_cache;
extern struct rb_root p_global_pids_root;


static inline void p_rb_init_pid_node(struct rb_node *rb) {

// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Entering function <p_rb_init_pid_node>\n");
#endif

   rb->__rb_parent_color = 0;
   rb->rb_right = NULL;
   rb->rb_left = NULL;
   RB_CLEAR_NODE(rb);

// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_rb_init_pid_node>\n");
#endif

}

struct p_protected_pid *p_rb_find_pid(struct rb_root *p_root, pid_t p_arg);
struct p_protected_pid *p_rb_add_pid(struct rb_root *p_root, pid_t p_arg, struct p_protected_pid *p_source);
void p_rb_del_pid(struct rb_root *p_root, struct p_protected_pid *p_source);
int p_init_rb_pids(void);
void p_delete_rb_pids(void);

#endif
