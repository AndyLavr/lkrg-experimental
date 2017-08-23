/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Protected features main module
 *
 * Notes:
 *  - None
 *
 * Timeline:
 *  - Created: 12.IX.2016
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#include "../../p_lkrg_main.h"

/*
 * CAP_SYS_RAWIO API
 */

/*
 * If Protected Features are correctly initialized, we need to remove
 * CAP_SYS_RAWIO capability from every NOT Protected Process context.
 */
void p_protected_lower_caps(pid_t p_arg) {

   struct task_struct *p_task_struct = pid_task(find_vpid(p_arg), PIDTYPE_PID);

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_protected_lower_caps>\n");

   if (p_task_struct) {
      struct cred *p_new = (struct cred *)p_task_struct->cred;

      if (cap_raised(p_new->cap_effective, CAP_SYS_RAWIO)) {
         cap_lower(p_new->cap_bset, CAP_SYS_RAWIO);
         cap_lower(p_new->cap_permitted, CAP_SYS_RAWIO);
         cap_lower(p_new->cap_effective, CAP_SYS_RAWIO);
         cap_lower(p_new->cap_inheritable, CAP_SYS_RAWIO);
//         cap_lower(p_new->cap_ambient, CAP_SYS_RAWIO);

         p_new = (struct cred *)p_task_struct->real_cred;

         cap_lower(p_new->cap_bset, CAP_SYS_RAWIO);
         cap_lower(p_new->cap_permitted, CAP_SYS_RAWIO);
         cap_lower(p_new->cap_effective, CAP_SYS_RAWIO);
         cap_lower(p_new->cap_inheritable, CAP_SYS_RAWIO);
//         cap_lower(p_new->cap_ambient, CAP_SYS_RAWIO);
      }
   }

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_protected_lower_caps>\n");
}

/*
 * If Protected Features are correctly initialized, we need to raise
 * CAP_SYS_RAWIO capability for newly created / added Protected Process
 * Context.
 */
void p_protected_raise_caps(pid_t p_arg) {

   struct task_struct *p_task_struct = pid_task(find_vpid(p_arg), PIDTYPE_PID);

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_protected_raise_caps>\n");

   if (p_task_struct) {
      struct cred *p_new = (struct cred *)p_task_struct->cred;

      if (!cap_raised(p_new->cap_effective, CAP_SYS_RAWIO)) {
         cap_raise(p_new->cap_bset, CAP_SYS_RAWIO);
         cap_raise(p_new->cap_permitted, CAP_SYS_RAWIO);
         cap_raise(p_new->cap_effective, CAP_SYS_RAWIO);
         cap_raise(p_new->cap_inheritable, CAP_SYS_RAWIO);
//         cap_raise(p_new->cap_ambient, CAP_SYS_RAWIO);

         p_new = (struct cred *)p_task_struct->real_cred;

         cap_raise(p_new->cap_bset, CAP_SYS_RAWIO);
         cap_raise(p_new->cap_permitted, CAP_SYS_RAWIO);
         cap_raise(p_new->cap_effective, CAP_SYS_RAWIO);
         cap_raise(p_new->cap_inheritable, CAP_SYS_RAWIO);
//         cap_raise(p_new->cap_ambient, CAP_SYS_RAWIO);
      }
   }

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_protected_raise_caps>\n");
}


/*
 * Protected PIDs API
 */
int p_protect_process(pid_t p_arg) {

   int p_ret = P_LKRG_SUCCESS;
   struct p_protected_pid *p_tmp;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_protect_process>\n");

   if ( (p_tmp = p_alloc_pids()) == NULL) {
      p_print_log(P_LKRG_ERR,
             "p_alloc_pids() returned NULL for pid %d :(\n",p_arg);
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_protect_process_out;
   }

   p_tmp->p_pid = p_arg;
   p_rb_init_pid_node(&p_tmp->p_rb);
   if (p_rb_add_pid(&p_global_pids_root, p_arg, p_tmp)) {
      p_print_log(P_LKRG_INFO,
                   "pid => %d, is already inserted!\n",p_arg);
      p_free_pids(p_tmp);
      p_ret = 0x1;
      goto p_protect_process_out;
   } else {
      p_print_log(P_LKRG_INFO,
                   "Inserting pid => %d\n", p_arg);
      p_protected_raise_caps(p_arg);
   }

p_protect_process_out:

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_protect_process> (p_ret => %d)\n",p_ret);

   return p_ret;
}


int p_unprotect_process(pid_t p_arg) {

   int p_ret = P_LKRG_SUCCESS;
   struct p_protected_pid *p_tmp;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_unprotect_process>\n");

   if ( (p_tmp = p_rb_find_pid(&p_global_pids_root, p_arg)) == NULL) {
      // This process is not on the list!
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_unprotect_process_out;
   }

   p_rb_del_pid(&p_global_pids_root, p_tmp);
   p_print_log(P_LKRG_INFO, "Removing pid => %d\n", p_arg);
   p_protected_lower_caps(p_arg);

p_unprotect_process_out:

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_unprotect_process> (p_ret => %d)\n",p_ret);

   return p_ret;
}


inline int p_is_protected_pid(pid_t p_arg) {

   register int p_ret;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_is_protected_pid>\n");

   p_ret = p_rb_find_pid(&p_global_pids_root, p_arg) ? 1 : 0;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_is_protected_pid> (p_ret => %d)\n",p_ret);

   return p_ret;
}
/* END - protected PIDs */

/* Protected inodes helper functions */
inline void p_safe_file_func(struct p_protected_inode *p_arg) {

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_safe_file_func>\n");

   /* struct inode_operations */
   p_arg->p_inode_orig = p_arg->p_inode->i_op;
//   memcpy(&p_arg->p_inode_new,p_arg->p_inode_orig,sizeof(struct inode_operations));

   /* struct file_operations */
   p_arg->p_file_orig = p_arg->p_inode->i_fop;
//   memcpy(&p_arg->p_file_new,p_arg->p_file_orig,sizeof(struct file_operations));

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_safe_file_func>\n");
}

inline void p_hook_file_func(struct p_protected_inode *p_arg) {

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_hook_file_func>\n");

   if (p_arg->p_opt == P_PROTECTED_FILES_OPT_FILE) {

// STRONG_DEBUG
      p_debug_log(P_LKRG_STRONG_DBG,
             " => Protected Files mode!\n");

      /*
       * We can hook i_op and f_op function pointers.
       * Current design doesn't require it (previous one has that).
       */

      p_iget_file(p_arg->p_inode);

   } else if (p_arg->p_opt == P_PROTECTED_FILES_OPT_LOGS) {

// STRONG_DEBUG
      p_debug_log(P_LKRG_STRONG_DBG,
             " => Protected Logs mode!\n");

      p_iget_logs(p_arg->p_inode);

   } else {

      /* I should NEVER be here! */
      p_print_log(P_LKRG_CRIT,
             "Protected File / Logs has WIERD value[0x%x]! I should never be here... "
             "Protection is NOT enforced! :(\n",
             p_arg->p_opt);

   }

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_hook_file_func>\n");
}

inline void p_restore_file_func(struct p_protected_inode *p_prot, struct inode *p_arg) {

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_restore_file_func>\n");

   if (p_prot->p_opt == P_PROTECTED_FILES_OPT_FILE) {

      /* struct inode_operations */
//      p_arg->i_op = p_prot->p_inode_orig;
      /* struct file_operations */
//      p_arg->i_fop = p_prot->p_file_orig;

      p_iput_file(p_arg, p_prot->p_iuid, p_prot->p_igid);

   } else if (p_prot->p_opt == P_PROTECTED_FILES_OPT_LOGS) {

      p_iput_logs(p_arg);

   } else {

      /* I should NEVER be here! */
      p_print_log(P_LKRG_CRIT,
             "Protected File / Logs has WIERD value[0x%x]! I should never be here... "
             "Unrotection is NOT enforced! :(\n",
             p_prot->p_opt);

   }

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_restore_file_func>\n");
}


/* Protected parent inodes helper functions */
inline void p_safe_p_file_func(struct p_protected_p_inode *p_arg) {

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_safe_p_file_func>\n");

   /* struct inode_operations */
   p_arg->p_inode_orig = p_arg->p_inode->i_op;
//   memcpy(&p_arg->p_inode_new,p_arg->p_inode_orig,sizeof(struct inode_operations));

   /* struct file_operations */
   p_arg->p_file_orig = p_arg->p_inode->i_fop;
//   memcpy(&p_arg->p_file_new,p_arg->p_file_orig,sizeof(struct file_operations));

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_safe_p_file_func>\n");
}

inline void p_hook_p_file_func(struct p_protected_p_inode *p_arg) {

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_hook_p_file_func>\n");

   /*
    * We can hook i_op and f_op function pointers.
    * Current design doesn't require it (previous one has that).
    */

   p_iget_parent(p_arg->p_inode);

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_hook_p_file_func>\n");
}

inline void p_restore_p_file_func(struct p_protected_p_inode *p_prot, struct inode *p_arg) {

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_restore_p_file_func>\n");

   /* struct inode_operations */
//   p_arg->i_op = p_prot->p_inode_orig;
   /* struct file_operations */
//   p_arg->i_fop = p_prot->p_file_orig;

   p_iput_parent(p_arg);

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_restore_p_file_func>\n");
}


/*
 * Protected inodes API
 */
int p_protect_inode(struct inode *p_inode, struct inode *p_parent_inode, unsigned int p_opt) {

   int p_ret = P_LKRG_SUCCESS;
   struct p_protected_inode *p_tmp;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_protect_inode>\n");

   if ( (p_tmp = p_alloc_inodes()) == NULL) {
      p_print_log(P_LKRG_INFO, "p_alloc_inodes() returned NULL for inode 0x%p :(\n",p_inode);
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_protect_inode_out;
   }

   p_tmp->p_inode = p_inode;
   p_tmp->p_parent_inode = p_parent_inode;
   p_tmp->p_opt = p_opt;
   p_rb_init_inode_node(&p_tmp->p_rb);
   if (p_rb_add_inode(&p_global_inodes_root, p_tmp->p_inode, p_tmp)) {
      p_print_log(P_LKRG_INFO,
             "inode => 0x%p, is already inserted!\n",p_tmp->p_inode);
      p_free_inodes(p_tmp);
      p_ret = 0x1;
      goto p_protect_inode_out;
   } else {
      p_tmp->p_iuid.val = p_inode->i_uid.val;
      p_tmp->p_igid.val = p_inode->i_gid.val;
      p_safe_file_func(p_tmp);
      p_hook_file_func(p_tmp);
      p_print_log(P_LKRG_INFO,
                        "Inserting inode => 0x%p\n", p_tmp->p_inode);
      p_protect_p_inode(p_tmp->p_parent_inode);
   }

p_protect_inode_out:

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_protect_inode> (p_ret => %d)\n",p_ret);

   return p_ret;
}

int p_unprotect_inode(struct inode *p_arg, unsigned int p_opt) {

   int p_ret = P_LKRG_SUCCESS;
   struct p_protected_inode *p_tmp;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_unprotect_inode>\n");

   if ( (p_tmp = p_rb_find_inode(&p_global_inodes_root, p_arg)) == NULL) {
      // This inode is not on the list!
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_unprotect_inode_out;
   }

   if (p_tmp->p_opt != p_opt) {
      p_print_log(P_LKRG_CRIT,
             "Unrotecting (%s) is requested but inode is Protected (%s). "
             "Unprotection is NOT enforced! Ignoring request... :(\n",
             (p_opt == P_PROTECTED_FILES_OPT_FILE)?"File":"Logs",
             (p_tmp->p_opt == P_PROTECTED_FILES_OPT_FILE)?"File":"Logs");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_unprotect_inode_out;
   }

   p_restore_file_func(p_tmp, p_tmp->p_inode);
   p_unprotect_p_inode(p_tmp->p_parent_inode);
   p_rb_del_inode(&p_global_inodes_root, p_tmp);
   p_print_log(P_LKRG_INFO,"Removing inode => 0x%p\n", p_arg);

p_unprotect_inode_out:

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_unprotect_inode> (p_ret => %d)\n",p_ret);

   return p_ret;
}

int p_is_protected_inode(struct inode *p_arg) {

   register int p_ret;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_is_protected_inode>\n");

   p_ret = p_rb_find_inode(&p_global_inodes_root, p_arg) ? 1 : 0;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_is_protected_inode> (p_ret => %d)\n",p_ret);

   return p_ret;
}
/* END - protected inodes */


/*
 * Protected parent inodes API
 */
int p_protect_p_inode(struct inode *p_inode) {

   int p_ret = P_LKRG_SUCCESS;
   struct p_protected_p_inode *p_tmp = NULL;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_protect_p_inode>\n");

   if ( (p_tmp = p_is_protected_p_inode(p_inode)) != NULL) {
      p_tmp->p_num++;
      p_print_log(P_LKRG_INFO,"Increasing parent inode[0x%p] ref => %ld\n",
                                                      p_tmp->p_inode,p_tmp->p_num);
   } else {
      if ( (p_tmp = p_alloc_p_inodes()) == NULL) {
         p_print_log(P_LKRG_INFO, "p_alloc_p_inodes() returned NULL for "
                                                 "parent inode 0x%p :(\n",p_inode);
         p_ret = P_LKRG_GENERAL_ERROR;
         goto p_protect_p_inode_out;
      }

      p_tmp->p_inode = p_inode;
      p_rb_init_p_inode_node(&p_tmp->p_rb);
      if (p_rb_add_p_inode(&p_global_p_inodes_root, p_tmp->p_inode, p_tmp)) {
         /* I should NEVER be here */
         p_print_log(P_LKRG_INFO,
                "Parent inode => 0x%p, is already inserted!\n",p_tmp->p_inode);
         p_free_p_inodes(p_tmp);
         p_ret = 0x1;
         goto p_protect_p_inode_out;
      } else {
         p_safe_p_file_func(p_tmp);
         p_hook_p_file_func(p_tmp);
         p_tmp->p_num = 0x1;
         p_print_log(P_LKRG_INFO,"Inserting parent inode[0x%p] => %ld\n",
                                                     p_tmp->p_inode,p_tmp->p_num);
      }
   }

p_protect_p_inode_out:

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_protect_p_inode> (p_ret => %d)\n",p_ret);

   return p_ret;
}

int p_unprotect_p_inode(struct inode *p_arg) {

   int p_ret = P_LKRG_SUCCESS;
   struct p_protected_p_inode *p_tmp = NULL;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_unprotect_p_inode>\n");

   if ( (p_tmp = p_is_protected_p_inode(p_arg)) == NULL) {
      // This inode is not on the list!
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_unprotect_p_inode_out;
   }

   if (p_tmp->p_num != 1) {
      p_tmp->p_num--;
      p_print_log(P_LKRG_INFO,
                  "Decreasing parent[0x%p] inode ref => %ld\n",
                                           p_tmp->p_inode,p_tmp->p_num);
   } else {
      p_restore_p_file_func(p_tmp, p_tmp->p_inode);
      p_rb_del_p_inode(&p_global_p_inodes_root, p_tmp);
      p_print_log(P_LKRG_INFO,"Removing parent inode => 0x%p\n", p_arg);
   }

p_unprotect_p_inode_out:

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_unprotect_p_inode> (p_ret => %d)\n",p_ret);

   return p_ret;
}

struct p_protected_p_inode *p_is_protected_p_inode(struct inode *p_arg) {

   register struct p_protected_p_inode *p_ret;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_is_protected_p_inode>\n");

   p_ret = p_rb_find_p_inode(&p_global_p_inodes_root, p_arg);

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_is_protected_p_inode> (p_ret => 0x%p)\n",p_ret);

   return p_ret;
}
/* END - protected inodes */

int p_get_inode(char *p_arg, struct inode **p_out_inode, struct inode **p_parent_out_inode, struct path *p_path) {

   int p_ret = P_LKRG_SUCCESS;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_get_inode>\n");

// DEBUG
   p_debug_log(P_LKRG_DBG,
          "Trying to resolve [%s]\n",p_arg);

   if ( (p_ret = kern_path(p_arg, LOOKUP_FOLLOW, p_path)) != P_LKRG_SUCCESS) {
      p_print_log(P_LKRG_ERR,
             "[kern_path] Can\'t resolve filename path :(");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_get_inode_out;
   }

// DEBUG
   p_debug_log(P_LKRG_DBG,
          "p_path->dentry->d_inode[0x%p] p_path->dentry->d_parent[0x%p]\n",
                                   p_path->dentry->d_inode,p_path->dentry->d_parent);
   p_debug_log(P_LKRG_DBG,
          "p_path->dentry->d_inode[0x%p] d_parent->d_inode[0x%p]\n",
                                   p_path->dentry->d_inode,p_path->dentry->d_parent->d_inode);

   *p_out_inode = p_path->dentry->d_inode;
   *p_parent_out_inode = p_path->dentry->d_parent->d_inode;

p_get_inode_out:

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_get_inode> (p_ret => %d)\n",p_ret);

   return p_ret;
}


/* For communication channel */
void p_offload_protected_inode(unsigned int p_protected_files, unsigned long p_inode, char *p_path_val) {

   struct p_inode_work_struct *p_tmp;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_offload_protected_inode>\n");
   p_debug_log(P_LKRG_STRONG_DBG,
          "p_protected_files[%d] p_inode[%ld] p_path_val[0x%p]\n",
          p_protected_files,p_inode,p_path_val);

   /*
    * __GFP_NOFAIL flag will always generate slowpath warn because developers
    * decided to depreciate this flag ;/
    */
   while ( (p_tmp = kzalloc(sizeof(struct p_inode_work_struct),
                                          GFP_ATOMIC)) == NULL);

   INIT_WORK(&p_tmp->p_worker, p_offload_protected_inode_run);
   p_tmp->p_protected_files = p_protected_files;
   p_tmp->p_inode = p_inode;
   p_tmp->p_path_val = kstrdup(p_path_val, GFP_ATOMIC); // must be strdup();
   if (!p_tmp->p_path_val) {
      p_print_log(P_LKRG_ERR,
             "Not enough memory! Can\'t make file %s (inode %ld) protected :(\n",
             p_path_val,p_inode);
      kzfree(p_tmp);
      goto p_offload_protected_inode_out;
   }

   /* schedule for execution */
   queue_work(system_unbound_wq, &p_tmp->p_worker);

p_offload_protected_inode_out:

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_offload_protected_inode>\n");

   return;
}

void p_offload_protected_inode_run(struct work_struct *p_arg) {

   struct p_inode_work_struct *p_tmp = (struct p_inode_work_struct *)p_arg;
   int p_ret;
   struct inode *p_inode = NULL;
   struct inode *p_parent_inode = NULL;
   struct path p_path;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_offload_protected_inode_run>\n");

   if (!p_tmp->p_path_val) {
      p_print_log(P_LKRG_CRIT,
             "Can\'t get inode: path_arg is empty! :(\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_offload_protected_inode_run_out;
   }

   if ( (p_ret = p_get_inode(p_tmp->p_path_val,&p_inode,&p_parent_inode, &p_path)) == P_LKRG_GENERAL_ERROR) {
      p_print_log(P_LKRG_CRIT,
             "Can\'t get inode for file => %s :(\n",p_tmp->p_path_val);
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_offload_protected_inode_run_out;
   }

   if (p_inode->i_ino != p_tmp->p_inode) {
      p_print_log(P_LKRG_CRIT,
             "Got inode[%ld] but requested was[%ld]... ignoring it! :(\n",p_inode->i_ino,p_tmp->p_inode);
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_offload_protected_inode_run_out_path;
   }

   switch(p_tmp->p_protected_files) {

      case 0:
         p_print_log(P_LKRG_CRIT,
                "Unprotecting file[%s] with inode[%ld]\n",p_tmp->p_path_val,p_inode->i_ino);
         p_unprotect_inode(p_inode,P_PROTECTED_FILES_OPT_FILE);
         break;

      case 1:
         p_print_log(P_LKRG_CRIT,
                "Protecting file[%s] with inode[%ld]\n",p_tmp->p_path_val,p_inode->i_ino);
         p_protect_inode(p_inode,p_parent_inode,P_PROTECTED_FILES_OPT_FILE);
         break;

      case 2:
         p_print_log(P_LKRG_CRIT,
                "Unprotecting logs[%s] with inode[%ld]\n",p_tmp->p_path_val,p_inode->i_ino);
         p_unprotect_inode(p_inode,P_PROTECTED_FILES_OPT_LOGS);
         break;

      case 3:
         p_print_log(P_LKRG_CRIT,
                "Protecting logs[%s] with inode[%ld]\n",p_tmp->p_path_val,p_inode->i_ino);
         p_protect_inode(p_inode,p_parent_inode,P_PROTECTED_FILES_OPT_LOGS);
         break;

      default:
         /* I should NEVER be here! */
         p_print_log(P_LKRG_CRIT,
                "p_protected_files has WIERD value[0x%x]! I should never be here... canceling request! :(\n",
                 p_tmp->p_protected_files);
         break;

   }

p_offload_protected_inode_run_out_path:

   path_put(&p_path);

p_offload_protected_inode_run_out:

   /* kstrdup() */
   kfree(p_tmp->p_path_val);

   /* Destroy WQ item */
   kzfree(p_tmp);

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_offload_protected_inode_run>\n");

}
/* END */

int p_protected_features_init(void) {

   int p_ret;
   struct inode *p_inode = NULL;
   struct inode *p_parent_inode = NULL;
   struct file *p_filep = NULL;
   struct path p_path;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_protected_features_init>\n");

   if (p_init_rb_pids()) {
      p_print_log(P_LKRG_ERR,
             "ERROR: Can\'t initialize pids cache and red-black tree :(\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_protected_features_init_out;
   }

   if (p_init_rb_inodes()) {
      p_print_log(P_LKRG_ERR,
             "ERROR: Can\'t initialize inodes cache and red-black tree :(\n");
      /*
       * PIDs red-black tree need to be deleted first!
       */
      p_delete_rb_pids();
      p_print_log(P_LKRG_INFO, "kmem_cache \"protected_pids\" destroyed!\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_protected_features_init_out;
   }

   if (p_init_rb_p_inodes()) {
      p_print_log(P_LKRG_ERR,
             "ERROR: Can\'t initialize parent inodes cache and red-black tree :(\n");
      /*
       * PIDs red-black tree need to be deleted first!
       */
      p_delete_rb_pids();
      p_print_log(P_LKRG_INFO, "kmem_cache \"protected_pids\" destroyed!\n");
      /*
       * Inodes red-black tree must be deleted here as well!
       */
      p_delete_rb_inodes();
      p_print_log(P_LKRG_INFO, "kmem_cache \"protected_inodes\" destroyed!\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_protected_features_init_out;
   }

   /*
    * Init file
    */

   /*
    * First, check if the file exist... 
    * Maybe someone tries to load us again while we are already there...
    */
   if ( (p_ret = p_get_inode(P_PROTECTED_FEATURES_INIT,&p_inode,&p_parent_inode, &p_path)) != P_LKRG_GENERAL_ERROR) {
      path_put(&p_path);
      p_print_log(P_LKRG_CRIT,
             "Init file exists! Please delete it first => %s\n",P_PROTECTED_FEATURES_INIT);
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_protected_features_init_out;
   }

   /* ... if not, we are not loaded yet, so create init file... */
   if ( (p_filep = p_file_open(P_PROTECTED_FEATURES_INIT, O_WRONLY|O_CREAT|O_EXCL, 0)) == NULL) {
      p_print_log(P_LKRG_CRIT,
             "Can't open file [%s]! Exiting... :(\n",P_PROTECTED_FEATURES_INIT);
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_protected_features_init_out;
   }
   p_file_sync(p_filep);
   p_file_close(p_filep);

   /* And make it protected, so nobody can delete it :) */
   p_protect_inode(p_filep->f_inode,p_filep->f_path.dentry->d_parent->d_inode,P_PROTECTED_FILES_OPT_FILE);

   if ( (p_ret = p_get_inode(P_LKRG_KMOD_CLI,&p_inode,&p_parent_inode, &p_path)) == P_LKRG_GENERAL_ERROR) {
      p_print_log(P_LKRG_CRIT,
             "Can\'t get inode for file => %s :(\n",P_LKRG_KMOD_CLI);
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_protected_features_init_err;
   }

   p_print_log(P_LKRG_CRIT,
          "Protecting inode[0x%p] parent[0x%p]\n",p_inode,p_parent_inode);
   p_protect_inode(p_inode,p_parent_inode,P_PROTECTED_FILES_OPT_FILE);
   path_put(&p_path);

   if ( (p_ret = p_get_inode(P_LKRG_USER_CLI,&p_inode,&p_parent_inode, &p_path)) == P_LKRG_GENERAL_ERROR) {
      p_print_log(P_LKRG_CRIT,
             "Can\'t get inode for file => %s :(\n",P_LKRG_USER_CLI);
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_protected_features_init_err;
   }

   p_print_log(P_LKRG_CRIT,
          "Protecting inode[0x%p] parent[0x%p]\n",p_inode,p_parent_inode);
   p_protect_inode(p_inode,p_parent_inode,P_PROTECTED_FILES_OPT_FILE);
   path_put(&p_path);

   if (p_install_sys_ptrace_hook()) {
      p_print_log(P_LKRG_ERR,
             "ERROR: Can\'t hook ptrace syscall :(\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_protected_features_init_err;
   }

   if (p_install_sys_execve_hook()) {
      p_print_log(P_LKRG_ERR,
             "ERROR: Can\'t hook execve syscall :(\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_protected_features_init_err;
   }

   if (p_install_do_exit_hook()) {
      p_print_log(P_LKRG_ERR,
             "ERROR: Can\'t hook exit syscall :(\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_protected_features_init_err;
   }

   if (p_install_do_fork_hook()) {
      p_print_log(P_LKRG_ERR,
             "ERROR: Can\'t hook fork syscall :(\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_protected_features_init_err;
   }

   if (p_install_sys_tgkill_hook()) {
      p_print_log(P_LKRG_ERR,
             "ERROR: Can\'t hook tgkill syscall :(\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_protected_features_init_err;
   }

   if (p_install_sys_tkill_hook()) {
      p_print_log(P_LKRG_ERR,
             "ERROR: Can\'t hook tkill syscall :(\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_protected_features_init_err;
   }

   if (p_install_sys_kill_hook()) {
      p_print_log(P_LKRG_ERR,
             "ERROR: Can\'t hook kill syscall :(\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_protected_features_init_err;
   }

   if (p_install_sys_rt_sigqueueinfo_hook()) {
      p_print_log(P_LKRG_ERR,
             "ERROR: Can\'t hook rt_sigqueueinfo syscall :(\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_protected_features_init_err;
   }

   if (p_install_sys_rt_tgsigqueueinfo_hook()) {
      p_print_log(P_LKRG_ERR,
             "ERROR: Can\'t hook rt_sigqueueinfo syscall :(\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_protected_features_init_err;
   }

   if (p_install_may_open_hook()) {
      p_print_log(P_LKRG_ERR,
             "ERROR: Can\'t hook may_open function :(\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_protected_features_init_err;
   }

   if (p_install_write_enabled_file_bool_hook()) {
      p_print_log(P_LKRG_ERR,
             "ERROR: Can\'t hook write_enabled_file_bool function :(\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_protected_features_init_err;
   }

   if (p_install_process_vm_rw_hook()) {
      p_print_log(P_LKRG_ERR,
             "ERROR: Can\'t hook process_vm_rw function :(\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_protected_features_init_err;
   }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
   if (p_install_kprobe_seq_start_hook()) {
      p_print_log(P_LKRG_ERR,
             "ERROR: Can\'t hook kprobe_seq_start function :(\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_protected_features_init_err;
   }
#endif

   p_ret = P_LKRG_SUCCESS;

#ifdef P_LKRG_DEBUG
   P_DUMP_RB_INODES_TREE;
   P_DUMP_RB_PIDS_TREE;
#endif

   goto p_protected_features_init_out;

p_protected_features_init_err:

   p_protected_features_exit();

p_protected_features_init_out:

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_protected_features_init> (p_ret => %d)\n",p_ret);

   return p_ret;
}

void p_protected_features_exit(void) {

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_protected_features_exit>\n");

   p_uninstall_sys_ptrace_hook();
   p_uninstall_sys_execve_hook();
   p_uninstall_do_exit_hook();
   p_uninstall_do_fork_hook();
   p_uninstall_sys_tgkill_hook();
   p_uninstall_sys_tkill_hook();
   p_uninstall_sys_kill_hook();
   p_uninstall_sys_rt_sigqueueinfo_hook();
   p_uninstall_sys_rt_tgsigqueueinfo_hook();
   p_uninstall_may_open_hook();
   p_uninstall_write_enabled_file_bool_hook();
   p_uninstall_process_vm_rw_hook();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
   p_uninstall_kprobe_seq_start_hook();
#endif

   /* Before deleting cache i should clean each entry! */
   p_delete_rb_pids();
   p_print_log(P_LKRG_INFO, "kmem_cache \"protected_pids\" destroyed!\n");

   /* Before deleting cache i should clean each entry! */
   p_delete_rb_inodes();
   p_print_log(P_LKRG_INFO, "kmem_cache \"protected_inodes\" destroyed!\n");

   /* Before deleting cache i should clean each entry! */
   p_delete_rb_p_inodes();
   p_print_log(P_LKRG_INFO, "kmem_cache \"protected_p_inodes\" destroyed!\n");

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_protected_features_exit>\n");
}
