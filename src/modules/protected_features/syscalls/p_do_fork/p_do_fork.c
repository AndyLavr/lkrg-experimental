/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Intercept fork syscall
 *
 * Notes:
 *  - We are maintianing Red-Black tree of protected process pids. When protected
 *    process forks, child must be protected as well! We need to update RB tree.
 *
 * Caveats:
 *  - None
 *
 * Timeline:
 *  - Created: 13.IX.2016
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#include "../../../../p_lkrg_main.h"


char p_do_fork_kretprobe_state = 0x0;

static struct kretprobe p_do_fork_kretprobe = {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
    .kp.symbol_name = "do_fork",
#else
    .kp.symbol_name = "_do_fork",
#endif
    .handler = p_do_fork_ret,
    .entry_handler = p_do_fork_entry,
    .data_size = sizeof(struct p_do_fork_data),
    /* Probe up to 20 instances concurrently. */
    .maxactive = 40,
};


int p_do_fork_entry(struct kretprobe_instance *p_ri, struct pt_regs *p_regs) {

#ifdef P_LKRG_STRONG_KPROBE_DEBUG
// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Entering function <p_do_fork_entry>\n");
   p_print_log(P_LKRG_STRONG_DBG,
          "p_do_fork_entry: comm[%s] Pid:%d\n",current->comm,current->pid);
#endif
#endif

   if (!p_is_protected_pid(current->pid)) {
      /* It should NOT have CAP_SYS_RAWIO capability */
//      if (capable(CAP_SYS_RAWIO)) {

/*
         struct cred *p_cred;

         p_cred = prepare_creds();
         if (p_cred) {
            cap_lower(p_cred->cap_bset, CAP_SYS_RAWIO);
            commit_creds(p_cred);
         }
*/

      struct cred *p_new = (struct cred *)current->cred;

      if (cap_raised(p_new->cap_effective, CAP_SYS_RAWIO)) {
         cap_lower(p_new->cap_bset, CAP_SYS_RAWIO);
         cap_lower(p_new->cap_permitted, CAP_SYS_RAWIO);
         cap_lower(p_new->cap_effective, CAP_SYS_RAWIO);
         cap_lower(p_new->cap_inheritable, CAP_SYS_RAWIO);
//         cap_lower(p_new->cap_ambient, CAP_SYS_RAWIO);

         p_new = (struct cred *)current->real_cred;

         cap_lower(p_new->cap_bset, CAP_SYS_RAWIO);
         cap_lower(p_new->cap_permitted, CAP_SYS_RAWIO);
         cap_lower(p_new->cap_effective, CAP_SYS_RAWIO);
         cap_lower(p_new->cap_inheritable, CAP_SYS_RAWIO);
//         cap_lower(p_new->cap_ambient, CAP_SYS_RAWIO);
      }
//      }
   }

#ifdef P_LKRG_STRONG_KPROBE_DEBUG
// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_do_fork_entry>\n");
#endif
#endif


   /* A dump_stack() here will give a stack backtrace */
   return 0x0;
}


int p_do_fork_ret(struct kretprobe_instance *ri, struct pt_regs *p_regs) {

#ifdef P_LKRG_STRONG_KPROBE_DEBUG
// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Entering function <p_do_fork_ret>\n");
   p_print_log(P_LKRG_STRONG_DBG,
          "Fork returned value => %ld comm[%s] Pid:%d parent[%d]\n",
                       p_regs->ax,current->comm,current->pid,current->real_parent->pid);
#endif
#endif

   if (p_is_protected_pid(current->pid)) {
      p_print_log(P_LKRG_INFO, "Protected do_fork() comm[%s] Pid:%d RetPid:%ld\n",
                                                 current->comm,current->pid,p_regs->ax);
      p_protect_process(p_regs->ax);
   } else {
      /* It should NOT have CAP_SYS_RAWIO capability */
/*
      if (capable(CAP_SYS_RAWIO)) {
         struct cred *p_cred;

         p_cred = prepare_creds();
         if (p_cred) {
            cap_lower(p_cred->cap_bset, CAP_SYS_RAWIO);
            commit_creds(p_cred);
         }
      }
*/

      struct cred *p_new = (struct cred *)current->cred;

      if (cap_raised(p_new->cap_effective, CAP_SYS_RAWIO)) {
         cap_lower(p_new->cap_bset, CAP_SYS_RAWIO);
         cap_lower(p_new->cap_permitted, CAP_SYS_RAWIO);
         cap_lower(p_new->cap_effective, CAP_SYS_RAWIO);
         cap_lower(p_new->cap_inheritable, CAP_SYS_RAWIO);
//         cap_lower(p_new->cap_ambient, CAP_SYS_RAWIO);

         p_new = (struct cred *)current->real_cred;

         cap_lower(p_new->cap_bset, CAP_SYS_RAWIO);
         cap_lower(p_new->cap_permitted, CAP_SYS_RAWIO);
         cap_lower(p_new->cap_effective, CAP_SYS_RAWIO);
         cap_lower(p_new->cap_inheritable, CAP_SYS_RAWIO);
//         cap_lower(p_new->cap_ambient, CAP_SYS_RAWIO);
      }

   }

#ifdef P_LKRG_STRONG_KPROBE_DEBUG
// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_do_fork_ret>\n");
#endif
#endif

   return 0x0;
}


int p_install_do_fork_hook(void) {

   int p_ret;

// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Entering function <p_install_do_fork_hook>\n");
#endif

   if ( (p_ret = register_kretprobe(&p_do_fork_kretprobe)) < 0) {
      p_print_log(P_LKRG_ERR, "[kretprobe] register_kretprobe() failed! [err=%d]\n",p_ret);
      goto p_install_do_fork_hook_out;
   }
   p_print_log(P_LKRG_INFO, "Planted [kretprobe] <%s> at: %p\n",
                         p_do_fork_kretprobe.kp.symbol_name, p_do_fork_kretprobe.kp.addr);
   p_do_fork_kretprobe_state = 0x1;

//   p_ret = 0x0; <- should be 0x0 anyway...

p_install_do_fork_hook_out:

// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_install_do_fork_hook> (p_ret => %d)\n",p_ret);
#endif

   return p_ret;
}


void p_uninstall_do_fork_hook(void) {

// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Entering function <p_uninstall_do_fork_hook>\n");
#endif

   if (!p_do_fork_kretprobe_state) {
      p_print_log(P_LKRG_INFO, "[kretprobe] <%s> at 0x%p is NOT installed\n",
                     p_do_fork_kretprobe.kp.symbol_name, p_do_fork_kretprobe.kp.addr);
   } else {
      unregister_kretprobe(&p_do_fork_kretprobe);
      p_print_log(P_LKRG_INFO, "Removing [kretprobe] <%s> at 0x%p\n",
                     p_do_fork_kretprobe.kp.symbol_name, p_do_fork_kretprobe.kp.addr);
      p_do_fork_kretprobe_state = 0x0;
   }

// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_uninstall_do_fork_hook>\n");
#endif

}
