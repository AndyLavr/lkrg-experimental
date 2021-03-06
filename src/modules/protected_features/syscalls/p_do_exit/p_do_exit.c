/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Intercept exit syscall
 *
 * Notes:
 *  - We are maintianing Red-Black tree of protected process pids. When protected
 *    process dies/exists we need to update RB tree.
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


char p_do_exit_kretprobe_state = 0x0;

static struct kretprobe p_do_exit_kretprobe = {
    .kp.symbol_name = "do_exit",
    .handler = p_do_exit_ret,
    .entry_handler = p_do_exit_entry,
    .data_size = sizeof(struct p_do_exit_data),
    /* Probe up to 20 instances concurrently. */
    .maxactive = 40,
};


int p_do_exit_entry(struct kretprobe_instance *p_ri, struct pt_regs *p_regs) {

   p_debug_kprobe_log(
          "Entering function <p_do_exit_entry>\n");
   p_debug_kprobe_log(
          "p_do_exit_entry: comm[%s] Pid:%d\n",current->comm,current->pid);

   if (p_is_protected_pid(current->pid)) {
      p_print_log(P_LKRG_INFO, "Unprotecting comm[%s] Pid:%d\n",current->comm,current->pid);
      p_unprotect_process(current->pid);
   }

//   p_ed_enforce_validation();

   spin_lock(&p_rb_ed_pids_lock);
   if (p_remove_task_pid_f(task_pid_nr(current)))
      ;// DEBUG: p_print_log(P_LKRG_CRIT, "Can't remove ED pid (is not on the list) => %d [%s]\n",task_pid_nr(current),current->comm);
   spin_unlock(&p_rb_ed_pids_lock);

   p_debug_kprobe_log(
          "Entering function <p_do_exit_entry>\n");

   /* A dump_stack() here will give a stack backtrace */
   return 0x0;
}


int p_do_exit_ret(struct kretprobe_instance *ri, struct pt_regs *p_regs) {

   p_debug_kprobe_log(
          "Entering function <p_do_exit_ret>\n");

   p_ed_enforce_validation();

   p_debug_kprobe_log(
          "Entering function <p_do_exit_ret>\n");

   return 0x0;
}


int p_install_do_exit_hook(void) {

   int p_ret;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_install_do_exit_hook>\n");

   if ( (p_ret = register_kretprobe(&p_do_exit_kretprobe)) < 0) {
      p_print_log(P_LKRG_ERR, "[kretprobe] register_kretprobe() failed! [err=%d]\n",p_ret);
      goto p_install_do_exit_hook_out;
   }
   p_print_log(P_LKRG_INFO, "Planted [kretprobe] <%s> at: %p\n",
                         p_do_exit_kretprobe.kp.symbol_name, p_do_exit_kretprobe.kp.addr);
   p_do_exit_kretprobe_state = 0x1;

//   p_ret = 0x0; <- should be 0x0 anyway...

p_install_do_exit_hook_out:

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_install_do_exit_hook> (p_ret => %d)\n",p_ret);

   return p_ret;
}


void p_uninstall_do_exit_hook(void) {

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_uninstall_do_exit_hook>\n");

   if (!p_do_exit_kretprobe_state) {
      p_print_log(P_LKRG_INFO, "[kretprobe] <%s> at 0x%p is NOT installed\n",
               p_do_exit_kretprobe.kp.symbol_name, p_do_exit_kretprobe.kp.addr);
   } else {
      unregister_kretprobe(&p_do_exit_kretprobe);
      p_print_log(P_LKRG_INFO, "Removing [kretprobe] <%s> at 0x%p\n",
               p_do_exit_kretprobe.kp.symbol_name, p_do_exit_kretprobe.kp.addr);
      p_do_exit_kretprobe_state = 0x0;
   }

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_uninstall_do_exit_hook>\n");
}
