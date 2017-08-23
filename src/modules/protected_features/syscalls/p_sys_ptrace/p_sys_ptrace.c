/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Intercept ptrace syscall
 *
 * Notes:
 *  - We are maintianing Red-Black tree of protected process pids. Ptrace hook
 *    provides guarantee that anyone who want to interact in any form (using
 *    ptrace syscall) with the protected process, will be intercepted and blocked
 *
 * Caveats:
 *  - None
 *
 * Timeline:
 *  - Created: 12.IX.2016
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#include "../../../../p_lkrg_main.h"


char p_sys_ptrace_kretprobe_state = 0x0;

static struct kretprobe p_sys_ptrace_kretprobe = {
    .kp.symbol_name = "sys_ptrace",
    .handler = p_sys_ptrace_ret,
    .entry_handler = p_sys_ptrace_entry,
    .data_size = sizeof(struct p_sys_ptrace_data),
    /* Probe up to 20 instances concurrently. */
    .maxactive = 40,
};


int p_sys_ptrace_entry(struct kretprobe_instance *p_ri, struct pt_regs *p_regs) {

   p_debug_kprobe_log(
          "Entering function <p_sys_ptrace_entry>\n");

   if (p_is_protected_pid(current->pid)) {
      goto p_sys_ptrace_entry_out;
   }

   if (p_is_protected_pid(p_regs->si)) {
      p_print_log(P_LKRG_INFO,
                  "Normal process[%s] pid:%d tries to ptrace() protected pid:%ld\n",
                                               current->comm,current->pid,p_regs->si);

      p_regs->di = -1;
      p_regs->si = -1;
      p_regs->dx = -1;
      p_regs->cx = -1;
   }

p_sys_ptrace_entry_out:

   p_debug_kprobe_log(
          "Leaving function <p_sys_ptrace_entry>\n");

   /* A dump_stack() here will give a stack backtrace */
   return 0x0;
}


int p_sys_ptrace_ret(struct kretprobe_instance *ri, struct pt_regs *p_regs) {

   return 0x0;
}


int p_install_sys_ptrace_hook(void) {

   int p_ret;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_install_sys_ptrace_hook>\n");

   if ( (p_ret = register_kretprobe(&p_sys_ptrace_kretprobe)) < 0) {
      p_print_log(P_LKRG_ERR, "[kretprobe] register_kretprobe() failed! [err=%d]\n",p_ret);
      goto p_install_sys_ptrace_hook_out;
   }
   p_print_log(P_LKRG_INFO, "Planted [kretprobe] <%s> at: %p\n",
                     p_sys_ptrace_kretprobe.kp.symbol_name, p_sys_ptrace_kretprobe.kp.addr);
   p_sys_ptrace_kretprobe_state = 0x1;

//   p_ret = 0x0; <- should be 0x0 anyway...

p_install_sys_ptrace_hook_out:

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_install_sys_ptrace_hook> (p_ret => %d)\n",p_ret);

   return p_ret;
}


void p_uninstall_sys_ptrace_hook(void) {

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_uninstall_sys_ptrace_hook>\n");

   if (!p_sys_ptrace_kretprobe_state) {
      p_print_log(P_LKRG_INFO, "[kretprobe] <%s> at 0x%p is NOT installed\n",
                     p_sys_ptrace_kretprobe.kp.symbol_name, p_sys_ptrace_kretprobe.kp.addr);
   } else {
      unregister_kretprobe(&p_sys_ptrace_kretprobe);
      p_print_log(P_LKRG_INFO, "Removing [kretprobe] <%s> at 0x%p\n",
                     p_sys_ptrace_kretprobe.kp.symbol_name, p_sys_ptrace_kretprobe.kp.addr);
      p_sys_ptrace_kretprobe_state = 0x0;
   }

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_uninstall_sys_ptrace_hook>\n");
}
