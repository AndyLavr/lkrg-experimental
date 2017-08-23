/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Intercept kill syscall
 *
 * Notes:
 *  - Only Protected processes can send signals to each other.
 *    Intercept all signal sending API to check who is requesting
 *    this work and do not allow normal processes to continue if
 *    destination pid is coresponding to Protected Process.
 *
 * Caveats:
 *  - None
 *
 * Timeline:
 *  - Created: 25.IX.2016
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#include "../../../../../p_lkrg_main.h"


char p_sys_kill_kretprobe_state = 0x0;

static struct kretprobe p_sys_kill_kretprobe = {
    .kp.symbol_name = "sys_kill",
    .handler = p_sys_kill_ret,
    .entry_handler = p_sys_kill_entry,
    .data_size = sizeof(struct p_sys_kill_data),
    /* Probe up to 20 instances concurrently. */
    .maxactive = 40,
};

/*
 * x86-64 syscall ABI:
 *  *rax - syscall_number
 *    rdi - 1st argument
 *    rsi - 2nd argument
 *    rdx - 3rd argument
 *    rcx - 4rd argument
 *
 *    r8  - probably 5th one
 *    r9  - probably 5th one
 */

int p_sys_kill_entry(struct kretprobe_instance *p_ri, struct pt_regs *p_regs) {

   p_debug_kprobe_log(
          "Entering function <p_sys_kill_entry>\n");
   p_debug_kprobe_log(
          "p_sys_kill_entry: comm[%s] Pid:%d => Target: [pid:%ld signal:%ld]\n",
          current->comm,current->pid,p_regs->di,p_regs->si);

   if (p_is_protected_pid(current->pid)) {
      goto p_sys_kill_entry_out;
   }

   if (p_is_protected_pid(p_regs->di)) {
      p_print_log(P_LKRG_INFO,
             "Normal process[%s] pid:%d tries to kill() protected "
             "pid:%ld with sign:%ld\n",
             current->comm,current->pid,p_regs->di,p_regs->si);
      p_regs->di = INT_MAX;
      p_regs->si = INT_MAX;
   }

p_sys_kill_entry_out:

   p_debug_kprobe_log(
          "Leaving function <p_sys_kill_entry>\n");

   return 0x0;
}


int p_sys_kill_ret(struct kretprobe_instance *p_ri, struct pt_regs *p_regs) {

   return 0x0;
}


int p_install_sys_kill_hook(void) {

   int p_ret;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_install_sys_kill_hook>\n");

   if ( (p_ret = register_kretprobe(&p_sys_kill_kretprobe)) < 0) {
      p_print_log(P_LKRG_ERR, "[kretprobe] register_kretprobe() failed! [err=%d]\n",p_ret);
      goto p_install_sys_kill_hook_out;
   }
   p_print_log(P_LKRG_INFO, "Planted [kretprobe] <%s> at: %p\n",
                     p_sys_kill_kretprobe.kp.symbol_name, p_sys_kill_kretprobe.kp.addr);
   p_sys_kill_kretprobe_state = 0x1;

//   p_ret = 0x0; <- should be 0x0 anyway...

p_install_sys_kill_hook_out:

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_install_sys_kill_hook> (p_ret => %d)\n",p_ret);

   return p_ret;
}


void p_uninstall_sys_kill_hook(void) {

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_uninstall_sys_kill_hook>\n");

   if (!p_sys_kill_kretprobe_state) {
      p_print_log(P_LKRG_INFO, "[kretprobe] <%s> at 0x%p is NOT installed\n",
                     p_sys_kill_kretprobe.kp.symbol_name, p_sys_kill_kretprobe.kp.addr);
   } else {
      unregister_kretprobe(&p_sys_kill_kretprobe);
      p_print_log(P_LKRG_INFO, "Removing [kretprobe] <%s> at 0x%p\n",
                     p_sys_kill_kretprobe.kp.symbol_name, p_sys_kill_kretprobe.kp.addr);
      p_sys_kill_kretprobe_state = 0x0;
   }

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_uninstall_sys_kill_hook>\n");
}
