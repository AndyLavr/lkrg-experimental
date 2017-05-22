/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Intercept 'write_enabled_file_bool' function
 *
 * Notes:
 *  - *kprobes can be easily globally disabled using /sys interface:
 *    /sys/kernel/debug/kprobes/enabled
 *    To avoid situation when attacker globally siables our interceptions
 *    We need to force to fail this function
 *
 * Caveats:
 *  - None
 *
 * Timeline:
 *  - Created: 9.II.2017
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#include "../../../../p_lkrg_main.h"


char p_write_enabled_file_bool_kretprobe_state = 0x0;

static struct kretprobe p_write_enabled_file_bool_kretprobe = {
    .kp.symbol_name = "write_enabled_file_bool",
    .handler = p_write_enabled_file_bool_ret,
    .entry_handler = p_write_enabled_file_bool_entry,
    .data_size = sizeof(struct p_write_enabled_file_bool_data),
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

int p_write_enabled_file_bool_entry(struct kretprobe_instance *p_ri, struct pt_regs *p_regs) {

#ifdef P_LKRG_STRONG_KPROBE_DEBUG
// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Entering function <p_write_enabled_file_bool_entry>\n");
   p_print_log(P_LKRG_STRONG_DBG,
          "p_may_open_entry: comm[%s] Pid:%d => Arguments: "
          "[file:0x%lx user_buf:0x%lx count:0x%lx ppos:0x%lx]\n",
          current->comm,current->pid,p_regs->di,p_regs->si,p_regs->dx,p_regs->cx);
#endif
#endif

   if (p_is_protected_pid(current->pid)) {
      goto p_write_enabled_file_bool_entry_out;
   }

   p_print_log(P_LKRG_INFO,
          "Normal process[%s] pid:%d tries to access "
          "\"/sys/kernel/debug/kprobes/enabled\"\n",
          current->comm,current->pid);
   p_regs->di = -1;
   p_regs->si = -1;
   p_regs->dx = 0x0;
   p_regs->cx = INT_MAX;

p_write_enabled_file_bool_entry_out:

#ifdef P_LKRG_STRONG_KPROBE_DEBUG
// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_write_enabled_file_bool_entry>\n");
#endif
#endif

   return 0x0;
}


int p_write_enabled_file_bool_ret(struct kretprobe_instance *p_ri, struct pt_regs *p_regs) {

   return 0x0;
}


int p_install_write_enabled_file_bool_hook(void) {

   int p_ret;

// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Entering function <p_install_write_enabled_file_bool_hook>\n");
#endif

   if ( (p_ret = register_kretprobe(&p_write_enabled_file_bool_kretprobe)) < 0) {
      p_print_log(P_LKRG_ERR, "[kretprobe] register_kretprobe() failed! [err=%d]\n",p_ret);
      goto p_install_write_enabled_file_bool_hook_out;
   }
   p_print_log(P_LKRG_INFO, "Planted [kretprobe] <%s> at: %p\n",
                            p_write_enabled_file_bool_kretprobe.kp.symbol_name,
                            p_write_enabled_file_bool_kretprobe.kp.addr);
   p_write_enabled_file_bool_kretprobe_state = 0x1;

//   p_ret = 0x0; <- should be 0x0 anyway...

p_install_write_enabled_file_bool_hook_out:

// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_install_write_enabled_file_bool_hook> (p_ret => %d)\n",p_ret);
#endif

   return p_ret;
}


void p_uninstall_write_enabled_file_bool_hook(void) {

// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Entering function <p_uninstall_write_enabled_file_bool_hook>\n");
#endif

   if (!p_write_enabled_file_bool_kretprobe_state) {
      p_print_log(P_LKRG_INFO, "[kretprobe] <%s> at 0x%p is NOT installed\n",
                               p_write_enabled_file_bool_kretprobe.kp.symbol_name,
                               p_write_enabled_file_bool_kretprobe.kp.addr);
   } else {
      unregister_kretprobe(&p_write_enabled_file_bool_kretprobe);
      p_print_log(P_LKRG_INFO, "Removing [kretprobe] <%s> at 0x%p\n",
                               p_write_enabled_file_bool_kretprobe.kp.symbol_name,
                               p_write_enabled_file_bool_kretprobe.kp.addr);
      p_write_enabled_file_bool_kretprobe_state = 0x0;
   }

// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_uninstall_write_enabled_file_bool_hook>\n");
#endif

}
