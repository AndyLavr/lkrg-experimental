/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Intercept 'kprobe_seq_start' function
 *
 * Notes:
 *  - *kprobes function can be easily listed using /sys interface:
 *    /sys/kernel/debug/kprobes/list
 *    To avoid the situation where attacker leaks the intercepted
 *    functions with addresses we need to force 'kprobe_seq_start' to fail
 *
 * Caveats:
 *  - None
 *
 * Timeline:
 *  - Created: 13.II.2017
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#include "../../../../p_lkrg_main.h"


char p_kprobe_seq_start_kretprobe_state = 0x0;

static struct kretprobe p_kprobe_seq_start_kretprobe = {
    .kp.symbol_name = "kprobe_seq_start",
    .handler = p_kprobe_seq_start_ret,
    .entry_handler = p_kprobe_seq_start_entry,
    .data_size = sizeof(struct p_kprobe_seq_start_data),
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
 *    r9  - probably 6th one
 */

int p_kprobe_seq_start_entry(struct kretprobe_instance *p_ri, struct pt_regs *p_regs) {

#ifdef P_LKRG_STRONG_KPROBE_DEBUG
// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Entering function <p_kprobe_seq_start_entry>\n");
   p_print_log(P_LKRG_STRONG_DBG,
          "p_kprobe_seq_start_entry: comm[%s] Pid:%d => Arguments:"
          "[seq_file:%lx pos:0x%lx]\n",
          current->comm,current->pid,p_regs->di,p_regs->si);
#endif
#endif

   if (p_is_protected_pid(current->pid)) {
      goto p_kprobe_seq_start_entry_out;
   }

   do {
      unsigned long *p_addr = (unsigned long *)p_regs->si;

      if (p_addr) {
       *p_addr = ( (1 << 6) * 2);
//         *p_addr = KPROBE_TABLE_SIZE  * 2;
      }
   } while(0);

p_kprobe_seq_start_entry_out:

#ifdef P_LKRG_STRONG_KPROBE_DEBUG
// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Entering function <p_kprobe_seq_start_entry>\n");
#endif
#endif

   /* A dump_stack() here will give a stack backtrace */
   return 0x0;
}


int p_kprobe_seq_start_ret(struct kretprobe_instance *ri, struct pt_regs *p_regs) {

   return 0x0;
}


int p_install_kprobe_seq_start_hook(void) {

   int p_ret;

// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Entering function <p_install_kprobe_seq_start_hook>\n");
#endif

   if ( (p_ret = register_kretprobe(&p_kprobe_seq_start_kretprobe)) < 0) {
      p_print_log(P_LKRG_ERR, "[kretprobe] register_kretprobe() failed! [err=%d]\n",p_ret);
      goto p_install_kprobe_seq_start_hook_out;
   }
   p_print_log(P_LKRG_INFO, "Planted [kretprobe] <%s> at: %p\n",
                         p_kprobe_seq_start_kretprobe.kp.symbol_name, p_kprobe_seq_start_kretprobe.kp.addr);
   p_kprobe_seq_start_kretprobe_state = 0x1;

//   p_ret = 0x0; <- should be 0x0 anyway...

p_install_kprobe_seq_start_hook_out:

// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_install_kprobe_seq_start_hook> (p_ret => %d)\n",p_ret);
#endif

   return p_ret;
}


void p_uninstall_kprobe_seq_start_hook(void) {

// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Entering function <p_uninstall_kprobe_seq_start_hook>\n");
#endif

   if (!p_kprobe_seq_start_kretprobe_state) {
      p_print_log(P_LKRG_INFO, "[kretprobe] <%s> at 0x%p is NOT installed\n",
               p_kprobe_seq_start_kretprobe.kp.symbol_name, p_kprobe_seq_start_kretprobe.kp.addr);
   } else {
      unregister_kretprobe(&p_kprobe_seq_start_kretprobe);
      p_print_log(P_LKRG_INFO, "Removing [kretprobe] <%s> at 0x%p\n",
               p_kprobe_seq_start_kretprobe.kp.symbol_name, p_kprobe_seq_start_kretprobe.kp.addr);
      p_kprobe_seq_start_kretprobe_state = 0x0;
   }

// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_uninstall_kprobe_seq_start_hook>\n");
#endif

}
