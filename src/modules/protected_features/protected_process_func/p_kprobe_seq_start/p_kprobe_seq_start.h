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

#ifndef P_LKRG_PROTECTED_PROCESS_KPROBE_SEQ_START_H
#define P_LKRG_PROTECTED_PROCESS_KPROBE_SEQ_START_H

/* per-instance private data */
struct p_kprobe_seq_start_data {
    ktime_t entry_stamp;
};


int p_kprobe_seq_start_ret(struct kretprobe_instance *ri, struct pt_regs *p_regs);
int p_kprobe_seq_start_entry(struct kretprobe_instance *p_ri, struct pt_regs *p_regs);
int p_install_kprobe_seq_start_hook(void);
void p_uninstall_kprobe_seq_start_hook(void);

#endif
