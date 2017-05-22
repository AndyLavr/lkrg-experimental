/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Intercept 'may_open' function
 *
 * Notes:
 *  - To be able to block raw disk access we need to extend
 *    functionality of CAP_SYS_RAWIO capability. We are going
 *    to check in the intercepted function if process has this
 *    capability or not (only Protected Process should have it?)
 *
 * Caveats:
 *  - None
 *
 * Timeline:
 *  - Created: 1.II.2017
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#ifndef P_LKRG_PROTECTED_FILE_MAY_OPEN_H
#define P_LKRG_PROTECTED_FILE_MAY_OPEN_H

/* Same as PF_MEMPOLICY in old kernel but that's fine :) */
#define P_TEMP_CAP_FLAG 0x10000000

/* per-instance private data */
struct p_may_open_data {
    ktime_t entry_stamp;
};


int p_may_open_ret(struct kretprobe_instance *p_ri, struct pt_regs *p_regs);
int p_may_open_entry(struct kretprobe_instance *p_ri, struct pt_regs *p_regs);
int p_install_may_open_hook(void);
void p_uninstall_may_open_hook(void);

#endif
