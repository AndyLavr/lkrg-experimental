/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Intercept 'process_vm_rw' function
 *
 * Notes:
 *  - API for reading/writing to another process's memory
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

#ifndef P_LKRG_PROTECTED_PROCESS_PROCESS_VM_RW_H
#define P_LKRG_PROTECTED_PROCESS_PROCESS_VM_RW_H

/* per-instance private data */
struct p_process_vm_rw_data {
    ktime_t entry_stamp;
};


int p_process_vm_rw_ret(struct kretprobe_instance *ri, struct pt_regs *p_regs);
int p_process_vm_rw_entry(struct kretprobe_instance *p_ri, struct pt_regs *p_regs);
int p_install_process_vm_rw_hook(void);
void p_uninstall_process_vm_rw_hook(void);

#endif
