/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Intercept execveat syscall
 *
 * Notes:
 *  - To make it works, we must intercept pre-syscall to check what is the desired filename.
 *    Path could be in complicated form, and could be a symlink. We need to resolve it to get
 *    Real Path Name and compare if it is going to be executed protected process. If yes, we
 *    need to inform 'other' syscalls that specific PID must be protected. To do it, we inject
 *    new PID in the Red-Black tree which we maintain...
 *
 * Caveats:
 *  - Any [k]probes run under IRQ disabled, even documentation says that kretprobe is not.
 *    That's not correct and have specific implication. E.g. functions like 'kern_path' if
 *    trying to parse not existing pathname, can call 'gentle' function which checks if IRQs
 *    are enabled. If not they crash! That's why we reenabling IRQs here...
 *
 * Timeline:
 *  - Created: 02.I.2018
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#include "../../../../p_lkrg_main.h"

#ifdef P_LKRG_PROTECTED_PROCESS_SYS_EXECVEAT_H

char p_sys_execveat_kretprobe_state = 0x0;

static struct kretprobe p_sys_execveat_kretprobe = {
    .kp.symbol_name = "sys_execveat",
    .handler = p_sys_execveat_ret,
    .entry_handler = p_sys_execveat_entry,
    .data_size = sizeof(struct p_sys_execveat_data),
    /* Probe up to 20 instances concurrently. */
    .maxactive = 40,
};

int p_sys_execveat_entry(struct kretprobe_instance *p_ri, struct pt_regs *p_regs) {

   struct p_ed_process *p_tmp;

   p_debug_kprobe_log(
          "Entering function <p_sys_execveat_entry>\n");

    p_ed_enforce_validation();

   spin_lock(&p_rb_ed_pids_lock);
   task_lock(current);
   if ( (p_tmp = p_rb_find_ed_pid(&p_global_ed_pids_root, task_pid_nr(current))) != NULL) {
      // This process is on the ED list - set temporary 'disable' flag!
      p_set_ed_process_off(p_tmp);
   }
   task_unlock(current);
   spin_unlock(&p_rb_ed_pids_lock);
   p_debug_kprobe_log(
          "Leaving function <p_sys_execveat_entry>\n");

    return 0;
}


int p_sys_execveat_ret(struct kretprobe_instance *ri, struct pt_regs *p_regs) {

   struct inode *p_inode;
   struct p_ed_process *p_tmp;

   p_debug_kprobe_log(
          "Entering function <p_sys_execveat_ret>\n");

   p_inode = p_get_inode_from_task(current);

   p_debug_kprobe_log(
//   p_print_log(P_LKRG_CRIT,
          "p_sys_execveat_ret: returned value => %ld comm[%s] Pid:%d inode[%ld]\n",
           p_regs->ax,current->comm,current->pid,p_inode->i_ino);

   if (p_inode) {
      if (p_is_protected_inode(p_inode)) {
         p_print_log(P_LKRG_INFO, "Protected inode[%ld] execve() from pid:%d comm[%s]"
                                  " - creating protected process\n",
                                  p_inode->i_ino,current->pid,current->comm);
         p_protect_process(current->pid);
      }
   }

   // Update process
   spin_lock(&p_rb_ed_pids_lock);
   task_lock(current);
   if ( (p_tmp = p_rb_find_ed_pid(&p_global_ed_pids_root, task_pid_nr(current))) != NULL) {
      // This process is on the ED list - update information!
      p_print_log(P_LKRG_INFO, "Updating ED pid[%d]\n",task_pid_nr(current));
      p_update_ed_process(p_tmp, current);
      p_set_ed_process_on(p_tmp);
   }
   task_unlock(current);
   spin_unlock(&p_rb_ed_pids_lock);

//   p_ed_enforce_validation();

   p_debug_kprobe_log(
          "Leaving function <p_sys_execveat_ret>\n");

   return 0x0;
}


int p_install_sys_execveat_hook(void) {

   int p_ret;

   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_install_sys_execveat_hook>\n");

   if ( (p_ret = register_kretprobe(&p_sys_execveat_kretprobe)) < 0) {
      p_print_log(P_LKRG_ERR, "[kretprobe] register_kretprobe() failed! [err=%d]\n",p_ret);
      goto p_uninstall_sys_execveat_hook_out;
   }
   p_print_log(P_LKRG_INFO, "Planted [kretprobe] <%s> at: %p\n",
                     p_sys_execveat_kretprobe.kp.symbol_name, p_sys_execveat_kretprobe.kp.addr);
   p_sys_execveat_kretprobe_state = 0x1;

//   p_ret = 0x0; <- should be 0x0 anyway...

p_uninstall_sys_execveat_hook_out:

   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_install_sys_execveat_hook> (p_ret => %d)\n",p_ret);

   return p_ret;
}


void p_uninstall_sys_execveat_hook(void) {

   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_uninstall_sys_execveat_hook>\n");

   if (!p_sys_execveat_kretprobe_state) {
      p_print_log(P_LKRG_INFO, "[kretprobe] <%s> at 0x%p is NOT installed\n",
                     p_sys_execveat_kretprobe.kp.symbol_name ,p_sys_execveat_kretprobe.kp.addr);
   } else {
      unregister_kretprobe(&p_sys_execveat_kretprobe);
      p_print_log(P_LKRG_INFO, "Removing [kretprobe] <%s> at 0x%p\n",
                     p_sys_execveat_kretprobe.kp.symbol_name ,p_sys_execveat_kretprobe.kp.addr);
      p_sys_execveat_kretprobe_state = 0x0;
   }

   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_uninstall_sys_execveat_hook>\n");
}

#endif
