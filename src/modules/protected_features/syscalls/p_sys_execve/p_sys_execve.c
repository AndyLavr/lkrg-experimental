/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Intercept execve syscall
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
 *  - Created: 12.IX.2016
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#include "../../../../p_lkrg_main.h"


char p_pp_tmp_buf[P_MAX_PATH];
char p_sys_execve_kretprobe_state = 0x0;

static struct kretprobe p_sys_execve_kretprobe = {
    .kp.symbol_name = "sys_execve",
    .handler = p_sys_execve_ret,
    .entry_handler = p_sys_execve_entry,
    .data_size = sizeof(struct p_sys_execve_data),
    /* Probe up to 20 instances concurrently. */
    .maxactive = 40,
};


struct inode *p_get_inode_from_task(struct task_struct *p_arg) {

   struct mm_struct *p_mm;
   struct inode *p_inode = NULL;

   p_debug_kprobe_log(
          "Entering function <p_get_inode_from_task>\n");

   if (!p_arg) {
      goto p_get_inode_from_task_out;
   }

   /*
    * This function is called from the context of newly created
    * Process which is intercepted by our *probes. This means
    * Process did not take control yet. Before we finish our work
    * Nothing bad should happened in context of parsing mm_struct.
    * For this specific operation (reading pointer to exe_file)
    * It is safe to not use read lock. Process can't die before it
    * is not even taken control.
    * Additionally, we are under IRQ disabled context and it is
    * Not safe to take any mutex/semaphore since we can be forced
    * to sleep.
    * Current implementation works well!
    */
//   down_read(&p_arg->mm->mmap_sem);

   p_mm = p_arg->mm;
   if (p_mm->exe_file) {
      p_inode = p_mm->exe_file->f_inode;
   }

//   up_read(&p_arg->mm->mmap_sem);


p_get_inode_from_task_out:

   p_debug_kprobe_log(
          "Leaving function <p_get_inode_from_task> (p_inode => 0x%p)\n",p_inode);

   return p_inode;
}

int p_sys_execve_entry(struct kretprobe_instance *p_ri, struct pt_regs *p_regs) {

   p_iterate_processes(p_validate_task_f);
   return 0;
}


int p_sys_execve_ret(struct kretprobe_instance *ri, struct pt_regs *p_regs) {

   struct inode *p_inode;
   struct p_ed_process *p_tmp;

   p_debug_kprobe_log(
          "Entering function <p_sys_execve_ret>\n");

   p_inode = p_get_inode_from_task(current);

   p_debug_kprobe_log(
//   p_print_log(P_LKRG_CRIT,
          "p_sys_execve_ret: returned value => %ld comm[%s] Pid:%d inode[%ld]\n",
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
   if ( (p_tmp = p_rb_find_ed_pid(&p_global_ed_pids_root, task_pid_nr(current))) != NULL) {
      // This process is on the ED list - update information!
      p_print_log(P_LKRG_INFO, "Updating ED pid[%d]\n",current->pid);
      p_update_ed_process(p_tmp, current);
   }
   spin_unlock(&p_rb_ed_pids_lock);

   p_iterate_processes(p_validate_task_f);

   p_debug_kprobe_log(
          "Leaving function <p_sys_execve_ret>\n");

   return 0x0;
}


int p_install_sys_execve_hook(void) {

   int p_ret;

   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_install_sys_execve_hook>\n");

   if ( (p_ret = register_kretprobe(&p_sys_execve_kretprobe)) < 0) {
      p_print_log(P_LKRG_ERR, "[kretprobe] register_kretprobe() failed! [err=%d]\n",p_ret);
      goto p_uninstall_sys_execve_hook_out;
   }
   p_print_log(P_LKRG_INFO, "Planted [kretprobe] <%s> at: %p\n",
                     p_sys_execve_kretprobe.kp.symbol_name, p_sys_execve_kretprobe.kp.addr);
   p_sys_execve_kretprobe_state = 0x1;

//   p_ret = 0x0; <- should be 0x0 anyway...

p_uninstall_sys_execve_hook_out:

   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_install_sys_execve_hook> (p_ret => %d)\n",p_ret);

   return p_ret;
}


void p_uninstall_sys_execve_hook(void) {

   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_uninstall_sys_execve_hook>\n");

   if (!p_sys_execve_kretprobe_state) {
      p_print_log(P_LKRG_INFO, "[kretprobe] <%s> at 0x%p is NOT installed\n",
                     p_sys_execve_kretprobe.kp.symbol_name ,p_sys_execve_kretprobe.kp.addr);
   } else {
      unregister_kretprobe(&p_sys_execve_kretprobe);
      p_print_log(P_LKRG_INFO, "Removing [kretprobe] <%s> at 0x%p\n",
                     p_sys_execve_kretprobe.kp.symbol_name ,p_sys_execve_kretprobe.kp.addr);
      p_sys_execve_kretprobe_state = 0x0;
   }

   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_uninstall_sys_execve_hook>\n");
}
