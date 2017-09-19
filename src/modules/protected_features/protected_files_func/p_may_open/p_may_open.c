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

#include "../../../../p_lkrg_main.h"


char p_may_open_kretprobe_state = 0x0;

static struct kretprobe p_may_open_kretprobe = {
    .kp.symbol_name = "may_open",
    .handler = p_may_open_ret,
    .entry_handler = p_may_open_entry,
    .data_size = sizeof(struct p_may_open_data),
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

int p_may_open_entry(struct kretprobe_instance *p_ri, struct pt_regs *p_regs) {

// STRONG_DEBUG
   p_debug_kprobe_log(
          "Entering function <p_may_open_entry>\n");
   p_debug_kprobe_log(
          "p_may_open_entry: comm[%s] Pid:%d => Arguments: "
          "[path:0x%lx acc_mode:0x%lx flags:0x%lx]\n",
          current->comm,current->pid,p_regs->di,p_regs->si,p_regs->dx);

   if (p_is_protected_pid(current->pid)) {
      goto p_may_open_entry_out;
   }

   if (!capable(CAP_SYS_RAWIO)) {

      struct path *p_path = (struct path *)p_regs->di;
      struct dentry *p_dentry = NULL;
      struct inode *p_inode = NULL;


      if (!p_path) {
         goto p_may_open_entry_out;
      }

      p_dentry = p_path->dentry;

      if (!p_dentry) {
         goto p_may_open_entry_out;
      }

      p_inode = p_dentry->d_inode;

      if (!p_inode) {
         goto p_may_open_entry_out;
      }

      // Thanks to spender :)
      if (S_ISBLK(p_inode->i_mode) || (S_ISCHR(p_inode->i_mode) && imajor(p_inode) == RAW_MAJOR)) {
/*
         struct cred *p_new;

         p_new = prepare_creds();
         if (!p_new) {
            // Very bad... make it pain!
            p_regs->di = -1;
            p_regs->si = -1;
            p_regs->dx = -1;
         } else {
            p_new->fsuid.val = -1;
            if (capable(CAP_FOWNER)) {
               cap_lower(p_new->cap_bset, CAP_FOWNER);
               cap_lower(p_new->cap_permitted, CAP_FOWNER);
               cap_lower(p_new->cap_effective, CAP_FOWNER);
               cap_lower(p_new->cap_inheritable, CAP_FOWNER);
               current->flags |= P_TEMP_CAP_FLAG;
            }
            commit_creds(p_new);
            p_regs->dx = -1;
         }
*/


         struct cred *p_new = (struct cred *)current->cred;

         p_set_uid(&p_new->fsuid, -1);

         if (cap_raised(p_new->cap_effective, CAP_FOWNER)) {
            cap_lower(p_new->cap_bset, CAP_FOWNER);
            cap_lower(p_new->cap_permitted, CAP_FOWNER);
            cap_lower(p_new->cap_effective, CAP_FOWNER);
            cap_lower(p_new->cap_inheritable, CAP_FOWNER);
//            cap_lower(p_new->cap_ambient, CAP_FOWNER);

            p_new = (struct cred *)current->real_cred;
            p_set_uid(&p_new->fsuid, -1);

            cap_lower(p_new->cap_bset, CAP_FOWNER);
            cap_lower(p_new->cap_permitted, CAP_FOWNER);
            cap_lower(p_new->cap_effective, CAP_FOWNER);
            cap_lower(p_new->cap_inheritable, CAP_FOWNER);
//            cap_lower(p_new->cap_ambient, CAP_FOWNER);

            current->flags |= P_TEMP_CAP_FLAG;
         } else {
            p_new = (struct cred *)current->real_cred;
            p_set_uid(&p_new->fsuid, -1);
         }

         p_regs->dx = -1;

      }

   }

p_may_open_entry_out:

// STRONG_DEBUG
   p_debug_kprobe_log(
          "Leaving function <p_may_open_entry>\n");

   return 0x0;
}


int p_may_open_ret(struct kretprobe_instance *p_ri, struct pt_regs *p_regs) {

   if (p_get_uid(&current_cred()->fsuid) == -1) {

      struct cred *p_new;
/*
      p_new = prepare_creds();
      if (!p_new) {
         // Very bad... make it pain!
         p_regs->ax = -1;
      } else {
         p_new->fsuid = current_cred()->euid;
         if (current->flags & P_TEMP_CAP_FLAG) {
            cap_raise(p_new->cap_bset, CAP_FOWNER);
            cap_raise(p_new->cap_permitted, CAP_FOWNER);
            cap_raise(p_new->cap_effective, CAP_FOWNER);
            cap_raise(p_new->cap_inheritable, CAP_FOWNER);
            current->flags &= ~P_TEMP_CAP_FLAG; // disable
         }

         commit_creds(p_new);
      }
*/

      p_new = (struct cred *)current->cred;
      p_set_uid(&p_new->fsuid,p_get_uid(&current_cred()->euid));

      if (current->flags & P_TEMP_CAP_FLAG) {
         cap_raise(p_new->cap_bset, CAP_FOWNER);
         cap_raise(p_new->cap_permitted, CAP_FOWNER);
         cap_raise(p_new->cap_effective, CAP_FOWNER);
         cap_raise(p_new->cap_inheritable, CAP_FOWNER);
//         cap_raise(p_new->cap_ambient, CAP_FOWNER);

         p_new = (struct cred *)current->real_cred;
         p_set_uid(&p_new->fsuid,p_get_uid(&current_cred()->euid));

         cap_raise(p_new->cap_bset, CAP_FOWNER);
         cap_raise(p_new->cap_permitted, CAP_FOWNER);
         cap_raise(p_new->cap_effective, CAP_FOWNER);
         cap_raise(p_new->cap_inheritable, CAP_FOWNER);
//         cap_raise(p_new->cap_ambient, CAP_FOWNER);

         current->flags &= ~P_TEMP_CAP_FLAG; // disable
      } else {
         p_new = (struct cred *)current->real_cred;
         p_set_uid(&p_new->fsuid,p_get_uid(&current_cred()->euid));
      }

   }

   return 0x0;
}


int p_install_may_open_hook(void) {

   int p_ret;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_install_may_open_hook>\n");

   if ( (p_ret = register_kretprobe(&p_may_open_kretprobe)) < 0) {
      p_print_log(P_LKRG_ERR, "[kretprobe] register_kretprobe() failed! [err=%d]\n",p_ret);
      goto p_install_may_open_hook_out;
   }
   p_print_log(P_LKRG_INFO, "Planted [kretprobe] <%s> at: %p\n",
                     p_may_open_kretprobe.kp.symbol_name, p_may_open_kretprobe.kp.addr);
   p_may_open_kretprobe_state = 0x1;

//   p_ret = 0x0; <- should be 0x0 anyway...

p_install_may_open_hook_out:

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_install_may_open_hook> (p_ret => %d)\n",p_ret);

   return p_ret;
}


void p_uninstall_may_open_hook(void) {

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_uninstall_may_open_hook>\n");

   if (!p_may_open_kretprobe_state) {
      p_print_log(P_LKRG_INFO, "[kretprobe] <%s> at 0x%p is NOT installed\n",
                     p_may_open_kretprobe.kp.symbol_name, p_may_open_kretprobe.kp.addr);
   } else {
      unregister_kretprobe(&p_may_open_kretprobe);
      p_print_log(P_LKRG_INFO, "Removing [kretprobe] <%s> at 0x%p\n",
                     p_may_open_kretprobe.kp.symbol_name, p_may_open_kretprobe.kp.addr);
      p_may_open_kretprobe_state = 0x0;
   }

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_uninstall_may_open_hook>\n");
}
