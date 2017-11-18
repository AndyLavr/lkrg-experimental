/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Linux kernel Runtime Guard communcation channel module
 *    (server side)
 *
 * Notes:
 *  - Linux kernel Runtime Guard communication with the client
 *    throught the special channel - module notifier routine.
 *
 * Timeline:
 *  - Created: 29.III.2016
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#include "p_kmod_cli_srv.h"

p_lkrg_global_ctrl_struct p_lkrg_global_ctrl;
char *p_lkrg_random_ctrl_password = NULL;

DEFINE_SPINLOCK(p_mod_blocklock);
DEFINE_SPINLOCK(p_mod_blocklock_var);
struct module *p_mod_block_kmod;
unsigned long *p_mod_block_init;
//char p_mod_block_name[MODULE_NAME_LEN+1];

/* Generate password */
char *gen_rand_password(size_t p_pass_size) {

   char *p_tmp;
   unsigned char p_worker;
   size_t p_cnt;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <gen_rand_password>\n");

   /*
    * This is one-shot function not in the time-critical context/section. We can sleep here so
    * we are allowed to make 'slowpath' memory allocation - don't need to use emergency pools.
    *
    * __GFP_NOFAIL flag will always generate slowpath warn because developers
    * decided to depreciate this flag ;/
    */
   if ( (p_tmp = kzalloc(p_pass_size+1, GFP_KERNEL)) == NULL) {
      p_print_log(P_LKRG_CRIT,
             "GENERATING PASSWORD kzalloc() error! Can't allocate memory ;[\n");
      goto gen_rand_password_out;
   }

   get_random_bytes(p_tmp, p_pass_size);
   for(p_cnt = 0x0; p_cnt < p_pass_size; p_cnt++) {
      p_worker = p_tmp[p_cnt];
      p_worker %= 0x5E;
      p_worker += PI3_PASS_SHIFT;
      if (p_worker == 0x22)
         p_worker--;
      p_tmp[p_cnt] = p_worker;
   }

gen_rand_password_out:

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <gen_rand_password> (p_tmp => 0x%p)\n",p_tmp);

   return p_tmp;
}

/*
 * Initialize necessary data to established communcation channel
 * with Runtime Guard.
 */
int p_cli_init(void) {

   size_t p_tmp;
   ssize_t p_tmp_ret;
   struct file *p_filep;
   char p_buf[PI3_MAX_MESSAGE];
   char *p_message = "#\n# DELETE ME!!!\n#\n\nRandomly generated password is following:\n";
   int p_ret = P_LKRG_SUCCESS;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_cli_init>\n");

   get_random_bytes(&p_tmp, sizeof(size_t));
   p_tmp %= (PI3_PASSWORD_SIZE_MAX-PI3_PASSWORD_SIZE_MIN);
   p_tmp += PI3_PASSWORD_SIZE_MIN;

   /* Generate random password */
   if ( (p_lkrg_random_ctrl_password = gen_rand_password(p_tmp)) == NULL) {
      p_print_log(P_LKRG_CRIT,
             "Can't generate password! Exiting... :(\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_cli_init_out;
   }

   /* Create file with the password! */
   if ( (p_filep = p_file_open(PI3_PASSWORD_FILE, O_WRONLY|O_CREAT|O_EXCL, 0)) == NULL) {
      p_print_log(P_LKRG_CRIT,
             "Can't open file [%s]! Exiting... :(\n",PI3_PASSWORD_FILE);
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_cli_init_out;
   }

   snprintf(p_buf,PI3_MAX_MESSAGE-1,"%s%s\n\n",p_message,p_lkrg_random_ctrl_password);
   p_buf[PI3_MAX_MESSAGE-1] = 0x0;

   if ( (p_tmp_ret = p_file_write(p_filep,0x0,p_buf,strlen(p_buf))) < 0) {
      p_print_log(P_LKRG_CRIT,
             "Can't write to the file [%s]! Exiting... :(\n",PI3_PASSWORD_FILE);
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_cli_init_close;
   }

   p_file_sync(p_filep);

p_cli_init_close:

   p_file_close(p_filep);

p_cli_init_out:

   if (p_ret == P_LKRG_SUCCESS) {
      char *p_lkrg_random_ctrl_password_tmp = p_lkrg_random_ctrl_password;

      if (p_sha1_hash(&p_lkrg_random_ctrl_password, p_lkrg_random_ctrl_password_tmp,
                      strlen(p_lkrg_random_ctrl_password_tmp)) == NULL) {
         p_ret = P_LKRG_GENERAL_ERROR;
      }
      kzfree(p_lkrg_random_ctrl_password_tmp);
   }

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_cli_init> (p_ret => %d)\n",p_ret);

   return p_ret;
}

inline int p_discover_ctrl_structure(struct module *p_tmp, unsigned long *p_addr) {

   long *p_pass_arg = NULL;
   char *p_pass_val = NULL;
   long *p_path_arg = NULL;
   char *p_pass_hash = NULL;
//   char *p_path_val = NULL;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_discover_ctrl_structure> [%s] NR of parameters [%d][%p]\n",p_tmp->name,p_tmp->num_kp,p_tmp->kp);

   if (p_tmp->num_kp != 2)
      goto p_discover_out;

// DEBUG
   p_debug_log(P_LKRG_DBG,
          "<p_discover_ctrl_structure> param->name[0][%s] and param->name[1][%s]\n",
                                                        p_tmp->kp[0].name,p_tmp->kp[1].name);

//   spin_lock(&p_mod_blocklock_var);

   if (p_tmp->kp) {

      if (strlen(p_tmp->kp[0].name) != 8 || strlen(p_tmp->kp[1].name) != 8)
         goto p_discover_out;

      if (strncmp(p_tmp->kp[0].name,"pi3_pass",0x8)) {
         if (strncmp(p_tmp->kp[1].name,"pi3_pass",0x8)) {
            goto p_discover_out;
         } else {
            p_pass_arg = (long *)p_tmp->kp[1].arg;
            if (strncmp(p_tmp->kp[0].name,"pi3_path",0x8))
               goto p_discover_out;
            p_path_arg = (long *)p_tmp->kp[0].arg;
         }
      } else {
         p_pass_arg = (long *)p_tmp->kp[0].arg;
         if (strncmp(p_tmp->kp[1].name,"pi3_path",0x8))
            goto p_discover_out;
         p_path_arg = (long *)p_tmp->kp[1].arg;
      }

// DEBUG
      p_debug_log(P_LKRG_DBG,
             "<p_discover_ctrl_structure> param->name[0][%s] and param->name[1][%s]\n",
                                                           p_tmp->kp[0].name,p_tmp->kp[1].name);

      if (p_pass_arg) {
         p_pass_val = (char *)(*p_pass_arg); // read address
         if (p_pass_val) {

// DEBUG
            p_debug_log(P_LKRG_DBG,
                   "<p_discover_ctrl_structure> password[%s]\n",p_pass_val);

            /* OK argument looks valid, chech if password matches */
//            if (strlen(p_pass_val) != strlen(p_lkrg_random_ctrl_password)) {
//               p_print_log(P_LKRG_INFO,
//                      "CTRL Structure: Invalid password! [%s]\n",p_pass_val);
//               goto p_discover_out;
//            }

            if (p_sha1_hash(&p_pass_hash, p_pass_val, strlen(p_pass_val)) == NULL) {
               p_print_log(P_LKRG_INFO,
                      "CTRL Structure: Can\'t generate hash! [%s]\n",p_pass_val);
               goto p_discover_out;
            }

            if (strncmp(p_pass_hash,p_lkrg_random_ctrl_password,P_SHA1_SIZE)) {
               p_print_log(P_LKRG_INFO,
                      "CTRL Structure: Invalid password! [%s]\n",p_pass_val);
               goto p_discover_out;
            }

            /*
             * OK, password matches, let's try to find markers.
             * Maybe it was just coinsidence?
             */
            if (p_try_parse_ctrl_structure(p_addr,p_init_text_size(p_tmp),p_path_arg)) {
               p_print_log(P_LKRG_INFO,
                      "CTRL Structure: ERROR can't find markers!\n");
               goto p_discover_out; // smth went wrong
            }

            /* OK, looks like we have control structure :) */

// STRONG_DEBUG
            p_debug_log(P_LKRG_STRONG_DBG,
                   "Leaving function <p_discover_ctrl_structure> (SUCCESS)\n");

            return P_LKRG_SUCCESS;
         }
      }
   }

p_discover_out:

   if (p_pass_hash)
      kfree(p_pass_hash);

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_discover_ctrl_structure> (ERROR)\n");

   return P_LKRG_GENERAL_ERROR;
}

inline int p_try_parse_ctrl_structure(long *p_start, unsigned int p_size, long *p_path_arg) {

   char *p_tmp = (char *)p_start;
   unsigned int p_cnt;
   unsigned int *p_tmp_read;
   unsigned int p_timestamp,p_log_level,p_force_run,p_block_modules;
#ifdef P_LKRG_UNHIDE
   unsigned int p_hide_module;
#else
   unsigned int p_r0;
#endif
   unsigned int p_r1,p_r2,p_r3,p_r4,p_r5;
   unsigned int p_protected_process,p_pid;
   unsigned int p_protected_files;
#ifdef CONFIG_X86_64
   unsigned int p_pf_low,p_pf_high;
#else
   unsigned int p_pf_inode,p_padding;
#endif
   unsigned long p_inode;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_try_parse_ctrl_structure> p_start[%p] p_size[0x%x]\n",p_start,p_size);

   if (p_size < (PI3_MARKER_SIZE*2 + PI3_CTRL_STRUCT_SIZE + 1)) {

      p_print_log(P_LKRG_INFO, "Control module is WRONG! Size mismatch.\n");

// STRONG_DEBUG
      p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_try_parse_ctrl_structure> (ERROR)\n");

      return P_LKRG_GENERAL_ERROR;
   }

   p_cnt = 0x0;
   while (p_cnt < p_size-9 &&
          (*(p_tmp+0) != PI3_MARKET_INIT_START0 ||
           *(p_tmp+1) != PI3_MARKET_INIT_START1 ||
           *(p_tmp+2) != PI3_MARKET_INIT_START2 ||
           *(p_tmp+3) != PI3_MARKET_INIT_START3 ||
           *(p_tmp+4) != PI3_MARKET_INIT_START4 ||
           *(p_tmp+5) != PI3_MARKET_INIT_START5 ||
           *(p_tmp+6) != PI3_MARKET_INIT_START6 ||
           *(p_tmp+7) != PI3_MARKET_INIT_START7)
          ) {

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
       "[0x%02X] [0x%02X] [0x%02X] [0x%02X] [0x%02X] [0x%02X] [0x%02X] [0x%02X]\n",
       (*(p_tmp+0)) & 0xFF, (*(p_tmp+1)) & 0xFF, (*(p_tmp+2)) & 0xFF, (*(p_tmp+3)) & 0xFF,
       (*(p_tmp+4)) & 0xFF, (*(p_tmp+5)) & 0xFF, (*(p_tmp+6)) & 0xFF, (*(p_tmp+7)) & 0xFF);

      p_cnt++;
      p_tmp++;
   }

// DEBUG
   p_debug_log(P_LKRG_DBG,
          "<p_try_parse_ctrl_structure> p_cnt[%d] p_size[%d]\n",p_cnt,p_size);

   if (p_cnt == p_size-9 || !(p_cnt+PI3_CTRL_STRUCT_SIZE+PI3_MARKER_SIZE < p_size-1)) {

      p_print_log(P_LKRG_INFO, "Control module is WRONG! Size mismatch.\n");

// STRONG_DEBUG
      p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_try_parse_ctrl_structure> (ERROR)\n");

      return P_LKRG_GENERAL_ERROR; // Didn't find START marker...
   }

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "<p_try_parse_ctrl_structure> 2\n");

   if ( *(p_tmp+PI3_MARKER_SIZE+PI3_CTRL_STRUCT_SIZE+0) != PI3_MARKET_INIT_END0 ||
        *(p_tmp+PI3_MARKER_SIZE+PI3_CTRL_STRUCT_SIZE+1) != PI3_MARKET_INIT_END1 ||
        *(p_tmp+PI3_MARKER_SIZE+PI3_CTRL_STRUCT_SIZE+2) != PI3_MARKET_INIT_END2 ||
        *(p_tmp+PI3_MARKER_SIZE+PI3_CTRL_STRUCT_SIZE+3) != PI3_MARKET_INIT_END3 ||
        *(p_tmp+PI3_MARKER_SIZE+PI3_CTRL_STRUCT_SIZE+4) != PI3_MARKET_INIT_END4 ||
        *(p_tmp+PI3_MARKER_SIZE+PI3_CTRL_STRUCT_SIZE+5) != PI3_MARKET_INIT_END5 ||
        *(p_tmp+PI3_MARKER_SIZE+PI3_CTRL_STRUCT_SIZE+6) != PI3_MARKET_INIT_END6 ||
        *(p_tmp+PI3_MARKER_SIZE+PI3_CTRL_STRUCT_SIZE+7) != PI3_MARKET_INIT_END7) {
         /* This marker MUST be here... something is fucked-up! */

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
       "Leaving function <p_try_parse_ctrl_structure> (ERROR)\n"
       "[0x%02X] [0x%02X] [0x%02X] [0x%02X] [0x%02X] [0x%02X] [0x%02X] [0x%02X]\n",
       (*(p_tmp+PI3_MARKER_SIZE+PI3_CTRL_STRUCT_SIZE+0)) & 0xFF,
       (*(p_tmp+PI3_MARKER_SIZE+PI3_CTRL_STRUCT_SIZE+1)) & 0xFF,
       (*(p_tmp+PI3_MARKER_SIZE+PI3_CTRL_STRUCT_SIZE+2)) & 0xFF,
       (*(p_tmp+PI3_MARKER_SIZE+PI3_CTRL_STRUCT_SIZE+3)) & 0xFF,
       (*(p_tmp+PI3_MARKER_SIZE+PI3_CTRL_STRUCT_SIZE+4)) & 0xFF,
       (*(p_tmp+PI3_MARKER_SIZE+PI3_CTRL_STRUCT_SIZE+5)) & 0xFF,
       (*(p_tmp+PI3_MARKER_SIZE+PI3_CTRL_STRUCT_SIZE+6)) & 0xFF,
       (*(p_tmp+PI3_MARKER_SIZE+PI3_CTRL_STRUCT_SIZE+7)) & 0xFF);

      return P_LKRG_GENERAL_ERROR;
   }

   /* OK, looks like we have valid control structure. Let's parse it... */

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "<p_try_parse_ctrl_structure> 3\n");

   p_tmp += PI3_MARKER_SIZE;
   p_tmp_read = (unsigned int *)p_tmp;

   p_timestamp           = *p_tmp_read++;
   p_log_level           = *p_tmp_read++;
   p_force_run           = *p_tmp_read++;
   p_block_modules       = *p_tmp_read++;

#ifdef P_LKRG_UNHIDE
   p_hide_module       = *p_tmp_read++;
#else
   p_r0                  = *p_tmp_read++;
#endif

   p_protected_process   = *p_tmp_read++;
   p_pid                 = *p_tmp_read++;
   p_protected_files     = *p_tmp_read++;

#ifdef CONFIG_X86_64
   p_pf_low              = *p_tmp_read++;
   p_pf_high             = *p_tmp_read++;

   /* Little endian on x86*/
   p_inode = (unsigned long) p_pf_high << 0x20 | p_pf_low;
#else
   p_pf_inode            = *p_tmp_read++;
   p_padding             = *p_tmp_read++;

   p_inode = (unsigned long) p_pf_inode;
#endif

   p_r1                  = *p_tmp_read++;
   p_r2                  = *p_tmp_read++;
   p_r3                  = *p_tmp_read++;
   p_r4                  = *p_tmp_read++;
   p_r5                  = *p_tmp_read++;

   p_print_log(P_LKRG_INFO,
          "CTRL STRUCTURE:\n");

   p_print_log(P_LKRG_INFO,
          "\tTime stamp => [0x%x]\n",p_timestamp);
   p_print_log(P_LKRG_INFO,
          "\tLog level => [0x%x]\n",p_log_level);
   p_print_log(P_LKRG_INFO,
          "\tForce run => [0x%x]\n",p_force_run);
   p_print_log(P_LKRG_INFO,
          "\tBlock modules => [0x%x]\n",p_block_modules);
   p_print_log(P_LKRG_INFO,
          "\tProtected Process => [0x%x]\n",p_protected_process);
   p_print_log(P_LKRG_INFO,
          "\tPid => [0x%x]\n",p_pid);
   p_print_log(P_LKRG_INFO,
          "\tProtected Files => [0x%x]\n",p_protected_files);
#ifdef CONFIG_X86_64
   p_print_log(P_LKRG_INFO,
          "\tPF: Low => [0x%x]\n",p_pf_low);
   p_print_log(P_LKRG_INFO,
          "\tPF: High => [0x%x]\n",p_pf_high);
   p_print_log(P_LKRG_INFO,
          "\tPF: Inode => [0x%lx]\n",p_inode);
#else
   p_print_log(P_LKRG_INFO,
          "\tPF: pf_node => [0x%x]\n",p_pf_inode);
   p_print_log(P_LKRG_INFO,
          "\tPF: Padding => [0x%x]\n",p_padding);
   p_print_log(P_LKRG_INFO,
          "\tPF: Inode => [0x%lx]\n",p_inode);
#endif

#ifdef P_LKRG_UNHIDE
   p_print_log(P_LKRG_INFO,
          "\tHide myself => [0x%x]\n\n",p_hide_module);
#else
// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "\n\tp_r0 => [0x%x]\n",p_r0);
#endif

// DEBUG
   p_debug_log(P_LKRG_DBG,
          "\tp_r1 => [0x%x]\n",p_r1);
   p_debug_log(P_LKRG_DBG,
          "\tp_r2 => [0x%x]\n",p_r2);
   p_debug_log(P_LKRG_DBG,
          "\tp_r3 => [0x%x]\n",p_r3);
   p_debug_log(P_LKRG_DBG,
          "\tp_r4 => [0x%x]\n",p_r4);
   p_debug_log(P_LKRG_DBG,
          "\tp_r5 => [0x%x]\n",p_r5);

   /* Validate */
   if (p_validate_ctrl_structure(p_timestamp,p_log_level,p_force_run,
                                 p_block_modules,p_hide_module,
                                 p_protected_process,p_pid,p_protected_files,
                                 p_inode)) {
      p_print_log(P_LKRG_INFO,"CTRL structure validation failed! Non action taken.\n");

// STRONG_DEBUG
      p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_try_parse_ctrl_structure> (ERROR)\n");

      return P_LKRG_GENERAL_ERROR;
   }

   /* OK, now we can change internal state ;-) */

   /* Timer */
   if (p_timestamp != 0xFFFFFFFF)
      p_lkrg_global_ctrl.p_timestamp = p_timestamp;

   /* Log Level */
   if (p_log_level != 0xFFFFFFFF)
      p_lkrg_global_ctrl.p_log_level = p_log_level;

   /* Block or not modules */
   if (p_block_modules != 0xFFFFFFFF)
      p_lkrg_global_ctrl.p_block_modules = p_block_modules;

   /* Run integrity check? */
   if (p_force_run != 0xFFFFFFFF)
      p_offload_work(0); // run integrity check!

   if (p_protected_process != 0xFFFFFFFF) {
      if (p_protected_process) {
         p_print_log(P_LKRG_CRIT,
                "Protecting process[%d]\n",p_pid);
         p_protect_process(p_pid);
      } else {
         p_print_log(P_LKRG_CRIT,
                "Unprotecting process[%d]\n",p_pid);
         p_unprotect_process(p_pid);
      }
   }

   if (p_protected_files != 0xFFFFFFFF) {
      if (p_path_arg) {
         char *p_path_val = NULL;

         p_path_val = (char *)(*p_path_arg); // read address
         if (p_path_val)
            p_offload_protected_inode(p_protected_files, p_inode, p_path_val);
      }
   }

#ifdef P_LKRG_UNHIDE
   /*
    * Don't need to take mutex_lock here:
    * - if module blocking is disabled, before this function
    *   is finished, mutex_unlock() from the wrapper is NOT called
    * - if module blocking is disabled, module notifier won't call
    *   mutex_unlock*( until 'spin_unlock(&p_mod_blocklock_var);'
    *   is called. 'p_mod_blocklock_var' can be only unlocked
    *   by this driver after all work is finished!
    */

   /* (Un)hide myself? */
   if (p_hide_module != 0xFFFFFFFF) {
      if (p_hide_module) {
         p_hide_itself(); // Unhide module!
      } else {
         p_unhide_itself(); // Hide module!
      }
      p_lkrg_global_ctrl.p_hide_module = p_hide_module;
   }
#endif

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_try_parse_ctrl_structure> (SUCCESS)\n");

   return P_LKRG_SUCCESS;
}

inline int p_validate_ctrl_structure(unsigned int p_time, unsigned int p_log,
                                     unsigned int p_force, unsigned int p_block,
                                     unsigned int p_hide, unsigned int p_p_process,
                                     unsigned int p_pid, unsigned int p_p_files,
                                     unsigned long p_inode) {

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_validate_ctrl_structure>\n");

   p_print_log(P_LKRG_INFO,
          "\tTimer validation => [0x%x]\n",p_time);

   /* Timer */
   if (p_time < 5 || (p_time > 1800 && p_time != 0xFFFFFFFF)) {
      goto p_validate_ctrl_structure_err;
   }

   p_print_log(P_LKRG_INFO,
          "\tLog level => [0x%x]\n",p_log);

   /* Log Level */
   if (p_log >= P_LOG_LEVEL_MAX && p_log != 0xFFFFFFFF) {
      goto p_validate_ctrl_structure_err;
   }

   p_print_log(P_LKRG_INFO,
          "\tForce running validation => [0x%x]\n",p_force);

   if (p_force != 0xFFFFFFFF && p_force != 1) {
      goto p_validate_ctrl_structure_err;
   }

   p_print_log(P_LKRG_INFO,
          "\tModule blocking validation => [0x%x]\n",p_block);

   if (p_block != 0x1 && p_block != 0x0 && p_block != 0xFFFFFFFF) {
      goto p_validate_ctrl_structure_err;
   }

   p_print_log(P_LKRG_INFO,
          "\tHide module validation => [0x%x]\n",p_hide);

#ifdef P_LKRG_UNHIDE
   if (p_hide != 0x1 && p_hide != 0x0 && p_hide != 0xFFFFFFFF) {
      goto p_validate_ctrl_structure_err;
   }
#endif

   p_print_log(P_LKRG_INFO,
          "\tProtected Process validation => [0x%x]\n",p_p_process);

   if (p_p_process != 0x1 && p_p_process != 0x0 && p_p_process != 0xFFFFFFFF) {
      goto p_validate_ctrl_structure_err;
   }

   if (p_p_process != 0xFFFFFFFF) {
      p_print_log(P_LKRG_INFO,
             "\tProtected Process PID validation => [0x%x]\n",p_pid);

      if ((int)p_pid < 1) {
         goto p_validate_ctrl_structure_err;
      }
   }

   p_print_log(P_LKRG_INFO,
          "\tProtected Files validation => [0x%x]\n",p_p_files);

   if (p_p_files > 3 && p_p_files != 0xFFFFFFFF) {
      goto p_validate_ctrl_structure_err;
   }

   if (p_p_files != 0xFFFFFFFF) {
      p_print_log(P_LKRG_INFO,
             "\tProtected Files INODE validation => [0x%lx]\n",p_inode);

      if ((long)p_inode < 1) {
         goto p_validate_ctrl_structure_err;
      }
   }

   p_print_log(P_LKRG_INFO,
          "\tValidation complete!\n");

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_validate_ctrl_structure> (SUCCESS)\n");

   return P_LKRG_SUCCESS;

p_validate_ctrl_structure_err:

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_validate_ctrl_structure> (ERROR)\n");

   return P_LKRG_GENERAL_ERROR;
}

int p_block_always(void) {

   p_print_log(P_LKRG_CRIT,
          "!! Module insertion blocked (from always!) !!\n");

   return P_LKRG_GENERAL_ERROR;

}

int p_block_elegant(void) {

   struct module *p_tmp = p_mod_block_kmod;
   unsigned long *p_addr = p_mod_block_init;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_block_elegant>\n");

   p_tmp->init = (int (*)(void))p_addr;
   if (p_discover_ctrl_structure(p_tmp, p_addr)) {
      if (p_tmp->holders_dir)
         spin_unlock(&p_mod_blocklock_var);
      p_print_log(P_LKRG_CRIT,
                  "!! Module insertion blocked !!\n");

// STRONG_DEBUG
      p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_block_elegant> (blocked!)\n");

      return P_LKRG_GENERAL_ERROR;
   }

   /*
    * Return success, to inform password was right.
    * Now, this strange module should be unloaded!
    */
   if (p_tmp->holders_dir)
      spin_unlock(&p_mod_blocklock_var);

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_block_elegant> (allowed!)\n");

   return P_LKRG_SUCCESS;
}


/* Open file */
struct file *p_file_open(const char* p_path, int p_flags, int p_mode) {

   struct file *p_filp = NULL;
   mm_segment_t p_oldfs;
   int p_err = 0;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_file_open>\n");

   p_oldfs = get_fs();
   set_fs(get_ds());
   p_filp = filp_open(p_path, p_flags, p_mode);
   set_fs(p_oldfs);
   if(IS_ERR(p_filp)) {
      p_err = PTR_ERR(p_filp);
// STRONG_DEBUG
      p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_file_open> (ERROR)\n");
      return NULL;
   }

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_file_open> (SUCCESS)\n");

   return p_filp;
}

/* Close file */
void p_file_close(struct file *p_filp) {

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_file_close>\n");

   filp_close(p_filp, NULL);

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_file_close>\n");
}

/* Sync data to the file */
int p_file_sync(struct file *p_file) {

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_file_sync>\n");

   vfs_fsync(p_file, 0);

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_file_sync>\n");

   return P_LKRG_SUCCESS;
}

/* Write to the file */
int p_file_write(struct file *p_file, unsigned long long p_offset,
                             unsigned char *p_data, unsigned int p_size) {

   mm_segment_t p_oldfs;
   int p_ret;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_file_write>\n");

   p_oldfs = get_fs();
   set_fs(get_ds());

   p_ret = vfs_write(p_file, p_data, p_size, &p_offset);

   set_fs(p_oldfs);

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_file_write>\n");

   return p_ret;
}
