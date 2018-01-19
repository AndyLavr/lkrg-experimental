/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Kernel's modules module
 *
 * Notes:
 *  - Communication with the Linux kernel Runtime Guard
 *
 * Timeline:
 *  - Created: 29.III.2016
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#ifndef P_LKRG_KERNEL_CLI_HEADER
#define P_LKRG_KERNEL_CLI_HEADER

#include "p_kmod_cli_shared.h"

#define PI3_PASSWORD_FILE "/root/.DELETE_ME_p_lkrg_password.txt"
#define PI3_PASSWORD_SIZE_MIN 0x16
#define PI3_PASSWORD_SIZE_MAX 0x20
#define PI3_PASS_SHIFT 0x21


typedef struct _p_lkrg_global_ctrl_structure {

   unsigned int p_timestamp;
   unsigned int p_log_level;
   unsigned int p_force_run;
   unsigned int p_block_modules;
#ifdef P_LKRG_UNHIDE
   unsigned int p_hide_module;
#else
   /* Reserved values for possible future usage */
   unsigned int p_r0;
#endif
   unsigned int p_clean_message;
   unsigned int p_protected_process;
   unsigned int p_pid;
   unsigned int p_protected_files;
#ifdef CONFIG_X86_64
   unsigned int p_pf_low;
   unsigned int p_pf_high;
#else
   unsigned int p_pf_inode;
   unsigned int p_padding;
#endif

   unsigned int p_r1;
   unsigned int p_r2;
   unsigned int p_r3;
   unsigned int p_r4;
   unsigned int p_r5;

} p_lkrg_global_ctrl_struct;

extern p_lkrg_global_ctrl_struct p_lkrg_global_ctrl;
extern char *p_lkrg_random_ctrl_password;

extern spinlock_t p_mod_blocklock;
extern spinlock_t p_mod_blocklock_var;
//extern struct module *p_mod_block_kmod;
//extern unsigned long *p_mod_block_init;

char *gen_rand_password(size_t p_pass_size);
int p_cli_init(void);
inline int p_discover_ctrl_structure(struct module *p_tmp, unsigned long *p_addr);
inline int p_try_parse_ctrl_structure(long *p_start, unsigned int p_size, long *p_path_arg);
inline int p_validate_ctrl_structure(unsigned int p_time, unsigned int p_log,
                                     unsigned int p_force, unsigned int p_block,
                                     unsigned int p_hide, unsigned int p_clean_m,
                                     unsigned int p_p_process, unsigned int p_pid,
                                     unsigned int p_p_files, unsigned long p_inode);
int p_block_elegant(void);
int p_block_always(void);

/* File open/close/sync/write functions */
struct file *p_file_open(const char* p_path, int p_flags, int p_mode);
void p_file_close(struct file *p_filp);
int p_file_sync(struct file *p_file);
int p_file_write(struct file *p_file, unsigned long long p_offset,
                             unsigned char *p_data, unsigned int p_size);

#endif
