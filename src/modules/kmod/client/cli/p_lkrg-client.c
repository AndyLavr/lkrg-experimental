/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Linux kernel Runtime Guard configuration channel user-mode client.
 *
 * Notes:
 *  - To be secure and effective - must be part of Protected Files
 *    and Protected Process feature...
 *
 * Timeline:
 *  - Created: 29.III.2016
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <termios.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <sys/syscall.h>
#include <getopt.h>
#include <fcntl.h>
#include <elf.h>

#include "../../p_kmod_cli_shared.h"

#define MAX_PASS 0x80
#define P_PAGE_SIZE 0x1000
#define MAX_TRESHOLD P_PAGE_SIZE*100 /* 100 pages max*/

#define PI3_MODULE_PARAM_PASS "pi3_pass"
#define PI3_MODULE_PARAM_PF   "pi3_path"
//#define PI3_MODULE_CTRL_NAME "p_ctrl_module"
#define PI3_MODULE_CTRL_NAME "p_lkrg_kmod_cli"
#define P_DEFAULT_PATH   "/root/p_lkrg-beta/output/client/kmod/"PI3_MODULE_CTRL_NAME".ko"

#define VAL_TOO_BIG(a,b)             \
({                                   \
   __typeof__ (a) _a = (a);          \
   __typeof__ (b) _b = (b);          \
   _a > _b ? 1 : 0;                  \
})


void usage(char *arg);
int p_check_priv(void);
int p_validate_module_path(char *p_arg, int *p_fd);
int p_get_pass(char *p_buf, unsigned int p_size, char p_mask, FILE *p_fp);
int p_validate_ELF(char *p_buf);
int p_validate_ELF_hdr(char *p_buf);
off_t p_find_text_section(char *p_buf);
int p_change_ctrl_struct(void *p_buf);
static inline int init_module(void *module_image, unsigned long len, const char *param_values);
int p_load_ctrl_module(char *p_mem, char *p_pass);
static inline int delete_module(const char *p_name, int p_flags);
int p_unload_ctrl_module(void);
void p_print_warning(void);
int p_get_int(char *p_arg, char *p_err);
long p_get_long(char *p_arg, char *p_err);

off_t p_global_size;
char p_elf_32;
unsigned int p_timestamp;
unsigned int p_log_level;
unsigned int p_force_run;
unsigned int p_block_modules;
#ifdef P_LKRG_UNHIDE
unsigned int p_unhide_module;
#endif
unsigned int p_protected_process;
unsigned int p_pid;
unsigned int p_protected_file;
unsigned int p_pf_low;
unsigned int p_pf_high;

char *pi3_path = NULL;
char *p_config_module_path = P_DEFAULT_PATH;
off_t p_offset = 0x0;
char *p_protected_file_str = NULL;

int main(int argc, char *argv[]) {

   char p_pass[MAX_PASS];
   int p_ret,opt,p_fd = -1;
   char *p_mem = MAP_FAILED;
   char p_tmp_err;
   unsigned long p_inode;
   struct stat p_tmp_st;

   setvbuf(stdout, NULL, _IONBF, 0x0);
   setvbuf(stderr, NULL, _IONBF, 0x0);

   printf("\n   ...::: -=[ Linux Kernel Runtime Guard client (by Adam 'pi3' Zabrocki) ]=- :::...\n");
   printf("\n\t[?] Checking privileges...\r");
   if (p_check_priv() == -1) {
      printf("\t[+] Checking privileges... FAILED!\n");
      exit(-1);
   }
   printf("\t[+] Checking privileges... DONE!");
   printf("\n\t[+] Parsing arguments...\n");

   /* Default value - leave this option untouched */
   p_timestamp = p_log_level = p_force_run = p_block_modules = 0xFFFFFFFF;
#ifdef P_LKRG_UNHIDE
   p_unhide_module = 0xFFFFFFFF;
#endif
   p_protected_process = p_pid = p_protected_file = p_pf_low = p_pf_high = 0xFFFFFFFF;

   if (!argv[1])
      usage(argv[0]);

#ifdef P_LKRG_UNHIDE
   while((opt = getopt(argc,argv,"t:l:b:u:P:p:S:s:m:fh?")) != -1) {
#else
   while((opt = getopt(argc,argv,"t:l:b:m:P:p:S:s:fh?")) != -1) {
#endif
      switch(opt) {

         case 't':
            printf("\t   [?] Changing timer interrupt delay (timestamp)...\r");
            p_timestamp = p_get_int(optarg,&p_tmp_err);
            if (p_timestamp < 5 || p_timestamp > 1800 || p_tmp_err) {
               printf("\t   [-] Changing timer interrupt delay (timestamp)... FAILED!\n");
               if (p_tmp_err) {
                  printf("\t     *) Bad number format! - [%s]\n\n",optarg);
                  exit(-1);
               }
               printf("\t     *) Bad value for time stamp! - [%u]\n\n",p_timestamp);
               exit(-1);
            }
            printf("\t   [+] Changing timer interrupt delay (timestamp)... DONE!\n");
            printf("\t     *) New time stamp is %u seconds.\n",p_timestamp);
            break;

         case 'l':
            printf("\t   [?] Changing log level...\r");
            p_log_level = p_get_int(optarg,&p_tmp_err);
            if (p_log_level < 0 || p_log_level >= P_LOG_LEVEL_MAX || p_tmp_err) {
               printf("\t   [-] Changing log level... FAILED!\n");
               if (p_tmp_err) {
                  printf("\t     *) Bad number format! - [%s]\n\n",optarg);
                  exit(-1);
               }
               printf("\t     *) Bad value for log level! - [%u]\n\n",p_log_level);
               exit(-1);
            }
            printf("\t   [+] Changing log level... DONE!\n");
            printf("\t     *) New log level is %d [%s].\n",p_log_level,
                                                           (!p_log_level)?"none":
                                                           (p_log_level==1)?"alive":
                                                           (p_log_level==2)?"errors":
                                                           (p_log_level==3)?"warns":
                                                           (p_log_level==4)?"infos":
#ifdef P_LKRG_DEBUG
                                                           (p_log_level==5)?"debug":
                                                           (p_log_level==6)?"strong debug":
#endif
                                                           "unknown (error?)");
            break;

         case 'b':
            printf("\t   [?] Changing blocking modules flag...\r");
            p_block_modules = p_get_int(optarg,&p_tmp_err);
            if (p_tmp_err || (p_block_modules != 1 && p_block_modules != 0)) {
               printf("\t   [-] Changing blocking modules flag... FAILED!\n");
               if (p_tmp_err) {
                  printf("\t     *) Bad number format! - [%s]\n\n",optarg);
                  exit(-1);
               }
               printf("\t     *) Bad value for blocking modules flag! - [%u]\n\n",p_block_modules);
               exit(-1);
            }
            printf("\t   [+] Changing blocking modules flag... DONE!\n");
            printf("\t     *) New blocking modules flag is %u (%s blocking modules).\n",
                                                                           p_block_modules,
                                                                           (p_block_modules)?"enabling":
                                                                           "disabling");
            break;

#ifdef P_LKRG_UNHIDE
         case 'u':
            printf("\t   [?] Changing hide p_lkrg module flag...\r");
            p_unhide_module = p_get_int(optarg,&p_tmp_err);
            if (p_tmp_err || (p_unhide_module != 1 && p_unhide_module != 0)) {
               printf("\t   [-] Changing hide p_lkrg flag... FAILED!\n");
               if (p_tmp_err) {
                  printf("\t     *) Bad number format! - [%s]\n\n",optarg);
                  exit(-1);
               }
               printf("\t     *) Bad value for hide module flag! - [%u]\n\n",p_unhide_module);
               exit(-1);
            }
            printf("\t   [+] Changing hide p_lkrg module flag... DONE!\n");
            printf("\t     *) New hide p_lkrg module flag is %u (%s hiding p_lkrg module).\n",
                                                                           p_unhide_module,
                                                                           (p_unhide_module)?"Enable":
                                                                           "Disable");
            break;
#endif

         case 'P':
            printf("\t   [?] (Un)Protecting Process...\r");
            p_protected_process = p_get_int(optarg,&p_tmp_err);
            if (p_tmp_err || (p_protected_process != 1 && p_protected_process != 0)) {
               printf("\t   [-] (Un)Protecting Process... FAILED!\n");
               if (p_tmp_err) {
                  printf("\t     *) Bad number format! - [%s]\n\n",optarg);
                  exit(-1);
               }
               printf("\t     *) Bad value for (Un)Protecting Process flag! - [%u]\n\n",p_protected_process);
               exit(-1);
            }
            printf("\t   [+] (Un)Protecting Process... DONE!\n");
            printf("\t     *) New (Un)Protecting Process flag is %u (%s Protected Process).\n",
                                                                           p_protected_process,
                                                                           (p_protected_process)?"Enable":
                                                                           "Disable");
            break;

         case 'p':
            printf("\t   [?] Trying to get new process PID as part of (Un)Protecting Process...\r");
            p_pid = p_get_int(optarg,&p_tmp_err);
            if (p_tmp_err) {
               printf("\t   [-] Trying to get new process PID as part of (Un)Protecting Process... FAILED!\n");
               printf("\t     *) Bad number format! - [%s]\n\n",optarg);
               exit(-1);
            }
            printf("\t   [+] Trying to get new process PID as part of (Un)Protecting Process... DONE!\n");
            printf("\t     *) New (Un)protecting process PID is %u\n",p_pid);
            break;

         case 'S':
            printf("\t   [?] (Un)Protecting File/Logs...\r");
            p_protected_file = p_get_int(optarg,&p_tmp_err);
            if (p_tmp_err || p_protected_file > 3) {
               printf("\t   [-] (Un)Protecting File/Logs... FAILED!\n");
               if (p_tmp_err) {
                  printf("\t     *) Bad number format! - [%s]\n\n",optarg);
                  exit(-1);
               }
               printf("\t     *) Bad value for (Un)Protecting File/Logs flag! - [%u]\n\n",p_protected_file);
               exit(-1);
            }
            printf("\t   [+] (Un)Protecting File/Logs... DONE!\n");
            printf("\t     *) New (Un)Protecting File/logs flag is %u (%s Protected %s).\n",
                                                                           p_protected_file,
                                                                           (p_protected_file)?"Enable":
                                                                           "Disable",
                                                                           (p_protected_file>1)?"Logs":
                                                                           "File");
            break;

         case 's':

            printf("\t   [?] Trying to get new inode from path (%s) to be part of Protected Files...\r",
                                                                                                     optarg);
            if (strlen(optarg) > P_PAGE_SIZE) {
               printf("\t   [-] Trying to get new inode from path (%s) to be part of Protected Files... FAILED!\n",
                                                                                                              optarg);
               fprintf(stderr, "\t  *) Argument is too long (%lu) - MAX allowed length is %u\n\n",
                                                                     strlen(optarg),P_PAGE_SIZE);
               exit(-1);
            }
            if (stat(optarg,&p_tmp_st)) {
               printf("\t   [-] Trying to get new inode from path (%s) to be part of Protected Files... FAILED!\n",
                                                                                                              optarg);
               fprintf(stderr, "\t  *) %s() error: stat failed. [errno(%d) = %s]\n\n",
                                                          __func__,errno,strerror(errno));
               exit(-1);
            } else {
               /* This should never happened, but just in case :) */
               if ( (p_tmp_st.st_mode & S_IFMT) == S_IFLNK) {
                  printf("\t   [-] Trying to get new inode from path (%s) to be part of Protected Files... FAILED!\n",
                                                                                                              optarg);
                  printf("\t  *) Path points to symlink. We don't like symlinks :( Exiting...\n\n");
                  exit(-1);
               }
               if ( (p_tmp_st.st_mode & S_IFMT) == S_IFDIR) {
                  printf("\t   [-] Trying to get new inode from path (%s) to be part of Protected Files... FAILED!\n",
                                                                                                              optarg);
                  printf("\t  *) Path points to directory. We don't like it :( Exiting...\n\n");
                  exit(-1);
               }
               if ( (p_tmp_st.st_mode & S_IFMT) != S_IFREG) {
                  printf("\t   [-] Trying to get new inode from path (%s) to be part of Protected Files... FAILED!\n",
                                                                                                              optarg);
                  printf("\t  *) Path does NOT point to the regular file. We don't like it :( Exiting...\n\n");
                  exit(-1);
               }
            }
            p_inode    = (unsigned long)p_tmp_st.st_ino;
            p_pf_low   = (unsigned int) p_inode;
            p_pf_high  = (unsigned int)(p_inode >> 0x20);
            p_protected_file_str = strdup(optarg);
            if (!p_protected_file_str) {
               printf("\t   [-] Trying to get new inode from path (%s) to be part of Protected Files... FAILED!\n",
                                                                                                              optarg);
               fprintf(stderr, "\t  *) %s() error: strdup() failed. [errno(%d) = %s]\n\n",
                                                          __func__,errno,strerror(errno));
               exit(-1);
            }
            printf("\t   [-] Trying to get new inode from path (%s) to be part of Protected Files... DONE!\n",
                                                                                                p_protected_file_str);
            printf("\t     *) New (Un)Protecting File inode is %lu (high[%u] low[%u]).\n",
                                                                         p_inode,p_pf_high,p_pf_low);
            break;

         case 'm':
            printf("\t   [?] Changing path to the configuration module...\r");
            p_config_module_path = strdup(optarg);
            if (!p_config_module_path) {
               printf("\t   [-] Changing path to the configuration module... FAILED!\n");
               printf("\t     *) dup2() error! - [errno(%d) => %s]\n\n",errno,strerror(errno));
               exit(-1);
            }
            printf("\t   [+] Changing path to the configuration module... DONE!\n");
            printf("\t     *) New path to the configuration module is: [%s].\n",p_config_module_path);
            break;

         case 'f':
            printf("\t   [+] Force flag enabled (run integrity function after configuration change)\n");
            p_force_run = 0x1;
            break;

         case 'h':
         case '?':
         default:

             usage(argv[0]);
             break;

      }
   }

   if (p_timestamp == 0xFFFFFFFF && p_log_level == 0xFFFFFFFF &&
       p_force_run == 0xFFFFFFFF && p_block_modules == 0xFFFFFFFF
#ifdef P_LKRG_UNHIDE
       && p_unhide_module == 0xFFFFFFFF
#endif
       && (p_protected_process == 0xFFFFFFFF || p_pid == 0xFFFFFFFF)
       && (p_protected_file == 0xFFFFFFFF || p_pf_low == 0xFFFFFFFF ||
           p_pf_high == 0xFFFFFFFF || !p_protected_file_str)
       ) {
      fprintf(stderr,"\n\t   [+] None of the option changed default value... Exiting\n\n");
      exit(-1);
   }

   if ( (p_protected_process == 0xFFFFFFFF && p_pid != 0xFFFFFFFF) ||
        (p_protected_process != 0xFFFFFFFF && p_pid == 0xFFFFFFFF) ) {
      fprintf(stderr,"\n\t   [+] Protected Process MUST be set together with PID value! Exiting...\n\n");
      exit(-1);
   }

   if ( (p_protected_file == 0xFFFFFFFF && p_pf_low != 0xFFFFFFFF) ||
        (p_protected_file != 0xFFFFFFFF && p_pf_low == 0xFFFFFFFF) ) {
      fprintf(stderr,"\n\t   [+] Protected File MUST be set together with File Path value! Exiting...\n\n");
      exit(-1);
   }

   printf("\t[+] Validating configuration module path [%s]...\n",p_config_module_path);
   if (p_validate_module_path(p_config_module_path,&p_fd)) {
      fprintf(stderr,"\t  *) Validation FAILED! :( Exiting...\n\n");
      goto p_err;
   }

   printf("\t[+] mmap() configuration module ELF file...\n");
   if ( (p_mem = (char *)mmap(NULL,
                              p_global_size,
                              PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_FILE | MAP_POPULATE,
                              p_fd,
                              0x0)) == MAP_FAILED) {
      fprintf(stderr,"\t  *) %s() error: can't mmap() file [errno[%d] => %s]\n\n",
                                                          __func__,errno,strerror(errno));
      goto p_err;
   }
   printf("\t  *) DONE!\n");

   printf("\t[+] Validating and parsing ELF file/format...\n");
   if (p_validate_ELF(p_mem)) {
      fprintf(stderr,"\t  *) Validation FAILED! :( Exiting...\n\n");
      goto p_err;
   }
   printf("\t[+] Validation SUCCESS!\n");
   printf("\t  *) Found control structure at offset [0x%lx]...\n",p_offset);

   printf("\t[+] Changing control structure in the control module...\n");
   if ( (p_ret = p_change_ctrl_struct((void *)p_mem)) == -1) {
      fprintf(stderr,"\t  *) %s() error while changing control structure in control module ;(\n\n",
                                                                                              __func__);
      goto p_err;
   }
   printf("\t  *) DONE! (synced)\n");

   memset(p_pass,0x0,MAX_PASS);
   printf("\t[+] Please enter secret configuration module password\n");
   printf("\t  *) ");
   if ( (p_ret = p_get_pass(p_pass,MAX_PASS,(char)'*',stdin)) == -1) {
      fprintf(stderr,"\t  *) %s() error while reading password ;(\n\n", __func__);
      goto p_err;
   }

#ifdef P_LKRG_DEBUG
   printf("\n\t  *) I have read [%d chars length] password => [%s]\n",p_ret,p_pass);
#endif


   printf("\t[+] Trying to inject control module...\n");
   if ( (p_ret = p_load_ctrl_module(p_mem,p_pass)) == -1) {
      fprintf(stderr,"\t  *) %s() error while injecting control module to the kernel ;(\n\n",
                                                                                          __func__);
      printf("\t#############################################\n");
      printf("\t#### Did you type ??? Wrong password ??? ####\n");
      printf("\t#############################################\n\n");
      goto p_err;
   }
   printf("\t  *) DONE!\n");

// clear password in the buffer! - AGAIN (just in case)
   memset(p_pass,0x0,MAX_PASS);

   printf("\t[+] Trying to clean kernel from control module...\n");
   if ( (p_ret = p_unload_ctrl_module()) == -1) {
      fprintf(stderr,"\t  *) %s() error while deleting control module from the kernel ;(\n\n",
                                                                                          __func__);
      goto p_err;
   }
   printf("\t  *) DONE!\n");

//   printf("\n\t[+] SUCCESS! :)\n\n");
   p_print_warning();

p_err:

   if (p_fd >= 0x0) {
      if (close(p_fd)) {
         fprintf(stderr, "\n\t  *) %s() error: close failed. [errno(%d) = %s]\n\n",
                                                             __func__,errno,strerror(errno));
         exit(-1);
      }
   }

   if (p_mem != MAP_FAILED) {
      if (munmap(p_mem,p_global_size) == -1) {
         /* Something is REALY fucked up! */
         fprintf(stderr,"%s() error: can't munmap() file [errno[%d] => %s]\n",__func__,errno,strerror(errno));
         exit(-1);
      }
   }

   return 0x0;
}


void usage(char *arg) {

   printf("\t   [+] Usage:\n\n\t\t   -t <value>   : New timestamp value in seconds [between 5-1800]\n");
   printf("\t\t   -l <value>   : New log level value. Available modes:\n");
   printf("\t\t                      0 - none\n");
   printf("\t\t                      1 - alive\n");
   printf("\t\t                      2 - errors (unused)\n");
   printf("\t\t                      3 - warns\n");
   printf("\t\t                      4 - infos\n");
#ifdef P_LKRG_DEBUG
   printf("\t\t                      5 - debug\n");
   printf("\t\t                      6 - strong debug (!! a lot of data !!)\n");
#endif
   printf("\t\t   -b <value>   : Configure kernel module loading:\n");
   printf("\t\t                      0 - unblock\n");
   printf("\t\t                      1 - block\n");
#ifdef P_LKRG_UNHIDE
   printf("\t\t   -u <value>    : Configure (Un)hide p_lkrg module flag:\n");
   printf("\t\t                      0 - hide\n");
   printf("\t\t                      1 - unhide\n");
#endif
   printf("\t\t   -P <value>   : Protected Process action (must be used with -p switch):\n");
   printf("\t\t                      0 - Unprotect process\n");
   printf("\t\t                      1 - Protect process\n");
   printf("\t\t   -p <pid>     : <pid> for the (Un)Protected Process action (must be used with -P switch)\n");
   printf("\t\t   -S <value>   : Protected File/Logs action (must be used with -s switch):\n");
   printf("\t\t                      0 - Unprotect file\n");
   printf("\t\t                      1 - Protect file\n");
   printf("\t\t                      2 - Unprotect logs\n");
   printf("\t\t                      3 - Protect logs\n");
   printf("\t\t   -s <path>    : <path> for the (Un)Protected File action (must be used with -S switch)\n");
   printf("\t\t   -m <value>   : Change default configuration module path\n");
   printf("\t\t                      *) default path is [%s]\n",p_config_module_path);
   printf("\t\t   -f           : Run integrity function\n");
   printf("\t\t   -h           : This help screen.\n\n");
   exit(-1);

}

int p_check_priv(void) {

   uid_t p_ruid,p_euid,p_suid;
   gid_t p_rgid,p_egid,p_sgid;

   if (getresuid(&p_ruid,&p_euid,&p_suid))
      return -1;

#if 0
   printf("\nruid[%d] euid[%d] suid[%d]\n",p_ruid,p_euid,p_suid);
#endif

   /* SUID binary? */
   if (p_ruid != p_euid || p_ruid != p_suid || p_euid != p_suid)
      return -1;

   /* not root */
   if (p_ruid || p_euid || p_suid)
      return -1;

   if (getresgid(&p_rgid,&p_egid,&p_sgid))
      return -1;

#if 0
   printf("rgid[%d] egid[%d] sgid[%d]\n",p_rgid,p_egid,p_sgid);
#endif

   /* SGID binary? */
   if (p_rgid != p_egid || p_rgid != p_sgid || p_egid != p_sgid)
      return -1;

   /* not root */
   if (p_rgid || p_egid || p_sgid)
      return -1;

   return 0;
}

int p_validate_module_path(char *p_arg, int *p_out) {

   struct stat p_tmp;
   int p_ret;


   //  - check if it is not symlink
   if ( (*p_out = open(p_arg, O_RDONLY | O_EXCL | O_NOFOLLOW)) == -1) {
      fprintf(stderr, "\t  *) %s() error: open failed. [errno(%d) = %s]\n\n",
                                                          __func__,errno,strerror(errno));
      return -1;
   }

   if (fstat(*p_out,&p_tmp)) {
      fprintf(stderr, "\t  *) %s() error: stat failed. [errno(%d) = %s]\n\n",
                                                          __func__,errno,strerror(errno));
      p_ret = -1;
      goto p_err;
   } else {
      /* This should never happened, but just in case :) */
      if ( (p_tmp.st_mode & S_IFMT) == S_IFLNK) {
         printf("\t  *) Path points to symlink. We don't like symlinks :( Exiting...\n\n");
         p_ret = -1;
         goto p_err;
      }
      if ( (p_tmp.st_mode & S_IFMT) == S_IFDIR) {
         printf("\t  *) Path points to directory. We don't like it :( Exiting...\n\n");
         p_ret = -1;
         goto p_err;
      }
      if ( (p_tmp.st_mode & S_IFMT) != S_IFREG) {
         printf("\t  *) Path does NOT point to the regular file. We don't like it :( Exiting...\n\n");
         p_ret = -1;
         goto p_err;
      }
   }

   //  - check st_size

   if (p_tmp.st_size > MAX_TRESHOLD) {
      fprintf(stderr,"\t  *) %s() error: file is too big!\n\n",__func__);
      p_ret = -1;
      goto p_err;
   }

   p_global_size = p_tmp.st_size;

   /* Exclusive lock */
   if ( (p_ret = flock(*p_out,LOCK_EX)) == -1) {
      fprintf(stderr, "\t  *) %s() error: flock failed :( [errno(%d) = %s]\n\n",
                                                            __func__,errno,strerror(errno));
      goto p_err;
   }

   /* Set file offset to the beginning of the file */
   if ( (p_ret = lseek(*p_out,0x0,SEEK_SET)) == (off_t) -1) {
      fprintf(stderr, "\t  *) %s() error: lseek failed. [errno(%d) = %s]\n\n",
                                                          __func__,errno,strerror(errno));
      goto p_err;
   }

   /* Ftruncate for mmap() */
/*
   if ( (p_ret = ftruncate(*p_out, p_global_size)) == -1) {
      fprintf(stderr, "\t  *) %s() error: ftruncate failed. [errno(%d) = %s]\n\n",
                                                          __func__,errno,strerror(errno));
      goto p_err;
   }
*/

   /* SUCCESS - everythink went well! :) */
   p_ret = 0x0;
   return p_ret;

p_err:

   if (close(*p_out)) {
      fprintf(stderr, "\n\t  *) %s() error: [1] close failed. [errno(%d) = %s]\n\n",
                                                          __func__,errno,strerror(errno));
      exit(-1);
   }

   return p_ret;
}

int p_get_pass(char *p_buf, unsigned int p_size, char p_mask, FILE *p_fp) {

   struct termios p_kbd_old, p_kbd_new;
   int p_tmp; // for fgetc()
   unsigned int p_idx; // index in the buffer

   if (!p_buf || !p_fp || p_size > MAX_PASS || (p_mask < 0x20 || p_mask > 0x7E))
      return -1;

   if (tcgetattr(0, &p_kbd_old)) {
      fprintf(stderr, "\t  *) %s() error: tcgetattr failed.\n\n", __func__);
      return -1;
   }
   memcpy(&p_kbd_new, &p_kbd_old, sizeof(struct termios));

   p_kbd_new.c_lflag &= ~(ICANON | ECHO);
   p_kbd_new.c_cc[VTIME] = 0;
   p_kbd_new.c_cc[VMIN] = 1;

   if (tcsetattr (0, TCSANOW, &p_kbd_new)) {
      fprintf(stderr, "\t  *) %s() error: tcsetattr failed.\n\n", __func__);
      return -1;
   }

   p_idx = 0x0; // begin reading / writing
   while( ((p_tmp = fgetc(p_fp)) != '\n' && p_tmp != EOF && p_idx < p_size-1) ||
          (p_idx < p_size-1 && p_tmp == 0x7F) ) {

      if (p_tmp != 0x7F) {
         fputc(p_mask,stdout);
         p_buf[p_idx++] = p_tmp;
//         printf("p_idx => [%d]%d\n",p_tmp,p_idx);
      } else if (p_idx > 0) {
         fputc(0x8, stdout);
         fputc(' ', stdout);
         fputc(0x8, stdout);
         p_buf[--p_idx] = 0x0;
      }
   }
   p_buf[p_idx] = p_buf[p_size-1] = 0x0;

   /* reset original keyboard  */
   if (tcsetattr (0, TCSANOW, &p_kbd_old)) {
       fprintf(stderr, "\t  *) %s() error: tcsetattr failed.\n\n", __func__);
       return -1;
   }

   return p_idx;
}

int p_validate_ELF(char *p_buf) {

   int p_ret;
   off_t p_tmp_offset;

   if (p_validate_ELF_hdr(p_buf)) {
      p_ret = -1;
      goto p_err;
   }

   if ( (p_tmp_offset = p_find_text_section(p_buf)) < 0) {
      p_ret = -1;
      goto p_err;
   }

   /* SUCCESS! We have found offset! */
   p_offset = p_tmp_offset;
   p_offset += PI3_MARKER_SIZE;
   p_ret = 0x0;

p_err:

   return p_ret;

}

int p_validate_ELF_hdr(char *p_buf) {

   Elf64_Ehdr *p_hdr = (Elf64_Ehdr *)p_buf;
   Elf32_Ehdr *p_hdr_32 = (Elf32_Ehdr *)p_buf;

   if (!p_hdr)
      return -1;

   if (p_hdr->e_ident[EI_MAG0] != ELFMAG0) {
      fprintf(stderr, "\t  *) %s() error: ELF Header EI_MAG0 incorrect.\n\n",__func__);
      return -1;
   }

   if (p_hdr->e_ident[EI_MAG1] != ELFMAG1) {
      fprintf(stderr, "\t  *) %s() error: ELF Header EI_MAG1 incorrect.\n\n",__func__);
      return -1;
   }

   if (p_hdr->e_ident[EI_MAG2] != ELFMAG2) {
      fprintf(stderr, "\t  *) %s() error: ELF Header EI_MAG2 incorrect.\n\n",__func__);
      return -1;
   }

   if (p_hdr->e_ident[EI_MAG3] != ELFMAG3) {
      fprintf(stderr, "\t  *) %s() error: ELF Header EI_MAG3 incorrect.\n\n",__func__);
      return -1;
   }

/* 32 vs 64 */
//   if (p_hdr->e_ident[EI_CLASS] != /*ELFCLASS32*/ ELFCLASS64) {
//      fprintf(stderr, "%s() error: Unsupported ELF File Class.\n",__func__);
//      return -1;
//   }
   if (p_hdr->e_ident[EI_CLASS] == ELFCLASS32) {
      /* OK, so this is 32 bits ELF not 64! */
      p_elf_32 = 1;
      if (p_hdr_32->e_machine != EM_386) {
         fprintf(stderr, "\t  *) %s() error: Unsupported ELF File target. Binary is idetified"
                         "as ELF32 but file class is not EM_386!\n\n",__func__);
         return -1;
       }
   } else if (p_hdr->e_ident[EI_CLASS] == ELFCLASS64) {
      p_elf_32 = 0x0;
      /* 32 vs 64 */
      if (p_hdr->e_machine != EM_X86_64) {
         fprintf(stderr, "\t  *) %s() error: Unsupported ELF File target. Binary is idetified"
                         "as ELF64 but file class is not EM_X86_64!\n\n",__func__);
         return -1;
       }
   } else {
      fprintf(stderr, "\t  *) %s() error: Unsupported ELF File Class[%d].\n\n",
                                                          __func__,p_hdr->e_ident[EI_CLASS]);
      return -1;
   }

   if (p_elf_32) {

      if (p_hdr_32->e_ident[EI_DATA] != ELFDATA2LSB) {
         fprintf(stderr, "\t  *) %s() error: Unsupported ELF File byte order.\n\n",__func__);
         return -1;
      }

      if (p_hdr_32->e_ident[EI_VERSION] != EV_CURRENT) {
         fprintf(stderr, "\t  *) %s() error: Unsupported ELF File version.\n\n",__func__);
         return -1;
      }

      if (p_hdr_32->e_ident[EI_OSABI] != ELFOSABI_LINUX && p_hdr->e_ident[EI_OSABI] != ELFOSABI_SYSV) {
         fprintf(stderr, "\t  *) %s() error: Unsupported ELF ABI[%d] (only Linux!).\n\n",
                                                                __func__,p_hdr->e_ident[EI_OSABI]);
         return -1;
      }

      /* Only modules! */
      if(p_hdr_32->e_type != ET_REL) {
         fprintf(stderr, "\t  *) %s() error: Unsupported ELF File type.\n\n",__func__);
         return -1;
      }

   /* Offset might be different */
   } else {

      if (p_hdr->e_ident[EI_DATA] != ELFDATA2LSB) {
         fprintf(stderr, "\t  *) %s() error: Unsupported ELF File byte order.\n\n",__func__);
         return -1;
      }

      if (p_hdr->e_ident[EI_VERSION] != EV_CURRENT) {
         fprintf(stderr, "\t  *) %s() error: Unsupported ELF File version.\n\n",__func__);
         return -1;
      }

      if (p_hdr->e_ident[EI_OSABI] != ELFOSABI_LINUX && p_hdr->e_ident[EI_OSABI] != ELFOSABI_SYSV) {
         fprintf(stderr, "\t  *) %s() error: Unsupported ELF ABI[%d] (only Linux!).\n\n",
                                                                __func__,p_hdr->e_ident[EI_OSABI]);
         return -1;
      }

      /* Only modules! */
      if(p_hdr->e_type != ET_REL) {
         fprintf(stderr, "\t  *) %s() error: Unsupported ELF File type.\n\n",__func__);
         return -1;
      }

   }

   return 0x0;
}

off_t p_find_text_section(char *p_buf) {

   unsigned int p_tmp;
   char *p_tmp_name;
   off_t p_candidate = 0x0;
   unsigned long p_cnt;

   if (p_elf_32) {
      Elf32_Ehdr *p_hdr = (Elf32_Ehdr *) p_buf;
      Elf32_Shdr *p_shdr = (Elf32_Shdr *) ((long)p_hdr + (long)p_hdr->e_shoff);
//      Elf32_Phdr *p_phdr = (Elf32_Phdr *) ((long)p_hdr + (long)p_hdr->e_phoff);

      if (VAL_TOO_BIG(p_hdr->e_shoff,p_global_size-sizeof(Elf32_Shdr))) {
         fprintf(stderr, "\t  *) %s() error: ELF section header offset is invalid!\n\n",__func__);
         return -1;
      }

      if (VAL_TOO_BIG(p_hdr->e_shoff+(p_hdr->e_shnum*sizeof(Elf32_Shdr)),p_global_size)) {
         fprintf(stderr, "\t  *) %s() error: ELF section header offset and number of section "
                         "are too high!\n\n",
                         __func__);
         return -1;
      }

      if (p_hdr->e_phoff) {
         fprintf(stderr, "\t  *) %s() error: ET_REL objects should NOT include Program Header! :(\n\n",
                         __func__);
         return -1;
      }

/* ET_REL objects should NOT have Program Header */
/*
      if (VAL_TOO_BIG(p_hdr->e_phoff,p_global_size-sizeof(Elf32_Phdr))) {
         fprintf(stderr, "\t  *) %s() error: ELF program header offset is invalid!\n\n",__func__);
         return -1;
      }

      if (VAL_TOO_BIG(p_hdr->e_phoff+(p_hdr->e_phnum*sizeof(Elf32_Phdr)),p_global_size)) {
         fprintf(stderr, "\t  *) %s() error: ELF program header offset and number of segments "
                         "are too high!\n\n",
                         __func__);
         return -1;
      }
*/
      for (p_tmp = 0x0; p_tmp < p_hdr->e_shnum; p_tmp++) {
         p_tmp_name = (char*)((long)(p_shdr[p_tmp].sh_name)+
                                 ((long)p_hdr+(long)(p_shdr[p_hdr->e_shstrndx].sh_offset)));
         if (!strcmp(p_tmp_name,".init.text")) {
            /* OK we have candidate! */
            if (p_shdr[p_tmp].sh_type == 0x1 &&
                p_shdr[p_tmp].sh_flags & SHF_ALLOC &&
                p_shdr[p_tmp].sh_flags & SHF_EXECINSTR &&
                p_shdr[p_tmp].sh_info == 0x0)
               p_candidate = p_shdr[p_tmp].sh_offset;
         }
         printf("\t  *) Found Section [%s] size[0x%x]\n",
                                 (!p_shdr[p_tmp].sh_type)?"NULL":
                                 p_tmp_name,
                                 p_shdr[p_tmp].sh_size
                                 );
      }
      if (!p_candidate) {
         fprintf(stderr, "\t  *) %s() error: can't find valid candidate in ELF section :(\n\n",
                                                                                          __func__);
         return -1;
      }
      printf("\t  *) Candidate at offset [0x%lx]. Validating...\n",
                                                             p_candidate);

      if (VAL_TOO_BIG(p_candidate+PI3_CTRL_STRUCT_SIZE+PI3_MARKER_SIZE*2+0x1,p_global_size-1)) {
         fprintf(stderr, "\t  *) %s() error: ELF section header offset is invalid!\n\n",__func__);
         return -1;
      }


/* ET_REL objects should NOT have Program Header */
/*
      for (p_tmp = 0x0; p_tmp < p_hdr->e_phnum; p_tmp++) {
         printf("\t  *) Found Segment [%s] offset[0x%lx] flags[0x%x] filesz[0x%lx]\n",
                                 (!p_phdr[p_tmp].p_type)?"NULL":
                                 (p_phdr[p_tmp].p_type == 1)?"LOAD":
                                 (p_phdr[p_tmp].p_type == 2)?"DYNAMIC":
                                 (p_phdr[p_tmp].p_type == 3)?"INTERP":
                                 (p_phdr[p_tmp].p_type == 4)?"NOTE":
                                 (p_phdr[p_tmp].p_type == 5)?"SHLIB":
                                 (p_phdr[p_tmp].p_type == 6)?"PHDR":
                                 (p_phdr[p_tmp].p_type == 0x70000000)?":LOPROC":
                                 (p_phdr[p_tmp].p_type == 0x7FFFFFFF)?"HIPROC":
                                 "UKNOWN!",
                                 p_phdr[p_tmp].p_offset,
                                 p_phdr[p_tmp].p_flags,
                                 p_phdr[p_tmp].p_filesz);
      }
*/

      /* Let's find marker */

      p_tmp_name = p_buf + p_candidate;
      p_cnt = p_candidate;
      while (p_cnt < p_global_size-1-PI3_MARKER_SIZE &&
             (*(p_tmp_name+0) != PI3_MARKET_INIT_START0 ||
              *(p_tmp_name+1) != PI3_MARKET_INIT_START1 ||
              *(p_tmp_name+2) != PI3_MARKET_INIT_START2 ||
              *(p_tmp_name+3) != PI3_MARKET_INIT_START3 ||
              *(p_tmp_name+4) != PI3_MARKET_INIT_START4 ||
              *(p_tmp_name+5) != PI3_MARKET_INIT_START5 ||
              *(p_tmp_name+6) != PI3_MARKET_INIT_START6 ||
              *(p_tmp_name+7) != PI3_MARKET_INIT_START7)
             ) {
         p_cnt++;
         p_tmp_name++;
      }

      /* Not enough available data in the buffer */
      if (p_cnt == p_global_size-1-PI3_MARKER_SIZE || !(p_cnt+PI3_CTRL_STRUCT_SIZE+PI3_MARKER_SIZE < p_global_size-1)) {
         fprintf(stderr, "\t  *) %s() error: Validation of ELF section candidate FAILED :(\n\n",
                                                                                           __func__);
         return -1;
      }

      /*
       * OK we found marker in .text section.
       * Assumption is this marker is original enough that compiler
       * will never generate marker bytes next to each other.
       * It is possible user make changes by hand to put those bytes
       * Let's find next marker after control structure.
       *
       * At this point it is enough data in the buffer to safely
       * reference ending marker bytes. Both marker together is unique.
       *
       * It is still possible someone put by hand those markers but next
       * we are going to ask for the password which only administrator
       * should know and this will be verification token for our
       * communication channel (with Linux Kernel Runtime Guard).
       */

      if ( *(p_tmp_name+PI3_MARKER_SIZE+PI3_CTRL_STRUCT_SIZE+0) != PI3_MARKET_INIT_END0 ||
           *(p_tmp_name+PI3_MARKER_SIZE+PI3_CTRL_STRUCT_SIZE+1) != PI3_MARKET_INIT_END1 ||
           *(p_tmp_name+PI3_MARKER_SIZE+PI3_CTRL_STRUCT_SIZE+2) != PI3_MARKET_INIT_END2 ||
           *(p_tmp_name+PI3_MARKER_SIZE+PI3_CTRL_STRUCT_SIZE+3) != PI3_MARKET_INIT_END3 ||
           *(p_tmp_name+PI3_MARKER_SIZE+PI3_CTRL_STRUCT_SIZE+4) != PI3_MARKET_INIT_END4 ||
           *(p_tmp_name+PI3_MARKER_SIZE+PI3_CTRL_STRUCT_SIZE+5) != PI3_MARKET_INIT_END5 ||
           *(p_tmp_name+PI3_MARKER_SIZE+PI3_CTRL_STRUCT_SIZE+6) != PI3_MARKET_INIT_END6 ||
           *(p_tmp_name+PI3_MARKER_SIZE+PI3_CTRL_STRUCT_SIZE+7) != PI3_MARKET_INIT_END7) {
         /* This marker MUST be here... something is fucked-up! */
         fprintf(stderr, "\t  *) %s() error: Validation of ELF section candidate FAILED :(\n\n",
                                                                                           __func__);
         return -1;
      }
      p_candidate = p_tmp_name - p_buf;
   } else {
      Elf64_Ehdr *p_hdr = (Elf64_Ehdr *) p_buf;
      Elf64_Shdr *p_shdr = (Elf64_Shdr *) ((long)p_hdr + (long)p_hdr->e_shoff);
//      Elf64_Phdr *p_phdr = (Elf64_Phdr *) ((long)p_hdr + (long)p_hdr->e_phoff);

      if (VAL_TOO_BIG(p_hdr->e_shoff,p_global_size-sizeof(Elf64_Shdr))) {
         fprintf(stderr, "\t  *) %s() error: ELF section header offset is invalid!\n\n",__func__);
         return -1;
      }

      if (VAL_TOO_BIG(p_hdr->e_shoff+(p_hdr->e_shnum*sizeof(Elf64_Shdr)),p_global_size)) {
         fprintf(stderr, "\t  *) %s() error: ELF section header offset and number of section "
                         "are too high!\n\n",
                         __func__);
         return -1;
      }

      if (p_hdr->e_phoff) {
         fprintf(stderr, "\t  *) %s() error: ET_REL objects should NOT include Program Header! :(\n\n",
                         __func__);
         return -1;
      }

/* ET_REL objects should NOT have Program Header */
/*
      if (VAL_TOO_BIG(p_hdr->e_phoff,p_global_size-sizeof(Elf64_Phdr))) {
         fprintf(stderr, "\t  *) %s() error: ELF program header offset is invalid!\n\n",__func__);
         return -1;
      }

      if (VAL_TOO_BIG(p_hdr->e_phoff+(p_hdr->e_phnum*sizeof(Elf64_Phdr)),p_global_size)) {
         fprintf(stderr, "\t  *) %s() error: ELF program header offset and number of segments "
                         "are too high!\n\n",
                         __func__);
         return -1;
      }
*/
      for (p_tmp = 0x0; p_tmp < p_hdr->e_shnum; p_tmp++) {
         p_tmp_name = (char*)((long)(p_shdr[p_tmp].sh_name)+
                                 ((long)p_hdr+(long)(p_shdr[p_hdr->e_shstrndx].sh_offset)));
         if (!strcmp(p_tmp_name,".init.text")) {
            /* OK we have candidate! */
            if (p_shdr[p_tmp].sh_type == 0x1 &&
                p_shdr[p_tmp].sh_flags & SHF_ALLOC &&
                p_shdr[p_tmp].sh_flags & SHF_EXECINSTR &&
                p_shdr[p_tmp].sh_info == 0x0)
               p_candidate = p_shdr[p_tmp].sh_offset;
         }
         printf("\t  *) Found Section [%s] size[0x%zx]\n",
                                 (!p_shdr[p_tmp].sh_type)?"NULL":
                                 p_tmp_name,
                                 (size_t)p_shdr[p_tmp].sh_size
                                 );
      }
      if (!p_candidate) {
         fprintf(stderr, "\t  *) %s() error: can't find valid candidate in ELF section :(\n\n",
                                                                                          __func__);
         return -1;
      }
      printf("\t  *) Candidate at offset [0x%lx]. Validating...\n",
                                                             p_candidate);

      if (VAL_TOO_BIG(p_candidate+PI3_CTRL_STRUCT_SIZE+PI3_MARKER_SIZE*2+1,p_global_size-1)) {
         fprintf(stderr, "\t  *) %s() error: ELF section header offset is invalid!\n\n",__func__);
         return -1;
      }


/* ET_REL objects should NOT have Program Header */
/*
      for (p_tmp = 0x0; p_tmp < p_hdr->e_phnum; p_tmp++) {
         printf("\t  *) Found Segment [%s] offset[0x%lx] flags[0x%x] filesz[0x%lx]\n",
                                 (!p_phdr[p_tmp].p_type)?"NULL":
                                 (p_phdr[p_tmp].p_type == 1)?"LOAD":
                                 (p_phdr[p_tmp].p_type == 2)?"DYNAMIC":
                                 (p_phdr[p_tmp].p_type == 3)?"INTERP":
                                 (p_phdr[p_tmp].p_type == 4)?"NOTE":
                                 (p_phdr[p_tmp].p_type == 5)?"SHLIB":
                                 (p_phdr[p_tmp].p_type == 6)?"PHDR":
                                 (p_phdr[p_tmp].p_type == 0x70000000)?":LOPROC":
                                 (p_phdr[p_tmp].p_type == 0x7FFFFFFF)?"HIPROC":
                                 "UKNOWN!",
                                 p_phdr[p_tmp].p_offset,
                                 p_phdr[p_tmp].p_flags,
                                 p_phdr[p_tmp].p_filesz);
      }
*/

      /* Let's find marker */

      p_tmp_name = p_buf + p_candidate;
      p_cnt = p_candidate;
      while (p_cnt < p_global_size-1-PI3_MARKER_SIZE &&
             (*(p_tmp_name+0) != PI3_MARKET_INIT_START0 ||
              *(p_tmp_name+1) != PI3_MARKET_INIT_START1 ||
              *(p_tmp_name+2) != PI3_MARKET_INIT_START2 ||
              *(p_tmp_name+3) != PI3_MARKET_INIT_START3 ||
              *(p_tmp_name+4) != PI3_MARKET_INIT_START4 ||
              *(p_tmp_name+5) != PI3_MARKET_INIT_START5 ||
              *(p_tmp_name+6) != PI3_MARKET_INIT_START6 ||
              *(p_tmp_name+7) != PI3_MARKET_INIT_START7)
             ) {
         p_cnt++;
         p_tmp_name++;
      }

      /* Not enough available data in the buffer */
      if (p_cnt == p_global_size-1-PI3_MARKER_SIZE || !(p_cnt+PI3_CTRL_STRUCT_SIZE+PI3_MARKER_SIZE < p_global_size-1)) {
         fprintf(stderr, "\t  *) %s() error: Validation of ELF section candidate FAILED :(\n\n",
                                                                                           __func__);
         return -1;
      }

      /*
       * OK we found marker in .text section.
       * Assumption is this marker is original enough that compiler
       * will never generate marker bytes next to each other.
       * It is possible user make changes by hand to put those bytes
       * Let's find next marker after control structure.
       *
       * At this point it is enough data in the buffer to safely
       * reference ending marker bytes. Both marker together is unique.
       *
       * It is still possible someone put by hand those markers but next
       * we are going to ask for the password which only administrator
       * should know and this will be verification token for our
       * communication channel (with Linux Kernel Runtime Guard).
       */

      if ( *(p_tmp_name+PI3_MARKER_SIZE+PI3_CTRL_STRUCT_SIZE+0) != PI3_MARKET_INIT_END0 ||
           *(p_tmp_name+PI3_MARKER_SIZE+PI3_CTRL_STRUCT_SIZE+1) != PI3_MARKET_INIT_END1 ||
           *(p_tmp_name+PI3_MARKER_SIZE+PI3_CTRL_STRUCT_SIZE+2) != PI3_MARKET_INIT_END2 ||
           *(p_tmp_name+PI3_MARKER_SIZE+PI3_CTRL_STRUCT_SIZE+3) != PI3_MARKET_INIT_END3 ||
           *(p_tmp_name+PI3_MARKER_SIZE+PI3_CTRL_STRUCT_SIZE+4) != PI3_MARKET_INIT_END4 ||
           *(p_tmp_name+PI3_MARKER_SIZE+PI3_CTRL_STRUCT_SIZE+5) != PI3_MARKET_INIT_END5 ||
           *(p_tmp_name+PI3_MARKER_SIZE+PI3_CTRL_STRUCT_SIZE+6) != PI3_MARKET_INIT_END6 ||
           *(p_tmp_name+PI3_MARKER_SIZE+PI3_CTRL_STRUCT_SIZE+7) != PI3_MARKET_INIT_END7) {
         /* This marker MUST be here... something is fucked-up! */
         fprintf(stderr, "\t  *) %s() error: Validation of ELF section candidate FAILED :(\n\n",
                                                                                           __func__);
         return -1;
      }
      p_candidate = p_tmp_name - p_buf;
   }

   return p_candidate;
}

int p_change_ctrl_struct(void *p_buf) {

   unsigned int *p_val = (unsigned int *)(p_buf + (unsigned int)p_offset);

   *p_val++ = p_timestamp; // Timer timestamp
   *p_val++ = p_log_level; // Log level
   *p_val++ = p_force_run; // (Un)Force run ?
   *p_val++ = p_block_modules; // (Un)Block modules ?

#ifdef P_LKRG_UNHIDE
   *p_val++ = p_unhide_module; // Unhide p_lkrg module
#else
   *p_val++ = 0xffffffff; // Reserved
#endif

   *p_val++ = p_protected_process;   // Protected process...
   *p_val++ = p_pid;                 // ... if so, PID
   *p_val++ = p_protected_file;      // Protected files...
   *p_val++ = p_pf_low;              // ... if so, Low number or entire inode...
   *p_val++ = p_pf_high;             // ... High number or padding
   *p_val++ = 0xffffffff; // Reserved 1
   *p_val++ = 0xffffffff; // Reserved 2
   *p_val++ = 0xffffffff; // Reserved 3
   *p_val++ = 0xffffffff; // Reserved 4
   *p_val++ = 0xffffffff; // Reserved 5

   if (msync(p_buf, p_global_size, MS_SYNC)) {
      fprintf(stderr, "\t  *) %s() error: msync failed. [errno(%d) = %s]\n\n",
                                                          __func__,errno,strerror(errno));
      return -1;
   }

   return 0;
}

static inline int init_module(void *module_image, unsigned long len, const char *param_values) {
    return syscall(__NR_init_module, module_image, len, param_values);
}

int p_load_ctrl_module(char *p_mem, char *p_pass) {

   char p_tmp[MAX_PASS+strlen(PI3_MODULE_PARAM_PASS)+4+P_PAGE_SIZE+strlen(PI3_MODULE_PARAM_PF)+2];
   unsigned int p_size = MAX_PASS+strlen(PI3_MODULE_PARAM_PASS)+4+P_PAGE_SIZE+strlen(PI3_MODULE_PARAM_PF)+2;

   memset(p_tmp,0x0,p_size);
   if (p_protected_file != 0xFFFFFFFF && p_protected_file_str) {
      snprintf(p_tmp,p_size-1,"%s=%s %s=%s",
                              PI3_MODULE_PARAM_PASS,p_pass,
                              PI3_MODULE_PARAM_PF,p_protected_file_str);
//                              PI3_MODULE_PARAM_PF,p_protected_file_str,
//                              PI3_MODULE_PARAM_PASS,p_pass);

   } else {
      snprintf(p_tmp,p_size-1,"%s=%s",PI3_MODULE_PARAM_PASS,p_pass);
   }

   p_tmp[p_size-1]=0x0;
// load module and use pass as parameter!
   if (init_module(p_mem,p_global_size,p_tmp)) {
      fprintf(stderr, "\t  *) %s() error: init_module failed. [errno(%d) = %s]\n\n",
                                                          __func__,errno,strerror(errno));
      return -1;
   }

// clear password in the buffer!
   memset(p_tmp,0x0,p_size);
   memset(p_pass,0x0,MAX_PASS);

   return 0x0;
}

static inline int delete_module(const char *p_name, int p_flags) {
    return syscall(__NR_delete_module, p_name, p_flags);
}

int p_unload_ctrl_module(void) {

   if (delete_module(PI3_MODULE_CTRL_NAME, O_NONBLOCK | O_EXCL)) {
      fprintf(stderr, "\t  *) %s() error: delete_module failed. [errno(%d) = %s]\n\n",
                                                          __func__,errno,strerror(errno));
      return -1;
   }

   return 0x0;
}

void p_print_warning(void) {

   printf("\n\t#############################################\n");
   printf("\t####              WARNING:               ####\n");
   printf("\t#############################################\n");
   printf("\t##                                         ##\n");
   printf("\t##  If blocking module option is disabled  ##\n");
   printf("\t##    and you type _INCORRECT_ password    ##\n");
   printf("\t## it won't be detected and entire process ##\n");
   printf("\t## will look like SUCCESS!                 ##\n");
   printf("\t##                                         ##\n");
   printf("\t##                                         ##\n");
   printf("\t##            - take this into account and ##\n");
   printf("\t##              verify changes manually !! ##\n");
   printf("\t##                                         ##\n");
   printf("\t#############################################\n\n");

}

int p_get_int(char *p_arg, char *p_err) {

   int p_val;
   char *p_end;

   errno = 0;
   p_val = (int)strtol(p_arg, &p_end, 10);

   if (errno || p_end == p_arg) {
      *p_err = 0x1;
      return -1;
   }

   *p_err = 0x0;
   return p_val;
}

long p_get_long(char *p_arg, char *p_err) {

   long p_val;
   char *p_end;

   errno = 0;
   p_val = (long)strtol(p_arg, &p_end, 10);

   if (errno || p_end == p_arg) {
      *p_err = 0x1;
      return -1;
   }

   *p_err = 0x0;
   return p_val;
}
