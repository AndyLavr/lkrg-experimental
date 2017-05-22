/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Main module
 *
 * Notes:
 *  - None
 *
 * Timeline:
 *  - Created: 24.XI.2015
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#ifndef P_LKRG_MAIN_H
#define P_LKRG_MAIN_H

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/cpu.h>
#include <linux/random.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/cpufreq.h>
#include <linux/cpu_pm.h>
#include <linux/netdevice.h>
#include <net/netevent.h>
#include <net/addrconf.h>
#include <linux/inetdevice.h>
#include <linux/usb.h>
#include <linux/acpi.h>

#include <linux/kprobes.h>
#include <linux/namei.h>
#include <linux/dcache.h>
#include <linux/limits.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/rbtree.h>

#include <linux/major.h>

#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/scatterlist.h>


/*
 * p_lkrg modules
 */
#include "modules/print_log/p_lkrg_print_log.h"               // printing, error and debug module
#include "modules/hashing/p_super_fast_hash.h"                // Hashing module
#include "modules/hashing/p_crypto_sha1.h"                    // SHA1 module
#include "modules/ksyms/p_resolve_ksym.h"                     // Resolver module
#include "modules/database/p_database.h"                      // Database module
#include "modules/integrity_timer/p_integrity_timer.h"        // Integrity timer module
#include "modules/kmod/p_kmod.h"                              // Kernel's modules module
#include "modules/notifiers/p_notifiers.h"                    // Notifiers module
#include "modules/self-defense/hiding/p_hiding.h"             // Hiding module

/*
 * Protected features
 */
#include "modules/protected_features/p_protected_API.h"


extern unsigned int p_init_log_level;

#endif
