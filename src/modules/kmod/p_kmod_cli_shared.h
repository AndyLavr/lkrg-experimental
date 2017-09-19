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

#ifndef P_LKRG_KERNEL_CLI_SHARED_H
#define P_LKRG_KERNEL_CLI_SHARED_H

#include "../print_log/p_lkrg_log_level_shared.h"

#define P_LKRG_UNHIDE

#define PI3_MARKET_INIT_START0 0x41
#define PI3_MARKET_INIT_START1 0x64
#define PI3_MARKET_INIT_START2 0x61
#define PI3_MARKET_INIT_START3 0x6d
#define PI3_MARKET_INIT_START4 0x41
#define PI3_MARKET_INIT_START5 0x44
#define PI3_MARKET_INIT_START6 0x41
#define PI3_MARKET_INIT_START7 0x4d

#define PI3_MARKET_INIT_END0 0x41
#define PI3_MARKET_INIT_END1 0x44
#define PI3_MARKET_INIT_END2 0x41
#define PI3_MARKET_INIT_END3 0x4d
#define PI3_MARKET_INIT_END4 0x41
#define PI3_MARKET_INIT_END5 0x64
#define PI3_MARKET_INIT_END6 0x61
#define PI3_MARKET_INIT_END7 0x6d

#define PI3_MARKER_SIZE 0x8
#define PI3_MAX_MESSAGE 0x100
#define PI3_CTRL_STRUCT_SIZE 0x3c

#endif
