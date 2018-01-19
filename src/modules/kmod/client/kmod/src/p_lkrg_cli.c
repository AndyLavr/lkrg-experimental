/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Linux kernel Runtime Guard configuration channel module
 *
 * Notes:
 *  - None
 *
 * Timeline:
 *  - Created: 29.III.2016
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#include "p_lkrg_cli.h"

#define PI3_MARKER_INIT_START ".byte 0x41,0x64,0x61,0x6d,0x41,0x44,0x41,0x4d\n"
#define PI3_MARKER_INIT_END   ".byte 0x41,0x44,0x41,0x4d,0x41,0x64,0x61,0x6d\n"


char *pi3_pass;
char *pi3_path;

/*
 * Main entry point for the module - initialization.
 */
static int __init p_lkrg_kmod_cli_register(void) {

   __asm__("jmp p_kmod_cli_secret_label_1\n"
           PI3_MARKER_INIT_START
           ".int 0x00000000\n"     // Timestamp
           ".int 0x01010101\n"     // Log level
           ".int 0x02020202\n"     // Force to run checking routine
           ".int 0x03030303\n"     // Block / unblock dynamic module loading
           ".int 0x04040404\n"     // Hide / unhide or padding
           ".int 0x05050505\n"     // "Clean" message enable / disable
           ".int 0x06060606\n"     // Protected process...
           ".int 0x07070707\n"     // ... if so, PID
           ".int 0x08080808\n"     // Protected files...
           ".int 0x09090909\n"     // ... if so, Low number or entire inode...
           ".int 0x0a0a0a0a\n"     // ... High number or padding
           ".int 0x0b0b0b0b\n"     // Reserved 1
           ".int 0x0c0c0c0c\n"     // Reserved 2
           ".int 0x0d0d0d0d\n"     // Reserved 3
           ".int 0x0e0e0e0e\n"     // Reserved 4
           ".int 0x0f0f0f0f\n"     // Reserved 5
           PI3_MARKER_INIT_END

           /* Make compiler silent */
           "p_kmod_cli_secret_label_1:"
           :::);

   return 0x0;
}

/*
 * Nothink to do
 */
static void __exit p_lkrg_kmod_cli_deregister(void) {


}


module_init(p_lkrg_kmod_cli_register);
module_exit(p_lkrg_kmod_cli_deregister);

module_param(pi3_pass, charp, 0000);
MODULE_PARM_DESC(pi3_pass, "Meaning of Life... Universe... ;-)");
module_param(pi3_path, charp, 0000);
MODULE_PARM_DESC(pi3_path, "pi3ki31ny argument ;p");

MODULE_AUTHOR("Adam 'pi3' Zabrocki (http://pi3.com.pl)");
MODULE_DESCRIPTION("pi3's Linux kernel Runtime Guard");
MODULE_LICENSE("GPL"); // Don't think so...
