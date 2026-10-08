#include <kofmod/kofpathogen.h>

/*
 * kernel_selfhide_00.c - a kernel module unlinking itself from the kernel's
 * list of loaded modules.
 *
 *     list_del(&THIS_MODULE->list);
 *
 * After it, lsmod does not list the module, /proc/modules does not show it,
 * and it cannot be unloaded. There is no second use for the operation.
 *
 *
 * ---- WHY THIS IS A PROOF AND NOT A RARITY ARGUMENT ----------------------
 *
 * THIS_MODULE is a HANDLE. The kernel gives every module a struct module and
 * takes it back in every registration - proc_create, the owner field of any
 * file_operations, register_kprobe. A module passes it on; it has no reason
 * to look inside, because the contents are the kernel's bookkeeping ABOUT
 * the module rather than anything the module owns. Reaching into a FIELD of
 * it is editing what the kernel believes about you.
 *
 * MEASURED on 900 clean kernel modules from this machine: 2699 references to
 * __this_module, of which 2698 are offset zero - the handle. The one
 * exception is qlcnic.ko reading +0x18, its own name. NO clean module reaches
 * any other field. All four rootkit builds here do: both Diamorphine
 * generations at +4, +8, +0xc, +0x240, +0x244, and both hcrootkit builds at
 * +8 and +0xbc.
 *
 * NO OFFSET IS NAMED, deliberately. +8 is `list` on a 64-bit kernel and +4 on
 * a 32-bit one, and struct module's head has already been rearranged once;
 * naming the number would be a rule about one build. The statement is that
 * the module took the address of SOMETHING INSIDE its own struct module and
 * handed it to a list removal - which is layout free.
 *
 * IT COVERS TWO UNRELATED FAMILIES. Diamorphine and hcrootkit share no code,
 * no author and no resolver, and both do this. That is what a behaviour
 * looks like, as against a family's habits.
 *
 *
 * ---- WHAT THE ENGINE HAD TO LEARN ---------------------------------------
 *
 * A .ko is unlinked, so `mov rdi, &__this_module->list` assembles as
 * `48 c7 c7 00 00 00 00` - the operand is a HOLE and the symbol is in the
 * relocation beside it. The walk now reads the relocation table and carries
 * that identity on the register, which is what KOF_DIAG_FIELD_OF asks about.
 * Without it the register reads as holding zero.
 */

KOF_DIAG_NAME(DIAG_LKM_SELFHIDE);

/*
 * THE SYMBOL ROUTE ALONE. Everything here comes off the relocation table and
 * the instruction stream of one function; nothing has to be run.
 */
KOF_DIAG_VIA(KOF_DIAG_VIA_SYMBOL);

/*
 * A RELOCATABLE OBJECT, which on Linux is a loadable kernel module - and the
 * only kind of object whose operands carry relocations to read.
 */
KOF_DIAG_WHEN(KOF_FACT_OBJ_KIND, KOF_ELF_REL);

/*
 * ---- THE SYMBOL IS WHAT IS LOOKED FOR FIRST -----------------------------
 *
 * The analysis starts only for an object whose code refers INTO
 * __this_module, at an offset other than zero. That is a question about the
 * relocation table and decodes no instruction, and it is the cheap fact the
 * rest of this diagnose is a consequence of: a module cannot take the address
 * of a field of its own struct module without a relocation against that
 * symbol saying so.
 *
 * IT WAS NOT DECLARED, and the cost showed. With no sign at all this
 * diagnose passed its gate on every kernel module, so a verdict reading it
 * started the whole symbol route on all 900 clean ones: the kernel-module
 * corpus went from 1.45 s to 2.65 s for a question nearly none of them could
 * answer yes to. Declared, the route runs on the one clean module that
 * reaches a field - qlcnic.ko, which reads its own name - and on the
 * rootkits.
 *
 * A DECLARATION AND NOT SOMETHING THE ENGINE KNOWS: it has no idea that
 * __this_module matters. See KOF_DIAG_REFS for the one question it answers.
 */
KOF_DIAG_REFS("__this_module");

/*
 * ONE NODE AND NO LINK, because there is no second call to link to: the
 * removal is one operation on one object, and what makes it a statement is
 * WHOSE object it is. A tree would have nothing to say here that this does
 * not.
 *
 * `kmodule-list-edit` on its own is ordinary - 143 of 900 clean modules edit
 * a list, because a linked list is how the kernel holds everything. The
 * argument is the entire discriminator.
 */
KOF_DIAG_ANCHOR(d, KOF_NUCLEO_LIST_HIDE, 0);
KOF_DIAG_FIELD_OF(d, "__this_module");
