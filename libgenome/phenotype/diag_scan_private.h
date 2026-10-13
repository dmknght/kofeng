/*
 * diag_scan_private.h - what the files of the diagnose scan share (the scan object, its hits, and the sweep that fills them). NOT PART OF THE SURFACE.
 */
#ifndef KGENOME_DIAG_SCAN_PRIVATE_H
#define KGENOME_DIAG_SCAN_PRIVATE_H

#include <stdlib.h>
#include <string.h>
#include "diag_scan.h"
#include <kofdebug.h>
#include "diag_private.h"
#include <kofcore.h>
#include <celllysis/celllysis.h>
#include <celllysis/nucleo.h>
#include <celllysis/space.h>
#include <genotype/image/funcs.h>

/*
 * ---- THE FIXED-WIDTH PORTS ------------------------------------------------
 *
 * ARM and AArch64 reach the kernel through one instruction, `svc`, with the
 * number in a register the ABI names (r7, x8) and the arguments in the first
 * six. All of that is nucleo's kgenome_nucleo_abi - the same row the old whole-image sweep
 * read - so this is only the reading of it: no byte pattern to search for, no
 * second syscall encoding to tell apart, and none of the x86 special cases
 * (socketcall, the zero-on-success carry) because ARM has neither.
 *
 * OLD ARM ABI: `svc 0x9000NN` carries the number in the instruction itself and
 * r7 is not read. Both are seen in the static IoT builds, so both are handled.
 */
static inline int kgenome_diag_fixed_arch(const struct kgenome_obj *obj)
{
	return obj->arch == KGENOME_ARCH_ARM || obj->arch == KGENOME_ARCH_ARM64;
}

/* ---- what one part offers another ---- */

int kgenome_diag_arg_regs(const struct kgenome_obj *obj, const uint8_t **out);
void kgenome_diag_at_syscall(struct kgenome_diag_scan *s, struct kgenome_cell_cur *k,
		struct kgenome_diag_orgs *w, const struct kgenome_obj *obj, const struct kgenome_cell_insn *in);
uint64_t kgenome_diag_cand_at(const uint8_t *p, uint64_t from, uint64_t n);
uint64_t kgenome_diag_cand_fixed(const struct kgenome_obj *obj, const uint8_t *p, uint64_t off,
		uint64_t from, uint64_t n);

#endif /* KGENOME_DIAG_SCAN_PRIVATE_H */
