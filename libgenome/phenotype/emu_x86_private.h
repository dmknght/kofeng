/*
 * emu_x86_private.h - what the x86 entry of the emulator's dispatch table shares between its files.
 * NOT PART OF THE SURFACE.
 *
 * The emulator is one core and one entry per architecture (struct kgenome_emu_arch, emu_private.h):
 * the core owns memory, budgets, the run loop and its stops, and the Linux and Windows environments;
 * an entry owns the decode, the execution of an instruction by its id, its register state beyond the
 * general registers (struct kgenome_emu_x86), its flags and its calling and syscall conventions.
 * This header is the x86 entry's: the flag bits as EFLAGS places them, the operand helpers every
 * instruction group calls (emu_state.c), the groups themselves (emu_ops.c, emu_ops_ext.c, emu_vec*.c,
 * emu_x87.c), the delay-loop recogniser (emu_loop.c) and the stack push the Windows environment uses
 * to call a guest handler (a Windows guest is an x86 or x86-64 PE). The execute switch and the entry
 * itself are emu_x86.c. Private to libgenome/phenotype/.
 */
#ifndef KGENOME_EMU_X86_PRIVATE_H
#define KGENOME_EMU_X86_PRIVATE_H

#include "emu_private.h"

#define KGENOME_EMU_FL_CF  (1u << 0)
#define KGENOME_EMU_FL_PF  (1u << 2)
#define KGENOME_EMU_FL_AF  (1u << 4)
#define KGENOME_EMU_FL_ZF  (1u << 6)
#define KGENOME_EMU_FL_SF  (1u << 7)
#define KGENOME_EMU_FL_DF  (1u << 10)
#define KGENOME_EMU_FL_OF  (1u << 11)

/* The x87 status word's condition codes. */
#define KGENOME_EMU_FSW_C0 (1u << 8)
#define KGENOME_EMU_FSW_C1 (1u << 9)
#define KGENOME_EMU_FSW_C2 (1u << 10)
#define KGENOME_EMU_FSW_C3 (1u << 14)

/* A backward branch (at, `at_len` long) to `top` was taken for the Nth time running
 * (KGENOME_EMU_DELAY_PROBE): skip the rest of the loop when it is a counted delay. See emu_loop.c. */
void kgenome_emu_delay_note(struct kgenome_emu *e, uint64_t top, uint64_t at, unsigned at_len);

uint64_t kgenome_emu_mask_of(unsigned bytes);
uint64_t kgenome_emu_sext(uint64_t v, unsigned bytes);
uint64_t kgenome_emu_reg_rd(const struct kgenome_emu *e, unsigned r, unsigned bytes,
		int high8);
void kgenome_emu_reg_wr(struct kgenome_emu *e, unsigned r, unsigned bytes, int high8,
		uint64_t v);
/*
 * THE HOST RUNS THE UNDEFINED CORNER OF A 16 BIT DOUBLE SHIFT where the host is x86-64 (see
 * kgenome_emu_host_dshift16, emu_state.c, and the SHLD/SHRD case of emu_ops.c). DEFINED HERE, in the
 * header both files read: it was defined in emu_state.c, which emu_ops.c never sees, so the call was
 * compiled out and the instruction stopped the run (DEAD2-1, tests/lib/genome/emu_dshift_host.c).
 */
#if defined(__x86_64__)
#define KGENOME_EMU_HOST_DSHIFT 1
#endif
uint16_t kgenome_emu_host_dshift16(uint16_t dst, uint16_t src, uint8_t cnt,
		int left, uint64_t *fl);
void kgenome_emu_fl_logic(struct kgenome_emu *e, uint64_t r, unsigned bytes);
void kgenome_emu_fl_add(struct kgenome_emu *e, uint64_t a, uint64_t b, uint64_t cin,
		unsigned bytes);
void kgenome_emu_fl_sub(struct kgenome_emu *e, uint64_t a, uint64_t b, uint64_t bin,
		unsigned bytes);
void kgenome_emu_op_keep(struct kgenome_emu *e, const struct kgenome_x86_op *op, uint64_t v);
void kgenome_emu_fl_cfof(struct kgenome_emu *e, int on);
int kgenome_emu_div(unsigned sz, int sgn, uint64_t hi, uint64_t lo, uint64_t d, uint64_t *q, uint64_t *r);
void kgenome_emu_fault_de(struct kgenome_emu *e, int overflow);
void kgenome_emu_fault_priv(struct kgenome_emu *e);
uint8_t *kgenome_emu_xmm_of(struct kgenome_emu *e, const struct kgenome_x86_op *op);
int kgenome_emu_ea_of(struct kgenome_emu *e, const struct kgenome_emu_insn *ix, const struct kgenome_x86_op *op,
		uint64_t *out);
int kgenome_emu_op_rd(struct kgenome_emu *e, const struct kgenome_emu_insn *ix, const struct kgenome_x86_op *op,
		uint64_t *out);
int kgenome_emu_vec_rd(struct kgenome_emu *e, const struct kgenome_emu_insn *ix, const struct kgenome_x86_op *op,
		uint8_t *buf, unsigned *sz);
int kgenome_emu_vec_wr(struct kgenome_emu *e, const struct kgenome_emu_insn *ix, const struct kgenome_x86_op *op,
		const uint8_t *buf, unsigned sz);
int kgenome_emu_op_wr(struct kgenome_emu *e, const struct kgenome_emu_insn *ix, const struct kgenome_x86_op *op,
		uint64_t v);
int kgenome_emu_push(struct kgenome_emu *e, uint64_t v);

int kgenome_emu_run_str(struct kgenome_emu *e, struct kgenome_emu_insn *ixp);
int kgenome_emu_run_misc(struct kgenome_emu *e, struct kgenome_emu_insn *ixp);
int kgenome_emu_run_shift(struct kgenome_emu *e, struct kgenome_emu_insn *ixp);
int kgenome_emu_run_sys(struct kgenome_emu *e, struct kgenome_emu_insn *ixp);
int kgenome_emu_run_vec(struct kgenome_emu *e, struct kgenome_emu_insn *ixp);
int kgenome_emu_run_vec_int(struct kgenome_emu *e, struct kgenome_emu_insn *ixp);
int kgenome_emu_run_vec_fp(struct kgenome_emu *e, struct kgenome_emu_insn *ixp);

/* One lane of SSE floating point (emu_vec_fp.c): the operation, the operands as bits, MXCSR.RC. The answers
 * are the architecture's for NaN, infinity, zero and the rounding; see that file. */
enum { KGENOME_EMU_FP_ADD, KGENOME_EMU_FP_SUB, KGENOME_EMU_FP_MUL, KGENOME_EMU_FP_DIV, KGENOME_EMU_FP_MIN,
       KGENOME_EMU_FP_MAX, KGENOME_EMU_FP_SQRT };
uint64_t kgenome_emu_fpd(unsigned op, uint64_t ub, uint64_t vb, unsigned rc);
uint32_t kgenome_emu_fps(unsigned op, uint32_t ub, uint32_t vb, unsigned rc);
uint64_t kgenome_emu_f2d(uint32_t b);
uint32_t kgenome_emu_d2f(uint64_t b, unsigned rc);
uint32_t kgenome_emu_i2f(int64_t n, unsigned rc);
uint64_t kgenome_emu_i2d(int64_t n, unsigned rc);
uint64_t kgenome_emu_f2i(double d, unsigned w, int trunc_to_zero, unsigned rc);
int kgenome_emu_run_x87(struct kgenome_emu *e, struct kgenome_emu_insn *ixp);
int kgenome_emu_run_bcd(struct kgenome_emu *e, struct kgenome_emu_insn *ixp);
int kgenome_emu_run_ext(struct kgenome_emu *e, struct kgenome_emu_insn *ixp);

#endif /* KGENOME_EMU_X86_PRIVATE_H */
