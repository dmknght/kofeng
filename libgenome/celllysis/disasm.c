/*
 * disasm.c - the one entry (disasm.h): choose the architecture's decoder and
 * formatter, return the instruction as data.
 *
 * Nothing is decided twice: x86 is kgenome_x86_decode and kgenome_x86_format,
 * ARM is kgenome_arm32_decode and kgenome_arm32_format, AArch64 likewise; this file
 * reads a word where the architecture's instructions are words, turns the
 * formatter's result into the one result struct, and answers what an architecture
 * supports. The Thumb question is the one it cannot answer from bytes: an object's
 * entry point says it (bit 0 of e_entry), a bare buffer does not.
 */
#include <stdio.h>
#include <string.h>

#include <genotype/arm32/arm32.h>
#include <genotype/arm64/arm64.h>
#include <genotype/image/elf_image.h>
#include <genotype/image/obj.h>
#include <genotype/x86/x86.h>

#include "arch.h"
#include "disasm.h"

unsigned kgenome_disasm_level(unsigned arch)
{
	switch (arch) {
	case KGENOME_ARCH_X86:
	case KGENOME_ARCH_X86_64:
	case KGENOME_ARCH_ARM:
	case KGENOME_ARCH_ARM64:
		return KGENOME_DISASM_TEXT;
	default:
		return KGENOME_DISASM_NONE;
	}
}

unsigned kgenome_disasm_level_obj(const struct kgenome_obj *obj)
{
	unsigned lv;

	if (!obj)
		return KGENOME_DISASM_NONE;
	lv = kgenome_disasm_level(obj->arch);
	if (lv && obj->arch == KGENOME_ARCH_ARM && obj->format == KGENOME_FMT_ELF && obj->file_header &&
	    (kgenome_obj_elf(obj)->entry_addr & 1u))
		return KGENOME_DISASM_NONE;     /* Thumb: the entry point's low bit is the mode */
	return lv;
}

unsigned kgenome_disasm_arch(const struct kgenome_obj *obj, unsigned bits)
{
	if (obj && obj->arch != KGENOME_ARCH_X86 && obj->arch != KGENOME_ARCH_X86_64 &&
	    kgenome_disasm_level_obj(obj))
		return obj->arch;
	return bits == 32u ? KGENOME_ARCH_X86 : KGENOME_ARCH_X86_64;
}

const char *kgenome_disasm_name(unsigned arch)
{
	switch (arch) {
	case KGENOME_ARCH_X86: return "x86";
	case KGENOME_ARCH_X86_64: return "x64";
	case KGENOME_ARCH_ARM: return "a32";
	case KGENOME_ARCH_ARM64: return "a64";
	default: return NULL;
	}
}

unsigned kgenome_disasm_align(unsigned arch)
{
	return arch == KGENOME_ARCH_ARM || arch == KGENOME_ARCH_ARM64 ? 4u : 1u;
}

unsigned kgenome_disasm_max_len(unsigned arch)
{
	switch (arch) {
	case KGENOME_ARCH_X86:
	case KGENOME_ARCH_X86_64:
		return 16u;
	case KGENOME_ARCH_ARM:
	case KGENOME_ARCH_ARM64:
		return 4u;
	default:
		return 1u;
	}
}

int kgenome_disasm_code_be(const struct kgenome_obj *obj)
{
	return kgenome_obj_big_endian(obj) && !kgenome_obj_code_little_endian(obj);
}

static void put_text(const struct kgenome_disasm_req *req, const char *s)
{
	if (req->cap && req->text && !req->len_only)
		snprintf(req->text, req->cap, "%s", s);
}

static void from_gt(const struct kgenome_gt_fmt_res *g, struct kgenome_disasm_res *res)
{
	res->status = g->status;
	res->flow = g->flow;
	res->has_target = g->has_target;
	res->target = g->target;
}

/* the x86 instruction's flow and direct target, read from its category and first operand */
static void x86_flow(const struct kgenome_disasm_req *req, const struct kgenome_x86_insn *ix, struct kgenome_disasm_res *res)
{
	unsigned cat = kgenome_x86_cat(ix);
	struct kgenome_x86_op op;

	switch (cat) {
	case KGENOME_X86_C_CALL: res->flow = KGENOME_GT_FLOW_CALL; break;
	case KGENOME_X86_C_UNCOND_BR: res->flow = KGENOME_GT_FLOW_JUMP; break;
	case KGENOME_X86_C_COND_BR: res->flow = KGENOME_GT_FLOW_COND; break;
	case KGENOME_X86_C_RET: res->flow = KGENOME_GT_FLOW_RET; break;
	case KGENOME_X86_C_SYSCALL: case KGENOME_X86_C_INTERRUPT: case KGENOME_X86_C_UD:
		res->flow = KGENOME_GT_FLOW_TRAP;
		break;
	default:
		return;
	}
	if (res->flow == KGENOME_GT_FLOW_RET || res->flow == KGENOME_GT_FLOW_TRAP || !kgenome_x86_nops(ix))
		return;
	kgenome_x86_operand(ix, 0, &op);
	if (op.type == KGENOME_X86_OP_REL) {
		res->has_target = 1;
		res->target = req->va + ix->len + (uint64_t)op.v;
	}
}

static void do_x86(const struct kgenome_disasm_req *req, struct kgenome_disasm_res *res)
{
	char text[KGENOME_X86_TEXT];
	int mode = req->arch == KGENOME_ARCH_X86 ? 32 : 64;
	struct kgenome_x86_insn local;
	struct kgenome_x86_insn *ix = req->x86 ? req->x86 : &local;
	enum kgenome_status st = kgenome_x86_decode(ix, req->p, req->n, mode);

	if (st != KGENOME_OK) {
		res->status = st == KGENOME_TRUNCATED ? KGENOME_TRUNCATED : KGENOME_BAD_INPUT;
		res->len = 1;
		put_text(req, "(data)");
		return;
	}
	res->has_x86 = req->x86 != NULL;
	res->len = ix->len;
	res->status = KGENOME_OK;
	if (req->len_only)
		return;
	if (!kgenome_x86_format(ix, req->va, text, sizeof text))
		text[0] = 0;
	kgenome_x86_shorten(text);
	if (strlen(text) + 1u > req->cap) {
		res->status = KGENOME_TRUNCATED;
		return;
	}
	put_text(req, text);
	x86_flow(req, ix, res);
}

static void do_word(const struct kgenome_disasm_req *req, struct kgenome_disasm_res *res)
{
	uint32_t w;
	struct kgenome_gt_fmt_res g;

	if (req->n < 4u) {
		res->status = KGENOME_TRUNCATED;
		res->len = (uint32_t)req->n;
		put_text(req, "(data)");
		return;
	}
	if (req->arch == KGENOME_ARCH_ARM && req->be)
		w = (uint32_t)req->p[3] | (uint32_t)req->p[2] << 8 | (uint32_t)req->p[1] << 16 | (uint32_t)req->p[0] << 24;
	else
		w = (uint32_t)req->p[0] | (uint32_t)req->p[1] << 8 | (uint32_t)req->p[2] << 16 | (uint32_t)req->p[3] << 24;
	res->len = 4;
	if (req->len_only) {
		if (req->arch == KGENOME_ARCH_ARM64) {
			struct kgenome_arm64_insn in;

			res->status = kgenome_arm64_decode(&in, w) == KGENOME_OK ? KGENOME_OK : KGENOME_BAD_INPUT;
		} else {
			struct kgenome_arm32_insn in;

			res->status = kgenome_arm32_decode(&in, w) == KGENOME_OK ? KGENOME_OK : KGENOME_BAD_INPUT;
		}
		return;
	}
	if (req->arch == KGENOME_ARCH_ARM64) {
		struct kgenome_arm64_insn in;
		struct kgenome_arm64_fmt_req fr;

		(void)kgenome_arm64_decode(&in, w);
		fr.in = &in;
		fr.pc = req->va;
		fr.buf = req->text;
		fr.cap = req->cap;
		kgenome_arm64_format(&fr, &g);
	} else {
		struct kgenome_arm32_insn in;
		struct kgenome_arm32_fmt_req fr;

		(void)kgenome_arm32_decode(&in, w);
		fr.in = &in;
		fr.pc = req->va;
		fr.buf = req->text;
		fr.cap = req->cap;
		kgenome_arm32_format(&fr, &g);
	}
	from_gt(&g, res);
}

void kgenome_disasm(const struct kgenome_disasm_req *req, struct kgenome_disasm_res *res)
{
	memset(res, 0, sizeof *res);
	if (req->cap && req->text && !req->len_only)
		req->text[0] = 0;
	if (!req->n || !kgenome_disasm_level(req->arch)) {
		res->status = req->n ? KGENOME_UNSUPPORTED : KGENOME_TRUNCATED;
		return;
	}
	if (req->arch == KGENOME_ARCH_X86 || req->arch == KGENOME_ARCH_X86_64)
		do_x86(req, res);
	else
		do_word(req, res);
}
