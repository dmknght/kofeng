/*
 * frame - THE FRAME OF A FUNCTION (libgenome/phenotype/frame.h): the graph and the facts of one function's decoded code, made once and read by the signing and the lineage.
 *
 * Every object here is described to the lib at run time (an ELF header record of either byte order, an architecture) and the code is assembled by the cfg kit's writer
 * (abstract programs spelled in every architecture, both byte orders) or by hand; nothing is a stored binary. Rows:
 *   HAND_X86     a function with a frame pointer, a store through a pointer and a call: the blocks' byte starts, the per-block bits, `framed`; the same code with no
 *                frame pointer, and with a second writer of rbp, where `[rbp+x]` becomes a place
 *   BE           THE DEFECT FP-12: the lineage built its graph with `.be = 0` whatever the object; on a MIPS-BE function whose first branch is `b` (beq $0,$0) that reads
 *                the word byte-reversed, calls the branch conditional and makes the dead code behind it reachable. The frame takes the object's byte order. (The lineage
 *                itself runs on x86 only today, so the defect is latent: shown here on the one graph both consumers now read.)
 *   RANDOM       random programs for every architecture and byte order: the frame's graph equals the textbook reference (cfg_kit ref_build), and each block's `at` is the
 *                byte address of its first instruction; the frame made from the caller's decode (`pre`) equals the frame it decodes itself; made twice, equal
 *   CACHE        one build per function whatever the number of asks, the table length is the key, a refused allocation is a state that is NOT kept (the next ask builds),
 *                and every byte charged is given back (a counting allocator, a refusal injected at each allocation in turn)
 *   HOSTILE      an extent outside the object, no length, an architecture with no rules, a function over the allowance, garbage bytes for every architecture: a state, never
 *                a crash, and `bits` is there whenever a graph is
 * RED: on the base there is no frame; the row BE is shown against what the base did by building the same instructions with be = 0 (the `old` check inside it).
 * Why the old tests missed it: (a) the lineage's solve builds its graph on x86 only, where be = 0 is right, so the line ran with the one value that hides it; (b) the cfg tests
 * pass `be` themselves, nothing ran the lineage's call with another; (c) the lineage tests compare links, which a dead block that is also unreached by any node never changes.
 */
#include "cfg_kit.h"

#include <phenotype/diag_scan.h>
#include <phenotype/frame.h>
#include <genotype/image/obj.h>

static struct kgenome_elf_info ei_of(int be, uint32_t flags)
{
	struct kgenome_elf_info ei;

	memset(&ei, 0, sizeof ei);
	ei.elf_data = be ? KGENOME_ELFDATA_BE : 1;
	ei.e_flags = flags;
	return ei;
}

static void obj_of(struct kgenome_obj *obj, struct kgenome_elf_info *ei, unsigned arch, uint64_t size)
{
	memset(obj, 0, sizeof *obj);
	obj->format = KGENOME_FMT_ELF;
	obj->arch = (uint8_t)arch;
	obj->obj_size = size;
	obj->file_header = ei;
}

static struct kgenome_frame_src src_of(const struct kgenome_obj *obj, const uint8_t *b, uint64_t n)
{
	struct kgenome_frame_src s;

	memset(&s, 0, sizeof s);
	s.obj = obj;
	s.base = b;
	s.size = n;
	return s;
}

/* ---- HAND_X86 ---- */

static void hand_x86(void)
{
	/* 0 push rbp; 1 mov rbp,rsp; 4 mov [rbp-8],edi; 7 test edi,edi; 9 jz +7 (to 18); 11 mov [rax],edi; 13 call +0; 18 pop rbp; 19 ret */
	static const uint8_t framed[] = { 0x55, 0x48, 0x89, 0xe5, 0x89, 0x7d, 0xf8, 0x85, 0xff, 0x74, 0x07, 0x89, 0x38, 0xe8, 0, 0, 0, 0, 0x5d, 0xc3 };
	uint8_t plain[sizeof framed];
	struct kgenome_elf_info ei = ei_of(0, 0);
	struct kgenome_obj obj;
	struct kgenome_frame_src s;
	struct kgenome_frame f;

	obj_of(&obj, &ei, KGENOME_ARCH_X86_64, sizeof framed);
	s = src_of(&obj, framed, sizeof framed);
	CK(kgenome_frame_make(&s, 0, sizeof framed, KGENOME_FRAME_KEEP_INSN, &f) == KGENOME_FRAME_OK);
	CK(f.bits == NULL && f.framed == 0u);                                      /* the facts are a memo: not made until asked */
	{
		const uint16_t *p1 = kgenome_frame_facts(&f, f.in), *p2 = kgenome_frame_facts(&f, f.in);

		CK(p1 != NULL && p1 == p2 && p1 == f.bits);                         /* made once, the same array after */
	}
	CK(f.n_insn == 9u && f.in && f.cfg.n_all == 3u && f.cfg.n_blk == 3u);
	CK(f.cfg.b[0].at == 0u && f.cfg.b[1].at == 11u && f.cfg.b[2].at == 18u);          /* byte starts; the length of a block is the next start less its own */
	CK(f.cfg.b[0].term == KGENOME_CFG_T_COND && f.cfg.b[0].succ[0] == 2u && f.cfg.b[0].succ[1] == 1u);
	CK(f.framed == 1u && f.be == 0u && f.mapped == 0u && f.va == 0u && f.fn == KGENOME_FUNCS_NONE);
	/* [rbp-8] is a slot of the frame, not a place: block 0 holds no memory bit, only the push; block 1 stores through rax and calls; block 2 holds nothing */
	CK(f.bits[0] == KGENOME_FRAME_B_PUSH);                                     /* (the push rbp of the prologue) */
	CK(f.bits[1] == (KGENOME_FRAME_B_MEMCELL | KGENOME_FRAME_B_MEMSTORE | KGENOME_FRAME_B_CALL));
	CK(f.bits[2] == KGENOME_FRAME_B_RET);                                      /* pop rbp; ret */
	kgenome_frame_release(&f, NULL);
	/* no frame pointer (nop; nop; nop; nop in place of push/mov): every [rbp+x] is a place */
	memcpy(plain, framed, sizeof framed);
	memset(plain, 0x90, 4);
	s = src_of(&obj, plain, sizeof plain);
	CK(kgenome_frame_make(&s, 0, sizeof plain, KGENOME_FRAME_KEEP_INSN, &f) == KGENOME_FRAME_OK && kgenome_frame_facts(&f, f.in));
	CK(f.framed == 0u && (f.bits[0] & (KGENOME_FRAME_B_MEMCELL | KGENOME_FRAME_B_MEMSTORE)) == (KGENOME_FRAME_B_MEMCELL | KGENOME_FRAME_B_MEMSTORE));
	kgenome_frame_release(&f, NULL);
	/* a frame pointer that something else writes (mov rbp, rax in place of two nops of the test) is not one either */
	{
		/* push rbp; mov rbp,rsp; mov rbp,rax; mov [rbp-8],edi; ret */
		static const uint8_t d2[] = { 0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0xc5, 0x89, 0x7d, 0xf8, 0xc3 };

		s = src_of(&obj, d2, sizeof d2);
		CK(kgenome_frame_make(&s, 0, sizeof d2, KGENOME_FRAME_KEEP_INSN, &f) == KGENOME_FRAME_OK && kgenome_frame_facts(&f, f.in));
		CK(f.framed == 0u && (f.bits[0] & KGENOME_FRAME_B_MEMSTORE));
		kgenome_frame_release(&f, NULL);
	}
	/* bytes that decode as nothing: the frame says the graph is a cut one (`cut`, `n_skip`, status TRUNCATED) */
	{
		static const uint8_t d4[] = { 0x90, 0x06, 0x90, 0xc3 };        /* 0x06 is no instruction in 64-bit mode */

		s = src_of(&obj, d4, sizeof d4);
		CK(kgenome_frame_make(&s, 0, sizeof d4, 0u, &f) == KGENOME_FRAME_OK);
		CK(f.n_skip == 1u && f.cut == 1u && f.n_insn == 3u && f.cfg.status == KGENOME_TRUNCATED);
		kgenome_frame_release(&f, NULL);
		s = src_of(&obj, framed, sizeof framed);
		CK(kgenome_frame_make(&s, 0, sizeof framed, 0u, &f) == KGENOME_FRAME_OK && f.cut == 0u && f.n_skip == 0u && f.cfg.status == KGENOME_OK);
		kgenome_frame_release(&f, NULL);
	}
	/* THE NO-RETURN FACTS (the lineage's `stop()`): a function that calls and ends in ud2, followed in its extent by bytes that are not its code (a ret, a jump out): the unreachable
	 * block holds RET and LEAVES, the reachable one holds neither. RED on the base: there were no such bits, and the lineage read every branch of the extent, reachable or not. */
	{
		static const uint8_t d5[] = { 0xff, 0x15, 0, 0, 0, 0, 0x0f, 0x0b, 0x74, 0x7f, 0xc3 };      /* call [rip+0]; ud2; | jz +0x7f; ret (data) */

		s = src_of(&obj, d5, sizeof d5);
		CK(kgenome_frame_make(&s, 0, sizeof d5, KGENOME_FRAME_KEEP_INSN, &f) == KGENOME_FRAME_OK && kgenome_frame_facts(&f, f.in));
		CK(f.cfg.n_all == 2u && f.cfg.b[0].reach && !f.cfg.b[1].reach);          /* (a conditional jump out of the extent does not end a block) */
		CK(f.bits[0] == (KGENOME_FRAME_B_CALL | KGENOME_FRAME_B_MEMCELL));       /* (a call through a slot names a memory operand) */
		CK(f.bits[1] == (KGENOME_FRAME_B_LEAVES | KGENOME_FRAME_B_RET));
		kgenome_frame_release(&f, NULL);
		/* the same bits asked by a caller that holds no instructions (a callee): read again through the shared reader, once */
		CK(kgenome_frame_make(&s, 0, sizeof d5, 0u, &f) == KGENOME_FRAME_OK && f.bits == NULL);
		{
			const uint16_t *p1 = kgenome_frame_facts_of(&f, &s), *p2 = kgenome_frame_facts_of(&f, &s);

			CK(p1 && p1 == p2 && p1[0] == (KGENOME_FRAME_B_CALL | KGENOME_FRAME_B_MEMCELL) && p1[1] == (KGENOME_FRAME_B_LEAVES | KGENOME_FRAME_B_RET));
		}
		kgenome_frame_release(&f, NULL);
		CK(kgenome_frame_facts_of(NULL, &s) == NULL);
	}
	/* the facts that need a byte of the function: a push, an indirect jump (a block that jumps) */
	{
		static const uint8_t d3[] = { 0x50, 0xff, 0xe0 };      /* push rax; jmp rax */

		s = src_of(&obj, d3, sizeof d3);
		CK(kgenome_frame_make(&s, 0, sizeof d3, KGENOME_FRAME_KEEP_INSN, &f) == KGENOME_FRAME_OK && kgenome_frame_facts(&f, f.in));
		CK(f.cfg.n_all == 1u && f.bits[0] == (KGENOME_FRAME_B_PUSH | KGENOME_FRAME_B_JMP | KGENOME_FRAME_B_LEAVES));   /* jmp rax goes out of the extent */
		kgenome_frame_release(&f, NULL);
		/* THE FACTS ARE READ OF THE SAME INSTRUCTIONS THE GRAPH WAS MADE FROM: a frame made from a caller's decode that holds one instruction fewer than the extent has is not the frame of what
		 * the bytes decode to, and the memo refuses it (NULL, no bits) instead of laying the facts of one decode over the blocks of another. */
		{
			static const uint8_t d7[] = { 0x90, 0x90, 0x90, 0xc3 };
			struct kgenome_frame_insns pre;
			struct kgenome_frame_src sp;
			struct kgenome_frame whole;

			s = src_of(&obj, d7, sizeof d7);
			CK(kgenome_frame_make(&s, 0, sizeof d7, KGENOME_FRAME_KEEP_INSN, &whole) == KGENOME_FRAME_OK && whole.n_insn == 4u);
			pre = (struct kgenome_frame_insns){ .v = whole.in, .n = whole.n_insn - 1u, .skipped = 0, .off = 0, .len = sizeof d7 };
			sp = s;
			sp.pre = &pre;
			CK(kgenome_frame_make(&sp, 0, sizeof d7, 0u, &f) == KGENOME_FRAME_OK && f.n_insn == 3u);
			CK(kgenome_frame_facts_of(&f, &s) == NULL && f.bits == NULL);
			kgenome_frame_release(&f, NULL);
			CK(kgenome_frame_make(&s, 0, sizeof d7, 0u, &f) == KGENOME_FRAME_OK && kgenome_frame_facts_of(&f, &s) != NULL);   /* the same extent, made from its own decode: the facts */
			kgenome_frame_release(&f, NULL);
			kgenome_frame_release(&whole, NULL);
		}
		/* ONE CALL'S ALLOWANCE (src.max_bytes): the instructions of the extent are held to it, whether the frame reads them from the trace (the collector grows its array by doubling) or the caller
		 * hands them in (the array is counted). A function of nine instructions is over an allowance of 100 bytes both ways, and the state says so. */
		{
			static const uint8_t d8[] = { 0x55, 0x48, 0x89, 0xe5, 0x89, 0x7d, 0xf8, 0x85, 0xff, 0x74, 0x07, 0x89, 0x38, 0xe8, 0, 0, 0, 0, 0x5d, 0xc3 };
			struct kgenome_frame_insns pre;
			struct kgenome_frame_src sp;
			struct kgenome_frame whole;

			s = src_of(&obj, d8, sizeof d8);
			s.max_bytes = 100;
			CK(kgenome_frame_make(&s, 0, sizeof d8, 0u, &f) == KGENOME_FRAME_OVER_BUDGET && f.status == KGENOME_OVER_BUDGET);
			kgenome_frame_release(&f, NULL);
			s.max_bytes = 0;
			CK(kgenome_frame_make(&s, 0, sizeof d8, KGENOME_FRAME_KEEP_INSN, &whole) == KGENOME_FRAME_OK);
			pre = (struct kgenome_frame_insns){ .v = whole.in, .n = whole.n_insn, .skipped = 0, .off = 0, .len = sizeof d8 };
			sp = s;
			sp.pre = &pre;
			sp.max_bytes = 100;
			CK(kgenome_frame_make(&sp, 0, sizeof d8, 0u, &f) == KGENOME_FRAME_OVER_BUDGET);
			kgenome_frame_release(&f, NULL);
			sp.max_bytes = 0;
			CK(kgenome_frame_make(&sp, 0, sizeof d8, 0u, &f) == KGENOME_FRAME_OK && f.n_insn == whole.n_insn);
			kgenome_frame_release(&f, NULL);
			kgenome_frame_release(&whole, NULL);
		}
		/* THE EXTENT THAT RUNS OUT: the last block with no branch to end it runs on into whatever follows. After a call or a system call it is the call that does not come back (the
		 * compiler ends a function that way when it knows the callee does not return); after anything else it is the next function's code. A trap, a loop and a `ret` run out of nothing. */
		{
			static const struct { const char *name; const uint8_t b[8]; unsigned n; int out; } row[] = {
				{ "nop; nop", { 0x90, 0x90 }, 2, 1 },
				{ "mov eax,1", { 0xb8, 1, 0, 0, 0 }, 5, 1 },
				{ "call [rip+0]", { 0xff, 0x15, 0, 0, 0, 0 }, 6, 0 },
				{ "xor eax,eax; syscall", { 0x31, 0xc0, 0x0f, 0x05 }, 4, 0 },
				{ "ud2", { 0x0f, 0x0b }, 2, 0 },
				{ "jmp $", { 0xeb, 0xfe }, 2, 0 },
				{ "ret", { 0xc3 }, 1, 0 },
				{ "nop; jz $+2; nop", { 0x90, 0x74, 0x00, 0x90 }, 4, 1 },
				{ "jz over a nop; ret", { 0x74, 0x01, 0x90, 0xc3 }, 4, 0 },       /* the nop block falls into the block of the ret: it does not run out */
			};
			unsigned r;

			for (r = 0; r < sizeof row / sizeof row[0]; r++) {
				s = src_of(&obj, row[r].b, row[r].n);
				CK(kgenome_frame_make(&s, 0, row[r].n, KGENOME_FRAME_KEEP_INSN, &f) == KGENOME_FRAME_OK && kgenome_frame_facts(&f, f.in));
				if (!!(f.bits[f.cfg.n_all - 1u] & KGENOME_FRAME_B_RUNS_OUT) != row[r].out)
					printf("  %s: RUNS_OUT %d, wanted %d\n", row[r].name, !(row[r].out), row[r].out);
				CK(!!(f.bits[f.cfg.n_all - 1u] & KGENOME_FRAME_B_RUNS_OUT) == row[r].out);
				{
					uint32_t q;

					for (q = 0; q + 1u < f.cfg.n_all; q++)          /* only the last block of the extent can run out of it */
						CK(!(f.bits[q] & KGENOME_FRAME_B_RUNS_OUT));
				}
				kgenome_frame_release(&f, NULL);
			}
		}
		/* an indirect jump leaves the extent whatever target the decoder wrote beside it (the flag is the contract, the target a guess): a target inside is not a reason to stay */
		{
			static const uint8_t d6[] = { 0xff, 0xe0, 0x90 };                    /* jmp rax; nop */
			struct kgenome_cell_insn *c;

			s = src_of(&obj, d6, sizeof d6);
			CK(kgenome_frame_make(&s, 0, sizeof d6, KGENOME_FRAME_KEEP_INSN, &f) == KGENOME_FRAME_OK && f.in && f.n_insn == 2u);
			c = (struct kgenome_cell_insn *)f.in;
			CK(c[0].op == KGENOME_CELL_JMP && (c[0].flags & KGENOME_CELL_F_INDIRECT));
			c[0].target_va = f.va;
			CK(kgenome_frame_facts(&f, f.in) && (f.bits[0] & KGENOME_FRAME_B_LEAVES));
			kgenome_frame_release(&f, NULL);
		}
	}
}

/* ---- BE ---- */

static void put_be32(uint8_t *p, uint32_t w)
{
	p[0] = (uint8_t)(w >> 24); p[1] = (uint8_t)(w >> 16); p[2] = (uint8_t)(w >> 8); p[3] = (uint8_t)w;
}

static void be_row(void)
{
	/* 0 b +3 (beq $0,$0, target 0x10: offset 2 words after the delay slot's pc); 4 nop (delay slot); 8 addiu $v0,$0,1 (unreachable behind a real `b`); 12 nop; 16 jr $ra; 20 nop.
	 * A `b` at 0 with offset 3 lands at 0 + 4 + 12 = 16. */
	uint8_t code[24];
	struct kgenome_elf_info ei = ei_of(1, 0);
	struct kgenome_obj obj;
	struct kgenome_frame_src s;
	struct kgenome_frame f;
	struct kgenome_cell_insn *in = NULL;
	uint32_t n = 0, pos = 0;
	struct kgenome_cfg old;
	struct kgenome_cfg_req rq;

	put_be32(code + 0, 0x10000003u);        /* beq $0,$0,+3 */
	put_be32(code + 4, 0u);                 /* nop */
	put_be32(code + 8, 0x24020001u);        /* addiu $v0,$0,1 */
	put_be32(code + 12, 0u);
	put_be32(code + 16, 0x03e00008u);       /* jr $ra */
	put_be32(code + 20, 0u);
	obj_of(&obj, &ei, KGENOME_ARCH_MIPS, sizeof code);
	s = src_of(&obj, code, sizeof code);
	CK(kgenome_frame_make(&s, 0, sizeof code, KGENOME_FRAME_KEEP_INSN, &f) == KGENOME_FRAME_OK);
	CK(f.be == 1u);
	/* the graph of the object's byte order: the `b` is a jump, the addiu block is dead */
	CK(f.cfg.n_all == 3u && f.cfg.n_blk == 2u);
	CK(f.cfg.b[0].term == KGENOME_CFG_T_JUMP && !f.cfg.b[1].reach && f.cfg.b[2].reach);
	/*
	 * CS-4 (fixed, 2026-11-05): a request with `be` WRONG (0, not the 1 the bytes were written in) used to
	 * get this function wrong - the old cfg_isa.c re-read the raw object bytes with the REQUEST's `be` to
	 * decide a MIPS branch's class, a second, independent place the same bytes were parsed, and a caller
	 * that got `rq.be` wrong (the lineage's own request, before this fix) silently read a different
	 * instruction than the one `in[]` held. Decoded here (correctly, be=1: `in[]` already carries `beq
	 * $0,$0`'s registers and cond) and built with `rq.be` wrong anyway: the graph is IDENTICAL to `f.cfg`'s,
	 * because kgenome_cfg_isa_class no longer reads `be`/`bytes` for MIPS at all - only `in[]` matters now.
	 */
	in = calloc(8, sizeof *in);
	while (pos < sizeof code) {
		const uint32_t l = kgenome_cell_decode(KGENOME_ARCH_MIPS, 1, code + pos, (uint32_t)sizeof code - pos, pos, &in[n]);

		CK(l == 4u);
		if (!l)
			break;
		in[n].at = pos;
		n++;
		pos += l;
	}
	memset(&rq, 0, sizeof rq);
	rq.in = in; rq.n_in = n; rq.arch = KGENOME_ARCH_MIPS; rq.be = 0; rq.va_lo = 0; rq.va_hi = sizeof code; rq.bytes = code; rq.bytes_len = sizeof code;
	(void)kgenome_cfg_build(&rq, &old);
	CK(old.n_blk == f.cfg.n_blk && old.b[0].term == KGENOME_CFG_T_JUMP);       /* `rq.be` wrong changes nothing now */
	kgenome_cfg_free(&old, NULL);
	free(in);
	kgenome_frame_release(&f, NULL);
}

/* ---- RANDOM ---- */

static void random_rows(void)
{
	struct crng rg;
	unsigned i, k, graphs = 0;

	crng_seed(&rg, 20261103u);
	for (i = 0; i < N_ISAS; i++) {
		const struct isa_t *isa = &ISAS[i];

		for (k = 0; k < 300u; k++) {
			struct prog p;
			struct blob x;
			struct refg r;
			struct kgenome_elf_info ei = ei_of(isa->be, 0);
			struct kgenome_obj obj;
			struct kgenome_frame_src s;
			struct kgenome_frame f, f2, f3;
			struct kgenome_cell_insn *in = NULL;
			char tag[64];
			uint32_t b, nb;

			prog_random(isa, &rg, 2u + crng_below(&rg, 40u), &p);
			if (!blob_make(isa, &p, 0, &x)) {
				prog_free(&p);
				continue;
			}
			ref_build(isa, &p, &r);
			obj_of(&obj, &ei, isa->arch, x.len);
			s = src_of(&obj, x.b, x.len);
			snprintf(tag, sizeof tag, "%s #%u", isa->name, k);
			if (kgenome_frame_make(&s, 0, x.len, KGENOME_FRAME_KEEP_INSN, &f) == KGENOME_FRAME_OK) {
				const uint32_t n = blob_decode(isa, &x, &in);

				graphs++;
				CK(n == f.n_insn);
				blob_map_ops(&p, &x, in, n);
				CKM(cfg_equals_ref(&f.cfg, &r, &x, tag), "%s: the frame's graph is not the textbook one", tag);
				nb = f.cfg.n_all;
				for (b = 0; b < nb && b < r.nb; b++)
					CKM(f.cfg.b[b].at == x.va_of_op[r.first_op[b]], "%s: block %u at %u, its first op is at %u", tag, b, f.cfg.b[b].at,
					    x.va_of_op[r.first_op[b]]);
				CK(f.be == (uint8_t)isa->be || !isa->be);
				/* made again from the caller's decode: the same frame (and no decode: the array is the caller's, a block of `at` and bits compare) */
				{
					struct kgenome_frame_insns pre = { .v = in, .n = n, .skipped = 0, .off = 0, .len = x.len };
					struct kgenome_frame_src sp = s;

					sp.pre = &pre;
					CK(kgenome_frame_make(&sp, 0, x.len, 0u, &f2) == KGENOME_FRAME_OK);
					CK(f2.cfg.n_all == f.cfg.n_all && f2.cfg.n_blk == f.cfg.n_blk && f2.cfg.n_edge == f.cfg.n_edge && f2.n_insn == f.n_insn);
					CK(kgenome_frame_facts(&f, in) && kgenome_frame_facts(&f2, in));
					CK(!memcmp(f2.cfg.b, f.cfg.b, (size_t)f.cfg.n_all * sizeof *f.cfg.b) && !memcmp(f2.bits, f.bits, (size_t)f.cfg.n_all * sizeof *f.bits) && f2.framed == f.framed);
					/* a decode of ANOTHER extent is never used: the request decodes for itself */
					pre.len = x.len - 1u;
					pre.n = n > 1u ? n - 1u : n;                  /* (a different count too: using it would show) */
					CK(kgenome_frame_make(&sp, 0, x.len, 0u, &f3) == KGENOME_FRAME_OK && f3.n_insn == f.n_insn);
					kgenome_frame_release(&f2, NULL);
					kgenome_frame_release(&f3, NULL);
				}
				/* the facts recorded in the pass that makes the graph (src.facts) are the facts the memo makes */
				{
					struct kgenome_frame_src sf = s;
					struct kgenome_frame f4;

					sf.facts = 1;
					CK(kgenome_frame_make(&sf, 0, x.len, 0u, &f4) == KGENOME_FRAME_OK && f4.bits != NULL && f.bits != NULL);
					CK(f4.bits && f.bits && !memcmp(f4.bits, f.bits, (size_t)f.cfg.n_all * sizeof *f.bits) && f4.framed == f.framed);
					kgenome_frame_release(&f4, NULL);
				}
				/* idempotent */
				CK(kgenome_frame_make(&s, 0, x.len, 0u, &f2) == KGENOME_FRAME_OK && kgenome_frame_facts(&f2, in));
				CK(!memcmp(f2.cfg.b, f.cfg.b, (size_t)f.cfg.n_all * sizeof *f.cfg.b) && !memcmp(f2.bits, f.bits, (size_t)f.cfg.n_all * sizeof *f.bits));
				kgenome_frame_release(&f2, NULL);
				free(in);
			}
			kgenome_frame_release(&f, NULL);
			refg_free(&r);
			blob_free(&x);
			prog_free(&p);
		}
	}
	printf("  random: %u graphs compared with the textbook reference (6 ISAs x 300)\n", graphs);
	CK(graphs > 1000u);
}

/* ---- CACHE ---- */

static void cache_rows(void)
{
	/* three functions, each `nop; ret` -> a table of three entries */
	static const uint8_t code[] = { 0x90, 0xc3, 0x90, 0xc3, 0x90, 0xc3 };
	struct kgenome_func v[3] = { { .off = 0, .len = 2 }, { .off = 2, .len = 2 }, { .off = 4, .len = 2 } };
	struct kgenome_func_set fs;
	struct kgenome_elf_info ei = ei_of(0, 0);
	struct kgenome_obj obj;
	struct counting cn;
	struct kgenome_cfg_mem mem = COUNTING_MEM(&cn);
	struct kgenome_frame_cache *c;
	struct kgenome_frame_src s;
	const struct kgenome_frame *a, *b;
	struct kgenome_frame own;
	uint32_t fail;

	memset(&cn, 0, sizeof cn);
	memset(&fs, 0, sizeof fs);
	fs.v = v;
	fs.n = 3;
	obj_of(&obj, &ei, KGENOME_ARCH_X86_64, sizeof code);
	s = src_of(&obj, code, sizeof code);
	s.fs = &fs;
	c = kgenome_frame_cache_new(&mem, 0);
	CK(c != NULL);
	/* ONE BUILD PER FUNCTION, whatever the number of asks */
	a = kgenome_frame_get(c, &s, 1u);
	b = kgenome_frame_get(c, &s, 1u);
	CK(a && a == b && a->state == KGENOME_FRAME_OK && a->fn == 1u && a->off == 2u && a->len == 2u);
	CK(kgenome_frame_cache_built(c) == 1u && kgenome_frame_cache_hits(c) == 1u);
	CK(kgenome_frame_get(c, &s, 0u) != a && kgenome_frame_cache_built(c) == 2u);
	CK(kgenome_frame_get(c, &s, 3u) == NULL);                                  /* not an entry */
	/* the extent of an entry is the cache's; the extent of no entry is made, not kept */
	CK(kgenome_frame_of_extent(c, &s, 2u, 2u, &own) == a);
	memset(&own, 0, sizeof own);
	{
		const struct kgenome_frame *e = kgenome_frame_of_extent(c, &s, 2u, 4u, &own);

		CK(e == &own && own.state == KGENOME_FRAME_OK && kgenome_frame_cache_built(c) == 2u);
		kgenome_frame_release(&own, NULL);
	}
	/* a table of another length is not the cache's key */
	{
		struct kgenome_func_set fs2 = fs;

		fs2.n = 2;
		s.fs = &fs2;
		CK(kgenome_frame_get(c, &s, 0u) == NULL);
		s.fs = &fs;
	}
	CK(kgenome_frame_cache_bytes(c) == (uint64_t)cn.live);                    /* what the cache reports is what the allocator was charged */
	kgenome_frame_cache_free(c);
	CK(cn.live == 0);                                                          /* every byte charged is given back */
	/* THE CACHE'S BOUND is a bound of cost, never of an answer: at it `get` says NULL, `of_extent` still answers (made for the one use), the refusals are counted and what it keeps never passes it */
	{
		struct kgenome_frame_cache *cb = kgenome_frame_cache_new(NULL, 300u);                /* room for the slot table and one frame of two bytes, not two */
		struct kgenome_frame own2;
		uint32_t k;

		CK(cb != NULL);
		for (k = 0; k < 3u; k++) {
			const struct kgenome_frame *g = kgenome_frame_get(cb, &s, k), *h;

			memset(&own2, 0, sizeof own2);
			h = kgenome_frame_of_extent(cb, &s, v[k].off, v[k].len, &own2);
			CK(h != NULL && h->state == KGENOME_FRAME_OK && h->off == v[k].off && h->len == v[k].len);     /* an answer, kept or not */
			CK(g == NULL || h == g);
			if (h == &own2)
				kgenome_frame_release(&own2, NULL);
		}
		CK(kgenome_frame_cache_refused(cb) > 0u && kgenome_frame_cache_built(cb) < 3u);            /* it kept some and refused the rest */
		CK(kgenome_frame_cache_built(cb) == 1u && kgenome_frame_cache_bytes(cb) <= 300u);
		kgenome_frame_cache_free(cb);
	}
	/* A REFUSED ALLOCATION IS A STATE THAT IS NOT KEPT: inject a refusal at each allocation of the build in turn */
	for (fail = 1; fail < 40u; fail++) {
		struct counting cf;
		struct kgenome_cfg_mem mf;
		struct kgenome_frame_cache *cc;
		const struct kgenome_frame *fr;
		uint32_t a1, a2;

		memset(&cf, 0, sizeof cf);
		mf = (struct kgenome_cfg_mem)COUNTING_MEM(&cf);
		cf.fail_at = fail;
		cc = kgenome_frame_cache_new(&mf, 0);
		fr = kgenome_frame_get(cc, &s, 0u);
		a1 = kgenome_frame_cache_built(cc);
		CK(!fr || fr->state == KGENOME_FRAME_OK || fr->state == KGENOME_FRAME_NOMEM);
		if (!fr)
			CK(a1 == 0u);
		if (fr && fr->state == KGENOME_FRAME_NOMEM)
			CK(0);                                                     /* never kept */
		cf.fail_at = 0;
		fr = kgenome_frame_get(cc, &s, 0u);                                /* the next ask builds */
		a2 = kgenome_frame_cache_built(cc);
		CK(fr && fr->state == KGENOME_FRAME_OK && a2 >= 1u);
		kgenome_frame_cache_free(cc);
		CKM(cf.live == 0, "fail_at %u: %lld bytes charged and not given back", fail, (long long)cf.live);
	}
	/* a single make under the same sweep: a state, nothing leaked */
	for (fail = 1; fail < 40u; fail++) {
		struct counting cf;
		struct kgenome_frame fr;

		memset(&cf, 0, sizeof cf);
		cf.fail_at = fail;
		s.mem = (struct kgenome_cfg_mem)COUNTING_MEM(&cf);
		(void)kgenome_frame_make(&s, 0, 2u, 0u, &fr);
		CK(fr.state == KGENOME_FRAME_OK || fr.state == KGENOME_FRAME_NOMEM);
		kgenome_frame_release(&fr, &s.mem);
		CKM(cf.live == 0, "make, fail_at %u: %lld bytes not given back", fail, (long long)cf.live);
	}
	memset(&s.mem, 0, sizeof s.mem);
}

/* ---- HOSTILE ---- */

static void hostile_rows(void)
{
	static const uint8_t code[16] = { 0x90, 0x90, 0x90, 0xc3 };
	struct kgenome_elf_info ei = ei_of(0, 0);
	struct kgenome_obj obj;
	struct kgenome_frame_src s;
	struct kgenome_frame f;
	struct crng rg;
	unsigned i, k;

	obj_of(&obj, &ei, KGENOME_ARCH_X86_64, sizeof code);
	s = src_of(&obj, code, sizeof code);
	CK(kgenome_frame_make(&s, 0, 0, 0u, &f) == KGENOME_FRAME_UNDECODABLE);                 /* no length */
	CK(kgenome_frame_make(&s, 16, 1, 0u, &f) == KGENOME_FRAME_UNDECODABLE);                /* off at the end */
	CK(kgenome_frame_make(&s, 8, 9, 0u, &f) == KGENOME_FRAME_UNDECODABLE);                 /* length past it */
	CK(kgenome_frame_make(&s, UINT64_MAX, 2, 0u, &f) == KGENOME_FRAME_UNDECODABLE);
	CK(kgenome_frame_make(&s, 0, UINT64_MAX, 0u, &f) == KGENOME_FRAME_UNDECODABLE);
	CK(kgenome_frame_make(NULL, 0, 4, 0u, &f) == KGENOME_FRAME_UNDECODABLE);
	{
		struct kgenome_frame_src z = s;

		z.base = NULL;
		CK(kgenome_frame_make(&z, 0, 4, 0u, &f) == KGENOME_FRAME_UNDECODABLE);
	}
	/* an architecture with no control-flow rules */
	obj.arch = 0xfeu;
	CK(kgenome_frame_make(&s, 0, 4, 0u, &f) == KGENOME_FRAME_UNSUPPORTED || f.state == KGENOME_FRAME_UNDECODABLE);
	obj.arch = KGENOME_ARCH_X86_64;
	/* over the allowance of one call: the array alone is more than 64 bytes */
	s.max_bytes = 64;
	CK(kgenome_frame_make(&s, 0, 4, 0u, &f) == KGENOME_FRAME_OVER_BUDGET);
	CK(f.bits == NULL && f.cfg.n_all == 0u && kgenome_frame_facts(&f, (const struct kgenome_cell_insn *)code) == NULL);
	s.max_bytes = 0;
	/* the entry does not decode: bytes that are no instruction at offset 0 */
	{
		static const uint8_t bad[8] = { 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06 };     /* invalid in 64-bit mode */
		struct kgenome_frame_src z = src_of(&obj, bad, sizeof bad);

		(void)kgenome_frame_make(&z, 0, sizeof bad, 0u, &f);
		CK(f.state != KGENOME_FRAME_OK || f.cfg.n_all);
		kgenome_frame_release(&f, NULL);
	}
	/* garbage for every architecture and byte order: a state, bits whenever a graph */
	crng_seed(&rg, 77u);
	for (i = 0; i < N_ISAS; i++)
		for (k = 0; k < 400u; k++) {
			uint8_t g[160];
			struct kgenome_elf_info e2 = ei_of(ISAS[i].be, 0);
			struct kgenome_obj o2;
			struct kgenome_frame_src s2;
			uint32_t n = 4u + crng_below(&rg, 150u), j;
			enum kgenome_frame_state st;

			for (j = 0; j < n; j++)
				g[j] = (uint8_t)crng_next(&rg);
			obj_of(&o2, &e2, ISAS[i].arch, n);
			s2 = src_of(&o2, g, n);
			st = kgenome_frame_make(&s2, 0, n, 0u, &f);
			CK(st == f.state);
			if (st == KGENOME_FRAME_OK)
				CK(f.bits == NULL && f.cfg.n_all > 0u && f.cfg.b[0].at == 0u);
			else
				CK(f.bits == NULL && f.cfg.b == NULL && kgenome_frame_facts(&f, NULL) == NULL);      /* no graph, no facts */
			kgenome_frame_release(&f, NULL);
		}
}

int main(void)
{
	hand_x86();
	be_row();
	random_rows();
	cache_rows();
	hostile_rows();
	printf("frame: %d failure(s)\n", fails);
	return fails ? 1 : 0;
}
