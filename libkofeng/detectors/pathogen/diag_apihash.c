/*
 * diag_apihash.c - NAMING THE APIS A PE RESOLVES FOR ITSELF.
 *
 * A program that walks the loader data to find its own functions has none of
 * them in its import table, and what stands for an API in its code is a number
 * only the program understands: a hash, with a seed, a rotation and a combining
 * step the author picked and can change tomorrow. So nothing here reads the
 * number. The environment the emulator builds has a PEB, a module list and an
 * export directory for every library it models, and the program's own resolver
 * walks THAT - whatever it does with the names, it arrives at the stub of the
 * function it meant, and the stub reports which function it is.
 *
 * THIS IS AN ANALYSIS AND NOT A ROUTE'S SIDE EFFECT. Its product is a list of
 * calls - which API, from where, with what - and TWO things read it: the graph
 * (a node per call, see kof_diag_run_apihash) and the object's symbols (the
 * names become imports, see kof_apihash_syms). One result, computed once per
 * object and kept by whoever asked first; neither reader runs the program.
 * Written twice, the two would disagree about which calls were made.
 *
 * ASKED FOR, never assumed - KOF_DIAG_VIA_APIHASH, and KOF_DIAG_SERVES when the
 * engine wants the names for the object description. A program that does not
 * read the loader data costs a decode and nothing else; one that does costs a
 * run.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kofdiag.h"
#include "diag_int.h"
#include "../../kofcore/kofcore.h"
#include "../../kofcore/kofmod/kofcap.h"
#include "../../kofcore/kofmod/kofsym.h"
#include "../../kofcore/kofmod/pe.h"
#include "../../kofcore/kofmod/kdis.h"
#include "../../analyzers/parsers/binaries/pe/pe_parse.h"
#include "../../analyzers/parsers/binaries/pe/pe_sym.h"
#include "../../analyzers/parsers/binaries/disasm/kdis.h"
#include "../../analyzers/parsers/binaries/disasm/nucleo.h"
#include "../../disinfect/pzero.h"
#include "../../extractors/unpack/emu_unpack.h"
#include "../../../libkofemu/kofemu.h"

/*
 * ---- DOES THE PROGRAM READ THE LOADER DATA ---------------------------------
 *
 * A read of the thread block at the offset the PEB is at - fs:[0x30] on 32-bit
 * Windows, gs:[0x60] on 64-bit - and then, a few instructions later, a load
 * through that register at the offset of PEB.Ldr (0x18 / 0x0c). It is a SHAPE
 * with no constant of the program's own in it: the author can change the hash,
 * the seed, the rotation, the function; he cannot change where the OS put the
 * loader.
 *
 * THE PEB READ ALONE IS NOT ENOUGH. Every C runtime reads it, for the image
 * base, the heap, BeingDebugged. MEASURED on 300 PE, the read alone sent 46 of
 * them to the emulator and the walk is a fraction of those.
 */
#define PEB_TTL 8u

static void note_peb(struct kof_apihash *a, uint64_t at)
{
	if (a->n_peb == a->cap_peb) {
		uint32_t nc = a->cap_peb ? a->cap_peb * 2u : 16u;
		uint64_t *nv = realloc(a->peb, (size_t)nc * sizeof *nv);

		if (!nv)
			return;
		a->peb = nv;
		a->cap_peb = nc;
	}
	a->peb[a->n_peb++] = at;
}

/*
 * ---- FINDING THE LOADER WALK WITHOUT DECODING THE PROGRAM ------------------
 *
 * The test is about an instruction with a SEGMENT OVERRIDE, and a segment
 * override is a prefix byte: 0x65 (GS) on 64-bit, 0x64 (FS) on 32-bit. So the
 * candidates are the places that byte occurs, and the exact test - the decoded
 * operand's segment and displacement, then a load of PEB.Ldr a few instructions
 * on - is made on the instruction that starts there. About one byte in 256 is a
 * candidate; decoding every instruction of every executable section to find
 * them was 6.7 s of the 300-file corpus, and as an analysis every PE object
 * pays for (not only the few that read the loader) it made the scan of that
 * corpus 3.8 times slower.
 *
 * WHY THE LOAD IS PART OF THE TEST AND NOT A SECOND STAGE. A byte that is not
 * an instruction boundary - the 0x65 of `jne +0x65`, a displacement, a string -
 * decodes from there as SOMETHING, and 1 in a few hundred of those somethings is
 * a read at gs:[0x60]: MEASURED, the override test alone found reads in 57 of
 * 300 PE that a linear sweep does not; the five I read were all misaligned bytes.
 * A misaligned candidate followed within eight instructions by a load through
 * the register at +0x18 is another matter, and the loader-walk count is
 * IDENTICAL to the decode-everything version on all 300 files (10 with a walk,
 * 5 of them with calls resolved). A false candidate costs a run of the resolver
 * and names nothing wrong, since what it names is what the run called.
 *
 * WHAT THIS DOES NOT CATCH, said so it is not rediscovered: an override that
 * follows another legacy prefix (`66 65 ..`, `67 65 ..`) starts at the other
 * prefix and is decoded from the override, which loses the first.
 */
static int is_peb_read(const struct kdis_insn *in, int wide)
{
	unsigned q;

	for (q = 0; q < in->n_op; q++) {
		const struct kdis_operand *o = &in->o[q];

		if (o->kind == KDIS_O_MEM &&
		    o->seg == (wide ? KDIS_SEG_GS : KDIS_SEG_FS) &&
		    o->disp == (wide ? 0x60 : 0x30))
			return 1;
	}
	return 0;
}

static void atoms_in(struct kof_apihash *a, const struct kof_obj_ctx *ctx,
		     const uint8_t *base, uint64_t size, uint64_t off,
		     uint64_t n, int wide)
{
	const uint8_t seg = wide ? 0x65u : 0x64u;
	uint64_t pos = off, end = off + n;

	while (pos < end) {
		const uint8_t *hit = memchr(base + pos, seg, end - pos);
		struct kof_kdis k;
		struct kdis_insn in;

		if (!hit)
			break;
		pos = (uint64_t)(hit - base) + 1u;
		memset(&k, 0, sizeof k);
		if (!kof_kdis_seek(&k, (uint64_t)(hit - base), 0) ||
		    !kof_kdis_next(&k, ctx, base, size, &in) ||
		    !is_peb_read(&in, wide))
			continue;
		/* THE LOADER DATA ITSELF, a few instructions later: a load through
		 * the register the PEB went to, at the offset of PEB.Ldr. */
		if (in.n_op && in.o[0].kind == KDIS_O_REG) {
			int reg = in.o[0].reg;
			uint64_t at = in.at;
			unsigned ttl;

			for (ttl = 0; ttl < PEB_TTL && k.at < end; ttl++) {
				unsigned q;

				if (!kof_kdis_next(&k, ctx, base, size, &in))
					break;
				for (q = 0; q < in.n_op; q++) {
					const struct kdis_operand *o = &in.o[q];

					if (o->kind == KDIS_O_MEM &&
					    (int)o->reg == reg &&
					    o->disp == (wide ? 0x18 : 0x0c)) {
						a->n_ldr++;
						note_peb(a, at);
						ttl = PEB_TTL;
						break;
					}
				}
			}
		}
	}
}

/*
 * ---- RUNNING THE PROGRAM'S OWN RESOLVER -----------------------------------
 *
 * A program that finds its APIs by walking the loader data has none of them in
 * its import table, and what stands for an API in its code is a number. The
 * number is meaningful only to the program: a hash, with a seed, a rotation and
 * a combining step the author picked, any of which he can change tomorrow. So
 * nothing here reads it. The environment the emulator builds has a PEB, a
 * module list and an export directory for every library it models, and the
 * program's resolver walks THAT - whatever it does with the names, it arrives at
 * the stub of the function it meant, and the stub reports which function it is.
 *
 * MEASURED, on the plain Metasploit stager and on the same stager rebuilt with
 * `ror 14` and a new seed, with `xor` for `add`, and with `rol` for `ror`
 * (every hash recomputed): all four resolve the same seven calls in the same
 * order from the same places. A table of hash values finds the first two and
 * none of the others, which is the reason this is not one.
 *
 * ONLY FOR A PROGRAM THAT READS THE LOADER DATA, which is what
 * KOF_NUCLEO_SELF_RESOLVE says it does. The decode that finds the read is
 * already being made; the run is paid for by the objects that need it.
 *
 * THE LINKS COME FROM THE VALUES. A call's result is a value the program holds,
 * and a later call that takes that value as its descriptor or its buffer is the
 * same object: the socket WSASocketA returned is the first argument of the
 * connect and of both reads; the pointer VirtualAlloc returned is the buffer of
 * the second read. Each argument that has a role (kof_diag_role_of_arg) is
 * matched against the results so far, and a value too small to be a handle or
 * a pointer is not matched - 0x1000 is a length as often as it is anything.
 */
/*
 * THE RUN IS SLICED AND ENDS WHEN IT STOPS ANSWERING. A resolver costs about
 * twenty thousand instructions per API (it scans the modules for the hash), so
 * a stager that makes seven calls is done in 140 thousand; and a program that
 * is NOT resolving anything is the expensive case, because nothing tells the
 * run it has nothing to say. So it goes a slice at a time and stops after a few
 * slices with no new call, with the old two-million total as the ceiling.
 *
 * AND IT DOES NOT EXTEND. The default is to keep running past the budget for as
 * long as each slice writes a new page, which is right for an unpacker and
 * wrong here: MEASURED, 3 of 46 files ran 16-18 million instructions each, 87%
 * of the whole, to produce the same API calls the first million had.
 */
#define DIAG_PE_SLICE 16000ull
#define DIAG_PE_IDLE  12u
#define DIAG_PE_INSN  2000000ull        /* the ceiling: the emulate route's budget, diag_emu.c */


static void run_resolver(struct kof_apihash *a, const struct kof_obj_ctx *ctx,
			 const uint8_t *base, uint64_t size)
{
	struct kof_emu_unp_report rep;
	struct kof_emu *em;
	uint32_t n_ev, i;

	memset(&rep, 0, sizeof rep);
	em = kof_emu_unp_run_pe(base, size, kof_pe(ctx), DIAG_PE_SLICE, 0, 0, 1,
				NULL, 0, NULL, 0, 0, &rep);
	if (!em)
		return;
	{
		enum kof_emu_stop st = rep.stop;
		uint64_t done = kof_emu_insn_count(em);
		uint32_t seen = kof_emu_win_event_count(em), idle = 0;

		while (st == KOF_EMU_STOP_BUDGET && done < DIAG_PE_INSN &&
		       idle < DIAG_PE_IDLE) {
			uint32_t now;

			kof_emu_set_max_insn(em, done + DIAG_PE_SLICE);
			st = kof_emu_run(em);
			done = kof_emu_insn_count(em);
			now = kof_emu_win_event_count(em);
			idle = now > seen ? 0u : idle + 1u;
			seen = now;
		}
		/* THE BUDGET ENDED IT, said in the product: a caller told "these
		 * are the calls" when the run was cut short has no way to know
		 * there were more. */
		a->budget = st == KOF_EMU_STOP_BUDGET;   /* still running when it was stopped */
	}
	n_ev = kof_emu_win_event_count(em);
	a->call = calloc(n_ev ? n_ev : 1u, sizeof *a->call);
	if (!a->call) {
		a->budget = 1;
		kof_emu_free(em);
		return;
	}
	for (i = 0; i < n_ev; i++) {
		struct kof_emu_win_event ev;
		struct kof_apihash_call *c = &a->call[a->n_call];
		const char *nm, *dll;

		if (!kof_emu_win_event_at(em, i, &ev) || !ev.site)
			continue;
		nm = kof_emu_win_api_name(ev.api);
		dll = kof_emu_win_mod_name(kof_emu_win_api_mod(ev.api));
		if (!nm)
			continue;
		memset(c, 0, sizeof *c);
		c->site = ev.site;
		c->ret = ev.ret;
		memcpy(c->arg, ev.arg, sizeof c->arg);
		snprintf(c->api, sizeof c->api, "%s", nm);
		snprintf(c->dll, sizeof c->dll, "%s", dll ? dll : "");
		a->n_call++;
	}
	a->end_rip = kof_emu_get_rip(em);
	a->end_from = kof_emu_last_branch_at(em);
	kof_emu_free(em);
}

struct kof_apihash *kof_apihash_run(const struct kof_obj_ctx *ctx,
				    const uint8_t *base, uint64_t size)
{
	const struct kof_pe_info *p;
	struct kof_apihash *a;
	uint32_t i;
	int wide;

	if (!ctx || ctx->format != KOF_FMT_PE || !base || !size)
		return NULL;
	p = kof_pe(ctx);
	if (!p || !p->valid)
		return NULL;
	a = calloc(1, sizeof *a);
	if (!a)
		return NULL;
	wide = p->pe32_plus != 0;
	for (i = 0; i < p->sec_count; i++) {
		const struct kof_pe_sec *sc = &p->sec[i];
		uint64_t have;

		if (!(sc->perm & KOF_PE_PERM_X))
			continue;
		have = kof_clip_len(size, sc->file_off, sc->file_size);
		if (have)
			atoms_in(a, ctx, base, size, sc->file_off, have, wide);
	}
	/* Only a program that read the loader data and then loaded from it is
	 * worth a run. */
	if (a->n_ldr)
		run_resolver(a, ctx, base, size);
	return a;
}

void kof_apihash_free(struct kof_apihash *a)
{
	if (!a)
		return;
	free(a->peb);
	free(a->call);
	free(a);
}

/*
 * ---- THE GRAPH'S READING OF THE PRODUCT ------------------------------------
 *
 * THE ATOM FIRST, which is the detection layer and needs no resolver: a read
 * of the loader data that LEADS to the module list is a KOF_NUCLEO_SELF_RESOLVE
 * node at the instruction, and is there whether or not the run that follows
 * names anything. THIS IS THE ONLY PRODUCER of that node: the import walk in
 * diag_pe.c used to make one for every read of the PEB, which was the same job
 * done by a second path with a looser test, and a C runtime's read is not a
 * walk. Then a node per call, with the links from the values.
 */
void kof_diag_run_apihash(struct kof_diag_scan *s,
			  const struct kof_obj_ctx *ctx,
			  const uint8_t *base, uint64_t size)
{
	const struct kof_apihash *a;
	uint16_t *node;
	uint64_t *region, *rlen;
	uint32_t i, k;

	(void)base;
	(void)size;
	if (!ctx || ctx->format != KOF_FMT_PE)
		return;
	a = kof_diag_apihash(s, ctx);
	if (!a)
		return;
	for (i = 0; i < a->n_peb; i++)
		kof_diag_hit_add(s, a->peb[i], KOF_NUCLEO_SELF_RESOLVE, 0);
	/* STOPPED WHILE THE PROGRAM WAS STILL RUNNING - at the instruction
	 * ceiling or after a silence - so calls after this point are not in the
	 * list. A bound is allowed to cost cost; it is not allowed to be silent
	 * about what it cost (CLAUDE.md 4), so the scan says it did not finish. */
	if (a->budget)
		s->full = 1;
	if (!a->n_call)
		return;
	node = calloc(a->n_call, sizeof *node);
	region = calloc(a->n_call, sizeof *region);
	rlen = calloc(a->n_call, sizeof *rlen);
	if (!node || !region || !rlen)
		goto out;

	for (i = 0; i < a->n_call; i++) {
		const struct kof_apihash_call *c = &a->call[i];
		struct kof_diag_hit *h;
		uint8_t fl = 0;
		uint16_t cap;
		uint64_t at;
		uint32_t before;

		node[i] = 0xffffu;
		cap = kof_flow_cap_of_call(c->api, c->arg, &fl);
		if (cap == KOF_NUCLEO_NONE)
			continue;
		at = kof_pz_addr_to_off(ctx, c->site);
		if (at == KOF_BROKEN)
			continue;
		before = kof_diag_scan_count(s);
		h = kof_diag_hit_add(s, at, cap, fl);
		if (!h || kof_diag_scan_count(s) != before + 1u)
			continue;
		node[i] = (uint16_t)before;
		/* an allocation owns the range it returned, for the jump below */
		if (cap == KOF_NUCLEO_ALLOC || cap == KOF_NUCLEO_ALLOC_EXEC) {
			region[i] = c->ret;
			rlen[i] = c->arg[1];
		}
		for (k = 0; k < 4u; k++) {
			uint8_t role = kof_diag_role_of_arg(cap, k);
			uint32_t j;

			if (role == KOF_DIAG_ROLE_NONE || c->arg[k] < 0x100u)
				continue;
			for (j = 0; j < i; j++)
				if (node[j] != 0xffffu &&
				    a->call[j].ret == c->arg[k]) {
					kof_diag_note_in(h, node[j], role,
							 KOF_DIAG_KIND_PRODUCED);
					break;
				}
		}
	}

	/*
	 * THE JUMP INTO WHAT WAS ALLOCATED. The run ends where the stager hands
	 * over, and the instruction that handed over is the one that last
	 * transferred control: `jmp r15` with r15 the pointer VirtualAlloc
	 * returned. It is a node of its own - a branch into memory an earlier step
	 * produced, KOF_NUCLEO_EXEC_REG - and the link is from the allocation.
	 * Only the END of the run is looked at; a program that enters its buffer
	 * and carries on is not seen doing it.
	 */
	for (i = 0; i < a->n_call; i++)
		if (node[i] != 0xffffu && region[i] &&
		    a->end_rip >= region[i] &&
		    a->end_rip - region[i] < rlen[i]) {
			uint64_t at = a->end_from
				      ? kof_pz_addr_to_off(ctx, a->end_from)
				      : KOF_BROKEN;
			uint32_t before = kof_diag_scan_count(s);
			struct kof_diag_hit *h;

			if (at == KOF_BROKEN)
				break;
			h = kof_diag_hit_add(s, at, KOF_NUCLEO_EXEC_REG, 0);
			if (h && kof_diag_scan_count(s) == before + 1u)
				kof_diag_note_in(h, node[i], KOF_DIAG_ROLE_TARGET,
						 KOF_DIAG_KIND_PRODUCED);
			break;
		}
out:
	free(node);
	free(region);
	free(rlen);
}

uint32_t kof_apihash_syms(const struct kof_apihash *a, uint8_t *blk,
			  uint32_t n_bytes, uint32_t cap)
{
	const char **dll, **name;
	uint32_t i, n = 0;

	if (!a || !a->n_call)
		return n_bytes;
	dll = malloc((size_t)a->n_call * sizeof *dll);
	name = malloc((size_t)a->n_call * sizeof *name);
	if (!dll || !name) {
		free(dll);
		free(name);
		return n_bytes;
	}
	for (i = 0; i < a->n_call; i++) {
		uint32_t k;

		/* Once per API: the same function called from nine places is one
		 * thing the program uses. */
		for (k = 0; k < n; k++)
			if (!strcmp(name[k], a->call[i].api) &&
			    !strcmp(dll[k], a->call[i].dll))
				break;
		if (k < n)
			continue;
		dll[n] = a->call[i].dll;
		name[n] = a->call[i].api;
		n++;
	}
	n_bytes = kof_pe_syms_add_imports(blk, n_bytes, cap, dll, name, n);
	/* The list may be short, and the block's own byte says so. */
	if (a->budget && n_bytes >= KOF_SYM_HDRLEN)
		blk[KOF_SYM_H_TRUNC] = 1;
	free(dll);
	free(name);
	return n_bytes;
}
