/*
 * pe_run_once.c - ONE EMULATION RUN OF A PE OBJECT FROM ITS ENTRY (EA8).
 *
 * A PE whose code reads the loader data (fs:[0x30], then PEB.Ldr) is run by the API-resolution
 * analysis (diag_apihash.c, the RECOVER step) and, when the scan wants the interpreter, by the unpack
 * run (the UNPACK step). Both start the same machine at the same entry with the same image and
 * imports; before this, the second built and ran a second machine from the entry, so the
 * instructions the first had executed were executed again. Now the resolver's machine is handed
 * to the unpack run, which carries it on.
 *
 * Counted at the link (UNIT_LIBS_pe_run_once wraps kgenome_emu_new): the engine carries no counter
 * for this. The bytes are SIMULATED: a PE32 from hk.h whose code is written here.
 *
 *   A  the program returns at once: the resolver's run ends it (the return to the sentinel) and
 *      the unpack run reads that machine, runs nothing more: one machine, a few instructions.
 *   B  the program loops for 1.2 million instructions and makes no API call: the resolver stops
 *      when it goes silent (32 slices of 16000, 512000 instructions), the unpack run carries the
 *      same machine on to the return. One machine, and the tree's instruction count is that of ONE
 *      run: 1200004, where two machines made it 1712004 (measured on the base).
 *
 * The code section is filled after the program with every byte value twice, so the unpack gate
 * (code denser than 7.5 bits a byte) asks for the run under KOF_EMU_AUTO, as it does for a packer.
 * The loop keeps a push and a pop in it: a countdown alone is a delay loop the interpreter skips.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/kofeng.h"
#include "../lib/genome/hk.h"

struct kgenome_emu;
struct kgenome_emu_cfg;
struct kgenome_emu *__real_kgenome_emu_new(const struct kgenome_emu_cfg *cfg);
struct kgenome_emu *__wrap_kgenome_emu_new(const struct kgenome_emu_cfg *cfg);

static unsigned g_new;

struct kgenome_emu *__wrap_kgenome_emu_new(const struct kgenome_emu_cfg *cfg)
{
	g_new++;
	return __real_kgenome_emu_new(cfg);
}

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	unsigned *objs = user;

	(void)name; (void)bytes; (void)len; (void)res;
	(*objs)++;
	return 0;
}

/* The PE32, its code at the entry: the loader-data read, a loop of `laps` laps, ret. */
static void make_pe(struct hk_pe *pe, uint32_t laps)
{
	uint8_t code[] = {
		0x64, 0xa1, 0x30, 0x00, 0x00, 0x00,     /* mov eax, fs:[0x30]   the PEB          */
		0x8b, 0x40, 0x0c,                       /* mov eax, [eax+0x0c]  PEB.Ldr          */
		0xb9, 0, 0, 0, 0,                       /* mov ecx, laps                         */
		0x51,                                   /* push ecx                              */
		0x5a,                                   /* pop  edx                              */
		0x49,                                   /* dec  ecx                              */
		0x75, 0xfb,                             /* jnz  push                             */
		0xc3                                    /* ret  to the loader's sentinel         */
	};
	unsigned i;

	hk_w(code + 10, laps, 4, 0);
	hk_pe(pe, 0);
	for (i = 0; i < 0x200u; i++)
		pe->b[pe->text_off + i] = (uint8_t)(i * 167u);
	memcpy(pe->b + pe->text_off, code, sizeof code);
}

struct run { unsigned machines, objs; struct kof_stats st; };

static void scan(struct kof_engine *eng, const struct hk_pe *pe, uint32_t emu_use, struct run *r)
{
	struct kof_scanner *sc = kscan_new(eng);
	struct kof_scan_option opt;

	memset(r, 0, sizeof *r);
	CK(sc != NULL);
	if (!sc)
		return;
	memset(&opt, 0, sizeof opt);
	opt.max_object_depth = 4;
	opt.heur_level = KOF_HEUR_LEVEL_MAX;
	opt.emu_use = emu_use;
	g_new = 0;
	kscan_bytes(sc, pe->b, pe->n, "pe", &opt, on_object, &r->objs);
	r->machines = g_new;
	r->st = *kscan_stats(sc);
	kscan_free(sc);
}

int main(void)
{
	static struct hk_pe pe;
	struct kof_engine *eng = keng_open("build/release/databases");
	struct run r;

	CK(eng != NULL);
	if (!eng) {
		printf("pe_run_once: no release database (build it with make)\n");
		return 1;
	}

	/* A: the resolver's run is the whole run */
	make_pe(&pe, 16u);
	scan(eng, &pe, KOF_EMU_AUTO, &r);
	printf("  A: objects %u, machines built %u, unpack runs %llu, instructions %llu\n", r.objs, r.machines,
	       (unsigned long long)r.st.heur_emu, (unsigned long long)r.st.emu_insn);
	CK(r.st.heur_emu == 1u);                /* the unpack run was asked for ... */
	CK(r.machines == 1u);                   /* ... and read the resolver's machine */
	CK(r.st.emu_insn == 68u);               /* 3 + 4 x 16 + the ret: once (two machines made it 136) */

	/* B: the unpack run carries the resolver's machine on */
	make_pe(&pe, 300000u);
	scan(eng, &pe, KOF_EMU_AUTO, &r);
	printf("  B: objects %u, machines built %u, unpack runs %llu, instructions %llu\n", r.objs, r.machines,
	       (unsigned long long)r.st.heur_emu, (unsigned long long)r.st.emu_insn);
	CK(r.st.heur_emu == 1u);
	CK(r.machines == 1u);
	/* one run of the program, not the resolver's 512000 instructions run again */
	CK(r.st.emu_insn == 1200004u);

	/* C: no unpack run (the interpreter is not wanted): the resolver's machine is kept, nobody takes
	 *    it, and it is let go when the UNPACK row ends (oc_emu_kept_drop; the sanitised build checks
	 *    that nothing leaks). Its instructions are charged once. */
	scan(eng, &pe, KOF_EMU_NEVER, &r);
	printf("  C: objects %u, machines built %u, unpack runs %llu, instructions %llu\n", r.objs, r.machines,
	       (unsigned long long)r.st.heur_emu, (unsigned long long)r.st.emu_insn);
	CK(r.st.heur_emu == 0u && r.machines == 1u && r.st.emu_insn == 512000u);

	keng_close(eng);
	printf("pe_run_once: %s\n", hk_fails ? "FAIL" : "ok");
	return hk_fails ? 1 : 0;
}
