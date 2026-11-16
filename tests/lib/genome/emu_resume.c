/*
 * emu_resume.c - A PE MACHINE CARRIED ON BY ITS SECOND READER (EA8), against the lib alone.
 *
 * kgenome_emu_unp_pe_req.resume hands the unpack run the machine the API-resolution run started from
 * the same entry; kgenome_emu_adopt is the step that gives the machine its new owner. The property is
 * DIFFERENTIAL: a run that carries a machine on to a ceiling ends exactly where a machine built for
 * that ceiling ends (stop, instruction count, rip), because the program is the same and nothing it
 * did is done twice. The refusals are checked too: a request that declares what the machine was not
 * built with, other bytes, another account, a machine the program already ended.
 *
 * SIMULATED bytes: a PE32 from hk.h whose code is written here (a push/pop loop of `laps` laps, then
 * ret to the loader's sentinel).
 */
#include <kgenome.h>
#include <phenotype/emu.h>
#include <phenotype/emu_unpack.h>
#include "hk.h"

static void make_pe(struct hk_pe *pe, uint32_t laps)
{
	uint8_t code[] = {
		0xb9, 0, 0, 0, 0,       /* mov ecx, laps */
		0x51,                   /* push ecx      */
		0x5a,                   /* pop  edx      */
		0x49,                   /* dec  ecx      */
		0x75, 0xfb,             /* jnz  push     */
		0xc3                    /* ret           */
	};

	hk_w(code + 1, laps, 4, 0);
	hk_pe(pe, 0);
	memcpy(pe->b + pe->text_off, code, sizeof code);
}

static int rs_acct_calls;
static int rs_acct(void *user, int64_t bytes)
{
	(void)user;
	(void)bytes;
	rs_acct_calls++;
	return 1;
}
static int rs_acct_other(void *user, int64_t bytes)
{
	(void)user;
	(void)bytes;
	return 1;
}

/* A run of `pe` to `max_insn`, handed `resume` (or none), the rest of the request zero. */
static struct kgenome_emu *run(const struct hk_pe *pe, const struct kgenome_pe_info *pi, uint64_t max_insn,
			       int hand_back, uint64_t idle, unsigned n_oep, struct kgenome_emu_unp_kept *resume,
			       struct kgenome_emu_unp_report *rep)
{
	static const struct kgenome_emu_oep oep = { 0x1000, 0x10 };
	struct kgenome_budget bud;

	kgenome_budget_default(&bud, pe->n, pe->n);
	bud.max_insn = max_insn;
	bud.max_bytes = 16u << 20;
	bud.account = rs_acct;
	return kgenome_emu_unp_run_pe(&(const struct kgenome_emu_unp_pe_req){
			.file = pe->b, .n = pe->n, .info = pi, .bud = &bud, .idle = idle,
			.hand_back = hand_back, .oep = &oep, .n_oep = n_oep, .rep = rep, .resume = resume });
}

/* The first reader: a run of `first` instructions, its machine kept as the API-resolution run keeps it. */
static void keep_first(const struct hk_pe *pe, const struct kgenome_pe_info *pi, uint64_t first, uint64_t idle,
		       struct kgenome_emu_unp_kept *k)
{
	memset(k, 0, sizeof *k);
	k->em = run(pe, pi, first, 1, idle, 0, NULL, &k->rep);
	k->file = pe->b;
	k->n = pe->n;
}

int main(void)
{
	static struct hk_pe pe;
	static struct kgenome_pe_info pi;
	struct kgenome_obj o;
	struct kgenome_emu_unp_report r1, r2;
	struct kgenome_emu_unp_kept k;
	struct kgenome_emu *fresh, *carried;

	make_pe(&pe, 100000u);                  /* 4 x 100000 + 2 instructions */
	CK(kgenome_pe_image_parse(kof_buf_make(pe.b, pe.n), &pi, &o));

	/* 1. carried on to the end: the same stop, count and rip as one machine run to the end */
	fresh = run(&pe, &pi, 2000000u, 0, 0, 0, NULL, &r1);
	keep_first(&pe, &pi, 16000u, 0, &k);
	CK(k.em && k.rep.stop == KGENOME_EMU_STOP_BUDGET && k.rep.insn == 16000u);
	carried = run(&pe, &pi, 2000000u, 0, 0, 0, &k, &r2);
	CK(k.em == NULL);                       /* taken over */
	CK(fresh && carried && r2.resumed == 1 && r1.resumed == 0);
	CK(r1.stop == KGENOME_EMU_STOP_FAULT && r1.returned == 1 && r1.insn == 400002u);
	CK(r2.stop == r1.stop && r2.returned == r1.returned && r2.insn == r1.insn);
	CK(kgenome_emu_rip(carried) == kgenome_emu_rip(fresh));
	CK(r2.entry == r1.entry && r2.stack_lo == r1.stack_lo && r2.stack_hi == r1.stack_hi);
	kgenome_emu_free(fresh);
	kgenome_emu_free(carried);

	/* 2. carried on to a ceiling: it stops where a machine built for that ceiling stops */
	fresh = run(&pe, &pi, 50000u, 0, 0, 0, NULL, &r1);
	keep_first(&pe, &pi, 16000u, 0, &k);
	carried = run(&pe, &pi, 50000u, 0, 0, 0, &k, &r2);
	CK(r1.stop == KGENOME_EMU_STOP_BUDGET && r1.insn == 50000u);
	CK(r2.resumed == 1 && r2.stop == r1.stop && r2.insn == r1.insn);
	kgenome_emu_free(fresh);
	kgenome_emu_free(carried);

	/* 3. the ceiling is the new owner's, not raised from the first's: a first reader stopped by a
	 *    stall with a ceiling of a million is carried on to 30000 and stops there */
	keep_first(&pe, &pi, 1000000u, 2000u, &k);
	CK(k.em && k.rep.stop == KGENOME_EMU_STOP_STALLED && k.rep.insn < 30000u);
	carried = run(&pe, &pi, 30000u, 0, 1u << 22, 0, &k, &r2);
	CK(r2.resumed == 1 && r2.stop == KGENOME_EMU_STOP_BUDGET && r2.insn == 30000u);
	kgenome_emu_free(carried);

	/* 4. a machine the program already ended is read, not run: nothing more executes */
	keep_first(&pe, &pi, 2000000u, 0, &k);
	CK(k.rep.stop == KGENOME_EMU_STOP_FAULT && k.rep.returned == 1);
	carried = run(&pe, &pi, 2000000u, 0, 0, 0, &k, &r2);
	CK(r2.resumed == 1 && r2.stop == KGENOME_EMU_STOP_FAULT && r2.returned == 1 && r2.insn == k.rep.insn);
	kgenome_emu_free(carried);

	/* 5. a request that declares a program range is built fresh: the range applies from the entry */
	fresh = run(&pe, &pi, 50000u, 0, 0, 1, NULL, &r1);
	keep_first(&pe, &pi, 16000u, 0, &k);
	carried = run(&pe, &pi, 50000u, 0, 0, 1, &k, &r2);
	CK(k.em == NULL && r2.resumed == 0 && r2.insn == r1.insn && r2.stop == r1.stop);
	kgenome_emu_free(fresh);
	kgenome_emu_free(carried);

	/* 6. other bytes (another buffer, even with the same content): built fresh */
	keep_first(&pe, &pi, 16000u, 0, &k);
	k.file = pe.b + 1;
	carried = run(&pe, &pi, 50000u, 0, 0, 0, &k, &r2);
	CK(k.em == NULL && r2.resumed == 0 && r2.insn == 50000u);
	kgenome_emu_free(carried);

	/* 7. adopt: another account is refused and changes nothing; NULL is refused */
	keep_first(&pe, &pi, 16000u, 0, &k);
	{
		struct kgenome_emu_cfg c;

		memset(&c, 0, sizeof c);
		c.account = rs_acct_other;
		c.max_insn = 5u;
		CK(kgenome_emu_adopt(k.em, &c) == -1);
		CK(kgenome_emu_last_stop(k.em) == KGENOME_EMU_STOP_BUDGET);
		c.account = rs_acct;
		CK(kgenome_emu_adopt(k.em, &c) == 1);
		CK(kgenome_emu_adopt(NULL, &c) == -1 && kgenome_emu_adopt(k.em, NULL) == -1);
		CK(kgenome_emu_last_stop(NULL) == KGENOME_EMU_STOP_BUDGET);
	}
	kgenome_emu_free(k.em);

	/* 8. a request the lib refuses outright still takes the machine over (no leak, no double free) */
	keep_first(&pe, &pi, 16000u, 0, &k);
	CK(kgenome_emu_unp_run_pe(&(const struct kgenome_emu_unp_pe_req){ .file = NULL, .resume = &k }) == NULL);
	CK(k.em == NULL);

	/* 9. a program that EXITED is not run again: ExitProcess through the import table, then a loop
	 *    that a machine run on past the exit would spin in */
	{
		static const uint8_t ex[] = {
			0x6a, 0x00,                             /* push 0                        */
			0xff, 0x15, 0xa0, 0x20, 0x40, 0x00,     /* call [0x4020a0]  ExitProcess  */
			0x40,                                   /* inc eax                       */
			0xeb, 0xfd                              /* jmp inc                       */
		};

		memcpy(pe.b + pe.text_off, ex, sizeof ex);
		CK(kgenome_pe_image_parse(kof_buf_make(pe.b, pe.n), &pi, &o));
		keep_first(&pe, &pi, 16000u, 0, &k);
		CK(k.em && k.rep.stop == KGENOME_EMU_STOP_EXIT);
		carried = run(&pe, &pi, 2000000u, 0, 0, 0, &k, &r2);
		CK(r2.resumed == 1 && r2.stop == KGENOME_EMU_STOP_EXIT && r2.insn == k.rep.insn);
		kgenome_emu_free(carried);
	}

	/* 10. a kept record that holds no machine is a request without one */
	memset(&k, 0, sizeof k);
	carried = run(&pe, &pi, 50000u, 0, 0, 0, &k, &r2);
	CK(carried && r2.resumed == 0);
	kgenome_emu_free(carried);

	CK(rs_acct_calls > 0);
	printf("emu_resume: %s\n", hk_fails ? "FAIL" : "ok");
	return hk_fails ? 1 : 0;
}
