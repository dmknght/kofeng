/*
 * diag/emu_code - the interpreter on code bytes: the step counter is the CPU bound and the account callback is the allocation cap.
 *
 * The input is [width][code]: width 0 maps 64-bit, anything else 32-bit; the code is mapped read+execute at 0x400000 with a read+write
 * stack and a read+write data page, rip at the start, the registers set from the first bytes. The machine runs under max_insn (a few
 * thousand) and an `account` that is unlimited for the two equivalence runs and, for the third, refuses what the pages take past a few KiB beyond the creation's charge. Held:
 *   - the stop is in the enum and has a name; the instructions executed never pass the budget (the budget is counted per instruction)
 *   - ICACHE EQUIVALENCE (emu.h: "a run with it off and the same run with it on make the same stops, registers and instruction counts"):
 *     the run is made twice, once each way, and compared - stop, rip, instruction count, the eight low registers
 *   - what the guest wrote reads back: a write of n bytes into the data page is read by kgenome_emu_read, and a read that is refused writes nothing
 *   - the caller's count (insn_spent) is what the machine says it executed
 *   - an account that refuses is said (kgenome_emu_hit has MEM), never silent: the run with a cap of one page differs from the full run only
 *     with that bit set
 * The row claims no function of the public surface: stage 4b's own adapter (work package 6) does; this one is the diagnose route's view
 * of the machine (the emulate route, the API-hash run, the rel-gaps walk all drive it with bytes that came out of a file).
 */
#include "diag_seed.h"

#include <phenotype/emu.h>

static const char *const dict[] = { "\x0f\x05", "\xcd\x80", "\xeb\xfe", "\xe8", "\xff\xd0", "\xc3", "\xf3\xa4", "\x0f\x0b", "\xd9", "\x0f\x38", "\x0f\x3a", "\xc5", "\x62", NULL };

static void seeds(struct fz_corpus *c)
{
	static struct ds_code code;
	uint8_t b[DS_CODE_MAX + 1u];
	unsigned i;

	for (i = 0; i < DS_NPROG; i++) {
		ds_prog(&code, i);
		b[0] = (uint8_t)(i & 1u);
		memcpy(b + 1, code.b, code.n);
		fz_corpus_add(c, "prog", b, code.n + 1u);
	}
	{
		static const uint8_t loop[] = { 0, 0x31, 0xc0, 0xff, 0xc0, 0xeb, 0xfc };      /* xor eax,eax ; inc eax ; jmp -4 */
		static const uint8_t rep[] = { 0, 0x48, 0xc7, 0xc1, 0x00, 0x10, 0, 0, 0xf3, 0xa4, 0xc3 };   /* mov rcx,0x1000 ; rep movsb ; ret */

		fz_corpus_add(c, "loop", loop, sizeof loop);
		fz_corpus_add(c, "rep", rep, sizeof rep);
	}
}

struct acct {
	int64_t held, cap;
	int     refused;
};

static int account(void *u, int64_t bytes)
{
	struct acct *a = (struct acct *)u;

	if (bytes > 0 && a->held + bytes > a->cap) {
		a->refused = 1;
		return 0;
	}
	a->held += bytes;
	return 1;
}

struct res {
	enum kgenome_emu_stop stop;
	uint64_t rip, insn, reg[8], spent;
	unsigned hit, bad;
	int      made;
};

/* `extra`: the bytes the machine may take beyond what its creation charges (negative: no limit) */
static struct res one(const uint8_t *code, size_t len, unsigned bits, int icache, int64_t extra, uint64_t max_insn)
{
	static uint8_t data[4096];
	struct res r;
	struct acct a = { 0, INT64_MAX, 0 };
	struct kgenome_emu_cfg cfg;
	struct kgenome_emu *e;
	unsigned i;

	memset(&r, 0, sizeof r);
	memset(&cfg, 0, sizeof cfg);
	cfg.max_insn = max_insn;
	cfg.max_pages = 64;
	cfg.bits = bits;
	cfg.account = account;
	cfg.account_user = &a;
	cfg.insn_spent = &r.spent;
	e = kgenome_emu_new(&cfg);
	if (!e)
		return r;
	r.made = 1;
	if (extra >= 0)
		a.cap = a.held + extra;                   /* the creation is paid for; what the pages take after it is the cap */
	kgenome_emu_set_icache(e, icache);
	if (!kgenome_emu_map(e, 0x400000u, code, len, (len + 0xfffu) & ~0xfffu, KGENOME_EMU_R | KGENOME_EMU_X) ||
	    !kgenome_emu_map(e, 0x7ff000u, NULL, 0x2000u, 0x2000u, KGENOME_EMU_R | KGENOME_EMU_W) ||
	    !kgenome_emu_map(e, 0x600000u, data, sizeof data, sizeof data, KGENOME_EMU_R | KGENOME_EMU_W)) {
		r.hit = kgenome_emu_hit(e);
		kgenome_emu_free(e);
		return r;
	}
	kgenome_emu_set_rip(e, 0x400000u);
	for (i = 0; i < 8u; i++)
		kgenome_emu_set_reg(e, i, i == 4u ? 0x800800u : 0x600000u + 8u * i + (len ? code[i % len] : 0u));
	r.stop = kgenome_emu_run(e);
	r.rip = kgenome_emu_get_rip(e);
	r.insn = kgenome_emu_insn_count(e);
	for (i = 0; i < 8u; i++)
		r.reg[i] = kgenome_emu_get_reg(e, i);
	r.hit = kgenome_emu_hit(e);
	/* what is written reads back, and a refused read leaves the buffer alone */
	{
		uint8_t w[16], g[16];
		unsigned k;

		for (k = 0; k < sizeof w; k++)
			w[k] = (uint8_t)(0x30u + k + (r.insn & 0xffu));
		memset(g, 0xcc, sizeof g);
		if (kgenome_emu_write(e, 0x600100u, w, sizeof w) && kgenome_emu_read(e, 0x600100u, g, sizeof g))
			r.bad |= memcmp(w, g, sizeof w) ? 1u : 0u;
		memset(g, 0xcc, sizeof g);
		if (!kgenome_emu_read(e, 0x1000u, g, sizeof g))
			for (k = 0; k < sizeof g; k++)
				if (g[k] != 0xcc)
					r.bad |= 2u;      /* a refused read wrote into the buffer (emu-read-was-partial) */
	}
	kgenome_emu_free(e);
	return r;
}

/* the clean run of the last input, for the run with an allocation refused (c->failk) */
static struct {
	uint64_t in_hash;
	struct res r;
	int have;
} clean;

static uint64_t hash_in(const uint8_t *p, size_t n)
{
	uint64_t h = 1469598103934665603ull;
	size_t i;

	for (i = 0; i < n; i++)
		h = (h ^ p[i]) * 1099511628211ull;
	return h ^ n;
}

static int same(const struct res *a, const struct res *b)
{
	unsigned i;

	if (a->stop != b->stop || a->rip != b->rip || a->insn != b->insn)
		return 0;
	for (i = 0; i < 8u; i++)
		if (a->reg[i] != b->reg[i])
			return 0;
	return 1;
}

static int run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	struct res a, b, f;
	unsigned bits;
	uint64_t max_insn = 400u + fz_below(c->rng, 6000);
	unsigned i;

	if (n < 2)
		return 1;
	bits = in[0] ? 32u : 64u;
	if (n - 1u > DS_CODE_MAX)
		n = DS_CODE_MAX + 1u;
	a = one(in + 1, n - 1u, bits, 1, -1, max_insn);
	if (c->failk) {
		/* an allocation was refused somewhere in the call: the run may differ from the clean one, and then the machine must have said so */
		if (a.made && clean.have && clean.in_hash == hash_in(in, n) && !same(&a, &clean.r))
			FZ_CHECK(c, (a.hit & KGENOME_EMU_HIT_MEM) != 0, "an allocation refused changed the run and the memory bit is not set");
		fz_digest(c, (uint64_t)a.made);
		return 0;
	}
	b = one(in + 1, n - 1u, bits, 0, -1, max_insn);
	clean.in_hash = hash_in(in, n);
	clean.r = a;
	clean.have = a.made;
	if (!a.made || !b.made) {
		fz_digest(c, 0xe0e0u);
		return 2;
	}
	fz_step(&c->steps, a.insn + b.insn);
	FZ_CHECK(c, (unsigned)a.stop <= (unsigned)KGENOME_EMU_STOP_BUDGET + 16u && kgenome_emu_stop_name(a.stop) != NULL, "a stop with no name");
	FZ_CHECK(c, a.insn <= max_insn + 1u, "more instructions executed than the budget (counted per instruction)");
	FZ_CHECK(c, a.spent == a.insn, "the caller's count is not what the machine executed");
	FZ_CHECK(c, a.stop == b.stop && a.rip == b.rip && a.insn == b.insn, "ICACHE EQUIVALENCE: the cache changed the stop, the rip or the instruction count");
	for (i = 0; i < 8u; i++)
		FZ_CHECK(c, a.reg[i] == b.reg[i], "ICACHE EQUIVALENCE: the cache changed a register");
	FZ_CHECK(c, !(a.bad & 1u), "a written block did not read back");
	FZ_CHECK(c, !(a.bad & 2u), "a refused read wrote into the buffer");
	/* a cap of 0..4 pages: the answer differs from the full run only with the memory bit set */
	f = one(in + 1, n - 1u, bits, 1, (int64_t)fz_below(c->rng, 5) * 4096, max_insn);
	if (f.made && (f.stop != a.stop || f.insn != a.insn || f.rip != a.rip))
		FZ_CHECK(c, (f.hit & KGENOME_EMU_HIT_MEM) != 0, "an account that refused changed the run and the memory bit is not set");
	fz_digest(c, a.rip ^ (a.insn << 8) ^ ((uint64_t)a.stop << 56));
	for (i = 0; i < 8u; i++)
		fz_digest(c, a.reg[i]);
	return 0;
}

FZ_ADAPTER(emu_code, .name = "kgenome/diag_emu_code", .covers = "", .flags = FZ_MAY_HIT_CAP, .backstop_s = 3000, .steps_base = 200000u, .steps_per_byte = 64,
	   .shape = FZ_REQ, .seeds = seeds, .dict = dict, .run = run);
