/*
 * emu_syscall_watch - the emulator's watch for `syscall` sees every syscall
 * instruction the guest executes, and stops on nothing else.
 *
 * THE WATCH IS WHAT THE DIAGNOSE RUN IS BUILT ON (diag_emu.c): it pauses before
 * each `0f 05`, reads the number and the arguments, lets the emulator make the
 * call (kgenome_emu_step) and goes on. A call it does not pause on is a call
 * the diagnose never sees.
 *
 * THE DEFECT THIS GUARDS AGAINST (it was a KNOWN-MISS here until fixed; see run_step in
 * emu_interp.c): kgenome_emu_run's watch compared a fetch buffer that only an instruction-cache
 * MISS filled. A cached instruction was matched against the bytes of whatever was last DECODED,
 * so a polled `syscall` was paused on once (the first visit) and not again, and a cached
 * instruction that is NOT a syscall was paused on as one when the last decode was a `0f 05`. The
 * run now takes the bytes, the length and the address from one per-step record filled the same
 * way on a hit and a miss, so these are plain checks:
 *
 *   - a polled `syscall` is paused on at every visit, the first (a decode) and every later one
 *     (a cache hit);
 *   - a cached non-syscall is never paused on, whatever was decoded before it;
 *   - a run with the instruction cache forced off and the same run with it on make exactly the
 *     same stops, registers and instruction counts (the cache is an acceleration).
 *
 * The fixtures are hand-built bytes in memory.
 *
 * AND WHAT NEVER DEPENDED ON IT: a syscall that is
 * decoded every time it runs (its cache slot is taken by another instruction
 * between visits) is paused on every time, and the first visit of any
 * instruction is decoded, so a straight line of distinct syscalls loses none.
 *
 * THE DIAGNOSE RUN'S QUIET WINDOW (KGENOME_DIAG_EMU_QUIET, diag_emu_private.h) is
 * built on exactly those stops and is checked below the same way: a decoded
 * program polls one syscall site from a loop whose body evicts it from the
 * cache, so every visit is a pause AT AN ADDRESS ALREADY SEEN.
 *
 *   256 such pauses in a row     the run is ended and the scan says TRUNCATED
 *   255                          it is not
 *   a pause at a NEW address     starts the count again
 */

#include "caps_fix.h"
#include <phenotype/emu.h>

#define CODE_VA  0x400000ull
#define STACK_VA 0x7ff00000ull

#define MAX_STOPS 4096u

struct watched {
	unsigned stops;                 /* pauses on the watched bytes              */
	unsigned at_syscall;            /* ...of them, at a real `0f 05`            */
	unsigned at_other;              /* ...of them, at something else            */
	uint64_t insn;                  /* instructions the run executed            */
	enum kgenome_emu_stop end;
	uint64_t rip;                   /* where the run ended                      */
	uint64_t gpr[16];               /* ...and the registers it ended with       */
	uint64_t pause_rip[64];         /* the first 64 pauses, in order            */
};

/*
 * Run `code` (mapped at `base`) with the watch on `0f 05`, answering every pause
 * the way the diagnose does: step over the instruction, go on. A pause is "at a
 * syscall" when the bytes of the image at rip are `0f 05` - the image is the
 * test's own, so this does not ask the emulator.
 */
static struct watched drive_ic(const uint8_t *code, unsigned len, uint64_t base,
			       uint64_t max_insn, int icache)
{
	static const uint8_t pat[2] = { 0x0f, 0x05 };
	struct kgenome_emu_cfg cfg = { 0 };
	struct kgenome_emu *e;
	struct watched w;

	memset(&w, 0, sizeof w);
	cfg.bits = 64;
	cfg.max_insn = max_insn;
	e = kgenome_emu_new(&cfg);
	if (!e)
		return w;
	kgenome_emu_map(e, base, code, len, 0x1000, KGENOME_EMU_R | KGENOME_EMU_X);
	kgenome_emu_map(e, STACK_VA, NULL, 0, 0x1000, KGENOME_EMU_R | KGENOME_EMU_W);
	kgenome_emu_set_rip(e, base);
	kgenome_emu_set_reg(e, KGENOME_EMU_RSP, STACK_VA + 0x800);
	kgenome_emu_set_icache(e, icache);
	kgenome_emu_watch_insn(e, pat, sizeof pat);
	for (;;) {
		enum kgenome_emu_stop st = kgenome_emu_run(e);
		uint64_t rip;

		if (st != KGENOME_EMU_STOP_INSN || w.stops >= MAX_STOPS) {
			w.end = st;
			break;
		}
		rip = kgenome_emu_get_rip(e);
		if (w.stops < 64u)
			w.pause_rip[w.stops] = rip;
		w.stops++;
		if (rip >= base && rip - base + 2u <= len &&
		    code[rip - base] == 0x0f && code[rip - base + 1u] == 0x05)
			w.at_syscall++;
		else
			w.at_other++;
		(void)kgenome_emu_step(e);
	}
	w.insn = kgenome_emu_insn_count(e);
	w.rip = kgenome_emu_get_rip(e);
	{
		unsigned r;

		for (r = 0; r < 16u; r++)
			w.gpr[r] = kgenome_emu_get_reg(e, r);
	}
	kgenome_emu_free(e);
	return w;
}

static struct watched drive(const uint8_t *code, unsigned len, uint64_t base,
			    uint64_t max_insn)
{
	return drive_ic(code, len, base, max_insn, 1);
}

/*
 *     mov ebx,N
 *  L: mov eax,39 ; syscall ; dec ebx ; jnz L
 *     hlt
 * One getpid, polled N times. `ebx`, not `ecx`: a real syscall clobbers rcx.
 */
static unsigned poll_loop(uint8_t *c, uint32_t n)
{
	unsigned at = 0;

	c[at++] = 0xbb; put32(c, at, n); at += 4;             /* mov ebx,n        */
	c[at++] = 0xb8; put32(c, at, 39); at += 4;            /* L: mov eax,39    */
	c[at++] = 0x0f; c[at++] = 0x05;                        /* syscall          */
	c[at++] = 0xff; c[at++] = 0xcb;                        /* dec ebx          */
	c[at++] = 0x75; c[at++] = 0xf5;                        /* jnz L (-11)      */
	c[at++] = 0xf4;                                        /* hlt              */
	return at;
}

/*
 * A syscall reached ONCE as a cache miss, after the code that follows it has
 * been decoded already:
 *
 *      mov ebx,2 ; mov eax,39
 *      jmp T
 *   S: syscall                 <- first decoded on the second lap
 *   T: xor edx,edx             <- two bytes, decoded on the first lap, cached
 *      dec ebx
 *      jz S                    <- lap 2: taken
 *      js done                 <- after S falls through T: ebx is -1
 *      jmp T
 * done: hlt
 *
 * Lap 1 decodes everything but S. Lap 2 hits T, dec and jz, then DECODES S - the
 * last decode is `0f 05`, the buffer holds it - pauses (correctly), steps, and
 * falls into T, a cache HIT of two bytes that are not a syscall, matched against
 * the buffer: a pause at T. The correct run makes ONE pause, at S.
 */
static unsigned false_stop(uint8_t *c, unsigned *s_at, unsigned *t_at)
{
	unsigned at = 0;

	c[at++] = 0xbb; put32(c, at, 2); at += 4;             /* mov ebx,2        */
	c[at++] = 0xb8; put32(c, at, 39); at += 4;            /* mov eax,39       */
	c[at++] = 0xeb; c[at++] = 0x02;                        /* jmp T            */
	*s_at = at;
	c[at++] = 0x0f; c[at++] = 0x05;                        /* S: syscall       */
	*t_at = at;
	c[at++] = 0x31; c[at++] = 0xd2;                        /* T: xor edx,edx   */
	c[at++] = 0xff; c[at++] = 0xcb;                        /* dec ebx          */
	c[at++] = 0x74; c[at++] = 0xf8;                        /* jz S (-8)        */
	c[at++] = 0x78; c[at++] = 0x02;                        /* js done (+2)     */
	c[at++] = 0xeb; c[at++] = 0xf6;                        /* jmp T (-10)      */
	c[at++] = 0xf4;                                        /* done: hlt        */
	return at;
}

static void polled_syscall(void)
{
	uint8_t c[64];
	struct watched w;
	unsigned n = poll_loop(c, 1000);

	w = drive(c, n, CODE_VA, 1u << 20);
	printf("    measured: 1000 laps, %u pause(s), %u at a syscall, %u elsewhere, %llu insn\n",
	       w.stops, w.at_syscall, w.at_other, (unsigned long long)w.insn);
	/* the fixture is what it says: the loop ran a thousand laps of four */
	CK(w.insn >= 4000u);
	CK(w.at_other == 0);
	/* every executed syscall instruction is seen */
	CK(w.stops == 1000u && w.at_syscall == 1000u);

	/* A short poll: the first visit decodes, the rest hit */
	n = poll_loop(c, 3);
	w = drive(c, n, CODE_VA, 1u << 20);
	CK(w.stops == 3u && w.at_syscall == 3u);
	/* ...and what holds either way: the first visit IS seen */
	CK(w.at_syscall >= 1u);
	CK(w.at_other == 0);
}

static void cached_non_syscall(void)
{
	uint8_t c[64];
	struct watched w;
	unsigned s, t, n = false_stop(c, &s, &t);

	w = drive(c, n, CODE_VA, 1u << 20);
	printf("    measured: %u pause(s), %u at a syscall, %u elsewhere\n",
	       w.stops, w.at_syscall, w.at_other);
	CK(w.insn >= 10u);                      /* the fixture ran to its hlt */
	CK(w.at_syscall >= 1u);                 /* S is paused on, right          */
	/* ...and nothing else is: T is two bytes that are not `0f 05` */
	CK(w.stops == 1u && w.at_other == 0u);
}

/*
 * THE FIRST VISIT TO EVERY INSTRUCTION IS DECODED, so a straight line of
 * distinct syscalls loses none: the buffer is right on every miss. This is what
 * the diagnose run's "a decoder of a thousand different harmless calls is
 * followed" rests on.
 */
static void straight_line(void)
{
	uint8_t c[8192];
	struct watched w;
	unsigned at = 0, k;

	for (k = 0; k < 500u; k++) {
		c[at++] = 0xb8; put32(c, at, 39); at += 4;    /* mov eax,39       */
		c[at++] = 0x0f; c[at++] = 0x05;                /* syscall          */
	}
	c[at++] = 0xf4;
	w = drive(c, at, CODE_VA, 1u << 20);
	CK(w.stops == 500u && w.at_syscall == 500u && w.at_other == 0u);
}

/* ---- the diagnose run's quiet window ---------------------------------------- */

static unsigned char view[1u << 22];
static uint8_t img[1u << 20];
static uint8_t code[1u << 18];

/* Where cf_elf64 puts the first byte of code, and how long the decoder in front
 * of the payload is. */
#define ELF_CODE_VA 0x400078ull
#define DECODER_LEN 20u

/* The instruction cache's slot of an address - emu_interp.c run_fetch: a
 * multiplicative hash into KGENOME_EMU_ICACHE (2048) slots. The fixture needs a
 * `syscall` and another instruction that share one, so every visit to the
 * syscall is a decode;
 * that this is so is CHECKED by running the fixture (probe_pauses), not assumed. */
static unsigned slot_of(uint64_t va)
{
	return (unsigned)(((va * 0x9e3779b97f4a7c15ull) >> 40) & 2047u);
}

struct quiet {
	unsigned d1, d2;        /* the evicting `ret`s are this far past X and past A */
	unsigned stager_len;
};

/*
 * THE PAYLOAD, laid out so that every visit to the polled `syscall` is a DECODE
 * and nothing is paused on that is not a syscall:
 *
 *       mov ebx,N1 ; call poll
 *       [mov eax,39 ; syscall          a SECOND, new site (the reset)
 *        mov ebx,N2 ; call poll]
 *       <the rwx_exec stager, or `hlt` of the same length for the probe>
 *  poll: L: mov eax,39
 *       X: syscall                      decoded: ev1 took its cache slot
 *       A: dec ebx                      decoded: ev2 took its cache slot
 *          call ev1 ; call ev2 ; jz out ; jmp L
 *       out: ret
 *       <nops, never executed>
 *  ev1: ret     at X + d1, the same cache slot as X
 *  ev2: ret     at A + d2, the same cache slot as A
 *
 * WHY TWO. The stale-buffer miss (emu_syscall_watch above) makes every CACHED
 * instruction after a decoded `0f 05` look like a syscall until something else is
 * decoded. A is the instruction after X, so A is evicted too, and the decode of
 * `dec ebx` leaves `ff cb` in the buffer, which no later hit of the lap can mistake.
 * Both evictors run BEFORE the exit test, so the last lap evicts too and the
 * second call of a poll is a decode like every other. The window under test then
 * counts exactly what the fixture says: one pause per lap, at one address, and
 * the count does not move if the stale buffer is ever fixed.
 *
 * d is searched for the address the layout gives (the multiplicative hash puts
 * two addresses in one slot only some distance apart - ~1.7 KB). Returns the
 * length; fills `q`.
 */
static unsigned quiet_payload(uint8_t *c, uint64_t pay_va, unsigned n1, unsigned n2,
			      int mid, int real_stager, struct quiet *q)
{
	uint8_t tmp[64];
	unsigned head = 5u + 5u + (mid ? 7u + 5u + 5u : 0u), at = 0, poll, d, call1, call2 = 0;
	unsigned ev1, ev2, end;
	uint64_t x;

	q->stager_len = cf_stager64(tmp, 0);
	poll = head + q->stager_len;
	x = pay_va + poll + 5u;
	for (d = 31u; d < 8000u && slot_of(x + d) != slot_of(x); d++)
		;
	CK(d < 8000u);
	q->d1 = d;
	for (d = 31u; d < 8000u && (slot_of(x + 2u + d) != slot_of(x + 2u) ||
				     x + 2u + d == x + q->d1); d++)
		;
	CK(d < 8000u);
	q->d2 = d;
	ev1 = poll + 5u + q->d1;
	ev2 = poll + 7u + q->d2;
	end = (ev1 > ev2 ? ev1 : ev2) + 1u;
	c[at++] = 0xbb; put32(c, at, n1); at += 4;             /* mov ebx,N1       */
	c[at++] = 0xe8; call1 = at; at += 4;                   /* call poll        */
	if (mid) {
		c[at++] = 0xb8; put32(c, at, 39); at += 4;     /* mov eax,39       */
		c[at++] = 0x0f; c[at++] = 0x05;                /* syscall: a new site */
		c[at++] = 0xbb; put32(c, at, n2); at += 4;     /* mov ebx,N2       */
		c[at++] = 0xe8; call2 = at; at += 4;           /* call poll        */
	}
	put32(c, call1, poll - (call1 + 4u));
	if (mid)
		put32(c, call2, poll - (call2 + 4u));
	if (real_stager) {
		at = cf_stager64(c, at);
	} else {
		c[at++] = 0xf4;                                /* hlt              */
		memset(c + at, 0x90, q->stager_len - 1u);
		at += q->stager_len - 1u;
	}
	/* poll: 31 bytes, X at +5, A at +7 */
	c[at++] = 0xb8; put32(c, at, 39); at += 4;             /* L: mov eax,39    */
	c[at++] = 0x0f; c[at++] = 0x05;                        /* X: syscall       */
	c[at++] = 0xff; c[at++] = 0xcb;                        /* A: dec ebx       */
	c[at++] = 0xe8;                                        /* call ev1         */
	put32(c, at, ev1 - (at + 4u)); at += 4;
	c[at++] = 0xe8;                                        /* call ev2         */
	put32(c, at, ev2 - (at + 4u)); at += 4;
	c[at++] = 0x0f; c[at++] = 0x84;                        /* jz out           */
	put32(c, at, 5u); at += 4;
	c[at++] = 0xe9;                                        /* jmp L            */
	put32(c, at, (uint32_t)(poll - (at + 4u))); at += 4;
	c[at++] = 0xc3;                                        /* out: ret         */
	memset(c + at, 0x90, end - at);                        /* never executed   */
	c[ev1] = 0xc3;
	c[ev2] = 0xc3;
	return end;
}

/* The payload as a program on its own, the stager replaced by `hlt`: how many
 * times is X paused on? One per lap when it is evicted at every lap. */
static unsigned probe_pauses(unsigned n)
{
	uint8_t p[16384];
	struct quiet q;
	unsigned len = quiet_payload(p, ELF_CODE_VA + DECODER_LEN, n, 0, 0, 0, &q);
	struct watched w = drive(p, len, ELF_CODE_VA + DECODER_LEN, 1u << 20);

	return w.at_other == 0 ? w.stops : 0xffffffffu;
}

/* [xor decoder] [payload ^ key]: the file holds no `0f 05` and no `cd 80`, so
 * only a run can see the calls. Returns the code length. */
static unsigned encode_payload(const uint8_t *pay, unsigned pn)
{
	unsigned key, k, n = 0;

	for (key = 1; key < 256u; key++) {
		int ok = 1;

		for (k = 0; k + 1u < pn; k++) {
			uint8_t a = pay[k] ^ (uint8_t)key, b = pay[k + 1u] ^ (uint8_t)key;

			if ((a == 0x0f && b == 0x05) || (a == 0xcd && b == 0x80))
				ok = 0;
		}
		if (ok)
			break;
	}
	code[n++] = 0x48; code[n++] = 0x8d; code[n++] = 0x35;  /* lea rsi,[rip+13]  */
	put32(code, n, 13); n += 4;
	code[n++] = 0xb9; put32(code, n, pn); n += 4;          /* mov ecx,len       */
	code[n++] = 0x80; code[n++] = 0x36; code[n++] = (uint8_t)key; /* xor [rsi],key */
	code[n++] = 0x48; code[n++] = 0xff; code[n++] = 0xc6;  /* inc rsi           */
	code[n++] = 0xe2; code[n++] = (uint8_t)-8;             /* loop              */
	CK(n == DECODER_LEN);
	for (k = 0; k < pn; k++)
		code[n++] = pay[k] ^ (uint8_t)key;
	return n;
}

static unsigned encoded_payload(unsigned n1, unsigned n2, int mid)
{
	uint8_t pay[16384];
	struct quiet q;
	unsigned pn = quiet_payload(pay, ELF_CODE_VA + DECODER_LEN, n1, n2, mid, 1, &q);

	return encode_payload(pay, pn);
}

/*
 * A SHARED WRAPPER, the shape of a static libc: every call goes through ONE `syscall`
 * instruction (in W: mov eax,39 ; syscall ; ret) and the callers are what differ.
 *
 *   `sites` > 0   that many DIFFERENT call sites, `call rbx` (rbx = W) once each, then the stager
 *   `sites` == 0  ONE call site polled `laps` times: L: call W ; dec ebx ; jnz L, then the stager
 */
static unsigned wrapper_payload(uint8_t *c, unsigned sites, uint32_t laps)
{
	uint8_t tmp[64];
	unsigned slen = cf_stager64(tmp, 0), at = 0, w, k;

	if (sites) {
		/* `call rbx` is two bytes, so the object stays small enough to be emulated at all
		 * with tens of thousands of sites; rbx is W, set once */
		uint64_t wva;

		w = 10u + 2u * sites + slen;
		wva = ELF_CODE_VA + DECODER_LEN + w;
		c[at++] = 0x48; c[at++] = 0xbb;                /* mov rbx,W       */
		for (k = 0; k < 8u; k++)
			c[at++] = (uint8_t)(wva >> (8u * k));
		for (k = 0; k < sites; k++) {
			c[at++] = 0xff; c[at++] = 0xd3;        /* call rbx        */
		}
	} else {
		w = 5u + 5u + 2u + 2u + slen;
		c[at++] = 0xbb; put32(c, at, laps); at += 4;   /* mov ebx,laps    */
		c[at++] = 0xe8;                                /* L: call W       */
		put32(c, at, w - (at + 4u)); at += 4;
		c[at++] = 0xff; c[at++] = 0xcb;                /* dec ebx         */
		c[at++] = 0x75; c[at++] = (uint8_t)-9;         /* jnz L           */
	}
	at = cf_stager64(c, at);                               /* the stager      */
	CK(at == w);
	c[at++] = 0xb8; put32(c, at, 39); at += 4;             /* W: mov eax,39   */
	c[at++] = 0x0f; c[at++] = 0x05;                        /* syscall         */
	c[at++] = 0xc3;                                        /* ret             */
	return at;
}

struct got { int match; enum kgenome_status st; int static_blind; };

static struct got run_quiet(unsigned n1, unsigned n2, int mid)
{
	struct kof_obj_ctx ctx;
	struct kgenome_diag_scan *s;
	struct got g;
	unsigned n = encoded_payload(n1, n2, mid);
	uint64_t len;

	memset(view, 0, sizeof view);
	len = cf_elf64(img, sizeof img, code, n);
	s = cf_scan(img, len, KGENOME_DIAG_RUN_SYSCALL, &ctx, view);
	g.static_blind = s && kgenome_diag_scan_count(s) == 0u;
	kgenome_diag_scan_free(s);
	memset(view, 0, sizeof view);
	s = cf_scan(img, len, KGENOME_DIAG_RUN_ALL, &ctx, view);
	g.match = cf_match_rwx(s);
	g.st = kgenome_diag_scan_status(s);
	kgenome_diag_scan_free(s);
	return g;
}

static struct got run_wrapper(unsigned sites, uint32_t laps)
{
	struct kof_obj_ctx ctx;
	struct kgenome_diag_scan *s;
	struct got g;
	static uint8_t pay[1u << 17];
	unsigned pn = wrapper_payload(pay, sites, laps), n = encode_payload(pay, pn);
	uint64_t len;

	memset(view, 0, sizeof view);
	len = cf_elf64(img, sizeof img, code, n);
	s = cf_scan(img, len, KGENOME_DIAG_RUN_SYSCALL, &ctx, view);
	g.static_blind = s && kgenome_diag_scan_count(s) == 0u;
	kgenome_diag_scan_free(s);
	memset(view, 0, sizeof view);
	s = cf_scan(img, len, KGENOME_DIAG_RUN_ALL, &ctx, view);
	g.match = cf_match_rwx(s);
	g.st = kgenome_diag_scan_status(s);
	kgenome_diag_scan_free(s);
	return g;
}

/*
 * THE STOP'S IDENTITY IS ITS ADDRESS AND ITS CALLER. A wrapper reached from many different call
 * sites is progress at every one; the same site reaching the same instruction over and over is a
 * poll and is ended - 256 repeats in a row, counted from the third visit (the call history of
 * the first two can differ).
 */
static void wrapper_identity(void)
{
	struct got g;

	/* three hundred distinct call sites through one address: every one is new work, the run
	 * is not turned round and reaches the stager behind them */
	g = run_wrapper(300, 0);
	CK(g.static_blind);
	CK(g.match == 1 && g.st == KGENOME_OK);
	/* and far past the window: 1000 distinct sites */
	g = run_wrapper(1000, 0);
	CK(g.match == 1 && g.st == KGENOME_OK);

	/* the DoS bound is REPORTED: more distinct call sites than KGENOME_DIAG_EMU_SITES (32768)
	 * and the run is said to be cut, not silently dropped */
	g = run_wrapper(33000, 0);
	CK(g.match == 0 && g.st == KGENOME_TRUNCATED);

	/* one site polled: 255 repeats are tolerated, 256 end the run */
	g = run_wrapper(0, 3);
	CK(g.match == 1 && g.st == KGENOME_OK);
	g = run_wrapper(0, 257);                 /* 255 repeats */
	CK(g.match == 1 && g.st == KGENOME_OK);
	g = run_wrapper(0, 258);                 /* 256 repeats */
	CK(g.match == 0 && g.st == KGENOME_TRUNCATED);
	g = run_wrapper(0, 259);
	CK(g.match == 0 && g.st == KGENOME_TRUNCATED);
	g = run_wrapper(0, 1000);
	CK(g.match == 0 && g.st == KGENOME_TRUNCATED);
}

static void quiet_window(void)
{
	struct got g;

	/* THE FIXTURE IS WHAT IT SAYS: the polled site is paused on at every lap
	 * (a decode each time), and the file hides it from the sweep. */
	CK(probe_pauses(3) == 3u);
	CK(probe_pauses(40) == 40u);

	g = run_quiet(5, 0, 0);
	CK(g.static_blind);
	CK(g.match == 1 && g.st == KGENOME_OK);
	/* A STOP IS A REPEAT FROM ITS THIRD VISIT (the call history of the first two can differ),
	 * so a poll of N laps makes N-2 repeats: 255 of them at N = 257 - the stager's mmap is a
	 * new stop and the run goes on. */
	g = run_quiet(256, 0, 0);
	CK(g.match == 1 && g.st == KGENOME_OK);
	g = run_quiet(257, 0, 0);
	CK(g.match == 1 && g.st == KGENOME_OK);
	/* 256 repeats in a row (N = 258): the run is turned round and the scan says it was cut -
	 * the stager behind the poll is not reached. */
	g = run_quiet(258, 0, 0);
	CK(g.match == 0 && g.st == KGENOME_TRUNCATED);
	g = run_quiet(1000, 0, 0);
	CK(g.match == 0 && g.st == KGENOME_TRUNCATED);

	/* A stop with a NEW identity starts the count again: a poll of 255 repeats (257 laps), a
	 * new site, and a second poll of 255 repeats (256 laps: its first lap is a new identity
	 * but its second repeats the first poll's) are 510 repeats in all and the run is not
	 * ended. */
	g = run_quiet(257, 256, 1);
	CK(g.match == 1 && g.st == KGENOME_OK);
	/* ...and the second poll is held to the window as the first was. */
	g = run_quiet(257, 257, 1);
	CK(g.match == 0 && g.st == KGENOME_TRUNCATED);
}


/*
 * EVERY EXECUTED SYSCALL INSTRUCTION IS SEEN, on the first visit and on every later one: a poll of
 * N laps is N pauses, all at the one `syscall`, for any N - 1 (a decode only) up to a count that
 * wraps the cache's recency many times over.
 */
static void every_visit_seen(void)
{
	static const uint32_t ns[] = { 1, 2, 3, 7, 64, 255, 256, 257, 1000 };
	uint8_t c[64];
	unsigned i, k;

	for (i = 0; i < sizeof ns / sizeof ns[0]; i++) {
		unsigned n = poll_loop(c, ns[i]);
		struct watched w = drive(c, n, CODE_VA, 1u << 22);

		CK(w.stops == ns[i] && w.at_syscall == ns[i] && w.at_other == 0u);
		/* every pause is at the one site */
		for (k = 1; k < ns[i] && k < 64u; k++)
			CK(w.pause_rip[k] == w.pause_rip[0]);
	}
}

/*
 * THE CACHE IS AN ACCELERATION, NEVER A CHANGE OF SEMANTICS: each fixture is run with the
 * instruction cache forced off and again with it on, and the two runs must agree on everything the
 * run reports - the pauses (how many, at which addresses, which were syscalls), the instruction
 * count, the stop, the final rip and every register.
 */
static void same_run(const struct watched *a, const struct watched *b)
{
	CK(a->stops == b->stops && a->at_syscall == b->at_syscall && a->at_other == b->at_other);
	CK(a->insn == b->insn);
	CK(a->end == b->end);
	CK(a->rip == b->rip);
	CK(!memcmp(a->gpr, b->gpr, sizeof a->gpr));
	CK(!memcmp(a->pause_rip, b->pause_rip, sizeof a->pause_rip));
}

static void cache_off_equals_on(void)
{
	uint8_t c[8192];
	unsigned i, n, s, t, at;
	static const uint32_t ns[] = { 1, 3, 100, 1000 };

	for (i = 0; i < sizeof ns / sizeof ns[0]; i++) {
		struct watched off, on;

		n = poll_loop(c, ns[i]);
		off = drive_ic(c, n, CODE_VA, 1u << 22, 0);
		on = drive_ic(c, n, CODE_VA, 1u << 22, 1);
		CK(off.stops == ns[i]);
		same_run(&off, &on);
	}
	{
		struct watched off, on;

		n = false_stop(c, &s, &t);
		off = drive_ic(c, n, CODE_VA, 1u << 20, 0);
		on = drive_ic(c, n, CODE_VA, 1u << 20, 1);
		CK(off.stops == 1u);
		same_run(&off, &on);
	}
	{
		struct watched off, on;

		for (at = 0, i = 0; i < 500u; i++) {
			c[at++] = 0xb8; put32(c, at, 39); at += 4;
			c[at++] = 0x0f; c[at++] = 0x05;
		}
		c[at++] = 0xf4;
		off = drive_ic(c, at, CODE_VA, 1u << 20, 0);
		on = drive_ic(c, at, CODE_VA, 1u << 20, 1);
		CK(off.stops == 500u);
		same_run(&off, &on);
	}
	/* The quiet-window payload: a poll whose body evicts the syscall's cache slot at every
	 * lap, so the cache is exercised both ways inside one run. */
	{
		uint8_t p[16384];
		struct quiet q;
		unsigned len = quiet_payload(p, ELF_CODE_VA + DECODER_LEN, 300, 0, 0, 0, &q);
		struct watched off = drive_ic(p, len, ELF_CODE_VA + DECODER_LEN, 1u << 20, 0);
		struct watched on = drive_ic(p, len, ELF_CODE_VA + DECODER_LEN, 1u << 20, 1);

		CK(off.stops == 300u);
		same_run(&off, &on);
	}
}

int main(void)
{
	quiet_window();
	wrapper_identity();
	polled_syscall();
	cached_non_syscall();
	straight_line();
	every_visit_seen();
	cache_off_equals_on();
	printf("emu syscall watch: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
