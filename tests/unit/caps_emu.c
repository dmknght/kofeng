/*
 * caps_emu - limits of the emulate route (diag_emu.c): the syscalls of a
 * program that DECODES ITSELF, which only a run can show. Evidence just INSIDE
 * and just OUTSIDE each limit.
 *
 * THE FIXTURE is a XOR-decoder stub in front of an encoded payload (the shape
 * msfvenom's x64/xor encoder and every hand-rolled one produce): N `getpid`
 * calls and then the rwx_exec stager. The encoded bytes contain no `0f 05` and
 * no `cd 80`, so the sweep finds NOTHING in the file - asserted below, because
 * a fixture the static route could answer would prove nothing about the run.
 *
 * WHAT THIS CATCHES:
 *
 *   DIAG_EMU_QUIET (256)  the run ends when 256 syscall stops IN A ROW reach no
 *                         address it had not reached before (diag_emu.c,
 *                         route_progress). It was "the 256th syscall, whatever it
 *                         is" - max(256, 4 x the sites the static routes found) -
 *                         and a decoder that makes 254 harmless calls (each at its
 *                         own site, no node, nothing to scale by) hid the stager
 *                         behind them. Miss class: "run ends before the evidence".
 *                         A stop at a NEW address is progress and starts the count
 *                         again, so a decoder of a thousand different harmless
 *                         calls is followed. The other half - a loop that polls
 *                         ONE call ending the run, and the converse - one
 *                         libc wrapper reached from 300 different call sites is
 *                         NOT a loop (a stop is its address AND its caller) - are
 *                         checked at the window's edges by emu_syscall_watch.c.
 *   DIAG_EMU_INSN (2M)    the instruction budget, max(2M, 64 x code bytes); spent,
 *                         the scan says KGENOME_OVER_BUDGET. A delay loop of 1M
 *                         iterations before the decoder - the cheapest
 *                         anti-analysis there is - ended the run with nothing, and
 *                         so did one of 2.5M iterations in a 100 KB object (the
 *                         emulator calls a run finished after KGENOME_EMU_IDLE, 4M
 *                         instructions, without a new page). A COUNTED delay is now
 *                         accounted by its iterations, not run (emu_loop.c), so
 *                         neither bound sees it. A wait that is NOT that shape - a
 *                         counter in memory, a spin - is still what the budget is
 *                         for, and the scan still says so.
 *
 * Every pair is a normal check now. What stays bounded is checked as such: the
 * budget's half asserts the status of the bound that bit, so a bound that stops
 * hiding its cut is a failure here too.
 */

#include "caps_fix.h"
#include "known_miss.h"

static unsigned char view[1u << 22];
static uint8_t img[1u << 22];
static uint8_t code[1u << 21];

/*
 * [delay loop of `delay` iterations] ; xor-decoder ; payload ^ key, where the
 * payload is `n_getpid` salted `mov esi,x ; mov eax,39 ; syscall` then the
 * stager. Returns the code length; *key is the byte chosen so that no
 * encoded byte pair is a kernel entry.
 */
enum pre_kind { PRE_COUNTED, PRE_MEMCOUNT };

static unsigned encoded(unsigned n_getpid, unsigned delay, enum pre_kind kind)
{
	static uint8_t pay[1u << 16];
	unsigned pn = 0, k, key, n = 0;

	for (k = 0; k < n_getpid; k++) {
		pay[pn] = 0xbe;
		put32(pay, pn + 1u, k * 2654435761u);
		pn += 5;
		pay[pn++] = 0xb8;
		put32(pay, pn, 39);             /* getpid */
		pn += 4;
		pay[pn++] = 0x0f;
		pay[pn++] = 0x05;
	}
	pn = cf_stager64(pay, pn);
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
	if (delay && kind == PRE_COUNTED) {
		code[n++] = 0xb9; put32(code, n, delay); n += 4;   /* mov ecx,delay */
		code[n++] = 0xff; code[n++] = 0xc9;                /* dec ecx       */
		code[n++] = 0x75; code[n++] = 0xfc;                /* jnz -4        */
	} else if (delay && kind == PRE_MEMCOUNT) {
		/* a wait whose counter is in memory: not a counted register loop */
		code[n++] = 0xc7; code[n++] = 0x44; code[n++] = 0x24; code[n++] = 0xf8;
		put32(code, n, delay); n += 4;                     /* mov dword [rsp-8],delay */
		code[n++] = 0xff; code[n++] = 0x4c; code[n++] = 0x24; code[n++] = 0xf8; /* dec dword [rsp-8] */
		code[n++] = 0x75; code[n++] = 0xfa;                /* jnz -6        */
	}
	code[n++] = 0x48; code[n++] = 0x8d; code[n++] = 0x35;  /* lea rsi,[rip+15] */
	put32(code, n, 15); n += 4;
	code[n++] = 0xb9; put32(code, n, pn); n += 4;          /* mov ecx,len   */
	code[n++] = 0x80; code[n++] = 0x36; code[n++] = (uint8_t)key; /* xor [rsi],key */
	code[n++] = 0x48; code[n++] = 0xff; code[n++] = 0xc6;  /* inc rsi       */
	code[n++] = 0xe2; code[n++] = (uint8_t)-8;             /* loop          */
	for (k = 0; k < pn; k++)
		code[n++] = pay[k] ^ (uint8_t)key;
	return n;
}

struct got { int match; enum kgenome_status st; unsigned nodes; int static_match; };

static struct got run_kind(unsigned n_getpid, unsigned delay, enum pre_kind kind,
			   unsigned pad_bytes);

static struct got run(unsigned n_getpid, unsigned delay)
{
	return run_kind(n_getpid, delay, PRE_COUNTED, 0);
}

static struct got run_padded(unsigned n_getpid, unsigned delay, unsigned pad_bytes)
{
	return run_kind(n_getpid, delay, PRE_COUNTED, pad_bytes);
}

static struct got run_kind(unsigned n_getpid, unsigned delay, enum pre_kind kind,
			   unsigned pad_bytes)
{
	struct kof_obj_ctx ctx;
	struct kgenome_diag_scan *s;
	struct got g;
	unsigned n = encoded(n_getpid, delay, kind);
	uint64_t len;

	/* `pad_bytes` of inert code after the payload: the code is bigger, which is
	 * what the instruction budget scales with, and nothing runs it. */
	if (pad_bytes) {
		memset(code + n, 0x90, pad_bytes);
		n += pad_bytes;
	}

	memset(view, 0, sizeof view);
	len = cf_elf64(img, sizeof img, code, n);
	s = cf_scan(img, len, KGENOME_DIAG_RUN_SYSCALL, &ctx, view);
	g.static_match = cf_match_rwx(s) || kgenome_diag_scan_count(s) != 0;
	kgenome_diag_scan_free(s);

	memset(view, 0, sizeof view);
	s = cf_scan(img, len, KGENOME_DIAG_RUN_ALL, &ctx, view);
	g.match = cf_match_rwx(s);
	g.st = kgenome_diag_scan_status(s);
	g.nodes = kgenome_diag_scan_count(s);
	kgenome_diag_scan_free(s);
	return g;
}

static void stops(void)
{
	struct got g = run(0, 0);

	CK(!g.static_match);            /* the sweep sees nothing: only the run can */
	CK(g.match == 1);
	g = run(253, 0);
	CK(!g.static_match);
	CK(g.match == 1 && g.st == KGENOME_OK);
	/* The 254th and the 1000th harmless call used to be the 256th stop and the
	 * end of the run. Each is at a site of its own - progress, not a loop. */
	g = run(254, 0);
	CK(g.match == 1 && g.st == KGENOME_OK);
	g = run(1000, 0);
	CK(g.match == 1 && g.st == KGENOME_OK);
}

static void insn(void)
{
	struct got g = run(0, 900000);

	CK(!g.static_match);
	CK(g.match == 1 && g.st == KGENOME_OK);         /* 1.8M instructions of delay: inside */
	/* 2.2M and 5M instructions of COUNTED delay: accounted by iterations, so
	 * neither the budget (2M, and 6.4M in the bigger object) nor the stall stop
	 * (4M without a new page) is spent. */
	g = run(0, 1100000);
	CK(g.match == 1 && g.st == KGENOME_OK);
	g = run_padded(0, 1100000, 100000);
	CK(g.match == 1 && g.st == KGENOME_OK);
	g = run_padded(0, 2500000, 100000);
	CK(g.match == 1 && g.st == KGENOME_OK);
	/* A counted delay of any length: the count is arithmetic. */
	g = run(0, 0xfffffff0u);
	CK(g.match == 1 && g.st == KGENOME_OK);

	/* A wait that is NOT a counted register loop (the counter is in memory) is
	 * still run, and the budget still ends it - 2 instructions an iteration.
	 * Inside the budget it is matched; past it the scan says so. */
	g = run_kind(0, 300000, PRE_MEMCOUNT, 0);
	CK(g.match == 1 && g.st == KGENOME_OK);
	g = run_kind(0, 1100000, PRE_MEMCOUNT, 0);
	CK(g.match == 0 && g.st == KGENOME_OVER_BUDGET);
	/* The budget scales with the code, as before: 6.4M for 100 KB. */
	g = run_kind(0, 1100000, PRE_MEMCOUNT, 100000);
	CK(g.match == 1 && g.st == KGENOME_OK);
}

int main(void)
{
	stops();
	insn();
	printf("caps emu: %u known miss(es) recorded, %s\n", km_known(),
	       fails || km_failed() ? "FAILED" : "ok");
	return fails != 0 || km_failed();
}
