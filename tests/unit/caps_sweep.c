/*
 * caps_sweep - limits of the syscall sweep (lineages.c) and of the node and
 * name stores, probed at the boundary: evidence just INSIDE the limit, and just
 * OUTSIDE it.
 *
 * WHAT THIS CATCHES. Every one was a way a detection was silently MISSED (or, for
 * a clean file, silently decided on a part of the evidence). The state after the
 * kgenome budget/status work:
 *
 *   node store         was a fixed 4096; now max(4096, code_bytes / 8), at most
 *                      65534 - the 16-bit node index. The 4096 boundary is
 *                      inside; the new one (65531 fillers) is past the index and
 *                      still a KNOWN-MISS for the match, but SAID now: the scan
 *                      status is KGENOME_TRUNCATED.
 *   DIAG_LEAD (256)    a syscall's argument set-up more than 256 bytes before the
 *                      instruction was not decoded. A candidate whose arguments
 *                      are unread is now walked again from 4096 bytes back
 *                      (DIAG_LEAD_WIDE); past THAT it is still a miss and the
 *                      status is KGENOME_TRUNCATED.
 *   DIAG_IDLE (64)     the window of one candidate ends after 64 instructions
 *                      that carry nothing; the instruction it ended on, and the
 *                      values read in those before it, were in nobody's window -
 *                      7 of 120 placements lost the stager. FIXED: the window is
 *                      suspended and the next candidate resumes it.
 *   DIAG_MAX_IN (4)    a node takes four incoming links (the module ABI's graph
 *                      block has four); the fifth DISTINCT one is refused and
 *                      sets KGENOME_TRUNCATED.
 *   KGENOME_DIAG_STR_MAX  64 -> 256 bytes; a longer name is refused, COUNTED
 *                      (kgenome_diag_scan_refused) and sets the status.
 *   names              1024 -> max(1024, the node limit): the count boundary of
 *                      a small object is 4096, past it the status is set.
 *
 * EVERY EXPECTATION IS WRITTEN AS THE CORRECT BEHAVIOUR. Where the engine does
 * not do it today the check is a KM_CHECK (known_miss.h): it prints KNOWN-MISS,
 * passes, and FAILS the day the engine does the right thing, so the marker is
 * removed with the fix. Where the engine is right today it is a plain CK.
 */

#include "caps_fix.h"
#include "known_miss.h"
#include <phenotype/diag_int.h>

static unsigned char view[1u << 22];
static uint8_t img[1u << 21];
static uint8_t code[1u << 20];

/* The width of a node index (KGENOME_MAX_INDEX = 65534 nodes): 1 carried mmap, k
 * fillers and the stager's three nodes. */
#define FILLERS_AT_INDEX_LIMIT 65530u

static struct kgenome_diag_scan *scan_code(unsigned n, struct kof_obj_ctx *ctx)
{
	uint64_t len;

	memset(view, 0, sizeof view);
	len = cf_elf64(img, sizeof img, code, n);
	return cf_scan(img, len, KGENOME_DIAG_RUN_SYSCALL, ctx, view);
}

/*
 * `k` unrelated read syscalls, then the stager. Returns match; *full = flag.
 *
 * `carry` puts a live value in r12 first (an RW mmap, which is not the
 * diagnose's allocation, kept in a register nothing overwrites): a sweep window
 * stays open while anything is carried, so the fillers are one window and the
 * DIAG_IDLE seam below is not what this measures. Without it, 4096 fillers
 * are ~60 windows and some of them lose a node at the seam - a different cap.
 */
static int filler_then_stager(unsigned k, int carry, enum kgenome_status *full,
			      unsigned *nodes)
{
	static const uint8_t keep[] = {
		0x31, 0xff, 0xb8, 9, 0, 0, 0, 0xbe, 0, 0x10, 0, 0,
		0xba, 3, 0, 0, 0, 0x41, 0xba, 0x22, 0, 0, 0,
		0x45, 0x31, 0xc9, 0x0f, 0x05,
		0x49, 0x89, 0xc4                        /* mov r12,rax */
	};
	struct kof_obj_ctx ctx;
	struct kgenome_diag_scan *s;
	unsigned n = carry ? cf_emit(code, 0, keep, sizeof keep) : 0, i;
	int m;

	for (i = 0; i < k; i++)
		n = cf_filler64(code, n, i);
	n = cf_stager64(code, n);
	s = scan_code(n, &ctx);
	m = cf_match_rwx(s);
	if (full)
		*full = kgenome_diag_scan_status(s);
	if (nodes)
		*nodes = kgenome_diag_scan_count(s);
	kgenome_diag_scan_free(s);
	return m;
}

static void max_node(void)
{
	enum kgenome_status full = KGENOME_OK;
	unsigned nodes = 0;

	/* 1 carried mmap + 4092 fillers + the stager's three nodes = 4096: the old
	 * limit, and now far from full. */
	CK(filler_then_stager(4092, 1, &full, &nodes) == 1);
	CK(nodes == 4096u && full == KGENOME_OK);

	/* ONE MORE FILLER, and the big-.text case: the stager's exec node was the
	 * 4097th and refused, and the diagnose was not matched although the object
	 * carries it whole. The limit now scales with the code (max(4096, code / 8))
	 * so both are kept - this was DIAG_MAX_NODE. */
	CK(filler_then_stager(4093, 1, &full, &nodes) == 1);
	CK(nodes == 4097u && full == KGENOME_OK);
	CK(filler_then_stager(6000, 1, &full, &nodes) == 1);
	CK(nodes == 6004u && full == KGENOME_OK);

	/* THE NEW BOUNDARY, the width of a node index: 65534 nodes exactly fit... */
	CK(filler_then_stager(FILLERS_AT_INDEX_LIMIT, 1, &full, &nodes) == 1);
	CK(nodes == 65534u && full == KGENOME_OK);
	/* ...and the next filler is the first thing dropped: the stager's last node
	 * is the 65535th. Still not matched (a node index cannot name it) but no longer
	 * silent - the scan says it is partial. */
	KM_CHECK(filler_then_stager(FILLERS_AT_INDEX_LIMIT + 1u, 1, &full, &nodes) == 1,
		 "stager after 65531 unrelated syscalls is matched",
		 "KGENOME_MAX_INDEX (16-bit node index)");
	CK(nodes == 65534u);
	CK(full == KGENOME_TRUNCATED);
}

/* mmap with `mov edx,7` set `pad` bytes before the syscall, then the rest. */
static unsigned lead_stager(unsigned pad)
{
	static const uint8_t head[] = { 0x31, 0xff, 0xba, 7, 0, 0, 0,
					0xb8, 9, 0, 0, 0 };
	static const uint8_t rest[] = { 0xbe, 0, 0x10, 0, 0, 0x41, 0xba, 0x22, 0, 0, 0,
					0x45, 0x31, 0xc9, 0x0f, 0x05,
					0x48, 0x89, 0xc6, 0x31, 0xff, 0xba, 0, 0x10, 0, 0,
					0x31, 0xc0, 0x0f, 0x05, 0xff, 0xe6 };
	unsigned n = cf_emit(code, 0, head, sizeof head), k;

	for (k = 0; k < pad / 6u; k++) {        /* lea esi,[esi+0]: inert */
		code[n] = 0x8d; code[n + 1] = 0xb6;
		put32(code, n + 2, 0);
		n += 6;
	}
	return cf_emit(code, n, rest, sizeof rest);
}

static int lead_matches(unsigned pad, enum kgenome_status *st)
{
	struct kof_obj_ctx ctx;
	struct kgenome_diag_scan *s = scan_code(lead_stager(pad), &ctx);
	int m = cf_match_rwx(s);

	if (st)
		*st = kgenome_diag_scan_status(s);
	kgenome_diag_scan_free(s);
	return m;
}

static void lead(void)
{
	enum kgenome_status st = KGENOME_OK;

	CK(lead_matches(0, &st) == 1 && st == KGENOME_OK);
	CK(lead_matches(200, NULL) == 1);       /* set-up ~215 bytes before the syscall */
	/* PAST THE OLD 256: the argument is unread at that lead, so the candidate is
	 * walked again from 4096 bytes back (DIAG_LEAD_WIDE) - this was DIAG_LEAD. */
	CK(lead_matches(300, &st) == 1 && st == KGENOME_OK);
	CK(lead_matches(2000, &st) == 1 && st == KGENOME_OK);
	CK(lead_matches(3900, NULL) == 1);      /* set-up ~3915 bytes back: inside 4096 */
	/* PAST THE NEW ONE: still unread, still a miss - and said. */
	KM_CHECK(lead_matches(5000, &st) == 1,
		 "PROT_EXEC set 5000 bytes before the mmap syscall is read",
		 "DIAG_LEAD_WIDE (4096)");
	CK(st == KGENOME_TRUNCATED);
}

/*
 * The DIAG_IDLE seam. `k` salted syscalls then the stager. The window of the
 * last candidate ends 65 idle instructions after it; for one residue of k the
 * instruction it ends on is the stager's `mov eax,9`, which is then in nobody's
 * window and the mmap site has no number. [Inference] from the measured period
 * (every 17th k with an 11-byte filler) and the loop in sweep_region.
 */
static void idle_seam(void)
{
	unsigned k, miss = 0, first = 0;

	for (k = 0; k < 120u; k++)
		if (!filler_then_stager(k, 0, NULL, NULL)) {
			if (!miss)
				first = k;
			miss++;
		}
	printf("  idle seam: %u of 120 placements lose the stager (first at k=%u)\n",
	       miss, first);
	CK(miss == 0);          /* was DIAG_IDLE: 7 of 120 */

	/* The other direction is not a loss: a pointer a register still carries
	 * is carried through any number of instructions, so a read 300
	 * instructions after the mmap is still linked to it. */
	{
		static const uint8_t pre[] = {
			0x31, 0xff, 0xb8, 9, 0, 0, 0, 0xbe, 0, 0x10, 0, 0,
			0xba, 7, 0, 0, 0, 0x41, 0xba, 0x22, 0, 0, 0,
			0x45, 0x31, 0xc9, 0x0f, 0x05, 0x48, 0x89, 0xc6 };
		static const uint8_t post[] = {
			0x31, 0xff, 0xba, 0, 0x10, 0, 0, 0x31, 0xc0, 0x0f, 0x05,
			0xff, 0xe6 };
		struct kof_obj_ctx ctx;
		struct kgenome_diag_scan *s;
		unsigned n = cf_emit(code, 0, pre, sizeof pre), i;

		for (i = 0; i < 300u; i++)
			code[n++] = 0x90;
		n = cf_emit(code, n, post, sizeof post);
		s = scan_code(n, &ctx);
		CK(cf_match_rwx(s) == 1);
		kgenome_diag_scan_free(s);
	}
}

static void max_in(void)
{
	struct kof_obj_ctx ctx;
	struct kgenome_diag_scan *s;
	struct kgenome_diag_hit *h;
	uint32_t src[6], tgt, j;

	/* a scan with the engine's own node store, then six producers and one
	 * consumer that takes a value from five of them (different producers,
	 * so no two links are the same link). */
	code[0] = 0xc3;
	s = scan_code(1, &ctx);
	for (j = 0; j < 6u; j++) {
		h = kgenome_diag_hit_add(s, 0x80u + j, KGENOME_NUCLEO_ALLOC_EXEC, 0);
		CK(h != NULL);
		src[j] = kgenome_diag_scan_count(s) - 1u;
	}
	h = kgenome_diag_hit_add(s, 0x100, KGENOME_NUCLEO_MEM_READ, 0);
	CK(h != NULL);
	tgt = kgenome_diag_scan_count(s) - 1u;
	for (j = 0; j < 4u; j++)
		kgenome_diag_note_in(s, kgenome_diag_hit_of(s, tgt), (uint16_t)src[j],
				 KGENOME_DIAG_ROLE_BUFFER, KGENOME_DIAG_KIND_PRODUCED);
	h = kgenome_diag_hit_of(s, tgt);
	CK(h && h->n_in == 4u);                 /* the four slots are kept... */
	CK(kgenome_diag_scan_status(s) == KGENOME_OK);  /* ...and four is not a loss */
	/* A REPEAT of a link it holds is not a fifth. */
	kgenome_diag_note_in(s, h, (uint16_t)src[0], KGENOME_DIAG_ROLE_BUFFER,
			 KGENOME_DIAG_KIND_PRODUCED);
	CK(kgenome_diag_scan_status(s) == KGENOME_OK);
	/* The FIFTH distinct link is refused, and said (it was dropped silently:
	 * DIAG_MAX_IN). It is not kept because the graph block the modules read has
	 * four slots - raising this one would move the loss to that boundary. */
	kgenome_diag_note_in(s, h, (uint16_t)src[4], KGENOME_DIAG_ROLE_BUFFER,
			 KGENOME_DIAG_KIND_PRODUCED);
	CK(h && h->n_in == 4u);
	CK(kgenome_diag_scan_status(s) == KGENOME_TRUNCATED);
	kgenome_diag_scan_free(s);
}

static void names(void)
{
	struct kof_obj_ctx ctx;
	struct kgenome_diag_scan *s;
	char nm[KGENOME_DIAG_STR_MAX + 40u];
	unsigned i;

	code[0] = 0xc3;
	s = scan_code(1, &ctx);

	/* THE NAME LENGTH: was 64, is the record's 256. 64, 65 and 120 were refused
	 * silently (DIAG_STR_MAX); a C++ mangled symbol is well past 64. */
	for (i = 0; i < 3u; i++) {
		static const unsigned len[3] = { 64, 65, 120 };

		memset(nm, 'a' + (int)i, len[i]);
		nm[len[i]] = 0;
		CK(kgenome_diag_str_add(s, KGENOME_NUCLEO_MEM_READ, 0, nm) == 1);
		CK(kgenome_diag_str_at_node(s, KGENOME_NUCLEO_MEM_READ, 0, nm) == 1);
	}
	CK(kgenome_diag_scan_status(s) == KGENOME_OK && kgenome_diag_scan_refused(s) == 0);
	memset(nm, 'e', KGENOME_DIAG_STR_MAX);
	nm[KGENOME_DIAG_STR_MAX] = 0;
	CK(kgenome_diag_str_add(s, KGENOME_NUCLEO_MEM_READ, 0, nm) == 1);   /* 256: inside */
	CK(kgenome_diag_scan_status(s) == KGENOME_OK);

	/* ONE PAST IT: refused, COUNTED, and the scan says so. */
	memset(nm, 'f', KGENOME_DIAG_STR_MAX + 1u);
	nm[KGENOME_DIAG_STR_MAX + 1u] = 0;
	CK(kgenome_diag_str_add(s, KGENOME_NUCLEO_MEM_READ, 0, nm) == 0);
	CK(kgenome_diag_str_at_node(s, KGENOME_NUCLEO_MEM_READ, 0, nm) == 0);
	CK(kgenome_diag_scan_refused(s) == 1u);
	CK(kgenome_diag_scan_status(s) == KGENOME_TRUNCATED);
	kgenome_diag_scan_free(s);

	/* THE COUNT: was 1024 (the 1025th set "full"); now max(1024, the node limit),
	 * which for a one-byte object is the floor of 4096 nodes. 4096 distinct names
	 * fit, the 4097th is refused, counted and said. */
	s = scan_code(1, &ctx);
	for (i = 0; i < 4096u; i++) {
		snprintf(nm, sizeof nm, "name_%u", i);
		CK(kgenome_diag_str_add(s, KGENOME_NUCLEO_MEM_READ, 0, nm) == 1);
	}
	CK(kgenome_diag_scan_status(s) == KGENOME_OK);
	CK(kgenome_diag_str_add(s, KGENOME_NUCLEO_MEM_READ, 0, "one_too_many") == 0);
	CK(kgenome_diag_scan_status(s) == KGENOME_TRUNCATED);
	CK(kgenome_diag_scan_refused(s) == 1u);
	kgenome_diag_scan_free(s);
}

int main(void)
{
	max_node();
	lead();
	idle_seam();
	max_in();
	names();
	printf("caps sweep: %u known miss(es) recorded, %s\n", km_known(),
	       fails || km_failed() ? "FAILED" : "ok");
	return fails != 0 || km_failed();
}
