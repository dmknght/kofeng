/*
 * silent_loss_sites - a stager reached through a very large number of distinct call sites:
 * for EVERY size the answer is "found" or "a signal was raised", never an empty OK.
 *
 * THE INVARIANT (CLAUDE.md section 12, caps-must-not-lose-evidence): a limit is a DoS bound and
 * says so. The run that reaches the stager is bounded by KGENOME_DIAG_EMU_SITES (distinct stop
 * identities, diag_emu.c route_progress) and by the page ledger; both must set a kgenome status
 * (TRUNCATED, OVER_BUDGET, NOMEM). `status == OK` with no match is the one answer that is a lie:
 * "the object was examined and holds nothing".
 *
 * THE FIXTURE (hand-built bytes, in memory):
 *
 *     [xor decoder][ N x call-site ][ stager | W: mov eax,39 ; syscall ; ret ] ^ key
 *
 * Every call site reaches the ONE wrapper W, so each is a stop with a new identity (the address
 * and the two latest call instructions). Only the tail (stager and wrapper) is encoded: the file
 * holds no `0f 05` and no `cd 80`, so only a RUN can see the calls and the static sweep is blind.
 *
 * A TRAP THE FIRST VERSION OF THIS FIXTURE FELL INTO, kept here so nobody falls into it again:
 * encoding the WHOLE payload with one XOR key works to ~58000 five-byte sites and then no key
 * of 255 avoids every `0f 05`, encode falls back to key 0, and the file carries its syscalls in
 * the clear - the static sweep then finds the stager and the answer flips from "truncated" to
 * "match" for a reason that has nothing to do with the product. The fixture asserts it stayed
 * encoded (the static sweep finds nothing) at every size.
 *
 *   - 2-byte `call rbx` sites and 5-byte `call rel32` sites, 1 .. 5,000,000 sites
 *   - the same stager behind a very large PADDING (object size alone, 100 sites)
 */

#include "caps_fix.h"
#include "caps_e2e.h"
#include "known_miss.h"
#include "../../libkofeng/scanners/scan.h"

#define ELF_CODE_VA 0x400078ull
#define DECODER_LEN 20u

static unsigned char view[1u << 22];
static uint8_t *img, *code, *pay;
#define BUF (1u << 25)

/* [lea rsi,[rip+d] ; mov ecx,len ; L: xor [rsi],key ; inc rsi ; loop L] then the payload with
 * the bytes from `tail_at` on encoded. */
static unsigned encode_tail(const uint8_t *p, unsigned pn, unsigned tail_at)
{
	unsigned key, k, n = 0;

	for (key = 1; key < 256u; key++) {
		int ok = 1;

		for (k = tail_at; k + 1u < pn; k++) {
			uint8_t a = p[k] ^ (uint8_t)key, b = p[k + 1u] ^ (uint8_t)key;

			if ((a == 0x0f && b == 0x05) || (a == 0xcd && b == 0x80))
				ok = 0;
		}
		if (ok)
			break;
	}
	CK(key < 256u);
	code[n++] = 0x48; code[n++] = 0x8d; code[n++] = 0x35;
	put32(code, n, 13u + tail_at); n += 4;
	code[n++] = 0xb9; put32(code, n, pn - tail_at); n += 4;
	code[n++] = 0x80; code[n++] = 0x36; code[n++] = (uint8_t)key;
	code[n++] = 0x48; code[n++] = 0xff; code[n++] = 0xc6;
	code[n++] = 0xe2; code[n++] = (uint8_t)-8;
	CK(n == DECODER_LEN);
	for (k = 0; k < pn; k++)
		code[n++] = k < tail_at ? p[k] : p[k] ^ (uint8_t)key;
	return n;
}

/* `sites` of `call rel32 W` (site_len 5) or `call rbx` (site_len 2, rbx = W set first). The
 * sites come first and the encoded tail after them; *tail_at is where the tail starts. */
static unsigned sites_payload(uint8_t *c, unsigned sites, unsigned site_len, unsigned *tail_at)
{
	uint8_t tmp[64];
	unsigned slen = cf_stager64(tmp, 0), at = 0, w, k;

	if (site_len == 2u) {
		uint64_t wva;

		w = 10u + 2u * sites + slen;
		wva = ELF_CODE_VA + DECODER_LEN + w;
		c[at++] = 0x48; c[at++] = 0xbb;                /* mov rbx,W        */
		for (k = 0; k < 8u; k++)
			c[at++] = (uint8_t)(wva >> (8u * k));
		for (k = 0; k < sites; k++) {
			c[at++] = 0xff; c[at++] = 0xd3;        /* call rbx         */
		}
	} else {
		w = 5u * sites + slen;
		for (k = 0; k < sites; k++) {
			c[at++] = 0xe8;                        /* call W           */
			put32(c, at, w - (at + 4u)); at += 4;
		}
	}
	*tail_at = at;
	at = cf_stager64(c, at);
	CK(at == w);
	c[at++] = 0xb8; put32(c, at, 39); at += 4;             /* W: mov eax,39    */
	c[at++] = 0x0f; c[at++] = 0x05;                        /* syscall          */
	c[at++] = 0xc3;                                        /* ret              */
	return at;
}

struct got {
	int match;
	int blind;                  /* the static sweep alone found nothing          */
	enum kgenome_status st;     /* 99: the scan was refused outright             */
	uint64_t len;
};

static struct got run_sites(unsigned sites, unsigned site_len, uint64_t pad)
{
	struct kof_obj_ctx ctx;
	struct kgenome_diag_scan *s;
	struct got g;
	unsigned tail, pn = sites_payload(pay, sites, site_len, &tail);
	unsigned n = encode_tail(pay, pn, tail);
	uint8_t *im = img, *cd = code;

	if (pad) {
		im = malloc(0x78u + n + pad + 64u);
		cd = calloc(1, n + pad);
		memcpy(cd, code, n);
	}
	memset(view, 0, sizeof view);
	g.len = cf_elf64(im, pad ? 0x78u + n + pad + 64u : BUF, cd, n + pad);
	s = cf_scan(im, g.len, KGENOME_DIAG_RUN_SYSCALL, &ctx, view);
	g.blind = s && kgenome_diag_scan_count(s) == 0u;
	kgenome_diag_scan_free(s);
	memset(view, 0, sizeof view);
	s = cf_scan(im, g.len, KGENOME_DIAG_RUN_ALL, &ctx, view);
	g.match = cf_match_rwx(s);
	g.st = s ? kgenome_diag_scan_status(s) : (enum kgenome_status)99;
	kgenome_diag_scan_free(s);
	if (pad) {
		free(im);
		free(cd);
	}
	return g;
}

/* THE INVARIANT: found, or said so. */
static int answered(const struct got *g)
{
	return g->match || g->st != KGENOME_OK;
}

static void sweep(unsigned site_len, const unsigned *sizes, unsigned ns)
{
	unsigned i;

	for (i = 0; i < ns; i++) {
		struct got g = run_sites(sizes[i], site_len, 0);

		if (!g.blind || !answered(&g))
			printf("  sites %u (%u-byte) len %llu: blind %d match %d status %s\n",
			       sizes[i], site_len, (unsigned long long)g.len, g.blind, g.match,
			       kgenome_status_name(g.st));
		CK(g.blind);                 /* the fixture stayed encoded at this size */
		CK(answered(&g));            /* a match, or a status that is not OK     */
		if (sizes[i] <= 30000u)      /* below KGENOME_DIAG_EMU_SITES: followed  */
			CK(g.match == 1 && g.st == KGENOME_OK);
		else if (sizes[i] > 33000u)  /* past it: reported, not followed         */
			CK(g.match == 0 && g.st == KGENOME_TRUNCATED);
	}
}

/*
 * THE SAME INVARIANT THROUGH THE ENGINE (kscan_bytes against the release database, whose
 * mem_execsyscall diagnose runs the emulator): past the run's bound the object says it was not
 * looked at to the end - `broken` (LIMIT) and the syndrome's `incomplete` - and inside the
 * bound it says nothing. The release database gives this stager no verdict of its own, so what
 * a caller can read is the signal; an object with neither verdict nor signal would read as
 * clean. (KGENOME_TRUNCATED itself is not what kof_scan_incomplete reads - objctx_diag.c:710
 * takes OVER_BUDGET and NOMEM and leaves the per-diagnose limits to diag_unk - so this checks
 * that the other route, an open diagnose answering "cannot say", does carry it.)
 */
static struct e2e er;

static int engine_said(unsigned sites, unsigned site_len)
{
	unsigned tail, pn = sites_payload(pay, sites, site_len, &tail);
	unsigned n = encode_tail(pay, pn, tail);
	uint64_t len = cf_elf64(img, BUF, code, n);

	CK(e2e_scan(img, len, &er));
	return er.n > 0 && (er.o[0].broken == KOF_BROKEN_LIMIT || er.o[0].syn.incomplete);
}

static void engine_sweep(void)
{
	static const unsigned sizes[] = { 100, 30000, 33000, 40000, 100000, 1000000 };
	unsigned i, k;

	for (k = 0; k < 2; k++) {
		unsigned sl = k ? 2u : 5u;

		for (i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
			int said = engine_said(sizes[i], sl);

			if (sizes[i] <= 30000u)
				CK(!said && er.n > 0 && er.o[0].n == 0u);
			else
				CK(said);
		}
	}
}

/*
 * THE CASE THE ENGINE'S ANSWER RESTS ON A SECOND MECHANISM FOR: a diag scan whose status is
 * TRUNCATED while NO diagnose is marked "cannot say" (diag.unk empty) - e.g. every diagnose
 * that was read answered YES or its gate was closed, so the cut run's missing stops belong to
 * nobody who asked. kof_scan_incomplete reads only OVER_BUDGET and NOMEM (objctx_diag.c:710)
 * and then returns 0, so the verdict path shows a cut run as complete. diag_ledger_e2e.c pins
 * this as the design ("said by diag_unk, not here"); the invariant of CLAUDE.md section 12 is
 * that a caller can tell "nothing there" from "we stopped looking", which this state cannot.
 * Hand-built state, as status_direct does: the status is the one a 40000-site run leaves.
 */
static void truncated_without_unk(void)
{
	struct kof_obj_ctx ctx;
	kof_scanner *sc;

	if (!e2e_eng)
		return;
	sc = kscan_new(e2e_eng);
	CK(sc != NULL);
	if (!sc)
		return;
	memset(&ctx, 0, sizeof ctx);
	ctx.priv = sc;
	sc->obj.diag.status = KGENOME_TRUNCATED;
	CK(kof_scan_diag_status(&ctx) == KGENOME_TRUNCATED);
	KM_CHECK(kof_scan_incomplete(&ctx) == 1,
		 "a diag scan cut by a limit (TRUNCATED) shows as incomplete to the verdict path "
		 "even when no read diagnose answered 'cannot say'",
		 "kof_scan_incomplete objctx_diag.c:710 lost: TRUNCATED (KGENOME_DIAG_EMU_SITES, "
		 "node/name/site limits) is read only through diag_unk, so stops past the cut that "
		 "belong to no open diagnose leave the object reading as complete [Inference: low "
		 "severity, only diagnoses that were not asked about lose anything]");
	sc->obj.diag.status = KGENOME_OK;
	kscan_free(sc);
}

int main(int argc, char **argv)
{
	/* around the stop-identity bound (32768) and far past it */
	static const unsigned sizes[] = {
		1, 100, 1000, 10000, 30000, 32700, 32767, 32768, 32769, 33000, 40000, 58000, 58100,
		70000, 100000, 400000, 1000000, 5000000
	};
	/* the 2-byte form: 5,000,000 sites is 10 MB, 1,000,000 stays under the buffers */
	struct got g;

	img = malloc(BUF);
	code = malloc(BUF);
	pay = malloc(BUF);
	if (!img || !code || !pay)
		return 1;

	sweep(5u, sizes, sizeof sizes / sizeof sizes[0]);
	sweep(2u, sizes, sizeof sizes / sizeof sizes[0]);

	/* object SIZE alone: 100 sites behind a very large padding. Past the emulated address
	 * space's allowance the answer is NOMEM (the page ledger said so), never OK-and-empty. */
	g = run_sites(100, 5u, 1u << 20);
	CK(g.match == 1 && g.st == KGENOME_OK);
	g = run_sites(100, 5u, 16u << 20);
	CK(answered(&g));
	g = run_sites(100, 5u, 128u << 20);
	CK(answered(&g));
	CK(g.st == KGENOME_NOMEM || g.st == KGENOME_OVER_BUDGET || g.st == KGENOME_TRUNCATED ||
	   g.match);

	CK(e2e_open(argc > 1 ? argv[1] : "build/release/databases"));
	engine_sweep();
	truncated_without_unk();

	free(img);
	free(code);
	free(pay);
	printf("silent_loss_sites: %d failure(s), %u known miss(es)\n", fails, km_known());
	return fails != 0 || km_failed();
}
