/*
 * caps_pe - limits of the PE routes: the program that resolves its own APIs
 * (diag_apihash.c) and the import directory walk (pe_parse.c). Evidence just
 * INSIDE and just OUTSIDE each limit.
 *
 * WHAT THIS CATCHES:
 *
 *   DIAG_PE_IDLE (an eighth of the budget, at least 12 slices of 16000 insn)
 *                      the run ends after that many instructions with no new API
 *                      call. It was a fixed ~192000, and a stager that waits (a
 *                      busy loop, which is what sandbox evasion is) longer was
 *                      never seen making a call; the window follows the budget
 *                      now, and a wait past it is marked (a->status), the honest
 *                      half: the call it was waiting to make is "cannot say".
 *   DIAG_PE_INSN (max(4M, 64 x code))  the ceiling for a run that does keep
 *                      calling: a program that makes a cheap call every ~10000
 *                      instructions and THEN allocates. It was a fixed 2M.
 *   IMP_MAX_DLLS (256) and IMP_MAX_THUNKS (4096) - GONE: the 257th DLL's and
 *                      the 4097th import of one DLL were dropped without a word,
 *                      VirtualAlloc among them. Replaced by ONE budget, the
 *                      thunks of the whole directory <= file bytes / pointer
 *                      width, with KGENOME_TRUNCATED when it is reached. The
 *                      checks below are the old boundary (now inside) and the
 *                      new one (a directory of overlapping tables, past it).
 *
 * The first two are scanned through kgenome_diag_scan_with(KGENOME_DIAG_RUN_APIHASH),
 * the way diag_pe_emu.c does; the import cases through kgenome_pe_imports, which
 * is the walk every route reads.
 */

#include "caps_fix.h"
#include "known_miss.h"
#include "caps_pe_fix.h"
#include "../../libkofeng/analyzers/parsers/binaries/pe/pe_parse.h"
#include "../../libkofeng/analyzers/parsers/binaries/pe/pe_sym.h"
#include "../../libkofeng/kofcore/kofmod/pe.h"
#include "../../libkofeng/analyzers/genome_obj.h"

static unsigned char view[1u << 22];
static uint8_t img[1u << 22];

/*
 * peb walk ; [rounds x (delay ; GetTickCount())] ; delay ; VirtualAlloc(RWX).
 * Returns how many ALLOC_EXEC nodes the apihash route made, and *full.
 */
static unsigned alloc_after(unsigned rounds, unsigned round_iters,
			    unsigned sites, unsigned site_iters,
			    unsigned last_iters, enum kgenome_status *full)
{
	static const uint8_t peb[] = { 0x64, 0x8b, 0x15, 0x30, 0, 0, 0,
				       0x8b, 0x52, 0x0c };
	uint8_t code[2048], *p = code;
	struct kof_obj_ctx ctx;
	struct kgenome_diag_scan *s;
	unsigned i, c;
	uint64_t len;
	const struct kof_parser *pl;
	uint32_t np, q;
	kof_buf buf;

	memcpy(p, peb, sizeof peb);
	p += sizeof peb;
	if (rounds) {
		uint8_t *top;

		*p++ = 0xbf; put32(p, 0, rounds); p += 4;       /* mov edi,rounds */
		top = p;
		p = emit_delay(p, round_iters);
		p = emit_call(p, "GetTickCount");
		*p++ = 0x4f;                                    /* dec edi        */
		*p++ = 0x75;                                    /* jnz top        */
		*p = (uint8_t)(top - (p + 1));
		p++;
	}
	/* `sites` DISTINCT call sites, each after its own delay: each is a new
	 * event, which is what keeps the run alive past the idle limit */
	for (i = 0; i < sites; i++) {
		p = emit_delay(p, site_iters);
		p = emit_call(p, "GetTickCount");
	}
	p = emit_delay(p, last_iters);
	/* VirtualAlloc(0, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE) */
	*p++ = 0x6a; *p++ = 0x40;
	*p++ = 0x68; put32(p, 0, 0x1000); p += 4;
	*p++ = 0x68; put32(p, 0, 0x1000); p += 4;
	*p++ = 0x6a; *p++ = 0;
	p = emit_call(p, "VirtualAlloc");
	*p++ = 0xc3;
	len = pe32_code(img, sizeof img, code, (uint64_t)(p - code));

	memset(view, 0, sizeof view);
	buf.p = img;
	buf.n = len;
	memset(&ctx, 0, sizeof ctx);
	pl = kof_parser_list(&np);
	s = NULL;
	for (q = 0; q < np && !s; q++)
		if (pl[q].sniff && pl[q].sniff(buf) &&
		    pl[q].parse && pl[q].parse(buf, view, &ctx)) {
			struct kgenome_obj gobj;

			kof_genome_obj(&ctx, &gobj);
			s = kgenome_diag_scan_with(&gobj, img, len, KGENOME_DIAG_RUN_APIHASH);
		}
	c = cf_count_cap(s, KGENOME_NUCLEO_ALLOC_EXEC);
	if (full)
		*full = kgenome_diag_scan_status(s);
	kgenome_diag_scan_free(s);
	return c;
}

static void budget(void)
{
	enum kgenome_status full = KGENOME_OK;

	CK(stub_of("VirtualAlloc") != 0 && stub_of("GetTickCount") != 0);

	/* inside: ~100000 idle instructions before the first (only) API call */
	CK(alloc_after(0, 0, 0, 0, 50000, &full) == 1 && full == KGENOME_OK);
	/* ~300000: past what the old fixed window (12 slices, ~192000) allowed. The
	 * window is an eighth of the budget now (31 slices at the resolver's 4M floor, KGENOME_RESOLVE_MIN), so the
	 * allocation that was coming IS recorded. */
	CK(alloc_after(0, 0, 0, 0, 150000, &full) == 1 && full == KGENOME_OK);
	/* ~800000 is past even that: the run gives up with no new call, the
	 * allocation is not recorded and THE SCAN IS FLAGGED - "cannot say". */
	(void)alloc_after(0, 0, 0, 0, 400000, &full);
	CK(full == KGENOME_TRUNCATED);

	/*
	 * A POLLING LOOP IS ONE EVENT. The record is per (call site, API), so a
	 * loop that calls GetTickCount from one place for 300000 instructions
	 * adds nothing after the first lap and the run is declared idle - though
	 * the program is calling an API every 10000 instructions. The window scales
	 * with the budget, so thirty laps are inside; a hundred are still said.
	 */
	CK(alloc_after(10, 5000, 0, 0, 0, &full) == 1);
	CK(alloc_after(30, 5000, 0, 0, 0, &full) == 1 && full == KGENOME_OK);
	CK(alloc_after(100, 5000, 0, 0, 0, &full) == 0);
	CK(full == KGENOME_TRUNCATED);

	/*
	 * THE CEILING, isolated from the idle limit: every call from its own
	 * site, ~140000 instructions apart, so each is a new event. 16 sites is 2.2M
	 * instructions - past the old 2M ceiling, inside the 4M resolver floor that a small
	 * object gets now; 40 are 5.6M, past it, and the budget ends the run.
	 */
	CK(alloc_after(0, 0, 8, 70000, 0, &full) == 1 && full == KGENOME_OK);
	CK(alloc_after(0, 0, 16, 70000, 0, &full) == 1 && full == KGENOME_OK);
	CK(alloc_after(0, 0, 40, 70000, 0, &full) == 0);
	CK(full == KGENOME_OVER_BUDGET);        /* the caller's instruction budget ended it */
}

/* ---- the import directory ---------------------------------------------------- */

/*
 * One .idata-like section holding: `n_dll` descriptors and a terminator, each
 * DLL's name, thunk table and hint/name entries. `fn_of(d, t)` names thunk t of
 * DLL d; `count_of(d)` is how many it has.
 */
struct imp_walk { unsigned n; int saw_last_dll; int saw_last_fn; const char *want_dll; const char *want_fn;
		  enum kgenome_status st; };

static void on_import(void *user, uint64_t slot, const char *dll,
		      const char *name, uint32_t ordinal, uint64_t nameoff)
{
	struct imp_walk *w = user;

	(void)slot; (void)ordinal; (void)nameoff;
	w->n++;
	if (w->want_dll && !strcmp(dll, w->want_dll))
		w->saw_last_dll = 1;
	if (w->want_fn && name && !strcmp(name, w->want_fn))
		w->saw_last_fn = 1;
}

static uint64_t pe32_imports(uint8_t *b, uint64_t cap, unsigned n_dll,
			     unsigned thunks_first_dll, const char *last_dll,
			     const char *last_fn)
{
	const unsigned hdr = 0x400, o = 0x80 + 24, sec = o + 0xf0;
	const unsigned SEC = TEXT_RVA;          /* section rva == data base */
	unsigned desc_len = (n_dll + 1u) * 20u, at, d, t, total_names;
	unsigned *tbl = calloc(n_dll + 1u, sizeof *tbl);
	unsigned fa_end, name_at;

	memset(b, 0, (size_t)cap);
	b[0] = 'M'; b[1] = 'Z';
	put32(b, 0x3c, 0x80);
	memcpy(b + 0x80, "PE\0\0", 4);
	put16(b, 0x84, 0x014cu);
	put16(b, 0x86, 1);
	put16(b, 0x94, 0xf0);
	put16(b, 0x96, 0x22);
	put16(b, o, 0x10bu);
	b[o + 2] = 14;
	put32(b, o + 16, TEXT_RVA);
	put32(b, o + 20, TEXT_RVA);
	put32(b, o + 24, 0x1000);
	put32(b, o + 28, 0x400000);
	put32(b, o + 32, 0x1000);
	put32(b, o + 36, 0x200);
	put16(b, o + 40, 6);
	put16(b, o + 48, 6);
	put32(b, o + 60, hdr);
	put16(b, o + 68, 3);
	put32(b, o + 92, 16);
	memcpy(b + sec, ".idata\0\0", 8);

	/* data layout inside the section (offsets from SEC):
	 * [descriptors][dll names][thunk tables][hint/names] */
	at = desc_len;
	name_at = at;
	for (d = 0; d < n_dll; d++) {
		char nm[32];

		if (d + 1u != n_dll)
			snprintf(nm, sizeof nm, "lib%03u.dll", d);
		else
			snprintf(nm, sizeof nm, "%s", last_dll);
		put32(b, hdr + d * 20u + 12u, SEC + at);        /* Name */
		memcpy(b + hdr + at, nm, strlen(nm) + 1u);
		at += (unsigned)strlen(nm) + 1u;
	}
	at = (at + 3u) & ~3u;
	for (d = 0; d < n_dll; d++) {
		unsigned nt = d == 0 ? thunks_first_dll : 1u;

		tbl[d] = at;
		put32(b, hdr + d * 20u + 0u, SEC + at);         /* OriginalFirstThunk */
		put32(b, hdr + d * 20u + 16u, SEC + at);        /* FirstThunk */
		at += (nt + 1u) * 4u;
	}
	total_names = at;
	for (d = 0; d < n_dll; d++) {
		unsigned nt = d == 0 ? thunks_first_dll : 1u;
		int last_d = d + 1u == n_dll;

		for (t = 0; t < nt; t++) {
			char nm[40];
			int last_t = t + 1u == nt;

			if (last_d && last_t && last_fn)
				snprintf(nm, sizeof nm, "%s", last_fn);
			else if (d == 0 && last_t && thunks_first_dll > 1u && last_fn &&
				 !last_dll)
				snprintf(nm, sizeof nm, "%s", last_fn);
			else
				snprintf(nm, sizeof nm, "Fn%u_%u", d, t);
			put32(b, hdr + tbl[d] + t * 4u, SEC + at);
			memcpy(b + hdr + at + 2u, nm, strlen(nm) + 1u);
			at += 2u + (unsigned)strlen(nm) + 1u;
			at = (at + 1u) & ~1u;
		}
	}
	(void)name_at; (void)total_names;
	fa_end = at;
	put32(b, o + 96 + 8, SEC);                              /* import dir rva  */
	put32(b, o + 96 + 12, desc_len);
	put32(b, sec + 8, fa_end + 0x100);                      /* VirtualSize     */
	put32(b, sec + 12, SEC);
	put32(b, sec + 16, (fa_end + 0x1ff) & ~0x1ffu);         /* SizeOfRawData   */
	put32(b, sec + 20, hdr);
	put32(b, sec + 36, 0xc0000040u);
	put32(b, o + 56, SEC + ((fa_end + 0xfffu) & ~0xfffu));  /* SizeOfImage     */
	free(tbl);
	return hdr + ((fa_end + 0x1ff) & ~0x1ffu);
}

static struct imp_walk walk_imports(uint64_t len, const char *want_dll,
				    const char *want_fn)
{
	struct kof_obj_ctx ctx;
	struct imp_walk w;
	const struct kof_parser *pl;
	uint32_t np, q;
	kof_buf buf;

	memset(&w, 0, sizeof w);
	w.want_dll = want_dll;
	w.want_fn = want_fn;
	memset(view, 0, sizeof view);
	memset(&ctx, 0, sizeof ctx);
	buf.p = img;
	buf.n = len;
	pl = kof_parser_list(&np);
	for (q = 0; q < np; q++)
		if (pl[q].sniff && pl[q].sniff(buf) &&
		    pl[q].parse && pl[q].parse(buf, view, &ctx)) {
			(void)kgenome_pe_imports(buf, kof_pe(&ctx), on_import, &w, &w.st);
			break;
		}
	return w;
}

static void imports(void)
{
	struct imp_walk w;
	uint64_t len;

	/* sanity: the walker reads the table at all (a fixture that imports
	 * nothing would make the cap checks below pass for the wrong reason) */
	len = pe32_imports(img, sizeof img, 3, 2, "kernel32.dll", "VirtualAlloc");
	w = walk_imports(len, "kernel32.dll", "VirtualAlloc");
	CK(w.n == 4 && w.saw_last_dll && w.saw_last_fn);

	/* DLLs: the 256th is read, the 257th is not */
	len = pe32_imports(img, sizeof img, 256, 1, "kernel32.dll", "VirtualAlloc");
	w = walk_imports(len, "kernel32.dll", "VirtualAlloc");
	CK(w.saw_last_dll && w.saw_last_fn);
	len = pe32_imports(img, sizeof img, 257, 1, "kernel32.dll", "VirtualAlloc");
	w = walk_imports(len, "kernel32.dll", "VirtualAlloc");
	CK(w.saw_last_fn && w.st == KGENOME_OK);        /* was IMP_MAX_DLLS */
	len = pe32_imports(img, sizeof img, 300, 1, "kernel32.dll", "VirtualAlloc");
	w = walk_imports(len, "kernel32.dll", "VirtualAlloc");
	CK(w.saw_last_fn && w.st == KGENOME_OK);

	/* thunks: the 4096th import of the first DLL, and the 4097th */
	len = pe32_imports(img, sizeof img, 1, 4096, NULL, "VirtualAlloc");
	w = walk_imports(len, NULL, "VirtualAlloc");
	CK(w.n == 4096 && w.saw_last_fn);
	len = pe32_imports(img, sizeof img, 1, 4097, NULL, "VirtualAlloc");
	w = walk_imports(len, NULL, "VirtualAlloc");
	CK(w.saw_last_fn && w.n == 4097 && w.st == KGENOME_OK);   /* was IMP_MAX_THUNKS */

	/*
	 * THE NEW BOUNDARY: a hostile directory. 200 descriptors, every one pointing
	 * at descriptor 0's table of 3000 thunks - 600000 thunks to read from a file
	 * of ~60 KB, which holds 15000 pointer-sized words. The walk stops at the
	 * budget (file bytes / 4), says KGENOME_TRUNCATED, and costs what the FILE
	 * costs and not what the directory claims.
	 */
	{
		const unsigned hdr = 0x400;
		unsigned d;

		len = pe32_imports(img, sizeof img, 200, 3000, NULL, NULL);
		for (d = 1; d < 200u; d++) {
			memcpy(img + hdr + d * 20u + 0u, img + hdr + 0u, 4);
			memcpy(img + hdr + d * 20u + 16u, img + hdr + 16u, 4);
		}
		w = walk_imports(len, NULL, "no_such_function");
		CK(w.st == KGENOME_TRUNCATED);
		CK(w.n > 3000u && w.n <= len / 4u);
	}
}

int main(void)
{
	budget();
	imports();
	printf("caps pe: %u known miss(es) recorded, %s\n", km_known(),
	       fails || km_failed() ? "FAILED" : "ok");
	return fails != 0 || km_failed();
}
