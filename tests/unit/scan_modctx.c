/*
 * scan_modctx - the scanner's functions that take a MODULE CONTEXT (scanners/scan.h), driven
 * through the context the scanner itself hands a module.
 *
 * A module never sees a scanner: kof_mod_attach presents one through `struct kof_obj_ctx`, whose
 * `priv` the engine's side recovers with kof_scan_of. api_engine_scanint.c reaches the half of
 * scan.h that needs only a scanner; the rest was left "INDIRECT" (named only by what a whole scan
 * exercises). This test is the fake host for them: a scanner from kof_scan_new, a context made by
 * kof_mod_attach and filled by hand the way an object's facts would, and the answers read back.
 *
 *   ATTACH          kof_mod_attach sets the content vtable, the callbacks and priv; kof_mod_unpack_mode
 *                   swaps the producing surface in and out and drops a name a module left pending
 *   EXTENTS         kof_scan_resolve_range: KOF_SCAN_ALL is the object, a resolver that fills a fixed
 *                   buffer cuts the object once (and counts it once); the scanner's own
 *                   buffer grows against the ledger, is released with the object, and a ledger with no
 *                   room is a cut that says so
 *   DIAGNOSE STATE  kof_scan_diag_status reads the graph's own status live; kof_scan_incomplete says
 *                   incomplete for NOMEM / OVER_BUDGET, for TRUNCATED only when an analysis was asked
 *                   for; kof_scan_diag_drop gives the state back; kof_scan_verdict carries the flag
 *   NOTHING TO ASK  an object of no format, a context with no scanner: every one answers "nothing"
 *   EMULATE/SCRIPT  no source, wrong format: nothing attempted, nothing made; release is idempotent
 *   MUTATION        units of a plain buffer: sum within the buffer, a callback that stops the walk stops it
 *
 * Every group that gives a function a context it was not made for runs in a forked child with an
 * alarm (hostile_engine.h), so a fault is a result.
 */

#include "hostile_engine.h"
#include "known_miss.h"

#include "../../libkofeng/scanners/scan.h"
#include "../../libkofeng/scanners/scan_state.h"
#include "../../libkofeng/scanners/scan_int.h"
#include "../../libkofeng/detectors/mutations/kofmutation.h"
#include "../../libkofeng/analyzers/parsers/scripts/script_parse.h"
#include "../../libkofeng/analyzers/parsers/kofformat.h"
#include "../../libkofeng/databases/pack/dbtables.h"
#include <phenotype/diag_scan_state.h>

static kof_engine *eng;
static const char *dbdir = "build/release/databases";

/* ---- attach ------------------------------------------------------------------------------- */

static void t_attach(void)
{
	struct kof_scanner *sc = kof_scan_new(eng);
	struct kof_obj_ctx a, b;
	const struct kof_content *detect;

	CK(sc != NULL, "a scanner");
	if (!sc)
		return;
	memset(&a, 0, sizeof a);
	memset(&b, 0, sizeof b);
	kof_mod_attach(&a, sc);
	CK(a.priv == sc && kof_scan_of(&a) == sc, "priv is the scanner and kof_scan_of recovers it");
	CK(a.content != NULL && a.reserved_0 == NULL && a.debug != NULL, "vtable and debug are set, the report slot is reserved");
	detect = a.content;
	kof_mod_attach(&b, sc);
	CK(b.content == a.content && b.reserved_0 == a.reserved_0 && b.debug == a.debug, "attach is the same for every context");

	/* a name left pending dies with the module that set it */
	sc->pend.label_len = 7;
	kof_mod_unpack_mode(&a, 1);
	CK(a.content != detect && a.content != NULL, "unpack mode swaps the producing vtable in");
	CK(sc->pend.label_len == 0, "and clears what a module left pending (%u)", sc->pend.label_len);
	kof_mod_unpack_mode(&a, 0);
	CK(a.content == detect, "off puts the detecting surface back");
	kof_mod_unpack_mode(&a, 1);
	kof_mod_unpack_mode(&a, 5);
	CK(a.content != detect, "any non-zero is on");
	kof_mod_unpack_mode(&a, 0);
	CK(a.content == detect, "and a repeat of off is a no-op");
	kof_scan_free(sc);
}

/* ---- extents ------------------------------------------------------------------------------ */

static uint32_t fill_resolver(const struct kof_obj_ctx *ctx, uint32_t mask, struct kof_range *out, uint32_t max_out)
{
	uint32_t i;

	(void)ctx; (void)mask;
	for (i = 0; i < max_out; i++) {
		out[i].off = i * 2u;
		out[i].len = 1;
	}
	return max_out;                 /* the buffer filled exactly: cannot say whether it had more */
}

static uint32_t three_resolver(const struct kof_obj_ctx *ctx, uint32_t mask, struct kof_range *out, uint32_t max_out)
{
	(void)ctx; (void)mask;
	if (max_out < 3u)
		return 0;
	out[0].off = 0; out[0].len = 4;
	out[1].off = 8; out[1].len = 4;
	out[2].off = 16; out[2].len = 4;
	return 3;
}

/* A resolver that answers `want` one-byte ranges, as many as the buffer holds: a region of an object with
 * more extents than the scanner's first buffer. `want` is in the context's priv-free obj_size - 2 so no
 * state outside the call is needed. */
static uint32_t many_resolver(const struct kof_obj_ctx *ctx, uint32_t mask, struct kof_range *out, uint32_t max_out)
{
	uint32_t want = (uint32_t)(ctx->obj_size / 2u), i;

	(void)mask;
	for (i = 0; i < want && i < max_out; i++) {
		out[i].off = (uint64_t)i * 2u;
		out[i].len = 1;
	}
	return i;
}

static void t_ranges(void)
{
	struct kof_scanner *sc = kof_scan_new(eng);
	struct kof_obj_ctx c;
	static struct kof_range ext[KOF_SCAN_MAX_EXTENTS + 1];
	struct kof_ext_buf fixed = kof_ext_fixed(ext, KOF_SCAN_MAX_EXTENTS);
	struct kof_ext_buf *eb;
	uint64_t hits0, held0;

	CK(sc != NULL, "a scanner");
	if (!sc)
		return;
	memset(&c, 0, sizeof c);
	kof_mod_attach(&c, sc);
	c.obj_size = 1000;
	CK(kof_scan_resolve_range(&c, KOF_SCAN_ALL, &fixed) == 1 && ext[0].off == 0 && ext[0].len == 1000,
	   "ALL is the whole object and needs no resolver");
	c.obj_size = 0;
	CK(kof_scan_resolve_range(&c, KOF_SCAN_ALL, &fixed) == 0, "an empty object has no extent");
	c.obj_size = 1000;
	CK(kof_scan_resolve_range(&c, 2u, &fixed) == 0, "no resolver: nothing identified the object, only ALL is answerable");
	c.resolve_scan = three_resolver;
	CK(kof_scan_resolve_range(&c, 2u, &fixed) == 3 && ext[1].off == 8 && ext[2].off == 16 && sc->obj.open.broken == 0,
	   "a resolver's answer is passed through, the object is not broken");
	hits0 = kof_scan_stats(sc)->limit_hits;
	c.resolve_scan = fill_resolver;
	CK(kof_scan_resolve_range(&c, 2u, &fixed) == KOF_SCAN_MAX_EXTENTS, "a full caller-owned buffer answers the buffer");
	CK(sc->obj.open.cut == 1 && sc->obj.open.broken == 0 && kof_scan_stats(sc)->limit_hits == hits0 + 1u,
	   "and says so: the object is cut (reported LIMIT at its end), counted once, and its members are still opened (%llu)",
	   (unsigned long long)(kof_scan_stats(sc)->limit_hits - hits0));
	(void)kof_scan_resolve_range(&c, 2u, &fixed);
	CK(kof_scan_stats(sc)->limit_hits == hits0 + 1u, "a second full buffer on the same object is not counted again");

	/*
	 * THE SCANNER'S OWN BUFFER GROWS. A region with 30000 extents (a zip of 15000 entries, its NAMES) used to
	 * come back cut at 4096 and take the object's members with it; it comes back whole, from a larger buffer
	 * the ledger is charged for, and the object is not broken.
	 */
	sx_obj_begin(sc);                 /* a new object: its limit is its own to count */
	sc->ledger.resident = 0;
	sc->ledger.resident_max = 64ull << 20;
	c.obj_size = 60000;
	c.resolve_scan = many_resolver;
	eb = kof_scan_ext_buf(sc, 0);
	held0 = sc->ledger.resident;
	hits0 = kof_scan_stats(sc)->limit_hits;
	CK(kof_scan_resolve_range(&c, 2u, eb) == 30000u && sc->obj.open.broken == 0 && sc->obj.open.cut == 0 &&
	   eb->v[29999].off == 59998u && eb->v != sc->cache.ext && eb->cap >= 30000u,
	   "30000 extents: all of them, from a larger buffer, the object not broken");
	CK(sc->ledger.resident > held0 && sc->ledger.resident - held0 == eb->charged &&
	   eb->charged == (uint64_t)eb->cap * sizeof *eb->v && kof_scan_stats(sc)->limit_hits == hits0,
	   "the larger buffer is charged to the ledger, byte for byte, and nothing was counted as cut");
	sx_ext_release(sc);
	CK(sc->ledger.resident == held0 && eb->v == sc->cache.ext && eb->cap == KOF_SCAN_MAX_EXTENTS && !eb->heap &&
	   !eb->charged, "released at the end of the object: the ledger back where it was, the buffer back to its floor");

	/* The ledger has no room for the larger buffer: the part that fits, and the object says it was cut. */
	sx_obj_begin(sc);
	sc->ledger.resident = 0;
	sc->ledger.resident_max = (uint64_t)KOF_SCAN_MAX_EXTENTS * sizeof *eb->v;     /* room for nothing more */
	CK(kof_scan_resolve_range(&c, 2u, eb) == KOF_SCAN_MAX_EXTENTS && sc->obj.open.cut == 1 && sc->obj.open.broken == 0 &&
	   kof_scan_stats(sc)->limit_hits == hits0 + 1u && !eb->heap,
	   "no room in the ledger: the buffer's worth, the object cut and counted - never silent, and not stopped");
	/* A region with more extents than the object has bytes cannot exist: the buffer never grows past n + 1. */
	sx_obj_begin(sc);
	sc->ledger.resident_max = 64ull << 20;
	c.obj_size = 5000;
	c.resolve_scan = fill_resolver;
	CK(kof_scan_resolve_range(&c, 2u, eb) <= 5001u && eb->cap <= 5001u, "growth stops at one extent a byte (%u)", eb->cap);
	sx_ext_release(sc);
	kof_scan_free(sc);
}

/* ---- diagnose state ------------------------------------------------------------------------ */

static void t_diag_state(void)
{
	struct kof_scanner *sc = kof_scan_new(eng);
	struct kof_obj_ctx c;
	struct kgenome_diag_scan g;
	struct kof_finding vf;
	int incomplete;
	uint32_t n = 99;

	CK(sc != NULL, "a scanner");
	if (!sc)
		return;
	memset(&c, 0, sizeof c);
	kof_mod_attach(&c, sc);

	CK(kof_scan_diag_status(&c) == KGENOME_OK && kof_scan_incomplete(&c) == 0, "a fresh object is whole");
	sc->obj.diag.status = KGENOME_NOMEM;
	CK(kof_scan_diag_status(&c) == KGENOME_NOMEM && kof_scan_incomplete(&c) == 1, "NOMEM with no graph: read from the object, incomplete");
	sc->obj.diag.status = KGENOME_OVER_BUDGET;
	CK(kof_scan_incomplete(&c) == 1, "OVER_BUDGET is incomplete");
	sc->obj.diag.status = KGENOME_TRUNCATED;
	sc->obj.diag.ask = 0;
	CK(kof_scan_incomplete(&c) == 0, "TRUNCATED when nothing asked for the analysis says nothing about the object");
	sc->obj.diag.ask = 1;
	CK(kof_scan_incomplete(&c) == 1, "TRUNCATED when an analysis was demanded: the graph stops short");

	/* the graph's own status, read live and not cached */
	memset(&g, 0, sizeof g);
	sc->obj.diag.graph = &g;
	sc->obj.diag.ask = 0;
	CK(kof_scan_diag_status(&c) == KGENOME_OK && kof_scan_incomplete(&c) == 0, "a graph that ran whole");
	kgenome_diag_note(&g, KGENOME_NOMEM);
	CK(kof_scan_diag_status(&c) == KGENOME_NOMEM && kof_scan_incomplete(&c) == 1,
	   "a status the graph noted AFTER the scan is seen at once");
	sc->obj.diag.graph = NULL;

	/* the verdict carries the same flag, whatever else it reads */
	memset(&vf, 0xee, sizeof vf);
	sc->obj.diag.status = KGENOME_NOMEM;
	(void)kof_scan_verdict(&c, &vf, &incomplete);
	CK(incomplete == 1, "kof_scan_verdict's incomplete follows kof_scan_incomplete");
	sc->obj.diag.status = KGENOME_OK;
	CK(kof_scan_verdict(&c, &vf, &incomplete) == 0 && incomplete == 0 && vf.n_disease == 0,
	   "no disease found: no verdict, whole (%u diseases)", vf.n_disease);

	/* drop gives the state back */
	sc->obj.diag.status = KGENOME_TRUNCATED;
	sc->obj.diag.refused = 3;
	kof_scan_diag_drop(sc);
	CK(sc->obj.diag.graph == NULL && sc->obj.diag.charged == 0 && sc->obj.diag.status == KGENOME_OK && sc->obj.diag.refused == 0,
	   "kof_scan_diag_drop leaves no graph, no charge, no status");
	kof_scan_diag_drop(sc);
	CK(kof_scan_diag_status(&c) == KGENOME_OK, "and twice is the same");

	CK(kof_scan_served_syms(&c, &n) == NULL && n == 0, "no symbols served on an object of no format");
	CK(kof_scan_served_syms(&c, NULL) == NULL, "n may be NULL");
	kof_scan_free(sc);
}

/* ---- the diagnose questions, asked of an object that is nothing ------------------------------ */

static int diag_nothing(void *arg)
{
	struct kof_scanner *sc = kof_scan_new(eng);
	struct kof_obj_ctx c, none;
	struct kof_diag_report rep;
	uint32_t n = 99, count, bad = 0;

	(void)arg;
	if (!sc)
		return 9;
	memset(&c, 0, sizeof c);
	memset(&none, 0, sizeof none);
	kof_mod_attach(&c, sc);
	none.priv = NULL;

	/* a context with no scanner behind it: every answer is "nothing" */
	bad += kof_scan_diag_sign_asks(&none) != 0;
	bad += kof_scan_diag_feeds_verdict(&none) != 0;
	bad += kof_scan_incomplete(&none) != 0;
	bad += kof_scan_diag_status(&none) != KGENOME_OK;
	bad += kof_scan_diag_count(&none) != 0;
	bad += kof_scan_diag_report(&none, 0, &rep) != 0;
	bad += kof_scan_served_syms(&none, &n) != NULL || n != 0;
	bad += kof_scan_emu_unpack(&none, 1) != 0;
	bad += kof_scan_script_forms(&none, 1) != 0;
	kof_scan_diag_force(&none);
	kof_scan_emu_release(NULL);
	if (bad)
		return 1;

	/* an object with no format: nothing asks, nothing feeds, nothing reports */
	count = kof_scan_diag_count(&c);
	bad += count != (eng->n_diag < sc->diag.cap ? eng->n_diag : sc->diag.cap);
	bad += kof_scan_diag_sign_asks(&c) != 0;
	bad += kof_scan_diag_feeds_verdict(&c) != 0;
	bad += kof_scan_diag_report(&c, count, &rep) != 0;          /* one past the end */
	bad += kof_scan_diag_report(&c, 0xffffffffu, &rep) != 0;
	bad += kof_scan_diag_report(&c, 0, NULL) != 0;
	sc->obj.diag.all = 0;
	bad += count && kof_scan_diag_report(&c, 0, &rep) != 0;     /* not asked for when the object began */
	if (bad)
		return 2;

	/* no source and no format: the emulator and the script pass attempt nothing */
	bad += kof_scan_emu_unpack(&c, 0) != 0;
	bad += kof_scan_emu_unpack(&c, 1) != 0;
	bad += kof_scan_script_forms(&c, 0) != 0;
	bad += kof_scan_script_forms(&c, 1) != 0;
	c.format = KOF_FMT_ELF;
	bad += kof_scan_emu_unpack(&c, 1) != 0;                      /* an ELF with no header and no source */
	c.format = KOF_FMT_SCRIPT;
	bad += kof_scan_script_forms(&c, 1) != 0;
	if (bad)
		return 3;
	kof_scan_emu_release(sc);
	kof_scan_emu_release(sc);
	if (sc->emu.live || sc->emu.n_rgn || sc->emu.held)
		return 4;
	kof_scan_free(sc);
	return 0;
}

/* ---- mutation units ------------------------------------------------------------------------- */

struct fixed_seen {
	uint64_t off, len;
	unsigned whole, straddle;
};

/* A unit that is exactly the fixed extent, and any that has an edge of it inside. */
static int fixed_cb(void *user, uint32_t region, uint64_t off, uint64_t len, uint32_t side,
		    const struct kgenome_func *first)
{
	struct fixed_seen *f = user;
	uint64_t end = off + len;

	(void)region; (void)side; (void)first;
	f->whole += off == f->off && len == f->len;
	f->straddle += (off < f->off && end > f->off) ||
		       (off < f->off + f->len && end > f->off + f->len);
	return 0;
}

struct units {
	unsigned n, stop_at;
	uint64_t sum, bad;
	uint64_t limit;
};

static int unit_cb(void *user, uint32_t region, uint64_t off, uint64_t len, uint32_t side,
		   const struct kgenome_func *first)
{
	struct units *u = user;

	(void)region; (void)side; (void)first;
	u->n++;
	u->sum += len;
	if (off + len > u->limit || off + len < off)
		u->bad++;
	return u->stop_at && u->n >= u->stop_at;
}

static void t_mutation_units(void)
{
	struct kof_scanner *sc = kof_scan_new(eng);
	struct kof_obj_ctx c;
	static uint8_t buf[8192];
	struct kof_range extv[KOF_SCAN_MAX_EXTENTS];
	struct kof_ext_buf ext = kof_ext_fixed(extv, KOF_SCAN_MAX_EXTENTS);
	struct units u;
	kof_buf b;
	unsigned i, all;

	CK(sc != NULL, "a scanner");
	if (!sc)
		return;
	for (i = 0; i < sizeof buf; i++)
		buf[i] = (uint8_t)((i * 2654435761u) >> 11);
	memset(&c, 0, sizeof c);
	kof_mod_attach(&c, sc);
	c.format = 0;                   /* nothing identified it: one region, ALL */
	c.obj_size = sizeof buf;
	b.p = buf;
	b.n = sizeof buf;
	memset(&u, 0, sizeof u);
	u.limit = sizeof buf;
	kof_scan_mutation_units(&c, b, 0xffffffffu, NULL, &ext, unit_cb, &u);
	CK(u.n > 0 && u.bad == 0 && u.sum <= sizeof buf, "units of a plain buffer: %u of them, %llu bytes, none outside", u.n,
	   (unsigned long long)u.sum);
	all = u.n;
	/*
	 * A SCRIPT THE LIB LEXES HAS NO REGIONS, AND STILL HAS UNITS. The format lists HEADER, BODY and MARKUP, and an
	 * object that resolves none of them is one region, ALL: walking the format's list over it fed the matcher
	 * nothing, and every block on a php or shell file would have stopped matching with no error anywhere.
	 */
	{
		static uint8_t text[6000];
		struct kof_script_info info;
		struct kof_obj_ctx s;
		static const char word[] = "$value=base64_decode($input);if(isset($_POST['x'])){eval($value);}\n";
		size_t k;

		memcpy(text, "<?php\n", 6);
		for (k = 6; k < sizeof text; k++)
			text[k] = (uint8_t)word[(k * 7u + k / 13u) % (sizeof word - 1u)];
		memset(&s, 0, sizeof s);
		kof_mod_attach(&s, sc);
		CK(kof_script_parse(kof_buf_make(text, sizeof text), &info, &s) == 1 && kof_obj_regionless(&s),
		   "a php file is a script the lib lexes, and has no region");
		memset(&u, 0, sizeof u);
		u.limit = sizeof text;
		b.p = text;
		b.n = sizeof text;
		kof_scan_mutation_units(&s, b, 0xffffffffu, NULL, &ext, unit_cb, &u);
		CK(u.n > 0 && u.bad == 0, "units of a script with no region: %u of them, none outside", u.n);
		b.p = buf;
		b.n = sizeof buf;
	}
	/* the cut that a producer made is given whole, and nothing is cut across it */
	{
		const struct kof_range fx = { 1000, 700 };
		const struct kof_scan_cut cut = { NULL, NULL, &fx, 1 };
		struct fixed_seen seen = { 1000, 700, 0, 0 };

		kof_scan_mutation_units(&c, b, 0xffffffffu, &cut, &ext, fixed_cb, &seen);
		CK(seen.whole == 1u && seen.straddle == 0u,
		   "a fixed extent is one unit (%u whole, %u across an edge)", seen.whole, seen.straddle);
	}
	/* the callback stopping the walk stops it */
	if (all > 1u) {
		memset(&u, 0, sizeof u);
		u.limit = sizeof buf;
		u.stop_at = 1;
		kof_scan_mutation_units(&c, b, 0xffffffffu, NULL, &ext, unit_cb, &u);
		CK(u.n == 1u, "a callback that answers non-zero ends the walk (%u of %u units)", u.n, all);
	}
	/* no bytes, no callback: nothing happens */
	memset(&u, 0, sizeof u);
	u.limit = sizeof buf;
	b.p = NULL;
	kof_scan_mutation_units(&c, b, 0xffffffffu, NULL, &ext, unit_cb, &u);
	b.p = buf;
	kof_scan_mutation_units(&c, b, 0xffffffffu, NULL, &ext, NULL, &u);
	CK(u.n == 0, "no buffer, or no callback: no unit");
	b.n = 0;
	kof_scan_mutation_units(&c, b, 0xffffffffu, NULL, &ext, unit_cb, &u);
	CK(u.n == 0 && u.bad == 0, "an empty buffer has no unit");

	/* the feed has nothing to credit to: refused before it reads anything */
	{
		struct kof_mutation_ctx pc;

		memset(&pc, 0, sizeof pc);
		b.p = buf;
		b.n = sizeof buf;
		kof_scan_mutation_feed(NULL, &c, b, 0xffffffffu, 0, NULL, &ext);
		kof_scan_mutation_feed(&pc, &c, b, 0xffffffffu, 0, NULL, &ext);
		kof_scan_mutation_feed(&pc, &c, b, 0xffffffffu, 1, NULL, &ext);
		CK(pc.set == NULL && pc.bs == NULL, "a feed to a context with no set changes nothing");
	}
	kof_scan_free(sc);
}

/*
 * Two slots of the content vtable that have no wrapper macro, called the way a module calls a slot: through
 * ctx->content. Both are asked of an object with no diagnoses and no similarity set; "no" is the answer, and not a fault.
 */
static int slots_without_macro(void *arg)
{
	struct kof_scanner *sc = kof_scan_new(eng);
	struct kof_obj_ctx c;
	int bad = 0;

	(void)arg;
	if (!sc)
		return 9;
	memset(&c, 0, sizeof c);
	kof_mod_attach(&c, sc);
	bad += c.content->reserved_0 != NULL || c.content->reserved_1 != NULL ||
	       c.content->reserved_2 != NULL;                      /* the slots nobody implements are NULL */
	if (c.content->diag_share) {
		bad += c.content->diag_share(&c, 1, 1, 2) != 0;     /* the 16 bit form: two diagnoses that do not exist */
		bad += c.content->diag_share(&c, 0xffff, 0xffff, 0xffff) != 0;
	}
	if (c.content->diag_share32)
		bad += c.content->diag_share32(&c, 1, 1u, 2u) != 0;
	kof_mod_unpack_mode(&c, 1);
	kof_scan_free(sc);
	return bad ? 1 : 0;
}

/* ---- the walk's decode count -------------------------------------------------------------------- */

static void t_prod_sync(void)
{
	struct kof_scanner *sc = kof_scan_new(eng);

	CK(sc != NULL, "a scanner");
	if (!sc)
		return;
	CK(sc->obj.diag.walk == NULL && sc->obj.prod_runs[KOF_PROD_WALK] == 0, "no walk, no run");
	kof_prod_sync_walk(sc);
	CK(sc->obj.prod_runs[KOF_PROD_WALK] == 0, "syncing with no walk records no run");
	kof_scan_free(sc);
}

int main(int argc, char **argv)
{
	struct he_status st;

	if (argc > 1)
		dbdir = argv[1];
	eng = keng_open(dbdir);
	if (!eng) {
		printf("scan_modctx: no database at %s - nothing tested\n", dbdir);
		return 0;
	}
	t_attach();
	t_ranges();
	t_diag_state();
	st = he_child(diag_nothing, NULL, 20);
	CK(he_ok(st), "the diagnose, emulate and script entries on an object that is nothing: %s", he_how(st));
	st = he_child(slots_without_macro, NULL, 20);
	CK(he_ok(st), "the reserved slots and diag_share asked of an object with nothing: %s", he_how(st));
	t_mutation_units();
	t_prod_sync();
	keng_close(eng);
	printf("scan_modctx: %u checks, %u failed\n", he_checks, he_fails);
	return he_fails != 0 || km_failed();
}
