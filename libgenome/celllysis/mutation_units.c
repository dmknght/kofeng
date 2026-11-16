/*
 * mutation_units.c - how an object is cut into the units a block is made from.
 *
 * ONE CUT, FOR THE TWO PEOPLE WHO NEED IT. A block is the sketch of one unit of
 * an object, and a scanner finds it by sketching the units of the object in
 * front of it. If the author's tool and the scanner cut differently the same
 * bytes would never meet, with no error anywhere - so the cut lives here and
 * both call it.
 *
 * A unit is one of:
 *   - a function of the function table (one unit per function: no grouping of
 *     neighbours, no minimum length - by_function), in a region that is offered
 *     a function at a time, and the clusters of strings among its bytes;
 *   - a piece of any other region, cut where the window hash has its low bits
 *     clear - see kgenome_mutation_cut - so the same bytes are cut in the same places
 *     whatever was inserted before them.
 * A machine-code function unit is cut and listed and carries NO signature (kgenome_mutation_signature:
 * CFG signing disabled by the owner 2026-11-15); a script's function, kind KGENOME_FN_SCRIPT, keeps a
 * window sketch like any other unit; every other unit has windows.
 * Each carries its side - see enum kgenome_mutation_side - and a unit never spans a
 * join between the author's code and the static library.
 */

#include "mutation.h"
#include "cfg.h"

#include <string.h>

#include <genotype/image/obj.h>
#include <genotype/image/elf_types.h>
#include <genotype/image/pe_types.h>

_Static_assert((unsigned)KGENOME_SCAN_ELF_CODE == (unsigned)KGENOME_SCAN_PE_CODE, "kgenome_mutation_block_min tests one bit for both formats");
/*
 * A script's region axis (KOF_SCAN_SCRIPT_HEADER/_BODY/_MARKUP, kofmod/script.h) is NEVER what a
 * script object actually carries here: kof_obj_regionless (kofformat.c) answers true for every
 * language the lib's own lexer reads - PHP included, the only one kgenome_script_funcs_build
 * knows - precisely BECAUSE the lexer already reads the whole text as one pass of code/string/
 * comment/markup bytes, and a cut along tags first would be a second reading of the same thing
 * (script_parse.c's own comment on script_resolve_scan says so). A regionless object has ONE
 * region, ALL (KOF_SCAN_ALL = 1u<<0 in kofmod/kofregion.h, a libkofeng header this lib must not
 * include - named here under its own value for the same reason NORM_CODE_MASK in the engine's
 * scan_int.h names ELF/PE's shared CODE bit under its own value rather than one format's name).
 * So the row below reads ALL, not BODY: BODY is unreachable for PHP and would be dead code. This
 * was found the hard way (2026-11-05): an earlier version of this row matched BODY, which never
 * fired, and a live run of kofexaminer --blocks on a real PHP file was the only thing that showed
 * it (the unit tests call kgenome_mutation_units directly and cannot see what mask the engine
 * actually resolves) - recorded as a reason the brief's own instruction to verify end to end, not
 * only in isolation, is not optional.
 */
#define KGENOME_MUTATION_ALL_BIT (1u << 0)

int kgenome_mutation_by_function(uint32_t format, uint32_t mask)
{
	return (format == KGENOME_FMT_ELF && mask == KGENOME_SCAN_ELF_CODE) ||
	       (format == KGENOME_FMT_PE && mask == KGENOME_SCAN_PE_CODE) ||
	       (format == KGENOME_FMT_SCRIPT && mask == KGENOME_MUTATION_ALL_BIT);
}

int kgenome_mutation_has_blocks(uint32_t format)
{
	return format == KGENOME_FMT_ELF || format == KGENOME_FMT_PE || format == KGENOME_FMT_SCRIPT;
}

/*
 * THE DECISION (owner 2026-11-15): a machine-code function unit is not signed. The CFG sketch it had (2026-10-30 .. 2026-11-15) is
 * disabled with every other CFG feature; the default for what the unit carries instead is NOTHING (listed, unsigned, scores nothing, the
 * reason KGENOME_MUTATION_SIG_NONE_WHY), and data units keep their window sketches.
 * TODO(owner): function units: window sketch (measured weak: exp_cfg/report.md, x86-64 5/60 pairs, 0 on other architectures) or another
 * signing method. DISABLED by the owner 2026-11-15 (the CFG sketch): to re-enable, this line answers KGENOME_MUTATION_SIG_CFG again and the
 * #if 0 blocks of the CFG signing are taken out (cfg_sign.c, cfg_anchor.c, analyzers/cfgsign.c, scan_feed.c mutation_feed_func, kofmutation.c
 * kof_mutation_cfg_unit, scan_explain.c func_hold, kofexaminer_blocks.c blk_func, kv_mutation.c mtn_mark).
 */
uint32_t kgenome_mutation_signature(const struct kgenome_func *first)
{
	return (first && first->kind != KGENOME_FN_SCRIPT) ? KGENOME_MUTATION_SIG_NONE : KGENOME_MUTATION_SIG_WINDOWS;
}

uint32_t kgenome_mutation_unit_minhash(const struct kgenome_func *first, const uint8_t *p,
				       uint64_t n, uint32_t *out)
{
	if (kgenome_mutation_signature(first) != KGENOME_MUTATION_SIG_WINDOWS)
		return 0;
	return kgenome_mutation_minhash(p, n, out);
}

/*
 * NOT A COLLISION, CHECKED: KOF_SCAN_ALL is bit 0, KGENOME_SCAN_ELF_CODE/PE_CODE is bit 2, so a
 * script's unit (always mask ALL - see kgenome_mutation_by_function above) never takes the CFG
 * floor below, function or not: it falls to KGENOME_MUTATION_MIN_HASH like every other windows
 * unit. A defect comment once lived here, written against an earlier version of this file where
 * scripts matched the CODE bit through a since-removed BODY row; that row is gone, the floor this
 * bit gives a windows unit is no longer reachable from a script, and the comment was deleted
 * rather than left to describe a path that no longer exists.
 */
uint32_t kgenome_mutation_block_min(uint32_t scan_mask)
{
	/* a block whose region is EXACTLY a function region (kgenome_mutation_by_function: CODE of an ELF or of a PE, one bit in both) may be a CFG block */
	return scan_mask == (unsigned)KGENOME_SCAN_ELF_CODE ? KGENOME_CFG_MIN_KEYS : KGENOME_MUTATION_MIN_HASH;
}

static int fn_in(const struct kof_range *ext, uint32_t n, const struct kgenome_func *f)
{
	uint32_t k;

	for (k = 0; k < n; k++)
		if (f->off >= ext[k].off && f->len <= ext[k].len &&
		    f->off - ext[k].off <= ext[k].len - f->len)
			return 1;
	return 0;
}

static int fn_lib(const struct kgenome_true_all *lib, const struct kgenome_func *f)
{
	return lib && kgenome_true_touches(lib, f->off, f->len);
}

/* A function-region walk. A function the library owns is not offered. Answers 1 when the
 * callback said stop, so the caller does not offer it anything else. */
/* ONE UNIT PER FUNCTION (owner, 2026-11-03: no fixed size for a function). The function table is the list of units: there is no minimum length, no
 * grouping of neighbours into one unit signed by its largest (that grouping, FN_MIN 64 / FN_GAP 32 / FN_GROUP 256 bytes, cost start recall: x86-64 64% -> 38%,
 * ARM 77% -> 42%, Mirai.b 100% -> 50%, exp_funcdet, agent-reported), and no cap on the number of units. Whether a function can be hashed is decided after the
 * decode, from its metadata (kof_cfgsign_function), and a unit that cannot is listed unsigned with the reason. `first` is the function itself. */
static int by_function(const struct kgenome_mutation_req *rq)
{
	struct kgenome_mutation_tally none;
	struct kgenome_mutation_tally *t = rq->tally ? rq->tally : &none;
	uint32_t i;

	memset(&none, 0, sizeof none);
	for (i = 0; rq->funcs && i < rq->funcs->n; i++) {
		const struct kgenome_func *f = &rq->funcs->v[i];

		t->funcs++;
		/* a function that is not wholly in this region is not this region's; a function the library owns is not the author's: both are COUNTED (FP-18), neither is offered */
		if (!fn_in(rq->ext, rq->n_ext, f)) {
			t->outside++;
			continue;
		}
		if (fn_lib(rq->lib, f)) {
			t->lib++;
			continue;
		}
		t->units++;
		if (rq->fn(rq->user, f->off, f->len, KGENOME_MUTATION_SIDE_USER, f))
			return 1;
	}
	return 0;
}

/*
 * DATA IN A CODE REGION. Most static IoT builds put .rodata in the executable
 * segment, so the region is "code" by its load flags and the author's strings
 * would be cut nowhere: functions are the only unit offered there. A data unit
 * is found from the bytes alone - no name, no section table, no gap arithmetic
 * - as a cluster of NUL-terminated printable strings with no more than STR_GAP
 * bytes between one and the next, so the binary tables that sit between strings
 * stay inside the block and the block weighs what the data weighs.
 *
 * The gap was measured, not chosen: on a static x64 bot whose .rodata is 15153
 * bytes, a gap of 4 cut its strings into 41 pieces of at most 3 KB and a gap of
 * 128 into 9 blocks of up to 4.4 KB. Small pieces defeat the similarity this is
 * for - each is scored alone, so a variant that moves one string loses a whole
 * piece - and the largest the gap can usefully be is where clusters stop
 * merging (128 and 256 gave the same nine).
 *
 * Code almost never holds four printable bytes and a NUL in a row, so a
 * cluster of STR_MIN bytes or more is data. It is not tied to a function, and
 * may overlap the tail of one that the entry walk left open.
 */
#define STR_RUN 4u
#define STR_GAP 128u
#define STR_MIN 64u

static int printable(uint8_t c)
{
	/* 0x20..0x7e as one unsigned compare, and the three controls (9, 10, 13) as bits of a
	 * constant: this is read once per byte of every region cut, and ran at 40 instructions a
	 * byte of code in the cluster search before. */
	return (uint8_t)(c - 0x20u) < 0x5fu || (c < 14u && (0x2600u >> c & 1u));
}

static uint64_t side_run(const struct kgenome_true_all *lib, uint64_t pos,
			 uint64_t end, uint32_t *side);

/*
 * A cluster is cut where it crosses a library boundary, like every other unit:
 * the string that sits in a data unit the library's span touches used to make
 * the whole cluster LIB, and a block cut from the author's side then scored 0
 * on the file that carries it (1 of 149 measured carriers).
 */
static int emit_cluster(uint64_t from, uint64_t to, const struct kgenome_true_all *lib,
			kgenome_mutation_unit_fn fn, void *user)
{
	while (from < to) {
		uint32_t side;
		uint64_t len = side_run(lib, from, to, &side);

		if (!len)
			break;
		if (len >= KGENOME_MUTATION_NG &&
		    fn(user, from, len, side, NULL))
			return 1;
		from += len;
	}
	return 0;
}

/* The next printable run closed by a NUL at or after `pos`. Found from the NUL, which is the rarer
 * byte: the search is a memchr and the run is read backwards from it. */
static int next_string(const uint8_t *p, uint64_t pos, uint64_t end,
		       uint64_t *s, uint64_t *e)
{
	while (pos < end) {
		const uint8_t *z = memchr(p + pos, 0, (size_t)(end - pos));
		uint64_t q, from;

		if (!z)
			return 0;
		q = (uint64_t)(z - p);
		for (from = q; from > pos && printable(p[from - 1u]); from--)
			;
		if (q - from >= STR_RUN) {
			*s = from;
			*e = q + 1u;
			return 1;
		}
		pos = q + 1u;
	}
	return 0;
}

/* The next cluster of strings at or after `pos`: whole strings, each within
 * STR_GAP of the one before, at least STR_MIN bytes. A string that would pass
 * the size cap opens the next cluster, so no string is ever cut. */
static int next_cluster(const uint8_t *p, uint64_t pos, uint64_t end,
			uint64_t *from, uint64_t *to)
{
	uint64_t s, e;

	while (next_string(p, pos, end, &s, &e)) {
		*from = s;
		*to = e;
		while (next_string(p, *to, end, &s, &e) &&
		       s - *to <= STR_GAP &&
		       e - *from <= KGENOME_MUTATION_SEG_AVG * 4u)
			*to = e;
		if (*to - *from >= STR_MIN)
			return 1;
		pos = *to;
	}
	return 0;
}

/* How far from `pos` the side stays the same, and which side it is. */
static uint64_t side_run(const struct kgenome_true_all *lib, uint64_t pos,
			 uint64_t end, uint32_t *side)
{
	uint64_t next = end;
	uint32_t i;

	*side = KGENOME_MUTATION_SIDE_USER;
	for (i = 0; lib && i < lib->n; i++) {
		uint64_t a = lib->span[i].off;
		uint64_t b = a + lib->span[i].len;

		if (pos >= a && pos < b) {
			*side = KGENOME_MUTATION_SIDE_LIB;
			return (b < end ? b : end) - pos;
		}
		if (a > pos && a < next)
			next = a;
	}
	return next - pos;
}

struct cut_ctx {
	kgenome_mutation_unit_fn fn;
	void *user;
	uint64_t off;
	uint32_t side;
	int stopped;
};

static int cut_piece(void *user, uint64_t from, uint64_t to)
{
	struct cut_ctx *c = user;

	c->stopped = c->fn(c->user, c->off + from, to - from, c->side, NULL) != 0;
	return c->stopped;
}

/* Cut [from, to) by content, apart at library joins so no unit spans one. A
 * short run is still a unit: whether it can be scored is a count of hashes,
 * and is decided where the block is made. */
static int cut_span(const uint8_t *p, uint64_t from, uint64_t to,
		    const struct kgenome_true_all *lib, kgenome_mutation_unit_fn fn,
		    void *user)
{
	while (from < to) {
		struct cut_ctx c;
		uint64_t len;

		c.fn = fn; c.user = user; c.off = from; c.stopped = 0;
		len = side_run(lib, from, to, &c.side);
		if (!len)
			break;
		kgenome_mutation_cut(p + from, len, KGENOME_MUTATION_SEG_AVG,
			       KGENOME_MUTATION_SEG_AVG / 4u,
			       KGENOME_MUTATION_SEG_AVG * 4u, cut_piece, &c);
		if (c.stopped)
			return 1;
		from += len;
	}
	return 0;
}

/*
 * [pos, end) of one extent as strings, and - when `pieces` - what lies between them by
 * content. A region offered a function at a time keeps only the strings: its other
 * bytes are instructions, which the functions already cover.
 */
static int cut_bytes(const struct kgenome_mutation_req *rq, uint64_t pos, uint64_t end,
		     int pieces)
{
	uint64_t from, to;

	for (; pos < end; pos = to) {
		if (!next_cluster(rq->p, pos, end, &from, &to))
			from = to = end;
		if ((pieces && cut_span(rq->p, pos, from, rq->lib, rq->fn, rq->user)) ||
		    (to > from && emit_cluster(from, to, rq->lib, rq->fn, rq->user)))
			return 1;
	}
	return 0;
}

/*
 * THE BYTES OF A REGION, WITH THE FIXED UNITS LEFT WHOLE.
 *
 * A fixed extent is one unit whatever its bytes say, and the cut is told where
 * the unit is instead of finding it: only what lies between fixed units is cut
 * by what it holds. A view needs this for what its decode rewrote. A string
 * cluster is found from printable bytes and a NUL, and a payload that came out
 * of a decode is not printable - on the sample this was measured on, cutting the
 * decoded view again gave 21 clusters where the parent's cut gave 16, and one
 * 6656 byte cluster of the parent came back as pieces of 626, 602, 452 and 302. The
 * view's units are the parent's, hashed over what the view holds.
 */
static int by_bytes(const struct kgenome_mutation_req *rq, int pieces)
{
	uint32_t k, f = 0;

	for (k = 0; k < rq->n_ext; k++) {
		uint64_t pos = rq->ext[k].off, end;

		if (pos >= rq->n_obj)
			continue;
		end = rq->ext[k].len > rq->n_obj - pos ? rq->n_obj : pos + rq->ext[k].len;
		while (pos < end) {
			uint64_t lim = end, ue;

			while (f < rq->n_fixed && rq->fixed[f].off + rq->fixed[f].len <= pos)
				f++;
			if (f < rq->n_fixed && rq->fixed[f].off < end)
				lim = rq->fixed[f].off > pos ? rq->fixed[f].off : pos;
			if (lim > pos) {
				if (cut_bytes(rq, pos, lim, pieces))
					return 1;
				pos = lim;
				continue;
			}
			ue = rq->fixed[f].off + rq->fixed[f].len;
			if (ue > end)
				ue = end;
			if (emit_cluster(pos, ue, rq->lib, rq->fn, rq->user))
				return 1;
			pos = ue;
		}
	}
	return 0;
}

/*
 * SCRIPTS: WHAT IS NOT A FUNCTION IS STILL REAL CODE, so by_function's by_bytes(rq, 0) fallback -
 * right for ELF/PE, where a CODE region's leftover bytes are "instructions the functions already
 * cover" and only its string clusters are worth a unit - is wrong here: a webshell's whole body is
 * routinely ONE top-level statement with no function at all (`<?php system($_GET['c']); ?>`), and
 * even a file that does declare functions usually has top-level code around them. That code keeps
 * the ordinary content-defined cut, so this walks the region exactly as by_bytes does but treats
 * each function's span as a GAP TO SKIP, not a fixed-and-re-EMIT extent (by_bytes's own `fixed`
 * does the latter - right for a view's decoded blob, which by_function never also offered; wrong
 * here, where by_function has ALREADY emitted the function with its real kgenome_func, and a second
 * emission over the identical bytes with first NULL would be the same bytes scored as two units).
 */
static int script_remainder(const struct kgenome_mutation_req *rq)
{
	uint32_t k;

	for (k = 0; k < rq->n_ext; k++) {
		uint64_t pos = rq->ext[k].off, end;
		uint32_t f = 0;

		if (pos >= rq->n_obj)
			continue;
		end = rq->ext[k].len > rq->n_obj - pos ? rq->n_obj : pos + rq->ext[k].len;
		while (pos < end) {
			uint64_t lim = end;

			while (rq->funcs && f < rq->funcs->n &&
			       (rq->funcs->v[f].off + rq->funcs->v[f].len <= pos ||
				!fn_in(rq->ext, rq->n_ext, &rq->funcs->v[f]) ||
				fn_lib(rq->lib, &rq->funcs->v[f])))
				f++;
			if (rq->funcs && f < rq->funcs->n && rq->funcs->v[f].off < end)
				lim = rq->funcs->v[f].off > pos ? rq->funcs->v[f].off : pos;
			if (lim > pos) {
				if (cut_bytes(rq, pos, lim, 1))
					return 1;
				pos = lim;
				continue;
			}
			pos = rq->funcs->v[f].off + rq->funcs->v[f].len;       /* a function's own span: by_function already offered it, skip with no emission */
		}
	}
	return 0;
}

void kgenome_mutation_units(const struct kgenome_mutation_req *rq)
{
	if (!rq->p || !rq->fn)
		return;
	if (kgenome_mutation_by_function(rq->format, rq->mask)) {
		if (by_function(rq))
			return;
		if (rq->format == KGENOME_FMT_SCRIPT)
			script_remainder(rq);
		else
			by_bytes(rq, 0);
		return;
	}
	by_bytes(rq, 1);
}
