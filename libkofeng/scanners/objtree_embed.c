/*
 * objtree_embed.c - the objects an executable holds in its own variables, opened as children.
 *
 * WHAT THIS IS: the third source of a child (objtree.h has the other two: DECLARED by a container's
 * structure, and the carves a module makes). An ELF or PE can carry a payload as DATA - a byte array
 * compiled into a variable - and the program reaches it through a pointer or through the symbol of
 * the variable. The owner's rule (2026-11-03): when a variable's data starts with a format header at
 * its offset 0, running the sniff chain on that data succeeds, so the engine's object walk does it;
 * there is no module that searches and no second recogniser. The measurement is in
 * IMPROVE embed-sniff-1 (scan_walk.c) and its numbers are the reason for each choice below.
 *
 * THE CANDIDATES are computed once per object by the lib (kgenome_image_embed_starts: the target of
 * each pointer word in the host's data, the start of each sized OBJECT symbol), sorted and without
 * duplicates. Each one is offered to the chain (kof_parser_embedded: the rows that offer a variable,
 * each with its second check), and an accepted one becomes a window child of kind EMBEDDED, so it
 * re-enters the pipeline like any child.
 *
 * WHERE THE CANDIDATES MAY START: the host's data as the measurement defined it (kgenome_image_embed_spans:
 * loaded bytes that are not executable, the sections correcting the segments - not the engine's DATA region,
 * which is the PT_LOAD without X and so leaves .rodata inside an R-X segment out; the Mirai arrays of ELF
 * headers are in it). A host whose image has NO data at all - one RWX segment, a dump, a packed static
 * binary with its sections gone: 35 hosts and 329 of the 2159 real objects in the measurement sat in
 * CODE, all in hosts with nothing else - is read through its code instead, because for it that IS the data. Not the overlay and not the file's tail: those are the carve
 * modules' (bases/decomp/appended_00.c, overlay.c).
 *
 * THE VALUE OF A VARIABLE IS READ BY A GATE, THEN DECODED BY THE DECODER THE GATE NAMED (owner, 2026-11-03):
 * the first 8 bytes of the candidate are read once (embed_gate) and say which KIND of value it is -
 * escape text (`\\xNN`), hex text, base64 text, or anything else, which is a plain header (the chain,
 * kof_parser_embedded) and, when that refuses, a header written under an XOR key. A text kind is
 * decoded by kuncoat's transform (the one the normaliser's decoders call) and the decoded bytes go to
 * the SAME second check; the XOR kind derives its key from the header it must be (known plaintext:
 * key = first bytes ^ the magic, one candidate a magic and no loop over keys), peeks 64 decoded bytes
 * through the cipher the engine already runs for a module (oc_capsid_apply, kof_capsid), and goes on
 * only when the full header validation (kgenome_elf_hdr_valid) passes on them. So a random match of
 * the first bytes is never a child: every kind ends in the same check, and a kind that decodes to
 * nothing the chain accepts costs the decode and no child. A decoded value is a child of its own
 * bytes (oc_emit_all, oc_child, or oc_decrypt for the cipher), with its extent from its header.
 *
 * WHAT THE MODULE ABI CANNOT EXPRESS, so this stays in the host (nothing under bases/ is added): a
 * module gets the object and a window of it, and decodes a range through kunp_unpack (a KOF_UNP_*
 * method) or kunp_decrypt (a capsid); there is no method for base64 or for `\\xNN` runs (only
 * HEXTEXT, ASCIIHEX, ASCII85 and RUNLENGTH exist), no way to hand the module a candidate and have it
 * answer "this variable is a <format>", and a module's output is a whole child, never a verdict on
 * a peek. A module for it would need those three, and adding one changes the pack's bytes: an owner
 * decision. The XOR magic is the one spelling kgenome_elf_magic gives; a second format enters the
 * gate by naming its magic in `xor_magics`, which is a line and not a table of formats.
 *
 * THE OVERLAP RULE: a candidate that starts inside the extent of one already accepted is not
 * offered (51 of 2159 real objects were nested; the nested one is found when the outer object is
 * scanned as a child, where its own data is the host's). The extent comes from the format's own
 * header (ELF: the union of its headers, segments and sections; PE: up to the overlay; zip: the end
 * record; gzip: the trailer; script: the NUL of its string). A format with no extent ends at the next
 * accepted start or the end of its data span, and covers only its own first byte.
 *
 * EVERY BOUND HERE IS A COST AND IS SAID:
 *   - the candidate table grows with the candidates (a few percent of the words of the data) and is charged to
 *     the scan's ledger as it grows; when the ledger cannot give the next step the walk stops and the
 *     object is cut (oc_scan_limit);
 *   - the checks' work (header steps, inflated bytes, the scan for a script's NUL) is allowed
 *     4 steps per data byte and at least KOF_EMBED_WORK_MIN, the same shape as every other work bound of
 *     the tree (sized from the object, a floor for a small one); spent, the rest of the candidates
 *     are not examined and the object is cut;
 *   - the children are the tree's: no more are accepted than the child quota that is left, and one
 *     more than that is the sticky LIMIT every producer reports (oc_scan_broken).
 *
 * Offset 0 is never a candidate: a pointer to the image base, in a host read through its CODE,
 * would make the host its own child.
 */

#define _GNU_SOURCE

#include "objtree.h"
#include "scan_int.h"
#include "objctx_int.h"
#include "objsrc.h"
#include <kofmod/elf.h>
#include <kofmod/pe.h>
#include <kofmod/kofdecode.h>
#include <genotype/image/image_embed.h>
#include <genotype/image/elf_image.h>
#include <uncoat.h>
#include "../analyzers/genome_obj.h"
#include "../analyzers/parsers/kofformat.h"
#include <kofcmp.h>
#include <stdlib.h>
#include <string.h>

/* The floor of the checks' allowance, for a host whose data is smaller than a header. */
#define KOF_EMBED_WORK_MIN 4096u
#define KOF_EMBED_WORK_PER_BYTE 4u

/* The fewest characters a text value is worth decoding: a gzip header, one stored block and its trailer is 23 bytes, which is
 * 32 characters of base64; nothing the chain offers is smaller, and a run shorter than this is a word. */
#define KOF_EMBED_TEXT_MIN 32u

/* What the gate says a value is. */
enum embed_kind { EK_PLAIN = 0, EK_ESCAPE, EK_HEX, EK_B64, EK_XOR };

struct accepted {
	uint64_t off;
	uint64_t ext;       /* the child's length when its header says (0: the next accepted start or the span's end) */
	uint64_t src;       /* the bytes of the host the value occupies (an encoded value: its text; else = ext) */
	uint8_t  fmt;
	uint8_t  kind;      /* enum embed_kind */
	uint8_t  sep;       /* escape: the separator byte */
	uint8_t  key[4];    /* xor: the repeating key */
};

/* ---- tables that grow with what is put in them, charged to the ledger as they do ---- */

struct tab {
	struct kof_scanner *sc;
	void     *v;
	uint64_t  n, cap, charged;
	size_t    esz;
};

/* Room for `want` entries; 0 when the ledger would not hold them. */
static int tab_reserve(struct tab *t, uint64_t want)
{
	uint64_t nc = t->cap ? t->cap : 256u, delta;
	void *nv;

	if (want <= t->cap)
		return 1;
	while (nc < want)
		nc *= 2u;
	delta = (nc - t->cap) * t->esz;
	if (delta > oc_scan_room(t->sc) / 2u)
		return 0;
	nv = realloc(t->v, (size_t)(nc * t->esz));
	if (!nv)
		return 0;
	scan_charge(t->sc, delta);
	t->charged += delta;
	t->v = nv;
	t->cap = nc;
	return 1;
}

static int tab_add(struct tab *t, const void *e)
{
	if (!tab_reserve(t, t->n + 1u))
		return 0;
	memcpy((uint8_t *)t->v + t->n * t->esz, e, t->esz);
	t->n++;
	return 1;
}

static void tab_free(struct tab *t)
{
	free(t->v);
	oc_scan_release(t->sc, t->charged);
	memset(t, 0, sizeof *t);
}

/* The data spans of the host, as the lib defines them, in a table sized to them. */
static uint32_t data_spans(struct kof_scanner *sc, const struct kgenome_obj *obj, kof_buf file,
			   struct kgenome_embed_span **spans, uint64_t *bytes, uint64_t *charged)
{
	struct kgenome_embed_span tmp[KGENOME_EMBED_SPANS_MAX];
	uint32_t n, i;

	*spans = NULL;
	*bytes = 0;
	n = kgenome_image_embed_spans(obj, file, tmp);
	if (!n || (uint64_t)n * sizeof **spans > oc_scan_room(sc))
		return 0;
	*spans = malloc((size_t)n * sizeof **spans);
	if (!*spans)
		return 0;
	scan_charge(sc, (uint64_t)n * sizeof **spans);
	*charged += (uint64_t)n * sizeof **spans;
	memcpy(*spans, tmp, (size_t)n * sizeof **spans);
	for (i = 0; i < n; i++)
		*bytes += tmp[i].len;
	return n;
}

/* Where the data span holding `off` ends, or `limit` when none does. */
static uint64_t span_end_at(const struct kgenome_embed_span *sp, uint32_t n, uint64_t off, uint64_t limit)
{
	uint32_t i;

	for (i = 0; i < n; i++)
		if (off >= sp[i].off && off - sp[i].off < sp[i].len)
			return sp[i].off + sp[i].len < limit ? sp[i].off + sp[i].len : limit;
	return limit;
}

/* ---- the gate: the first bytes of a value, read once ---- */

struct embed_gate {
	uint8_t  b[8];
	unsigned n;         /* bytes read: 8, or fewer at the end of the object */
	uint8_t  kind;      /* enum embed_kind: a text kind, or EK_PLAIN for everything else */
	uint8_t  sep;       /* escape: b[0] */
};

static int is_hex(unsigned c)
{
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static int is_b64(unsigned c)
{
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/';
}

/*
 * Reads the first 8 bytes once and decides the kind. A text kind is recognised by byte tests only (no
 * regex): `\xNN` or `/xNN` for the escape coding, eight hex digits, eight base64 characters. The text kinds
 * and a binary header cannot be the same bytes - no header of a format offered in data is eight
 * characters of an alphabet and none begins with a backslash and an `x` - so a text kind skips
 * the plain check and the key. Anything else is EK_PLAIN, and the caller goes on to the chain and the key.
 */
static void embed_gate(kof_buf v, struct embed_gate *g)
{
	unsigned i, hex = 1, b64 = 1;

	g->n = v.n < sizeof g->b ? (unsigned)v.n : (unsigned)sizeof g->b;
	memcpy(g->b, v.p, g->n);
	g->kind = EK_PLAIN;
	g->sep = 0;
	if (g->n >= 4 && (g->b[0] == '\\' || g->b[0] == '/') && g->b[1] == 'x' && is_hex(g->b[2]) && is_hex(g->b[3])) {
		g->kind = EK_ESCAPE;
		g->sep = g->b[0];
		return;
	}
	if (g->n < sizeof g->b)
		return;
	for (i = 0; i < sizeof g->b; i++) {
		hex = hex && is_hex(g->b[i]);
		b64 = b64 && is_b64(g->b[i]);
	}
	if (hex)
		g->kind = EK_HEX;
	else if (b64)
		g->kind = EK_B64;
}

/* The magics a header written under an XOR key is looked for by: the key follows from the first bytes. */
static const struct { const uint8_t *magic; unsigned n; } xor_magics[] = {
	{ kgenome_elf_magic, 4 }
};

/* Is `c` a character of the alphabet the kind's text is written in: the byte before a candidate that is one means the candidate is
 * the middle of a run, not where a variable starts. */
static int in_alphabet(uint8_t kind, unsigned c)
{
	return kind == EK_B64 ? is_b64(c) : is_hex(c);
}

/* The bytes of a text value the host holds: the run of its alphabet from `v`, and how it ends. */
static uint64_t text_run(kof_buf v, const struct embed_gate *g)
{
	uint64_t n = 0;

	switch (g->kind) {
	case EK_ESCAPE:
		while (n + 4u <= v.n && v.p[n] == g->sep && v.p[n + 1u] == 'x' && is_hex(v.p[n + 2u]) && is_hex(v.p[n + 3u]))
			n += 4u;
		return n;
	case EK_HEX:
		while (n < v.n && is_hex(v.p[n]))
			n++;
		return n & ~(uint64_t)1u;
	case EK_B64:
		while (n < v.n && is_b64(v.p[n]))
			n++;
		while (n < v.n && v.p[n] == '=')
			if (++n % 4u == 0)
				break;
		return n;
	default:
		return 0;
	}
}

/* ---- the dispatch: the decoder a kind names, into `out`; the bytes it wrote (0: not decoded whole) ---- */

struct scratch {
	struct tab t;       /* bytes */
};

static uint8_t *scratch_get(struct scratch *s, uint64_t n)
{
	return tab_reserve(&s->t, n) ? s->t.v : NULL;
}

static uint64_t decode_text(const struct embed_gate *g, kof_buf v, uint64_t src, uint8_t *out, uint64_t cap)
{
	struct kuncoat_step st = { .algo = 0, .dir = KUNCOAT_DECODE, .flags = 0, .k32 = 0, .k32b = 0, .key = NULL,
				   .key_len = 0, .max_out = 0 };
	uint64_t got = 0;

	switch (g->kind) {
	case EK_ESCAPE: st.algo = KUNCOAT_ALGO_ESCAPE; st.k32 = g->sep; break;
	case EK_HEX:    st.algo = KUNCOAT_ALGO_HEX; st.flags = KUNCOAT_F_STRICT; break;
	case EK_B64:    st.algo = KUNCOAT_ALGO_B64; break;
	default:        return 0;
	}
	if (kuncoat_transform(&st, v.p, src, out, cap, &got) != KUNCOAT_OK)
		return 0;
	return got;
}

/* The key a header written under XOR would have, one candidate a magic: written into `key` (4 bytes). 0 when the bytes already are
 * the magic (no coding) or too few were read; else the 8 bytes decoded under it are in `id`, which the caller asks the
 * format whether they could start a header (the cheap half of the check, 8 xors) before anything else is decoded. */
static unsigned xor_key_of(const struct embed_gate *g, unsigned m, uint8_t key[4], uint8_t id[8])
{
	unsigned i, plain = 1;

	if (g->n < sizeof g->b)
		return 0;
	for (i = 0; i < 4u; i++) {
		key[i] = (uint8_t)(g->b[i] ^ xor_magics[m].magic[i]);
		plain = plain && !key[i];
	}
	for (i = 0; i < 8u; i++)
		id[i] = (uint8_t)(g->b[i] ^ key[i & 3u]);
	return plain ? 0u : xor_magics[m].n;
}

static void capsid_of(struct kof_capsid *c, const uint8_t key[4])
{
	c->algo = KOF_CAPSID_XOR_KEY;
	c->k32 = 0;
	c->key = key;
	c->key_len = 4;
	c->max_out = 0;
}

/* The header probe of a keyed value: the first 64 bytes decoded, and the full header validation on them. */
static int xor_probe(const struct kof_capsid *c, kof_buf v)
{
	uint8_t head[64];
	uint32_t got;

	if (v.n < sizeof head)
		return 0;
	got = oc_capsid_apply(c, v.p, (uint32_t)sizeof head, head, (uint32_t)sizeof head);
	return got == sizeof head && kgenome_elf_hdr_valid(kof_buf_make(head, got));
}

/*
 * THE DECISION FOR ONE CANDIDATE, taken when the lib emits it (so a candidate that is nothing is never stored, sorted or
 * looked at again: the clean host has 12.7 thousand of them a MB and no table of them). The gate reads the first 8 bytes once;
 * a text kind is decoded by the decoder it names; anything else goes to the chain and, when that refuses, to the key.
 * An accepted one is a record of what it is and where it ends.
 */
struct embedder {
	struct kof_scanner *sc;
	const struct kof_obj_ctx *ctx;
	kof_buf file;
	const struct kgenome_embed_span *spans;
	uint32_t nspan;
	uint64_t work;      /* what the checks may still spend; at zero the walk stops and the object is cut */
	struct tab acc;     /* struct accepted: first member `off`, so kof_cmp_u64 sorts it */
	struct scratch scr;
	int limit;          /* a bound ended the walk */
};

static int emit_cand(void *user, uint64_t off)
{
	struct embedder *em = user;
	struct embed_gate g;
	struct accepted a;
	kof_buf v;

	if (!off)
		return 1;
	if (!em->work) {
		em->limit = 1;
		return 0;
	}
	memset(&a, 0, sizeof a);
	v = kof_slice(em->file, off, em->file.n - off);
	embed_gate(v, &g);
	a.off = off;
	a.kind = g.kind;
	a.sep = g.sep;
	if (g.kind != EK_PLAIN) {
		/* a text kind: decode its run with the decoder the gate named, then the same second check */
		uint64_t rest = span_end_at(em->spans, em->nspan, off, em->file.n) - off;
		uint64_t room = rest < em->work ? rest : em->work, src, got, ext = 0;
		uint8_t *buf, fmt = 0;

		/* the run is read within the allowance and what is read is spent, so a table of pointers into
		 * one long run of an alphabet cannot make every candidate walk it again */
		/* a pointer into the middle of a run is not where a variable starts: the pointers into one long blob of an
		 * alphabet are all but one of them refused here, for the price of a byte */
		if (off && in_alphabet(g.kind, em->file.p[off - 1u]))
			return 1;
		src = text_run(kof_slice(v, 0, room), &g);
		em->work -= src < em->work ? src : em->work;
		if (src < KOF_EMBED_TEXT_MIN)
			return 1;
		if ((src == room && room < rest) || src > em->work) {
			em->limit = 1;      /* the allowance ended inside the run: it is not read whole */
			return 0;
		}
		em->work -= src;
		buf = scratch_get(&em->scr, src);
		if (!buf) {
			em->limit = 1;
			return 0;
		}
		got = decode_text(&g, v, src, buf, src);
		if (!got || !kof_parser_embedded(kof_buf_make(buf, got), &fmt, &ext, &em->work))
			return 1;
		a.fmt = fmt;
		a.ext = ext ? ext : got;
		a.src = src;
	} else if (kof_parser_embedded(v, &a.fmt, &a.ext, &em->work)) {
		a.src = a.ext;
	} else {
		/* neither a header nor a text kind: a header under a key the first bytes give */
		struct kof_capsid c;
		uint64_t ext = 0, win, got;
		uint8_t fmt = 0, *buf, id[8];
		unsigned m;

		for (m = 0; m < sizeof xor_magics / sizeof xor_magics[0]; m++) {
			if (!xor_key_of(&g, m, a.key, id) || !kgenome_elf_ident_valid(id))
				continue;
			capsid_of(&c, a.key);
			if (!xor_probe(&c, v))
				continue;
			win = span_end_at(em->spans, em->nspan, off, em->file.n) - off;
			if (win > em->work)
				win = em->work;
			buf = scratch_get(&em->scr, win);
			if (!buf) {
				em->limit = 1;
				return 0;
			}
			em->work -= win;
			got = oc_decrypt_peek(em->ctx, &c, off, win, buf, (uint32_t)win);
			if (got == win && kof_parser_embedded(kof_buf_make(buf, got), &fmt, &ext, &em->work)) {
				a.kind = EK_XOR;
				a.fmt = fmt;
				a.ext = ext ? ext : got;
				a.src = a.ext;
			}
			break;
		}
		if (a.kind != EK_XOR)
			return 1;
	}
	if (!tab_add(&em->acc, &a)) {
		em->limit = 1;
		return 0;
	}
	return 1;
}

uint32_t kof_objtree_embedded(const struct kof_obj_ctx *ctx, const struct kof_scan_option *opt)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	struct kgenome_embed_span *spans = NULL;
	struct kgenome_embed_req rq;
	struct kgenome_embed_res rs;
	struct kgenome_obj obj;
	struct embedder em;
	struct accepted *av;
	uint64_t bytes, covered = 0, spans_charged = 0, i, r;
	uint32_t nspan, made = 0, j;
	int over = 0;
	kof_buf file;

	if (!sc || !kof_objtree_may_open(opt) || !oc_can_produce(sc))
		return 0;
	if (ctx->format != KOF_FMT_ELF && ctx->format != KOF_FMT_PE)
		return 0;
	if (!ctx->file_header || !ctx->content || !ctx->content->window)
		return 0;
	if (ctx->format == KOF_FMT_ELF ? !kof_elf(ctx)->valid : !kof_pe(ctx)->valid)
		return 0;
	/* A view is not opened, only matched: what it holds was found in the object it came from. */
	if (kof_src_kind_of(sc->cur.src) == KOF_ENT_NORMALIZED)
		return 0;
	file = kof_src_buf(sc->cur.src);

	memset(&em, 0, sizeof em);
	em.sc = sc;
	em.ctx = ctx;
	em.file = file;
	em.acc = (struct tab){ sc, NULL, 0, 0, 0, sizeof(struct accepted) };
	em.scr.t = (struct tab){ sc, NULL, 0, 0, 0, 1 };
	kof_genome_obj(ctx, &obj);
	nspan = data_spans(sc, &obj, file, &spans, &bytes, &spans_charged);
	if (!nspan || !bytes)
		goto out;
	em.spans = spans;
	em.nspan = nspan;
	em.work = bytes * KOF_EMBED_WORK_PER_BYTE;
	if (em.work < KOF_EMBED_WORK_MIN)
		em.work = KOF_EMBED_WORK_MIN;
	memset(&rq, 0, sizeof rq);
	rq.obj = &obj;
	rq.file = file;
	rq.data = spans;
	rq.n_data = nspan;
	rq.flags = KGENOME_EMBED_SYMBOLS;
	rq.emit = emit_cand;
	rq.user = &em;
	kgenome_image_embed_starts(&rq, &rs);
	/* a bound ended the walk (the allowance, a table the ledger would not grow): the object is cut, said once */
	if (em.limit || kgenome_status_is_cut(rs.status))
		oc_scan_limit(sc);
	if (!em.acc.n)
		goto out;

	/* what was accepted, in file order and once each (a pointer stored twice names one place), then the overlap
	 * rule and the tree's quota */
	av = em.acc.v;
	qsort(av, (size_t)em.acc.n, sizeof *av, kof_cmp_u64);
	for (i = 0, r = 0; i < em.acc.n; i++) {
		if (r && av[r - 1].off == av[i].off)
			continue;
		if (av[i].off < covered)
			continue;
		/* at most as many as the tree may still take (its quota); the next one is the sticky limit a
		 * refused child says, said after the ones it does take are made */
		if (r >= sc->ledger.kids_left) {
			over = 1;
			break;
		}
		av[r++] = av[i];
		covered = av[i].off + (av[i].src ? av[i].src : 1u);
	}
	em.acc.n = r;
	for (j = 0; j < em.acc.n; j++) {
		struct accepted a = av[j];
		uint64_t len = a.ext;
		int ok = 1;

		/* an object of a format with no extent of its own ends at the next accepted start or its span's end */
		if (a.kind == EK_PLAIN && !len) {
			uint64_t lim = j + 1u < em.acc.n ? av[j + 1u].off : file.n;

			len = span_end_at(spans, nspan, a.off, lim) - a.off;
		}
		if (!len)
			continue;
		/* unnamed, of kind EMBEDDED: the child's name is what the kind says */
		if (ctx->content->name_next)
			ctx->content->name_next(ctx, 0, 0);
		if (ctx->content->child_kind)
			ctx->content->child_kind(ctx, KOF_ENT_EMBEDDED);
		if (a.kind == EK_PLAIN) {
			ok = ctx->content->window(ctx, a.off, len) != 0;      /* refused: its producer has said why */
		} else if (a.kind == EK_XOR) {
			struct kof_capsid c;

			capsid_of(&c, a.key);
			ok = oc_decrypt(ctx, &c, a.off, len) == len && oc_child(ctx);
		} else {
			struct embed_gate g;
			uint64_t got;
			uint8_t *buf = scratch_get(&em.scr, a.src);
			kof_buf v = kof_slice(file, a.off, a.src);

			embed_gate(v, &g);
			got = buf ? decode_text(&g, v, a.src, buf, a.src) : 0;
			ok = got >= len && oc_emit_exact(ctx, buf, len) && oc_child(ctx);
			if (!ok)
				oc_scan_limit(sc);
		}
		if (!ok)
			break;
		made++;
	}
	if (over)
		oc_scan_broken(sc, KOF_BROKEN_LIMIT);
out:
	tab_free(&em.scr.t);
	tab_free(&em.acc);
	free(spans);
	oc_scan_release(sc, spans_charged);
	return made;
}
