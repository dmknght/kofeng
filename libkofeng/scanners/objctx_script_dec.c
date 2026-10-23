/*
 * objctx_script_dec.c - what a script puts its own literals through, taken off: the engine's half
 * of the lib's decode hook (kgenome_textual_decode_fn), and the two ways the lib's form is asked for.
 *
 * `eval(gzinflate(base64_decode("...")))` is how a webshell hides what it is, and the form of it
 * with the literal still encoded says nothing: the payload is the program. The lib finds the literal
 * and which decoders wrap it; the algorithms are kuncoat's, and this is the hook that runs them.
 *
 * WHAT COMES OUT OF A DECODE IS FORMED TOO, when it is text. A payload is usually php, often with
 * another layer of the same inside it, and it is read the way the file was: the same form, the same
 * decoders, one level down. A layer is kept as it decoded when it is not text - a binary payload is
 * not php and its bytes are not to be reformatted.
 *
 * BOUNDED BY THE OBJECT, not by what the file says. Every layer's output is charged to one allowance
 * (oc_script_dec_room), the depth is thirty-two (the deepest wrapped webshell in the corpus, alfa, is sixteen layers; eight cut it
 * in the middle and left `eval($_GET[...])` undecoded), an inflate stops at the allowance and keeps what it had,
 * and every byte held is charged to the scanner's memory ceiling and given back by oc_script_dec_end.
 * A bound that fires is reported (oc_scan_limit), not silent.
 */

#define _GNU_SOURCE

#include <stdlib.h>
#include <string.h>

#include "objctx_int.h"
#include "objctx_decomp.h"
#include "../analyzers/parsers/containers/gzip_parse.h"
#include "../analyzers/parsers/scripts/script_apply.h"
#include <textual/textual.h>
#include <uncoat.h>

#define SCRIPT_DEC_DEPTH 32u

struct dbuf {
	uint8_t *p;
	size_t   n, cap;
};

struct oc_script_dec {
	struct kof_scanner *sc;
	uint32_t lang;
	uint32_t depth;
	uint64_t room;          /* decoded bytes still allowed, over every layer */
	uint64_t held;          /* bytes charged to the ceiling, given back at the end */
	uint32_t limit;         /* a bound fired */
	/*
	 * The chain's two buffers and the formed layer, ONE SET PER DEPTH. A layer is read while the
	 * form of it runs, and the form of it decodes in turn: sharing buffers would have the inner
	 * decode write over the bytes the outer form is still reading.
	 */
	struct dbuf a[SCRIPT_DEC_DEPTH + 1u], b[SCRIPT_DEC_DEPTH + 1u], c[SCRIPT_DEC_DEPTH + 1u];
};

/*
 * What a script of `n` bytes may decode to, in all: thirty-two times it and sixty-four kilobytes, never past the
 * object cap. The sum is over EVERY layer: C99madShell, 44 KB, is ten layers of about 40 KB and a body of 144 KB,
 * 562 KB or 12.7 times the file, and a factor of eight stopped it one layer short of its body.
 */
uint64_t oc_script_dec_room(const struct kof_scanner *sc, uint64_t n)
{
	uint64_t room = 32u * n + 65536u;

	return room < sc->ledger.obj_cap ? room : sc->ledger.obj_cap;
}

struct oc_script_dec *oc_script_dec_new(struct kof_scanner *sc, uint32_t lang, uint64_t room)
{
	struct oc_script_dec *d = calloc(1u, sizeof *d);

	if (!d)
		return NULL;
	d->sc = sc;
	d->lang = lang;
	d->room = room;
	return d;
}

/* Free everything, give the ceiling back what was charged, and say so if a bound fired. */
void oc_script_dec_end(struct oc_script_dec *d)
{
	uint32_t i;

	if (!d)
		return;
	for (i = 0; i <= SCRIPT_DEC_DEPTH; i++) {
		free(d->a[i].p);
		free(d->b[i].p);
		free(d->c[i].p);
	}
	oc_scan_release(d->sc, d->held);
	if (d->limit)
		oc_scan_limit(d->sc);
	free(d);
}

/* Room for `n` bytes in `b`, charged to the ceiling. 0 when the allowance, the ceiling or the allocator says no. */
static int dbuf_want(struct oc_script_dec *d, struct dbuf *b, uint64_t n)
{
	uint8_t *np;

	if (n > d->room + 4096u || n > 0x7fffffffu) {
		d->limit = 1;
		return 0;
	}
	if (n <= b->cap)
		return 1;
	if (n - b->cap > oc_scan_room(d->sc)) {
		d->limit = 1;
		return 0;
	}
	np = realloc(b->p, (size_t)n);
	if (!np) {
		d->limit = 1;
		return 0;
	}
	scan_charge(d->sc, n - b->cap);
	d->held += n - b->cap;
	b->p = np;
	b->cap = (size_t)n;
	return 1;
}

struct inf_sink {
	struct oc_script_dec *d;
	struct dbuf          *b;
	uint64_t              left;
};

static int inf_sink_fn(void *u, const uint8_t *p, uint32_t n)
{
	struct inf_sink *k = u;

	if (n > k->left) {
		k->d->limit = 1;
		return 0;
	}
	if (!dbuf_want(k->d, k->b, (uint64_t)k->b->n + n))
		return 0;
	memcpy(k->b->p + k->b->n, p, n);
	k->b->n += n;
	k->left -= n;
	return 1;
}

/* gzinflate, gzuncompress and gzdecode: the same deflate stream, behind nothing, two bytes or a header. */
static int dec_inflate(struct oc_script_dec *d, uint8_t id, const uint8_t *in, uint64_t len,
		       struct dbuf *dst)
{
	struct kof_scanner *sc = d->sc;
	struct inf_sink k = { d, dst, d->room };
	struct kuncoat_io io;
	enum kuncoat_status st;
	uint64_t skip = 0;

	/* The engine's own readings of the two wrappers: zlib_hdr_len, which answers 0 for raw deflate
	 * under a zlib name and is decoded from its first byte, and the gzip header parser. */
	if (id == KGENOME_TEXTUAL_DEC_ZLIB) {
		skip = zlib_hdr_len(in, len);
	} else if (id == KGENOME_TEXTUAL_DEC_GZIP) {
		struct kof_gzip_info g;

		if (!kof_gzip_header(kof_buf_make(in, len), &g) || g.data_off >= len)
			return 0;
		skip = g.data_off;
	}
	if (!sc->cache.inf) {
		sc->cache.inf = malloc(sizeof *sc->cache.inf);
		if (!sc->cache.inf) {
			d->limit = 1;
			return 0;
		}
	}
	dst->n = 0;
	io = (struct kuncoat_io){ .in = { in + skip, len - skip }, .sink = inf_sink_fn, .user = &k };
	st = kuncoat_inflate(sc->cache.inf, &io);
	/* What a bound of ours cut is the real beginning and is kept; a stream that is not one is not. */
	return dst->n && (st == KUNCOAT_OK || st == KUNCOAT_STOPPED);
}

/*
 * One function of bytes over `in`, into `dst`. 1 when it produced something. The inflate family is the engine's own (the
 * scanner's inflate state and allowance); every other op is kof_script_apply's, the one the evaluator and the gate use too.
 */
static int dec_step(struct oc_script_dec *d, const struct kgenome_textual_call *c, const uint8_t *in, uint64_t len,
		    struct dbuf *dst)
{
	uint64_t cap;
	uint32_t produced = 0;

	if (c->op == KGENOME_TEXTUAL_DEC_INFLATE || c->op == KGENOME_TEXTUAL_DEC_ZLIB || c->op == KGENOME_TEXTUAL_DEC_GZIP)
		return dec_inflate(d, (uint8_t)c->op, in, len, dst);
	if (len > 0xffffffffu)
		return 0;
	cap = kof_script_apply_room(c, len);
	if (!cap || !dbuf_want(d, dst, cap))
		return 0;
	if (!kof_script_apply(NULL, c, in, (uint32_t)len, dst->p, (uint32_t)cap, &produced) || !produced)
		return 0;
	dst->n = produced;
	return 1;
}

/* Is it text a person wrote - no NUL, and nearly all printable or white space. Only text is formed. */
static int dec_is_text(const uint8_t *p, uint64_t n)
{
	uint64_t i, odd = 0;

	for (i = 0; i < n; i++) {
		uint8_t c = p[i];

		if (c == 0)
			return 0;
		if ((c < 0x20u && c != '\n' && c != '\r' && c != '\t') || c == 0x7fu)
			odd++;
	}
	return n && odd * 20u <= n;
}

/*
 * The layer, formed. One that begins with "<" is a page - php with its tag, or markup around it, as
 * `eval("?>" . base64_decode(...))` runs - and one that does not is code, what eval takes, and is
 * formed as a fragment: php code does not begin with "<", and html always does. Getting it wrong
 * costs the view some formatting, never a byte. Answers 0 and leaves `dst` alone when it
 * is not text, or too deep, or the form would not fit.
 */
static int dec_layer(struct oc_script_dec *d, const uint8_t *p, uint64_t n, struct dbuf *dst)
{
	uint64_t k = 0, cap, extra;
	struct oc_script_form_req rq;
	uint32_t w;

	if (d->depth >= SCRIPT_DEC_DEPTH) {
		d->limit = 1;
		return 0;
	}
	if (n > 0x7fffff00u || !dec_is_text(p, n))
		return 0;
	while (k < n && kof_is_blank_byte(p[k]))
		k++;
	extra = d->room < 8u * n + 4096u ? d->room : 8u * n + 4096u;
	cap = KGENOME_TEXTUAL_FORM_CAP(n) + extra;
	if (!dbuf_want(d, dst, cap))
		return 0;
	rq = (struct oc_script_form_req){ .lang = d->lang, .in = p, .n = (uint32_t)n, .out = dst->p,
					  .cap = cap, .dec = d,
					  .fragment = !(k < n && p[k] == '<') };
	d->depth++;
	w = oc_script_form(&rq, NULL);
	d->depth--;
	if (!w)
		return 0;
	dst->n = w;
	return 1;
}

static int script_decode_hook(void *u, const uint8_t *chain, uint32_t n_chain, const uint8_t *in,
			      uint32_t len, const uint8_t **out, uint32_t *out_len)
{
	struct oc_script_dec *d = u;
	const uint8_t *cur = in;
	uint64_t curn = len;
	uint32_t i;

	for (i = 0; i < n_chain; i++) {
		struct dbuf *dst = i & 1u ? &d->b[d->depth] : &d->a[d->depth];

		struct kgenome_textual_call c = { .op = chain[i] };

		if (!dec_step(d, &c, cur, curn, dst))
			return 0;
		cur = dst->p;
		curn = dst->n;
	}
	if (curn > d->room) {
		d->limit = 1;
		return 0;
	}
	d->room -= curn;
	if (dec_layer(d, cur, curn, &d->c[d->depth])) {
		cur = d->c[d->depth].p;
		curn = d->c[d->depth].n;
	}
	*out = cur;
	*out_len = (uint32_t)curn;
	return 1;
}

/*
 * THE FORM OF A SCRIPT THE LIB CAN LEX: the whole text, in one call.
 *
 * The lexer finds where the language is - the islands of php in a page, the strings and the comments
 * inside them - so nothing here walks extents or copies what lies between them: the markup, the
 * tags and every string come back as they were typed, except the literals a decoder is put over,
 * which come back decoded when `dec` is given. A fragment is code with no tag, which is what the fold
 * builds and a layer that eval would run. Answers the length written, or 0 for "I will not touch
 * this", which the caller keeps the input for. `n_dec` (may be NULL) is how many literals were decoded and joins folded.
 */
uint32_t oc_script_form(const struct oc_script_form_req *rq, uint32_t *n_dec)
{
	struct kgenome_textual_form_req fq = {
		.in = rq->in, .n = rq->n, .lang = rq->lang,
		.flags = rq->fragment ? KGENOME_TEXTUAL_FRAGMENT : 0u,
		.out = rq->out, .cap = rq->cap,
		.decode = rq->dec ? script_decode_hook : NULL, .decode_user = rq->dec,
		/* a call on literals is rewritten where a decoded literal is: the view that says what the program does */
		.apply = rq->dec ? kof_script_apply : NULL };
	struct kgenome_textual_form_res rs;
	enum kgenome_textual_status st = kgenome_textual_form(&fq, &rs);

	if (n_dec)
		*n_dec = rs.n_decoded + rs.n_folded + rs.n_calls;       /* a join or a call written as one literal says something the file did not */
	if (rs.n_bound && rq->dec)
		rq->dec->limit = 1;                                     /* a work bound of the lexer fired (L3, L5): said at oc_script_dec_end, as the hook's own bounds are */
	return st == KGENOME_TEXTUAL_OK || st == KGENOME_TEXTUAL_OPEN ? rs.n_out : 0;
}
