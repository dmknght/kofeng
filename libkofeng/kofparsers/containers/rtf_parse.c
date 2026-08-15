/*
 * rtf_parse.c - reading RTF forward, because there is no other direction.
 *
 * One pass over the document tracking three things: how deep the braces are, what
 * the last control word was, and whether the bytes ahead are data rather than text.
 * Everything the view holds comes out of that pass.
 *
 * The walk has to be as lenient as a word processor and as bounded as a scanner,
 * which pull in opposite directions. Malformed RTF is the ordinary case - the
 * exploit documents are malformed on purpose, because a reader that recovers is a
 * reader that can be steered - so nothing here refuses a document. What it does
 * instead is bound every loop by the object and record what did not make sense.
 */

#include <string.h>

#include "rtf_parse.h"
#include "../runlist.h"

/* ---- character classes, ASCII only ------------------------------------------- */

static int is_alpha(uint8_t c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static int is_digit(uint8_t c)
{
	return c >= '0' && c <= '9';
}

static int is_hex(uint8_t c)
{
	return is_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static int is_space(uint8_t c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

/* ---- the walk's own state ---------------------------------------------------- */

struct rw {
	kof_buf f;
	struct kof_rtf_info *r;
	struct kof_runs runs;
	uint64_t body_from;     /* start of the body run being accumulated */
};

/*
 * Close the stretch of body ending here, then hand the data range to its class.
 *
 * Body is claimed in the gaps rather than as it is read, because a run per control
 * word would be thousands of runs in an ordinary document. What is left is one run
 * per stretch between two data blobs, which is a handful.
 */
static void cut_body(struct rw *s, uint64_t upto)
{
	if (upto > s->body_from)
		kof_runs_add(&s->runs, s->f.n, s->body_from, upto - s->body_from,
			     KOF_RTF_CLS_BODY);
}

/* ---- regions ------------------------------------------------------------------ */

static const uint32_t rtf_cls_bit[KOF_RTF_CLS_COUNT] = {
	KOF_SCAN_RTF_BODY,
	KOF_SCAN_RTF_OBJDATA,
	KOF_SCAN_RTF_BINARY
};

static uint32_t rtf_resolve_scan(const struct kof_obj_ctx *ctx, uint32_t mask,
				 struct kof_range *out, uint32_t max_out)
{
	const struct kof_rtf_info *r =
		(const struct kof_rtf_info *)ctx->file_header;

	if (!r || !r->valid || !out || max_out == 0)
		return 0;
	_Static_assert(sizeof r->run[0] == sizeof(struct kof_run),
		       "the view's run and runlist.h's have drifted apart");
	return kof_runs_resolve((const struct kof_run *)r->run, r->n_runs, mask,
				rtf_cls_bit, KOF_SCAN_RTF_UNCLAIMED,
				ctx->obj_size, out, max_out);
}

/* ---- pieces of the walk ------------------------------------------------------- */

/*
 * A control word, and the number after it if there is one.
 *
 * `\` then letters then an optional signed number then an optional single space
 * that belongs to the word rather than to the text. A control SYMBOL - `\` then one
 * non-letter - is one character and carries no name, which is why the length can
 * come back zero.
 */
static uint64_t read_control(struct rw *s, uint64_t at, char *name, uint32_t cap,
			     uint32_t *name_len, int64_t *param, int *has_param)
{
	uint32_t n = 0;
	uint8_t c = 0;
	int neg = 0;

	*name_len = 0;
	*has_param = 0;
	*param = 0;

	at++;                                   /* past the backslash */
	if (!kof_rd_u8(s->f, at, &c))
		return at;
	if (!is_alpha(c))
		return at + 1u;                 /* a control symbol */

	while (kof_rd_u8(s->f, at, &c) && is_alpha(c)) {
		if (n + 1u < cap)
			name[n] = (char)(c | 0x20u);   /* folded, ASCII only */
		n++;
		at++;
		if (n > KOF_RTF_CTRL_MAX * 4u) {
			/* Not a control word any reader would accept, and a long
			 * run of letters is how a real one gets hidden. */
			s->r->anomalies |= KOF_RTF_ANOM_LONG_CTRL;
			break;
		}
	}
	if (n > KOF_RTF_CTRL_MAX)
		s->r->anomalies |= KOF_RTF_ANOM_LONG_CTRL;
	*name_len = n < cap ? n : cap - 1u;
	name[*name_len] = 0;

	if (kof_rd_u8(s->f, at, &c) && c == '-') {
		neg = 1;
		at++;
	}
	while (kof_rd_u8(s->f, at, &c) && is_digit(c)) {
		*has_param = 1;
		if (*param < 0x7fffffff)
			*param = *param * 10 + (c - '0');
		at++;
	}
	if (neg)
		*param = -*param;

	/* One space after a control word is part of it. */
	if (kof_rd_u8(s->f, at, &c) && c == ' ')
		at++;
	return at;
}

/*
 * The hex of a destination, to the end of the group that holds it.
 *
 * This is where the format fights back, and the first version of this function lost.
 * It read hex until the first byte that was not hex or whitespace and stopped at
 * the brace - which is correct for a document nobody wrote to be misread, and wrong
 * for every one that was. A real sample:
 *
 *   \objdata866059{\*\auldb545969541 \bin00\900332684790692741}
 *   {\*\lineColor153098996 \bin00000\520161743563895995}
 *   46c3ea33020000000b0000006551756 \bin00
 *   154694f6e2e33000000...
 *
 * The payload is there, split by ignorable destinations and by \bin control words
 * asking for zero bytes. None of it changes what a word processor decodes, because
 * a destination's data is its TEXT and control words are not text - so a reader that
 * stops at the first one reads nothing while Word reads the exploit.
 *
 * So: walk to the brace that closes this destination, counting hex digits, stepping
 * over control words and skipping nested groups whole. Bounded by the object, and
 * every branch consumes a byte.
 */
static uint64_t read_hex(struct rw *s, uint64_t at, uint64_t *bytes, int *clean)
{
	uint64_t start = at, digits = 0;
	uint32_t depth = 0;
	uint8_t c = 0;

	*clean = 1;
	while (kof_rd_u8(s->f, at, &c)) {
		if (is_hex(c)) {
			digits++;
			at++;
			continue;
		}
		if (is_space(c)) {
			at++;
			continue;
		}
		if (c == '{') {
			/* A nested destination. Its content is not this object's
			 * data, so it is skipped entire. */
			uint32_t inner = 0;

			while (kof_rd_u8(s->f, at, &c)) {
				if (c == '\\') {
					at += 2u;      /* an escaped brace is text */
					continue;
				}
				if (c == '{')
					inner++;
				else if (c == '}' && --inner == 0) {
					at++;
					break;
				}
				at++;
			}
			continue;
		}
		if (c == '}') {
			if (depth == 0)
				break;         /* the destination ends here */
			depth--;
			at++;
			continue;
		}
		if (c == '\\') {
			/* A control word between digits. Stepped over, because it
			 * is not data - which is the whole of the trick. */
			at++;
			if (!kof_rd_u8(s->f, at, &c))
				break;
			if (!is_alpha(c)) {
				at++;          /* a control symbol */
				continue;
			}
			while (kof_rd_u8(s->f, at, &c) && is_alpha(c))
				at++;
			if (kof_rd_u8(s->f, at, &c) && c == '-')
				at++;
			while (kof_rd_u8(s->f, at, &c) && is_digit(c))
				at++;
			if (kof_rd_u8(s->f, at, &c) && c == ' ')
				at++;
			continue;
		}
		/*
		 * A byte that is none of those is SKIPPED, not an ending.
		 *
		 * A destination ends at its closing brace and nowhere else, so a
		 * reader that stops at the first surprising byte stops wherever the
		 * document chooses. One sample writes "\\'" followed by a raw 0xcc -
		 * a hex escape with no hex after it, which is malformed by any
		 * reading - and stopping there found nothing while a word processor
		 * skipped it and read the payload behind.
		 *
		 * Recorded, because well formed hex contains none of these.
		 */
		s->r->anomalies |= KOF_RTF_ANOM_BAD_HEX;
		at++;
	}
	if (digits & 1u)
		*clean = 0;                     /* an odd digit count is not bytes */
	*bytes = digits / 2u;
	return at > start ? at : start;
}

/* Decode the first `n` bytes of a hex run, for identifying what it is. */
static uint32_t hex_head(struct rw *s, uint64_t at, uint8_t *out, uint32_t n)
{
	uint32_t got = 0;
	uint8_t c = 0;
	int hi = -1;

	while (got < n && kof_rd_u8(s->f, at, &c)) {
		int v;

		if (is_space(c)) {
			at++;
			continue;
		}
		if (!is_hex(c))
			break;
		v = is_digit(c) ? c - '0' : (c | 0x20) - 'a' + 10;
		if (hi < 0) {
			hi = v;
		} else {
			out[got++] = (uint8_t)((hi << 4) | v);
			hi = -1;
		}
		at++;
	}
	return got;
}

/* ---- the parse ---------------------------------------------------------------- */

int kof_rtf_sniff(kof_buf file)
{
	uint8_t c = 0;

	if (!kof_in_range(file, 0, 5))
		return 0;
	if (file.p[0] != '{' || file.p[1] != '\\')
		return 0;
	return (file.p[2] | 0x20) == 'r' && (file.p[3] | 0x20) == 't' &&
	       kof_rd_u8(file, 4, &c) && is_alpha(c);
}

int kof_rtf_parse(kof_buf file, struct kof_rtf_info *r, struct kof_obj_ctx *ctx)
{
	struct rw s;
	uint64_t at = 0;
	uint32_t depth = 0;
	uint64_t pending_class = 0;
	uint32_t pending_class_len = 0;
	int pending_update = 0;

	memset(r, 0, sizeof *r);
	r->version = KOF_RTF_INFO_VERSION;

	if (!kof_rtf_sniff(file)) {
		r->anomalies |= KOF_RTF_ANOM_BAD_HEADER;
		return 0;
	}
	r->valid = 1;

	memset(&s, 0, sizeof s);
	s.f = file;
	s.r = r;
	s.body_from = 0;
	kof_runs_init(&s.runs, (struct kof_run *)r->run, KOF_RTF_MAX_EXTENTS,
		      KOF_RTF_CLS_COUNT);

	/*
	 * One pass, and it always advances.
	 *
	 * Every branch below either consumes at least one byte or breaks, so the
	 * walk ends on the object rather than on a counter - the same property the
	 * tar and RAR walks have, reached differently because there are no lengths
	 * here to step over.
	 */
	while (at < file.n) {
		uint8_t c = 0;
		char name[KOF_RTF_CTRL_MAX + 1u];
		uint32_t nlen;
		int64_t param;
		int has_param;
		uint64_t next;

		if (!kof_rd_u8(file, at, &c))
			break;

		if (c == '{') {
			if (depth < KOF_RTF_MAX_DEPTH) {
				depth++;
				if (depth > r->max_depth)
					r->max_depth = depth;
			} else {
				r->anomalies |= KOF_RTF_ANOM_DEPTH;
			}
			at++;
			continue;
		}
		if (c == '}') {
			if (depth)
				depth--;
			else
				r->anomalies |= KOF_RTF_ANOM_UNBALANCED;
			at++;
			continue;
		}
		if (c != '\\') {
			at++;                   /* document text */
			continue;
		}

		next = read_control(&s, at, name, sizeof name, &nlen, &param,
				    &has_param);
		if (next <= at)
			break;                  /* cannot happen; refuses to loop */
		r->n_controls++;
		at = next;

		if (nlen == 0)
			continue;               /* a control symbol */

		if (strcmp(name, "objupdate") == 0) {
			pending_update = 1;
			r->anomalies |= KOF_RTF_ANOM_OBJUPDATE;
			continue;
		}
		if (strcmp(name, "objclass") == 0) {
			/* The name runs to the closing brace. */
			uint64_t k = at;

			while (kof_rd_u8(file, k, &c) && c != '}' && c != '\\' &&
			       k - at < 128u)
				k++;
			pending_class = at;
			pending_class_len = (uint32_t)(k - at);
			at = k;
			continue;
		}

		if (strcmp(name, "bin") == 0 && has_param && param > 0) {
			uint64_t n = (uint64_t)param;
			uint64_t got = kof_clip_len(file.n, at, n);

			r->n_bin++;
			if (got != n)
				r->anomalies |= KOF_RTF_ANOM_TRUNCATED;
			if (got) {
				cut_body(&s, at);
				kof_runs_add(&s.runs, file.n, at, got,
					     KOF_RTF_CLS_BINARY);
				at += got;
				s.body_from = at;
			}
			continue;
		}

		if (strcmp(name, "objdata") == 0 || strcmp(name, "datastore") == 0) {
			uint64_t bytes = 0, end;
			int clean = 1;

			end = read_hex(&s, at, &bytes, &clean);
			if (end > at && bytes) {
				struct kof_rtf_object *o;
				uint8_t head[8];
				uint32_t got;

				cut_body(&s, at);
				kof_runs_add(&s.runs, file.n, at, end - at,
					     KOF_RTF_CLS_OBJDATA);

				if (r->n_objects < KOF_RTF_MAX_OBJECTS) {
					o = &r->obj[r->n_objects++];
					memset(o, 0, sizeof *o);
					o->data_off  = at;
					o->data_len  = end - at;
					o->hex_bytes = bytes;
					o->class_off = pending_class;
					o->class_len = pending_class_len;
					if (pending_update)
						o->suspicious |= KOF_RTF_OBJ_UPDATE;
					if (!clean) {
						o->suspicious |= KOF_RTF_OBJ_BAD_HEX;
						r->anomalies |= KOF_RTF_ANOM_BAD_HEX;
					}
					got = hex_head(&s, at, head, sizeof head);
					if (got == 8 && memcmp(head,
					    "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 8) == 0)
						o->suspicious |= KOF_RTF_OBJ_OLE;
					else if (got >= 4 && head[0] == 0x01 &&
						 head[1] == 0x05 && head[2] == 0 &&
						 head[3] == 0)
						o->suspicious |= KOF_RTF_OBJ_OLE1;
				} else {
					r->anomalies |= KOF_RTF_ANOM_OBJECTS_FULL;
				}
				at = end;
				s.body_from = at;
			}
			pending_class = 0;
			pending_class_len = 0;
			pending_update = 0;
			continue;
		}

		if (strcmp(name, "pict") == 0) {
			/* Picture data is hex like objdata and is not a payload
			 * this engine opens - claimed so it stops being searched
			 * as if it were text. */
			uint64_t bytes = 0, end;
			int clean;

			end = read_hex(&s, at, &bytes, &clean);
			if (end > at && bytes) {
				cut_body(&s, at);
				kof_runs_add(&s.runs, file.n, at, end - at,
					     KOF_RTF_CLS_BINARY);
				at = end;
				s.body_from = at;
			}
			continue;
		}
	}

	cut_body(&s, file.n);
	if (depth)
		r->anomalies |= KOF_RTF_ANOM_UNBALANCED;
	if (s.runs.full)
		r->anomalies |= KOF_RTF_ANOM_EXTENTS_FULL;
	if (s.runs.overlapped)
		r->anomalies |= KOF_RTF_ANOM_OVERLAP;

	kof_runs_settle(&s.runs, r->region_bytes);
	r->n_runs = s.runs.n;

	ctx->obj_size     = file.n;
	ctx->format       = KOF_FMT_RTF;
	ctx->file_header  = r;
	ctx->resolve_scan = rtf_resolve_scan;
	return 1;
}

/* ---- names -------------------------------------------------------------------- */

#define RTF_REGIONS(X)          \
	X(KOF_SCAN_RTF_BODY)      \
	X(KOF_SCAN_RTF_OBJDATA)   \
	X(KOF_SCAN_RTF_BINARY)    \
	X(KOF_SCAN_RTF_UNCLAIMED)

#define X_BIT(b)  (b),
#define X_CASE(b) case (b): return #b;

const uint32_t kof_rtf_region_bits[] = { RTF_REGIONS(X_BIT) };
_Static_assert(sizeof kof_rtf_region_bits / sizeof kof_rtf_region_bits[0] ==
	       KOF_RTF_REGION_COUNT, "region list and its count disagree");

const char *kof_rtf_region_name(uint32_t bit)
{
	switch (bit) {
	RTF_REGIONS(X_CASE)
	default: return 0;
	}
}

#undef X_BIT
#undef X_CASE

const char *kof_rtf_anomaly_name(unsigned index)
{
	static const char *const n[] = {
		"BAD_HEADER", "UNBALANCED", "DEPTH", "OBJECTS_FULL",
		"EXTENTS_FULL", "TRUNCATED", "BAD_HEX", "LONG_CTRL",
		"OBJUPDATE", "OVERLAP"
	};

	return index < sizeof n / sizeof n[0] ? n[index] : 0;
}
