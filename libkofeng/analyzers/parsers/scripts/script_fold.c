/*
 * script_fold.c - see script_norm.h, kof_script_fold. The constant folder: the other
 * half of what the header describes, apart from script_norm.c because it shares no state
 * with the line pass - it reads a statement, not a line, and keeps an arena of its own.
 */

#include <stdlib.h>
#include <string.h>

#include "../../../kofcore/kofcore.h"
#include "script_norm.h"

/* The same four bytes script_norm.c's line pass calls whitespace. */
static int is_ws(uint8_t c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\v' || c == '\f';
}

/* ---- the folding pass ------------------------------------------------------
 *
 * See the note over kof_script_fold in the header. The shape is a recursive
 * descent over ONE statement that knows four things and no more: a literal, a
 * join, a variable holding a constant, and str_replace over three constants.
 *
 * Everything else evaluates to "not a constant", which is not a failure - it is
 * the answer for most of every script ever written.
 */

#define FOLD_MAX_VARS   64u
#define FOLD_MAX_DEPTH  16u

struct val {
	uint32_t off, n;        /* into the arena - see the note below */
};

struct folder {
	const struct kof_lex *lx;
	const uint8_t *in;
	uint32_t n;

	/*
	 * THE ARENA EVERY CONSTANT LIVES IN, AND VALUES ARE OFFSETS INTO IT.
	 *
	 * Not pointers. The block is grown with realloc and MOVES when it does,
	 * so a struct holding char* would be a use-after-realloc that only
	 * appears on an input big enough to force a growth - which is exactly
	 * the input this pass exists for. Offsets survive the move; pointers
	 * are re-derived at each use and never stored.
	 */
	char    *arena;
	uint32_t a_n, a_cap;

	struct {
		const uint8_t *name;
		uint32_t       name_n;
		struct val     v;
	} var[FOLD_MAX_VARS];
	uint32_t n_var;
};

static int arena_put(struct folder *f, const char *p, uint32_t n)
{
	if (f->a_n + n < f->a_n)
		return 0;
	if (f->a_n + n > f->a_cap) {
		uint32_t want = f->a_cap ? f->a_cap : 4096u;
		char *na;

		while (want < f->a_n + n) {
			if (want > 0x20000000u)
				return 0;
			want *= 2u;
		}
		na = realloc(f->arena, want);
		if (!na)
			return 0;
		f->arena = na;
		f->a_cap = want;
	}
	if (n)
		memcpy(f->arena + f->a_n, p, n);
	f->a_n += n;
	return 1;
}

/* Append a slice of the arena to the arena. Through a bounce buffer would be
 * one copy more; the source is re-read after each growth instead. */
static int arena_put_self(struct folder *f, uint32_t off, uint32_t n)
{
	uint32_t k = 0;

	while (k < n) {
		uint32_t chunk = n - k > 256u ? 256u : n - k;
		char tmp[256];

		memcpy(tmp, f->arena + off + k, chunk);
		if (!arena_put(f, tmp, chunk))
			return 0;
		k += chunk;
	}
	return 1;
}

static int is_name_byte(uint8_t c)
{
	return kof_is_alnum(c) || c == '_';
}

static void skip_ws(const struct folder *f, uint32_t *i)
{
	while (*i < f->n && is_ws(f->in[*i]))
		(*i)++;
}

/* The decoded content of the literal starting at `*i`, which must be a quote. */
static int read_literal(struct folder *f, uint32_t *i, struct val *out)
{
	uint8_t q = f->in[*i];
	uint32_t j = *i + 1u;
	uint32_t start = f->a_n;
	int esc = !f->lx->no_bs_escape &&
		  (q == '"' || f->lx->sq_escapes);

	while (j < f->n && f->in[j] != q) {
		uint8_t c = f->in[j];
		char b;

		if (c != '\\' || !esc || j + 1u >= f->n) {
			if (!arena_put(f, (const char *)&c, 1u))
				return 0;
			j++;
			continue;
		}
		/*
		 * "\x41" AND "\101" ARE THE POINT OF THIS. A file that writes
		 * "phar://" as "\160\x68\141\x72\72\57\57" does it so that the
		 * seven bytes never appear, and the decoded form is what a
		 * marker can be written on.
		 */
		{
			uint8_t e = f->in[j + 1u];

			if (e == 'x' || e == 'X') {
				unsigned v = 0, k = 0;

				j += 2u;
				while (k < 2u && j < f->n) {
					uint8_t h = f->in[j];

					if (h >= '0' && h <= '9')
						v = v * 16u + (unsigned)(h - '0');
					else if (h >= 'a' && h <= 'f')
						v = v * 16u + (unsigned)(h - 'a' + 10);
					else if (h >= 'A' && h <= 'F')
						v = v * 16u + (unsigned)(h - 'A' + 10);
					else
						break;
					j++;
					k++;
				}
				if (!k)
					continue;
				b = (char)v;
			} else if (e >= '0' && e <= '7') {
				unsigned v = 0, k = 0;

				j += 1u;
				while (k < 3u && j < f->n &&
				       f->in[j] >= '0' && f->in[j] <= '7') {
					v = v * 8u + (unsigned)(f->in[j] - '0');
					j++;
					k++;
				}
				b = (char)(v & 0xffu);
			} else {
				static const char from[] = "nrtvf";
				static const char to[]   = "\n\r\t\v\f";
				const char *at = strchr(from, (int)e);

				b = at ? to[at - from] : (char)e;
				j += 2u;
			}
		}
		if (!arena_put(f, &b, 1u))
			return 0;
	}
	if (j >= f->n)
		return 0;               /* unterminated: not a constant */
	*i = j + 1u;
	out->off = start;
	out->n = f->a_n - start;
	return 1;
}

static int lookup(const struct folder *f, const uint8_t *name, uint32_t n,
		  struct val *out)
{
	uint32_t k;

	for (k = 0; k < f->n_var; k++)
		if (f->var[k].name_n == n && !memcmp(f->var[k].name, name, n)) {
			*out = f->var[k].v;
			return 1;
		}
	return 0;
}

static int eval(struct folder *f, uint32_t *i, uint32_t depth,
		struct val *out);

/* str_replace(A, B, C): C with every A in it replaced by B. */
static int do_replace(struct folder *f, struct val a, struct val b,
		      struct val c, struct val *out)
{
	uint32_t start = f->a_n, k = 0;

	if (!a.n)
		return 0;               /* replacing nothing would not end */
	while (k < c.n) {
		int same = k + a.n <= c.n &&
			   !memcmp(f->arena + c.off + k, f->arena + a.off, a.n);

		if (same) {
			if (!arena_put_self(f, b.off, b.n))
				return 0;
			k += a.n;
			continue;
		}
		if (!arena_put_self(f, c.off + k, 1u))
			return 0;
		k++;
	}
	out->off = start;
	out->n = f->a_n - start;
	return 1;
}

/* One term: a literal, a variable, or the one call this pass knows. */
static int term(struct folder *f, uint32_t *i, uint32_t depth, struct val *out)
{
	skip_ws(f, i);
	if (*i >= f->n)
		return 0;

	if (f->lx->quotes && strchr(f->lx->quotes, (int)f->in[*i]))
		return read_literal(f, i, out);

	if (f->in[*i] == (uint8_t)f->lx->var_sigil) {
		uint32_t s = *i + 1u, e = s;

		while (e < f->n && is_name_byte(f->in[e]))
			e++;
		if (e == s)
			return 0;
		*i = e;
		return lookup(f, f->in + s, e - s, out);
	}

	/*
	 * str_replace(A, B, C) AND NOTHING ELSE YET.
	 *
	 * It is the one call these generators use to put a cut-up program back
	 * together, and it is safe to apply because all three arguments have to
	 * be constants already - nothing is run and no value from outside the
	 * file is followed.
	 */
	if (*i + 12u <= f->n && !memcmp(f->in + *i, "str_replace(", 12u)) {
		struct val a, b, c;
		uint32_t j = *i + 12u;

		if (!eval(f, &j, depth + 1u, &a))
			return 0;
		skip_ws(f, &j);
		if (j >= f->n || f->in[j] != ',')
			return 0;
		j++;
		if (!eval(f, &j, depth + 1u, &b))
			return 0;
		skip_ws(f, &j);
		if (j >= f->n || f->in[j] != ',')
			return 0;
		j++;
		if (!eval(f, &j, depth + 1u, &c))
			return 0;
		skip_ws(f, &j);
		if (j >= f->n || f->in[j] != ')')
			return 0;
		*i = j + 1u;
		return do_replace(f, a, b, c, out);
	}
	return 0;
}

/* A term, then as many "join term" as follow it. */
static int eval(struct folder *f, uint32_t *i, uint32_t depth, struct val *out)
{
	struct val acc;

	if (depth > FOLD_MAX_DEPTH)
		return 0;
	if (!term(f, i, depth, &acc))
		return 0;

	for (;;) {
		struct val rhs;
		uint32_t save = *i, start;

		skip_ws(f, i);
		if (*i >= f->n || !f->lx->concat ||
		    f->in[*i] != (uint8_t)f->lx->concat) {
			*i = save;
			break;
		}
		(*i)++;
		if (!term(f, i, depth, &rhs)) {
			*i = save;
			break;
		}
		/* The halves are already in the arena and the result has to be
		 * contiguous, so a join is a third copy. That is what keeps the
		 * total bounded by the literals the file contains. */
		start = f->a_n;
		if (!arena_put_self(f, acc.off, acc.n) ||
		    !arena_put_self(f, rhs.off, rhs.n))
			return 0;
		acc.off = start;
		acc.n = f->a_n - start;
	}
	*out = acc;
	return 1;
}

uint32_t kof_script_fold(const struct kof_lex *lx, const uint8_t *in,
			 uint32_t n, uint8_t *out, uint32_t cap)
{
	struct folder f;
	struct val best;
	uint32_t i = 0;

	if (!lx || !in || !n || !out || !cap || !lx->var_sigil)
		return 0;
	memset(&f, 0, sizeof f);
	f.lx = lx;
	f.in = in;
	f.n = n;
	best.off = best.n = 0;

	/*
	 * ONE SWEEP, LEFT TO RIGHT, and that is why no second pass is needed: a
	 * generator writes the pieces before it joins them, so by the time the
	 * join is read every name in it is already known.
	 */
	while (i < n) {
		uint32_t name_s, name_e, at;
		struct val v;

		if (in[i] != (uint8_t)lx->var_sigil) {
			i++;
			continue;
		}
		name_s = i + 1u;
		name_e = name_s;
		while (name_e < n && is_name_byte(in[name_e]))
			name_e++;
		if (name_e == name_s) {
			i++;
			continue;
		}
		at = name_e;
		skip_ws(&f, &at);
		/* An assignment, not a comparison: "==" is not this. */
		if (at >= n || in[at] != '=' ||
		    (at + 1u < n && in[at + 1u] == '=')) {
			i = name_e;
			continue;
		}
		at++;
		if (!eval(&f, &at, 0, &v) || !v.n) {
			i = name_e;
			continue;
		}
		if (f.n_var < FOLD_MAX_VARS) {
			f.var[f.n_var].name = in + name_s;
			f.var[f.n_var].name_n = name_e - name_s;
			f.var[f.n_var].v = v;
			f.n_var++;
		}
		if (v.n > best.n)
			best = v;
		i = at;
	}

	if (best.n > cap)
		best.n = cap;
	if (best.n)
		memcpy(out, f.arena + best.off, best.n);
	free(f.arena);
	return best.n;
}
