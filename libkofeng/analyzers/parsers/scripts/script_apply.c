/*
 * script_apply.c - see script_apply.h.
 *
 * Each op is one kuncoat step. What is not a step of kuncoat's is not here: a function a language spells like php's and means
 * otherwise gets its own row in the language's table, not a branch in this file.
 */

#include "script_apply.h"

#include <stdlib.h>
#include <string.h>

#include <uncoat.h>

uint64_t kof_script_apply_room(const struct kgenome_textual_call *c, uint64_t len)
{
	switch (c->op) {
	case KGENOME_TEXTUAL_DEC_B64: case KGENOME_TEXTUAL_DEC_URL: case KGENOME_TEXTUAL_DEC_RAWURL:
	case KGENOME_TEXTUAL_DEC_ROT13: case KGENOME_TEXTUAL_DEC_REVERSE: case KGENOME_TEXTUAL_DEC_SLICE:
	case KGENOME_TEXTUAL_DEC_LOWER: case KGENOME_TEXTUAL_DEC_UPPER: case KGENOME_TEXTUAL_DEC_UCFIRST:
	case KGENOME_TEXTUAL_DEC_LCFIRST: case KGENOME_TEXTUAL_DEC_TRIM: case KGENOME_TEXTUAL_DEC_LTRIM:
	case KGENOME_TEXTUAL_DEC_RTRIM: case KGENOME_TEXTUAL_DEC_TRANSLATE:
		return len;
	case KGENOME_TEXTUAL_DEC_HEX: case KGENOME_TEXTUAL_DEC_HEXSTRICT:
		return len / 2u + 1u;
	case KGENOME_TEXTUAL_DEC_REPLACE:
		/* every match is `n2` instead of `n1` bytes; a search of nothing changes nothing */
		if (!c->n1 || c->n2 <= c->n1)
			return len;
		return len + (len / c->n1) * (uint64_t)(c->n2 - c->n1);
	default:
		return 0;
	}
}

/* A step with no parameters. */
static struct kuncoat_step plain(uint32_t algo, uint32_t flags, uint32_t k32)
{
	struct kuncoat_step s = { .algo = algo, .dir = KUNCOAT_DECODE, .flags = flags, .k32 = k32, .key = NULL,
				  .key_len = 0, .max_out = 0 };

	return s;
}

/* The step an op is, or algo 0 when it needs the parameters joined (the caller does that) or is not a step. */
static struct kuncoat_step step_of(const struct kgenome_textual_call *c)
{
	switch (c->op) {
	case KGENOME_TEXTUAL_DEC_B64:
		return plain(KUNCOAT_ALGO_B64, KUNCOAT_F_LAX, 0);       /* php's base64_decode skips what is not base64 */
	case KGENOME_TEXTUAL_DEC_HEX:
		return plain(KUNCOAT_ALGO_HEX, 0, 0);
	case KGENOME_TEXTUAL_DEC_HEXSTRICT:
		return plain(KUNCOAT_ALGO_HEX, KUNCOAT_F_STRICT, 0);
	case KGENOME_TEXTUAL_DEC_URL:
		return plain(KUNCOAT_ALGO_URL, KUNCOAT_F_LAX, 0);       /* urldecode keeps a stray "%" */
	case KGENOME_TEXTUAL_DEC_RAWURL:
		return plain(KUNCOAT_ALGO_URL, KUNCOAT_F_LAX | KUNCOAT_F_RAW, 0);
	case KGENOME_TEXTUAL_DEC_ROT13:
		return plain(KUNCOAT_ALGO_CAESAR, 0, 13u);
	case KGENOME_TEXTUAL_DEC_REVERSE:
		return plain(KUNCOAT_ALGO_REVERSE, 0, 0);
	case KGENOME_TEXTUAL_DEC_SLICE: {
		struct kuncoat_step s = plain(KUNCOAT_ALGO_SLICE, c->to_end ? KUNCOAT_F_TOEND : 0u, (uint32_t)c->k1);

		s.k32b = (uint32_t)c->k2;
		return s;
	}
	case KGENOME_TEXTUAL_DEC_LOWER:
		return plain(KUNCOAT_ALGO_CASE, 0, 0);
	case KGENOME_TEXTUAL_DEC_UPPER:
		return plain(KUNCOAT_ALGO_CASE, 0, 1u);
	case KGENOME_TEXTUAL_DEC_LCFIRST:
		return plain(KUNCOAT_ALGO_CASE, 0, 2u);
	case KGENOME_TEXTUAL_DEC_UCFIRST:
		return plain(KUNCOAT_ALGO_CASE, 0, 3u);
	case KGENOME_TEXTUAL_DEC_LTRIM:
		return plain(KUNCOAT_ALGO_TRIM, 0, 1u);
	case KGENOME_TEXTUAL_DEC_RTRIM:
		return plain(KUNCOAT_ALGO_TRIM, 0, 2u);
	case KGENOME_TEXTUAL_DEC_TRIM:
		return plain(KUNCOAT_ALGO_TRIM, 0, 3u);
	case KGENOME_TEXTUAL_DEC_REPEAT:
		return plain(KUNCOAT_ALGO_REPEAT, 0, (uint32_t)c->k1);
	case KGENOME_TEXTUAL_DEC_JOIN:
		return plain(KUNCOAT_ALGO_JOIN, 0, 0);
	case KGENOME_TEXTUAL_DEC_SPLIT:
		return plain(KUNCOAT_ALGO_SPLIT, 0, 0);
	case KGENOME_TEXTUAL_DEC_CUTHEAD:
		return plain(KUNCOAT_ALGO_CUTHEAD, 0, 0);
	case KGENOME_TEXTUAL_DEC_CUTTAIL:
		return plain(KUNCOAT_ALGO_CUTTAIL, 0, 0);
	case KGENOME_TEXTUAL_DEC_LENGTH:
		return plain(KUNCOAT_ALGO_LENGTH, 0, 0);
	case KGENOME_TEXTUAL_DEC_FORMAT:
		return plain(KUNCOAT_ALGO_FORMAT, 0, 0);
	case KGENOME_TEXTUAL_DEC_MAP:
		return plain(KUNCOAT_ALGO_MAP, 0, 0);
	default:
		return plain(KUNCOAT_ALGO_NONE, 0, 0);
	}
}

/* The two parameters of REPLACE and TRANSLATE are one key for kuncoat: the first then the second. */
/*
 * THE CALL'S FLAGS AS THE OP'S, the one table of the pairs (KGENOME_TEXTUAL_CALL_* -> KUNCOAT_F_*). All seven are carried to every op that takes flags; an op reads only its own bits
 * and ignores the rest - checked over every combination of the eight flags on every op that takes them (tests/unit/script_apply_flags.c), which is why the table needs no per-op mask.
 */
static uint32_t op_flags(const struct kgenome_textual_call *c)
{
	static const struct { uint32_t call, op; } map[] = {
		{ KGENOME_TEXTUAL_CALL_FIRST,     KUNCOAT_F_FIRST },
		{ KGENOME_TEXTUAL_CALL_ICASE,     KUNCOAT_F_ICASE },
		{ KGENOME_TEXTUAL_CALL_RANGES,    KUNCOAT_F_RANGES },
		{ KGENOME_TEXTUAL_CALL_DROPTRAIL, KUNCOAT_F_DROPTRAIL },
		{ KGENOME_TEXTUAL_CALL_WSLIST,    KUNCOAT_F_WSLIST },
		{ KGENOME_TEXTUAL_CALL_REUSE,     KUNCOAT_F_REUSE },
		{ KGENOME_TEXTUAL_CALL_ESC,       KUNCOAT_F_ESC },
	};
	uint32_t f = 0, i;

	for (i = 0; i < sizeof map / sizeof map[0]; i++)
		if (c->flags & map[i].call)
			f |= map[i].op;
	return f;
}

static int pair_step(const struct kgenome_textual_call *c, struct kuncoat_step *s, uint8_t **owned)
{
	uint8_t *k;

	*owned = NULL;
	if (c->op == KGENOME_TEXTUAL_DEC_TRANSLATE && !(c->flags & KGENOME_TEXTUAL_CALL_RANGES) && c->n1 != c->n2)
		return 0;       /* php's strtr with unequal lists uses the shorter; not read as the same function (tr's sets are checked by the op: RANGES) */
	k = malloc((size_t)c->n1 + c->n2 + 1u);
	if (!k)
		return 0;
	if (c->n1)
		memcpy(k, c->s1, c->n1);
	if (c->n2)
		memcpy(k + c->n1, c->s2, c->n2);
	*s = plain(c->op == KGENOME_TEXTUAL_DEC_REPLACE ? KUNCOAT_ALGO_REPLACE : KUNCOAT_ALGO_TRANSLATE, 0, c->n1);
	s->flags |= op_flags(c);
	s->key = k;
	s->key_len = c->n1 + c->n2;
	*owned = k;
	return 1;
}

int kof_script_apply(void *user, const struct kgenome_textual_call *c, const uint8_t *in, uint32_t len, uint8_t *out,
		     uint32_t cap, uint32_t *n_out)
{
	struct kuncoat_step s;
	uint8_t *owned = NULL;
	uint64_t produced = 0;
	enum kuncoat_status st;

	(void)user;
	*n_out = 0;
	if ((c->op == KGENOME_TEXTUAL_DEC_REPLACE || c->op == KGENOME_TEXTUAL_DEC_TRANSLATE) && !c->n1) {
		if (len > cap)          /* a search of nothing: the subject as it is */
			return 0;
		if (len)                /* an empty subject may come with no pointer */
			memcpy(out, in, len);
		*n_out = len;
		return 1;
	}
	if (c->op == KGENOME_TEXTUAL_DEC_REPLACE || c->op == KGENOME_TEXTUAL_DEC_TRANSLATE) {
		if (!pair_step(c, &s, &owned))
			return 0;
	} else {
		s = step_of(c);
		/* a separator (split, join), a cut's pattern, a mapping and a format's argument list are the call's parameter, the key of the op; its flags are the call's */
		if (c->op == KGENOME_TEXTUAL_DEC_SPLIT || c->op == KGENOME_TEXTUAL_DEC_JOIN || c->op == KGENOME_TEXTUAL_DEC_CUTHEAD ||
		    c->op == KGENOME_TEXTUAL_DEC_CUTTAIL || c->op == KGENOME_TEXTUAL_DEC_MAP || c->op == KGENOME_TEXTUAL_DEC_FORMAT) {
			s.key = c->s1;
			s.key_len = c->n1;
			s.flags |= op_flags(c);
		}
		/* a language's own white space (python's strip, vbscript's Trim): the bytes to take off are the call's, not php's */
		if (s.algo == KUNCOAT_ALGO_TRIM && (c->flags & KGENOME_TEXTUAL_CALL_SET)) {
			s.key = c->s1;
			s.key_len = c->n1;
		}
	}
	if (s.algo == KUNCOAT_ALGO_NONE) {
		free(owned);
		return 0;
	}
	if (!len && s.algo != KUNCOAT_ALGO_SPLIT && s.algo != KUNCOAT_ALGO_LENGTH && s.algo != KUNCOAT_ALGO_FORMAT) {
		free(owned);
		return 1;               /* every one of these maps nothing to nothing */
	}
	if (!in)                        /* a subject of nothing may come with no pointer; a split of it is one empty piece */
		in = (const uint8_t *)"";
	st = kuncoat_transform(&s, in, len, out, cap, &produced);
	free(owned);
	/* A decoder that read nothing it could use (base64 of no alphabet, hex of one digit) refuses; a string function
	 * that was given a subject and gave nothing (substr past the end) is an empty answer, and says OK. */
	if (st != KUNCOAT_OK || (!produced && c->op < KGENOME_TEXTUAL_DEC_REPLACE))
		return 0;
	*n_out = (uint32_t)produced;
	return 1;
}
