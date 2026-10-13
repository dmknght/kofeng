/*
 * syndrome.c - the verdict that comes from diseases: what an object has, and what
 * that makes.
 *
 * The scan stage COLLECTS (the modules' diseases as they report, the diagnoses'
 * on demand, in objctx_diag.c; scanners/scan_verdict.c reads the collection) and
 * this infers a name from the result - the inference itself is
 * databases/pack/kofsyndrome.c. It knows nothing of a scanner: its input is a
 * struct kof_verdict_in.
 */

#define _GNU_SOURCE

#include <string.h>

#include "../kofcore/koftypes.h"
#include "verdict.h"
#include "../kofcore/kofmod/kofsig.h"

static unsigned type_bit(uint32_t mask)
{
	unsigned t = 0;

	while (t < 32u && !((mask >> t) & 1u))
		t++;
	return t;
}

/* The types of `mask` but the first, "A+B" - a name has one type word, so the
 * rest ride in the reason. */
static void types_rest(uint32_t mask, char *out, size_t cap)
{
	unsigned t;
	size_t at = 0;

	out[0] = 0;
	for (t = type_bit(mask) + 1u; t < 32u; t++) {
		const char *w;

		if (!((mask >> t) & 1u))
			continue;
		w = kof_maltype_name(t);
		if (at + strlen(w) + 2u >= cap)
			break;
		if (at)
			out[at++] = '+';
		memcpy(out + at, w, strlen(w));
		at += strlen(w);
		out[at] = 0;
	}
}

/*
 * THE OBJECT'S VERDICT, from the diseases it has. The stage that asks runs once
 * per object, after every detector, rule and diagnose has said what it found, and
 * this is where that becomes a name. It reads what the scanner passed in (struct
 * kof_verdict_in) and nothing of the scanner:
 *
 *   a type proven            Infected  <type>:Agent
 *   one type left possible   Suspected <type>:Agent.Predict
 *   several left possible    Suspected Malware:Ambiguous?<types>
 *   no sample to read it by  Infected  Malware:Unresolved
 *
 * The grammar is kofsyndrome.h's and is still hard-coded there for the same
 * reason; what is written here is how it lands in a finding, and nothing else
 * decides a verdict from the diseases.
 */
void kof_verdict_syndrome(const struct kof_verdict_in *in, struct kof_finding *f)
{
	const struct kof_synd_result *r = in->synd;
	const char *family = "Agent", *variant = NULL;
	char rest[96];
	uint32_t m;

	memset(f, 0, sizeof *f);
	f->fmt = in->fmt;
	f->arch = in->arch;
	f->engine = (uint8_t)KOF_ENGINE_SYNDROME;
	f->type_known = 1;
	rest[0] = 0;
	if (r->guaranteed) {
		m = r->guaranteed;
		f->level = KOF_LEVEL_INFECT;
		f->type = (uint8_t)type_bit(m);
		types_rest(m, rest, sizeof rest);
	} else if (r->possible && !(r->possible & (r->possible - 1u))) {
		f->level = KOF_LEVEL_SUSPECT;
		f->type = (uint8_t)type_bit(r->possible);
		variant = "Predict";
	} else if (r->possible) {
		f->level = KOF_LEVEL_SUSPECT;
		f->type = (uint8_t)KOF_MALTYPE_COUNT;   /* "Malware": not one of them */
		family = "Ambiguous";
		/* every candidate, comma-separated: none of them is the type word */
		{
			unsigned t;
			size_t at = 0;

			for (t = 0; t < 32u; t++) {
				const char *w;

				if (!((r->possible >> t) & 1u))
					continue;
				w = kof_maltype_name(t);
				if (at + strlen(w) + 2u >= sizeof rest)
					break;
				if (at)
					rest[at++] = ',';
				memcpy(rest + at, w, strlen(w));
				at += strlen(w);
				rest[at] = 0;
			}
		}
	} else {
		f->level = KOF_LEVEL_INFECT;
		f->type = (uint8_t)KOF_MALTYPE_COUNT;
		family = "Unresolved";
	}
	f->verdict = (uint8_t)(f->level == KOF_LEVEL_INFECT ? KOF_VERDICT_INFECTED
							    : KOF_VERDICT_SUSPECTED);
	kof_verdict_name(f, family, variant, rest[0] ? rest : NULL);
}
