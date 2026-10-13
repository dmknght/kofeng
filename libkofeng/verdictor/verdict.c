/*
 * verdictor/verdict.c - naming a finding: the verdict word, the target, the family
 * and what the engine says about how it was reached.
 *
 * kverdict_* compose the string once, forward, and record where each part landed, so
 * nothing downstream searches for a separator. Nothing here reads the scanner: what a
 * name is made of is passed in. Which method word a finding carries and which finding
 * owns the object's one verdict slot are decided where the scan state is - see
 * scanners/scan_verdict.c.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../kofcore/koftypes.h"
#include "../kofcore/kofcore.h"   /* kof_hash_bytes */
#include "verdict.h"
#include "../kofcore/kofmod/kofsig.h"
#include "../kofcore/kofmod/script.h"
#include "../analyzers/parsers/kofformat.h"

/*
 * The one spelling. See kverdict_compose in kofeng.h for why it is a function.
 *
 * "#" between the family and the variant, not "-": a family name may contain a
 * hyphen and several in bases/ do, so the old separator could not be told from
 * the name around it by eye or by anything reading the string back. "#" appears
 * in no family and in no variant.
 */
void kverdict_compose(char *out, size_t cap, const char *target,
		      const char *maltype, const char *family,
		      const char *variant)
{
	int has_t = target && target[0];
	int has_v = variant && variant[0];

	if (!out || !cap)
		return;
	if (has_t && has_v)
		snprintf(out, cap, "%s/%s:%s#%s", target, maltype, family,
			 variant);
	else if (has_t)
		snprintf(out, cap, "%s/%s:%s", target, maltype, family);
	else if (has_v)
		snprintf(out, cap, "%s:%s#%s", maltype, family, variant);
	else
		snprintf(out, cap, "%s:%s", maltype, family);
}

/*
 * Compose onto a finding, and say where each part went.
 *
 * Written once, forward, so the offsets fall out of the writing rather than
 * being searched for afterwards - which is the whole point: nothing downstream
 * should ever have to look for a separator this function just placed.
 */
static void span_put(struct kof_finding *f, struct kof_name_span *sp,
		     size_t *at, const char *text)
{
	size_t n = 0;

	sp->at = (uint16_t)*at;
	if (text)
		while (text[n] && *at + n + 1u < sizeof f->name) {
			f->name[*at + n] = text[n];
			n++;
		}
	sp->n = (uint16_t)n;
	*at += n;
}

static void sep_put(struct kof_finding *f, size_t *at, char c)
{
	if (*at + 1u < sizeof f->name)
		f->name[(*at)++] = c;
}

void kverdict_name(struct kof_finding *f, const char *target,
		      const char *maltype, const char *family,
		      const char *variant, const char *shape)
{
	size_t at = 0;

	if (!f)
		return;
	f->target.at = f->target.n = 0;
	f->maltype = f->family = f->variant = f->shape = f->target;

	if (target && target[0]) {
		span_put(f, &f->target, &at, target);
		sep_put(f, &at, '/');
	}
	span_put(f, &f->maltype, &at, maltype);
	sep_put(f, &at, ':');
	span_put(f, &f->family, &at, family);
	if (variant && variant[0]) {
		sep_put(f, &at, '#');
		span_put(f, &f->variant, &at, variant);
	}
	if (shape && shape[0]) {
		/*
		 * "!" AND NOT "?".
		 *
		 * The mark says HOW the verdict was reached - a shape a
		 * heuristic recognised, a similarity measurement - and "?"
		 * reads as doubt about the whole name rather than as a label on
		 * the part after it. A reader scanning a log sees
		 * "Heur:Meterp#3!Shellcode" as a finding with its method
		 * attached, where the same line with a question mark reads as
		 * the engine being unsure it found anything.
		 */
		sep_put(f, &at, '!');
		span_put(f, &f->shape, &at, shape);
	}
	f->name[at] = 0;
}

/*
 * GET THE VERDICT NAME - see kofeng.h for the form and why it lives here.
 *
 * Written once, forward, so every span falls out of the writing. The fields
 * it reads are the enums on the finding; the three it is handed are the ones
 * that cannot be enums - a family a researcher chose, a variant, and a
 * reason some findings have and most do not.
 */
void kof_verdict_name(struct kof_finding *f, const char *family,
		      const char *variant, const char *reason)
{
	char tgt[32];
	size_t at = 0;

	if (!f)
		return;
	f->target.at = f->target.n = 0;
	f->maltype = f->family = f->variant = f->shape = f->reason = f->target;

	/*
	 * How sure, first, because that is what a reader sorts a log by. No
	 * span: the word is kof_verdict_word(f->verdict) and a caller that
	 * wants it has the value, so recording where it landed would be a
	 * second copy of a fact that cannot drift from itself.
	 */
	span_put(f, &f->target, &at, kof_verdict_word(f->verdict));
	f->target.at = f->target.n = 0;
	/*
	 * A HASH HERE AND A BANG LATER, and the reason is typographic
	 * rather than semantic: '#' is the wider glyph, so it makes the
	 * stronger break, and the strongest break in this name is between
	 * how sure the engine is and everything else. What follows -
	 * family, variant, engine - is one run about one thing, and the
	 * narrow '!' keeps it reading as a run.
	 */
	sep_put(f, &at, '#');

	kverdict_target(tgt, sizeof tgt, f->fmt, f->arch);
	if (tgt[0]) {
		span_put(f, &f->target, &at, tgt);
		sep_put(f, &at, '/');
	}

	/*
	 * WHAT IT IS. A rule that recognised a shape has not established a
	 * class and says so - `type_known` is 0 - and then the word is the
	 * one the vocabulary already has for "a rule, not a signature".
	 * Writing a maltype there would be claiming something nobody did.
	 */
	span_put(f, &f->maltype, &at,
		 f->type_known ? kof_maltype_name(f->type) : "Heur");
	sep_put(f, &at, ':');
	span_put(f, &f->family, &at, family);

	if (variant && variant[0]) {
		/*
		 * A DOT, because a variant is part of the family's name and
		 * not a mark against it: "Mirai.01" reads as one name with a
		 * generation, where "Mirai!01" reads as two things stuck
		 * together.
		 */
		sep_put(f, &at, '.');
		span_put(f, &f->variant, &at, variant);
	}
	if (f->engine != (uint8_t)KOF_ENGINE_NONE) {
		/* Attached, not separated: how it was found is an addition
		 * to the name above it, not a new field of equal weight. */
		sep_put(f, &at, '!');
		span_put(f, &f->shape, &at, kof_engine_name(f->engine));
	}
	if (reason && reason[0]) {
		sep_put(f, &at, '?');
		span_put(f, &f->reason, &at, reason);
	}
	f->name[at] = 0;
}

/*
 * "ELF-x64", or "ELF" when there is no architecture to name.
 *
 * An object with no architecture - a script, or one nothing identified - gets
 * the format alone: a "-any" suffix would be a field describing nothing.
 */
void kverdict_target(char *out, size_t cap, uint8_t format, uint8_t arch)
{
	const char *fmt = kof_format_name(format);

	if (arch == KGENOME_ARCH_ANY || format == KOF_FMT_UNKNOWN)
		snprintf(out, cap, "%s", fmt);
	else
		snprintf(out, cap, "%s-%s", fmt, kof_arch_name(arch));
}

/*
 * WHAT TO CALL AN OBJECT - see kof_object_label in kofeng.h.
 *
 * The order is the order of how much each answer says: the module that opened
 * the object says the most, a normalised view says what it is a view of, a
 * script says its language, and the format's name is what is left.
 */
void kof_object_label(uint32_t entry_kind, const char *packer, uint8_t format,
		      uint8_t subtype, char *out, size_t cap)
{
	const char *w;

	if (!out || !cap)
		return;
	if (packer && packer[0])
		w = packer;
	else if (entry_kind == KOF_ENT_NORMALIZED)
		w = "Norm";
	else if (format == KOF_FMT_SCRIPT && subtype != KOF_SCRIPT_ANY)
		w = kof_script_type_name(subtype);
	else
		w = kof_format_name(format);
	snprintf(out, cap, "%s", w);
}

/* ---- one verdict per top-level file ---------------------------------------- */

/*
 * A small open-addressed map keyed by the file name, because the objects of one file
 * need not arrive together (see verdict.h) and so a running "current file" cannot be
 * trusted. The entries are kept in first-seen order for a listing; the index holds
 * (array position + 1) and zero means empty, and grows when half full so probe chains
 * stay short.
 */
struct kverdict_filemap {
	struct kverdict_file *arr;
	size_t                n, cap;
	uint32_t             *idx;
	size_t                icap;       /* a power of two */
	uint64_t              files;      /* roots folded, clean ones included */
};

kverdict_filemap *kverdict_filemap_new(void)
{
	return calloc(1, sizeof(struct kverdict_filemap));
}

void kverdict_filemap_free(kverdict_filemap *m)
{
	size_t i;

	if (!m)
		return;
	for (i = 0; i < m->n; i++)
		free((void *)(uintptr_t)m->arr[i].file);   /* the map made it */
	free(m->arr);
	free(m->idx);
	free(m);
}

size_t kverdict_filemap_count(const kverdict_filemap *m)
{
	return m ? m->n : 0;
}

struct kverdict_file *kverdict_filemap_at(kverdict_filemap *m, size_t i)
{
	return m && i < m->n ? &m->arr[i] : NULL;
}

uint64_t kverdict_filemap_files(const kverdict_filemap *m)
{
	return m ? m->files : 0;
}

/* The engine's own FNV, not a second one - see kofcore.h. */
static uint32_t file_hash(const char *s, size_t n)
{
	return (uint32_t)kof_hash_bytes(s, (uint64_t)n);
}

/* The slot of `file`, or of the empty one it would take. */
static size_t file_slot(const kverdict_filemap *m, const char *file, size_t flen)
{
	size_t slot = file_hash(file, flen) & (uint32_t)(m->icap - 1u);

	for (; m->idx[slot]; slot = (slot + 1u) & (uint32_t)(m->icap - 1u)) {
		const struct kverdict_file *e = &m->arr[m->idx[slot] - 1u];

		if (strlen(e->file) == flen && !memcmp(e->file, file, flen))
			break;
	}
	return slot;
}

struct kverdict_file *kverdict_filemap_find(kverdict_filemap *m, const char *file,
					    size_t flen)
{
	size_t slot;

	if (!m || !m->icap)
		return NULL;
	slot = file_slot(m, file, flen);
	return m->idx[slot] ? &m->arr[m->idx[slot] - 1u] : NULL;
}

/* Find the file's entry, creating it if new. NULL only on OOM. */
static struct kverdict_file *file_get(kverdict_filemap *m, const char *file, size_t flen)
{
	size_t slot;
	struct kverdict_file *e;
	char *copy;

	/* Grow the index when it is half full. */
	if (m->n * 2u >= m->icap) {
		size_t nc = m->icap ? m->icap * 2u : 256u;
		uint32_t *ni = calloc(nc, sizeof *ni);
		size_t i;

		if (!ni)
			return NULL;
		for (i = 0; i < m->n; i++) {
			size_t s = file_hash(m->arr[i].file, strlen(m->arr[i].file)) &
				   (uint32_t)(nc - 1u);

			while (ni[s])
				s = (s + 1u) & (uint32_t)(nc - 1u);
			ni[s] = (uint32_t)(i + 1u);
		}
		free(m->idx);
		m->idx = ni;
		m->icap = nc;
	}
	slot = file_slot(m, file, flen);
	if (m->idx[slot])
		return &m->arr[m->idx[slot] - 1u];

	/* New file: append an entry and point the slot at it. */
	if (m->n == m->cap) {
		size_t nc = m->cap ? m->cap * 2u : 128u;
		struct kverdict_file *na = realloc(m->arr, nc * sizeof *na);

		if (!na)
			return NULL;
		m->arr = na;
		m->cap = nc;
	}
	copy = malloc(flen + 1u);
	if (!copy)
		return NULL;
	memcpy(copy, file, flen);
	copy[flen] = 0;
	/* The array is realloc'd, never zeroed, so every field is set here. */
	e = &m->arr[m->n];
	memset(e, 0, sizeof *e);
	e->file = copy;
	e->level = -1;
	m->idx[slot] = (uint32_t)(m->n + 1u);
	m->n++;
	return e;
}

/* The worst of an object's findings, by rank - never by the numbers of the levels. */
static const struct kof_finding *worst_finding(const struct kof_result *res)
{
	const struct kof_finding *w = NULL;
	uint32_t i;

	for (i = 0; i < res->n; i++)
		if (!w || kverdict_level_rank(res->v[i].level) >
			  kverdict_level_rank(w->level))
			w = &res->v[i];
	return w;
}

struct kverdict_file *kverdict_filemap_fold(kverdict_filemap *m, const char *object,
					    const struct kof_result *res,
					    int keep_clean)
{
	size_t flen;
	const struct kof_finding *w;
	struct kverdict_file *e;

	if (!m || !object || !res)
		return NULL;
	flen = kobj_toplevel_len(object);
	/* Each top-level FILE counted once: a root is the object whose name carries no
	 * separator, the one the engine puts between a parent and what it produced. */
	if (flen == strlen(object))
		m->files++;
	/* Non-clean objects always get an entry so the file is counted, and so does an
	 * object nothing was eligible for - it is not clean, and without an entry it would
	 * vanish into the clean count by subtraction. */
	if (!(res->n || res->broken || !res->examined || keep_clean))
		return NULL;
	e = file_get(m, object, flen);
	if (!e)
		return NULL;
	w = worst_finding(res);
	if (w && kverdict_level_rank(w->level) > kverdict_level_rank((uint32_t)e->level)) {
		e->level = (int)w->level;
		snprintf(e->name, sizeof e->name, "%s", w->name);
		/* The shape when the rule offered one, the family when it did not - the choice
		 * made on the engine's spans and not on the punctuation between them. */
		e->kind[0] = 0;
		if (kverdict_is_heur(w)) {
			const struct kof_name_span *k = w->shape.n ? &w->shape : &w->family;

			snprintf(e->kind, sizeof e->kind, "%.*s", (int)k->n, w->name + k->at);
		}
	}
	if (res->broken && !e->broken)
		e->broken = res->broken;
	if (res->examined)
		e->examined = 1;
	return e;
}
