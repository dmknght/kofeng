/*
 * verdictor/verdict.c - how a verdict is spelled: the verdict word, the target, the type
 * and behaviour and what the engine says about how it was reached.
 *
 * kof_verdict_name composes the string once, forward, and records where each part
 * landed, so nothing downstream searches for a separator. Nothing here reads the scanner: what a
 * name is made of is passed in. Which diseases an object has and which diagnoses
 * matched are collected where the scan state is - see scanners/scan_verdict.c.
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
#include "../kofcore/kofmod/kofdiagtree.h"   /* KOF_DIAG_DISEASE_LEN */
#include "../analyzers/parsers/kofformat.h"

/*
 * `room` is how many characters this part may take, and the name's own end is the
 * other bound. A part that does not fit sets `name_cut` on the finding - the
 * name is a fixed array (kof_finding.name, ABI) and a cut must be a thing a
 * reader can see, not a shorter name that looks whole.
 */
static void span_put_n(struct kof_finding *f, struct kof_name_span *sp,
		       size_t *at, const char *text, size_t room)
{
	size_t n = 0;

	sp->at = (uint16_t)*at;
	if (text)
		while (text[n] && n < room && *at + n + 1u < sizeof f->name) {
			f->name[*at + n] = text[n];
			n++;
		}
	if (text && text[n])
		f->name_cut = 1;
	sp->n = (uint16_t)n;
	*at += n;
}

static void span_put(struct kof_finding *f, struct kof_name_span *sp,
		     size_t *at, const char *text)
{
	span_put_n(f, sp, at, text, (size_t)-1);
}

static void sep_put(struct kof_finding *f, size_t *at, char c)
{
	if (*at + 1u < sizeof f->name)
		f->name[(*at)++] = c;
	else
		f->name_cut = 1;
}

static size_t slen(const char *s)
{
	return s ? strlen(s) : 0u;
}

/*
 * WHAT THE FAMILY MAY TAKE: what is left of the name once every other part and
 * its separator is written. The family is the part that gives, because it is the
 * only one whose length the pack builder bounds loosely (KOF_NAME_MAX_LEN, 191
 * characters) while the engine word and the reason are what say how the verdict was
 * reached, which a cut at the tail would take with no word. `rest` is those other
 * bytes. When even they do not fit the family gets nothing to keep and the tail cut
 * applies (and is flagged).
 */
static size_t family_room(size_t rest)
{
	size_t total = sizeof ((struct kof_finding *)0)->name - 1u;

	return rest < total ? total - rest : 0u;
}

/*
 * GET THE VERDICT NAME - see kofeng.h for the form and why it lives here.
 *
 * Written once, forward, so every span falls out of the writing. The fields
 * it reads are the enums on the finding; the two it is handed are the ones
 * that cannot be enums - a behaviour a researcher chose, and a reason some
 * verdicts have and most do not.
 */
void kof_verdict_name(struct kof_finding *f, const char *family,
		      const char *reason)
{
	char tgt[32];
	size_t at = 0, rest;

	if (!f)
		return;
	f->target.at = f->target.n = 0;
	f->maltype = f->family = f->shape = f->reason = f->target;
	f->name_cut = 0;

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
	 * family, engine - is one run about one thing, and the
	 * narrow '!' keeps it reading as a run.
	 */
	sep_put(f, &at, '#');

	kverdict_target(tgt, sizeof tgt, f->fmt, f->arch);
	/* Everything but the family, so the family is what gives (see family_room). */
	rest = slen(kof_verdict_word(f->verdict)) + 1u + (tgt[0] ? strlen(tgt) + 1u : 0u) +
	       slen(kof_maltype_name(f->type)) + 1u +
	       (f->engine != (uint8_t)KOF_ENGINE_NONE ? 1u + slen(kof_engine_name(f->engine)) : 0u) +
	       (reason && reason[0] ? 1u + slen(reason) : 0u);
	if (tgt[0]) {
		span_put(f, &f->target, &at, tgt);
		sep_put(f, &at, '/');
	}

	/*
	 * WHAT IT IS. A type the database does not name reads "Malware" - see
	 * kof_maltype_name - and is never left out.
	 */
	span_put(f, &f->maltype, &at, kof_maltype_name(f->type));
	sep_put(f, &at, ':');
	span_put_n(f, &f->family, &at, family, family_room(rest) ? family_room(rest) : (size_t)-1);

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

/* ---- the verdict of an object, from its diseases ------------------------------ */

/* How many parts a behaviour path has: "flood-network/raw-header" is two. */
static unsigned dis_parts(const struct kof_verdict_disease *d)
{
	unsigned n = 1;
	const char *p;

	if (!d->name || !d->name[0])
		return 0;
	for (p = d->name; *p; p++)
		n += *p == '/';
	return n;
}

/* Whether `a` leads `b`: more parts, then the lower type, then the lower id. */
static int dis_leads(const struct kof_verdict_disease *a, const struct kof_verdict_disease *b)
{
	unsigned pa = dis_parts(a), pb = dis_parts(b);

	if (pa != pb)
		return pa > pb;
	if (a->type != b->type)
		return a->type < b->type;
	return a->id < b->id;
}

/*
 * THE OBJECT'S VERDICT, from the diseases it has. Detection is one disease or more
 * (an OR: the first is enough). The name is a function of the diseases' type and
 * behaviour and of nothing else, so the same set of diseases is always called the
 * same thing:
 *
 *   <Type>:<behaviour>[?<other types>]
 *
 * The LEAD disease is the most specific - the behaviour path with the most parts,
 * then the lower type, then the lower id. Its type is the Type, its behaviour (the
 * path, '/' written '.') the family slot. Types the other diseases carry that the
 * lead's does not are the reason, joined with '+', in the order the types are
 * listed. A disease the database does not name is typed "Malware" and called
 * "unnamed" rather than left out: nothing found is dropped from the name's inputs.
 *
 * The finding carries what it was made of - the diseases and the diagnoses that
 * matched, each bounded by KOF_VERDICT_TRACE and with its true total beside it.
 */
void kof_verdict_make(const struct kof_verdict_in *in, struct kof_finding *f)
{
	const struct kof_verdict_disease *lead = NULL;
	char family[KOF_DIAG_DISEASE_LEN + 2u], rest[96];
	uint32_t i, others = 0, t;
	size_t at = 0;

	memset(f, 0, sizeof *f);
	f->fmt = in->fmt;
	f->arch = in->arch;
	f->engine = (uint8_t)(in->n_diag ? KOF_ENGINE_DIAGNOSE : KOF_ENGINE_NONE);
	f->verdict = (uint8_t)KOF_VERDICT_INFECTED;
	for (i = 0; i < in->n_dis; i++)
		if (!lead || dis_leads(&in->dis[i], lead))
			lead = &in->dis[i];
	f->type = (uint8_t)(lead && lead->type < (uint8_t)KOF_MALTYPE_COUNT
			    ? lead->type : (uint8_t)KOF_MALTYPE_COUNT);
	snprintf(family, sizeof family, "%s", lead && lead->name && lead->name[0]
		 ? lead->name : "unnamed");
	for (i = 0; family[i]; i++)
		if (family[i] == '/')
			family[i] = '.';
	for (i = 0; i < in->n_dis; i++)
		if (in->dis[i].type < (uint8_t)KOF_MALTYPE_COUNT &&
		    in->dis[i].type != f->type)
			others |= 1u << in->dis[i].type;
	rest[0] = 0;
	for (t = 0; t < (uint32_t)KOF_MALTYPE_COUNT; t++) {
		const char *w;

		if (!((others >> t) & 1u))
			continue;
		w = kof_maltype_name(t);
		if (at + strlen(w) + 2u >= sizeof rest)
			break;
		if (at)
			rest[at++] = '+';
		memcpy(rest + at, w, strlen(w));
		at += strlen(w);
		rest[at] = 0;
	}
	kof_verdict_name(f, family, rest[0] ? rest : NULL);

	f->disease_total = in->n_dis;
	f->n_disease = in->n_dis < KOF_VERDICT_TRACE ? in->n_dis : KOF_VERDICT_TRACE;
	for (i = 0; i < f->n_disease; i++)
		f->disease[i] = in->dis[i].id;
	f->diag_total = in->n_diag;
	f->n_diag = in->n_diag < KOF_VERDICT_TRACE ? in->n_diag : KOF_VERDICT_TRACE;
	for (i = 0; i < f->n_diag; i++)
		f->diag[i] = in->diag[i];
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
	m->idx[slot] = (uint32_t)(m->n + 1u);
	m->n++;
	return e;
}

struct kverdict_file *kverdict_filemap_fold(kverdict_filemap *m, const char *object,
					    const struct kof_result *res,
					    int keep_clean)
{
	size_t flen;
	struct kverdict_file *e;

	if (!m || !object || !res)
		return NULL;
	flen = kobj_toplevel_len(object);
	/* Each top-level FILE counted once: a root is the object whose name carries no
	 * separator, the one the engine puts between a parent and what it produced. */
	if (flen == strlen(object))
		m->files++;
	/* An object with a verdict, a broken reason or no module eligible for it always
	 * gets an entry: it is not clean, and without one it would vanish into the clean
	 * count by subtraction. Evidence alone (kof_result.v) is not a verdict and
	 * does not make an entry. */
	if (!(res->has_verdict || res->broken || !res->examined || keep_clean))
		return NULL;
	e = file_get(m, object, flen);
	if (!e)
		return NULL;
	/* The file's verdict is the first one made in its tree: the walk is parent
	 * first, and a verdict has no rank - what an object is called is a function
	 * of its diseases and of nothing else. */
	if (res->has_verdict && !e->has_verdict) {
		/* bounded by the array the name lives in: a finding handed in from elsewhere
		 * need not be terminated */
		size_t nl = strnlen(res->verdict.name, sizeof res->verdict.name);

		e->has_verdict = 1;
		snprintf(e->name, sizeof e->name, "%.*s", (int)nl, res->verdict.name);
	}
	if (res->broken && !e->broken)
		e->broken = res->broken;
	if (res->examined)
		e->examined = 1;
	return e;
}
